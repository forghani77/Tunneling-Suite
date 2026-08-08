package protocol

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

// wgProto tunnels datagrams through a real kernel WireGuard interface,
// configured with iproute2 (`ip`) and wireguard-tools (`wg`). Both ends must
// run as root and have the wireguard kernel module available; otherwise the
// protocol reports itself unavailable and is skipped.
//
// Data plane: the client sends UDP test frames to the server's internal
// tunnel address (10.9.0.1); the kernel routes them through the encrypted
// WireGuard interface to the server's wireguard UDP listener.
//
// Control plane: a short TCP exchange on the protocol's control port swaps
// public keys and the server's internal echo address.
type wgProto struct{}

func (wgProto) Name() string    { return "wireguard" }
func (wgProto) Kind() Kind      { return KindDatagram }
func (wgProto) Overhead() int   { return 88 } // 20 outer IP + 8 UDP + 32 WG + 20 inner IP + 8 UDP
func (wgProto) NeedsRoot() bool { return true }

const (
	wgServerIP = "10.9.0.1"
	wgClientIP = "10.9.0.2"
	wgPrefix   = "wgts" // interface name prefix (kept short for IFNAMSIZ=15)

	// wgControlTimeout bounds the whole client key exchange (TCP connect +
	// read) and each server-side handshake read. A peer that accepts TCP but
	// never speaks the protocol — e.g. an unrelated service squatting on the
	// control port, or a blind-mode probe of an absent protocol — must not
	// hang the dial or stall the accept loop forever.
	wgControlTimeout = 10 * time.Second
)

// wgServerInfo is exchanged over the control connection during setup.
type wgServerInfo struct {
	ServerPub  string `json:"server_pub"`
	InternalIP string `json:"internal_ip"`
	EchoPort   int    `json:"echo_port"`
}

func checkWGTools() error {
	if _, err := exec.LookPath("ip"); err != nil {
		return fmt.Errorf("iproute2 'ip' not found")
	}
	if _, err := exec.LookPath("wg"); err != nil {
		return fmt.Errorf("wireguard-tools 'wg' not found")
	}
	return nil
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// wgTempKeyFile writes a raw 32-byte key to a temporary file in base64 form.
// The wg(8) CLI treats `private-key` values as file paths, so keys must be
// passed by file; peer public keys are passed inline as base64.
func wgTempKeyFile(key []byte) (string, error) {
	f, err := os.CreateTemp("", "tunnelsuit-wgkey-*")
	if err != nil {
		return "", err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// wgSetPrivateKey runs `wg set <iface> private-key <file>`.
func wgSetPrivateKey(iface string, priv []byte) error {
	path, err := wgTempKeyFile(priv)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	return runCmd("wg", "set", iface, "private-key", path)
}

// wgKeypair generates a WireGuard private/public key pair.
func wgKeypair() (priv, pub []byte, err error) {
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return nil, nil, err
	}
	// Curve25519 clamping
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	return priv, pub, err
}

func wgIfaceName() string {
	// Keep the name short: interface names are limited to 15 chars (IFNAMSIZ).
	var b [2]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s%d%x", wgPrefix, os.Getpid()%100000, b)
}

func wgPortOffset(ctlPort int) int { return ctlPort + 1 }

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

type wgServer struct {
	iface      string
	ifaceReady bool
	pub        []byte
	ctl        net.Listener
	echo       *udpServer
	prevPeer   string // pubkey of the previously configured client peer
	closeOnce  sync.Once
}

func (wgProto) Listen(addr string, opts Options) (ProtoServer, error) {
	if err := checkWGTools(); err != nil {
		return nil, err
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ctlPort, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	udpPort := wgPortOffset(ctlPort)
	iface := wgIfaceName()

	// 1. Bring up the kernel WireGuard interface.
	if err := runCmd("ip", "link", "add", iface, "type", "wireguard"); err != nil {
		return nil, fmt.Errorf("create wireguard interface: %w (is the kernel module loaded?)", err)
	}
	cleanupIface := true
	defer func() {
		if cleanupIface {
			_ = runCmd("ip", "link", "del", iface)
		}
	}()

	priv, pub, err := wgKeypair()
	if err != nil {
		return nil, err
	}
	if err := runCmd("ip", "addr", "add", wgServerIP+"/24", "dev", iface); err != nil {
		return nil, err
	}
	if err := runCmd("wg", "set", iface, "listen-port", strconv.Itoa(udpPort)); err != nil {
		return nil, err
	}
	if err := wgSetPrivateKey(iface, priv); err != nil {
		return nil, err
	}
	if err := runCmd("ip", "link", "set", iface, "up"); err != nil {
		return nil, err
	}

	// 2. Echo listener bound to the internal tunnel address.
	server, err := (&udpProto{}).Listen(JoinHostPort(wgServerIP, 0), opts)
	if err != nil {
		return nil, err
	}
	echoSrv := server.(*udpServer)

	// 3. Control listener for key exchange.
	ctl, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	cleanupIface = false
	return &wgServer{iface: iface, ifaceReady: true, pub: pub, ctl: ctl, echo: echoSrv}, nil
}

// Accept performs the key exchange, configures the peer, then waits for the
// first datagram arriving through the encrypted tunnel. Transient per-client
// handshake failures are logged and skipped so a misbehaving client cannot
// take down the protocol for everyone else; only listener closure (shutdown)
// is reported as an error.
func (s *wgServer) Accept() (Tunnel, error) {
	for {
		c, err := s.ctl.Accept()
		if err != nil {
			return nil, err
		}
		tun, err := s.acceptClient(c)
		_ = c.Close()
		if err != nil {
			log.Printf("wireguard handshake failed: %v", err)
			continue
		}
		return tun, nil
	}
}

// acceptClient runs the key exchange for a single control connection.
func (s *wgServer) acceptClient(c net.Conn) (Tunnel, error) {
	// Bound the handshake (same pattern as the smtp protocol): a peer that
	// connects and never sends a line must not stall the accept loop for
	// every other client.
	_ = c.SetDeadline(time.Now().Add(wgControlTimeout))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read client pubkey: %w", err)
	}
	clientPubHex := strings.TrimSpace(line)
	clientPub, err := hex.DecodeString(clientPubHex)
	if err != nil {
		return nil, fmt.Errorf("bad client pubkey: %w", err)
	}
	// Drop the previous client's peer so repeated tests do not accumulate
	// overlapping allowed-IPs on the same interface. Note: `peer` keys must be
	// base64 for wg(8) (hex would fail parsing and be silently discarded).
	peerB64 := base64.StdEncoding.EncodeToString(clientPub)
	if s.prevPeer != "" {
		_ = runCmd("wg", "set", s.iface, "peer", s.prevPeer, "remove")
	}
	if err := runCmd("wg", "set", s.iface,
		"peer", peerB64,
		"allowed-ips", wgClientIP+"/32"); err != nil {
		return nil, err
	}
	s.prevPeer = peerB64

	echoPort := s.echo.LocalAddr().(*net.UDPAddr).Port
	info := wgServerInfo{
		ServerPub:  hex.EncodeToString(s.pub),
		InternalIP: wgServerIP,
		EchoPort:   echoPort,
	}
	if err := json.NewEncoder(c).Encode(info); err != nil {
		return nil, err
	}
	// Wait for the client's interface to come up and the first encrypted
	// packet to arrive on the echo socket.
	return s.echo.Accept()
}

func (s *wgServer) Close() error {
	s.closeOnce.Do(func() {
		_ = s.ctl.Close()
		_ = s.echo.Close()
		if s.ifaceReady {
			if err := runCmd("ip", "link", "del", s.iface); err != nil {
				log.Printf("warning: failed to delete wireguard interface %s: %v", s.iface, err)
			}
		}
	})
	return nil
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

type wgClientTunnel struct {
	*datagramTunnel
	iface      string
	ifaceReady bool
	closeOnce  sync.Once
}

func (t *wgClientTunnel) Close() error {
	t.closeOnce.Do(func() {
		_ = t.datagramTunnel.Close()
		if t.ifaceReady {
			if err := runCmd("ip", "link", "del", t.iface); err != nil {
				log.Printf("warning: failed to delete wireguard interface %s: %v", t.iface, err)
			}
		}
	})
	return nil
}

func (wgProto) Dial(addr string, opts Options) (Tunnel, error) {
	if err := checkWGTools(); err != nil {
		return nil, err
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ctlPort, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	udpPort := wgPortOffset(ctlPort)

	// 1. Control connection: exchange keys.
	c, err := net.DialTimeout("tcp", addr, wgControlTimeout)
	if err != nil {
		return nil, err
	}
	// Bound the key exchange (same pattern as the smtp protocol): a service
	// squatting on the control port that accepts TCP but never sends the
	// server info would otherwise hang the dial forever (the benchmark's
	// per-protocol budget only starts after Dial returns).
	_ = c.SetDeadline(time.Now().Add(wgControlTimeout))
	priv, pub, err := wgKeypair()
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if _, err := fmt.Fprintf(c, "%s\n", hex.EncodeToString(pub)); err != nil {
		_ = c.Close()
		return nil, err
	}
	var info wgServerInfo
	if err := json.NewDecoder(c).Decode(&info); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("key exchange failed (is another service on this port?): %w", err)
	}
	_ = c.Close()

	// 2. Bring up the local interface.
	iface := wgIfaceName()
	if err := runCmd("ip", "link", "add", iface, "type", "wireguard"); err != nil {
		return nil, fmt.Errorf("create wireguard interface: %w (is the kernel module loaded?)", err)
	}
	cleanupIface := true
	defer func() {
		if cleanupIface {
			_ = runCmd("ip", "link", "del", iface)
		}
	}()

	if err := runCmd("ip", "addr", "add", wgClientIP+"/24", "dev", iface); err != nil {
		return nil, err
	}
	endpoint := net.JoinHostPort(host, strconv.Itoa(udpPort))
	serverPub, err := hex.DecodeString(info.ServerPub)
	if err != nil {
		return nil, fmt.Errorf("bad server pubkey: %w", err)
	}
	if err := wgSetPrivateKey(iface, priv); err != nil {
		return nil, err
	}
	if err := runCmd("wg", "set", iface,
		"peer", base64.StdEncoding.EncodeToString(serverPub),
		"endpoint", endpoint,
		"allowed-ips", info.InternalIP+"/32",
		"persistent-keepalive", "5"); err != nil {
		return nil, err
	}
	if err := runCmd("ip", "link", "set", iface, "up"); err != nil {
		return nil, err
	}

	// 3. Datagram channel into the tunnel.
	ra := &net.UDPAddr{IP: net.ParseIP(info.InternalIP), Port: info.EchoPort}
	conn, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(wgClientIP), Port: 0}, ra)
	if err != nil {
		return nil, err
	}

	cleanupIface = false
	return &wgClientTunnel{
		datagramTunnel: &datagramTunnel{c: conn, label: "wireguard://" + addr},
		iface:          iface,
		ifaceReady:     true,
	}, nil
}
