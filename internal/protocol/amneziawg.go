package protocol

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// awgControlTimeout bounds the whole client key exchange (TCP connect + read)
// and each server-side handshake read. A peer that accepts TCP but never
// speaks the protocol — e.g. an unrelated service squatting on the control
// port, or a blind-mode probe of an absent protocol — must not hang the dial
// or stall the accept loop forever.
const awgControlTimeout = 10 * time.Second

// amneziaProto tunnels datagrams through AmneziaWG — the WireGuard fork with
// anti-DPI obfuscation — using the userspace amneziawg-go implementation over
// a TUN interface (requires root + /dev/net/tun; no kernel module needed).
//
// Two variants are provided:
//
//   - "amnezia"  (v1): junk packets (Jc/Jmin/Jmax), handshake padding (S1/S2)
//     and dynamic packet headers (H1–H4).
//   - "amnezia2" (v2): everything from v1 plus the CPS concealment-packet
//     tags (I1–I5), controlled junk (J1–J3) and the junk timeout (ITime).
//
// The obfuscation parameters must match on both ends; they are configured
// identically by this harness via the device's UAPI (IpcSet).
//
// Data plane: identical to the WireGuard protocol — the client sends UDP test
// frames to the server's internal tunnel address; the kernel routes them into
// the TUN, amneziawg-go encrypts them, and the peer's device decrypts them
// back onto its TUN.
type amneziaProto struct {
	params awgParams
}

func (p amneziaProto) Name() string    { return p.params.Name }
func (p amneziaProto) Kind() Kind      { return KindDatagram }
func (p amneziaProto) Overhead() int   { return p.params.overhead }
func (p amneziaProto) NeedsRoot() bool { return true }

// awgParams holds the AmneziaWG obfuscation parameters. Both ends of a tunnel
// must use identical values.
type awgParams struct {
	Name     string
	ServerIP string
	ClientIP string
	overhead int

	// Classic (v1) parameters.
	Jc, Jmin, Jmax, S1, S2 int
	H1, H2, H3, H4         uint32

	// 2.0 (CPS) parameters — empty for the v1 variant.
	I1, I2, I3, I4, I5 string
	J1, J2, J3         string
	ITime              int // seconds
}

// awgV1 is AmneziaWG 1.x with the classic obfuscation parameters.
var awgV1 = awgParams{
	Name: "amnezia", ServerIP: "10.11.0.1", ClientIP: "10.11.0.2", overhead: 88,
	Jc: 3, Jmin: 40, Jmax: 70, S1: 15, S2: 25,
	H1: 12345678, H2: 87654321, H3: 11223344, H4: 44332211,
}

// awgV2 is AmneziaWG 2.0: v1 parameters plus CPS concealment tags (I1–I5),
// controlled junk (J1–J3) and the junk timeout.
var awgV2 = awgParams{
	Name: "amnezia2", ServerIP: "10.12.0.1", ClientIP: "10.12.0.2", overhead: 92,
	Jc: 3, Jmin: 40, Jmax: 70, S1: 15, S2: 25,
	H1: 12345678, H2: 87654321, H3: 11223344, H4: 44332211,
	I1:    "<b 0xf6ab3267fa><c><b 0xf6ab><t><r 10><wt 10>",
	I2:    "<b 0xf6ab3267fa><r 20><t>",
	I3:    "<r 15><b 0xf6ab3267fa>",
	I4:    "<c><b 0xf6ab><r 30>",
	I5:    "<t><r 20><b 0xf6ab3267fa>",
	J1:    "<b 0xdeadbeef><r 30>",
	J2:    "<r 40><b 0xfeedface>",
	J3:    "<r 25><c>",
	ITime: 5,
}

// deviceLines renders the device-level UAPI configuration. Note: the UAPI
// parser (loadExactHex) accepts keys strictly in hex form.
func (p awgParams) deviceLines(priv []byte, listenPort int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(priv))
	fmt.Fprintf(&b, "listen_port=%d\n", listenPort)
	fmt.Fprintf(&b, "jc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\n", p.Jc, p.Jmin, p.Jmax, p.S1, p.S2)
	fmt.Fprintf(&b, "h1=%d\nh2=%d\nh3=%d\nh4=%d\n", p.H1, p.H2, p.H3, p.H4)
	if p.I1 != "" {
		fmt.Fprintf(&b, "i1=%s\ni2=%s\ni3=%s\ni4=%s\ni5=%s\n", p.I1, p.I2, p.I3, p.I4, p.I5)
		fmt.Fprintf(&b, "j1=%s\nj2=%s\nj3=%s\n", p.J1, p.J2, p.J3)
		fmt.Fprintf(&b, "itime=%d\n", p.ITime)
	}
	return b.String()
}

func awgIfaceName(proto string) string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	prefix := "awts"
	if proto == "amnezia2" {
		prefix = "aw2t"
	}
	// Keep within IFNAMSIZ=15: 4 + 5 (pid) + 6 (hex) chars.
	return fmt.Sprintf("%s%d%x", prefix, os.Getpid()%100000, b)
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

type awgServer struct {
	params    awgParams
	dev       *device.Device
	ctl       net.Listener
	echo      *udpServer
	pub       []byte
	prevPeer  string // hex pubkey of the previously configured client peer
	closeOnce sync.Once
}

func (p amneziaProto) Listen(addr string, opts Options) (ProtoServer, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ctlPort, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	dataPort := ctlPort + 1
	iface := awgIfaceName(p.params.Name)

	tdev, err := tun.CreateTUN(iface, 1420)
	if err != nil {
		return nil, fmt.Errorf("create tun %s: %w (needs root + /dev/net/tun)", iface, err)
	}
	cleanupTun := func() { _ = tdev.Close() }
	if err := runCmd("ip", "addr", "add", p.params.ServerIP+"/24", "dev", iface); err != nil {
		cleanupTun()
		return nil, err
	}
	if err := runCmd("ip", "link", "set", iface, "up"); err != nil {
		cleanupTun()
		return nil, err
	}

	priv, pub, err := wgKeypair()
	if err != nil {
		cleanupTun()
		return nil, err
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "awg: "))
	// From here on, dev.Close() owns the TUN fd (it closes it).
	if err := dev.IpcSet(p.params.deviceLines(priv, dataPort)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("awg device config: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}

	echoSrv, err := (&udpProto{}).Listen(JoinHostPort(p.params.ServerIP, 0), opts)
	if err != nil {
		dev.Close()
		return nil, err
	}
	ctl, err := net.Listen("tcp", addr)
	if err != nil {
		dev.Close()
		_ = echoSrv.Close()
		return nil, err
	}

	return &awgServer{
		params: p.params,
		dev:    dev,
		ctl:    ctl,
		echo:   echoSrv.(*udpServer),
		pub:    pub,
	}, nil
}

// Accept performs the key exchange, configures the peer, then waits for the
// first datagram arriving through the encrypted tunnel. Transient per-client
// handshake failures are logged and skipped so a misbehaving client cannot
// take down the protocol for everyone else; only listener closure (shutdown)
// is reported as an error.
func (s *awgServer) Accept() (Tunnel, error) {
	for {
		c, err := s.ctl.Accept()
		if err != nil {
			return nil, err
		}
		tun, err := s.acceptClient(c)
		_ = c.Close()
		if err != nil {
			log.Printf("%s handshake failed: %v", s.params.Name, err)
			continue
		}
		return tun, nil
	}
}

// acceptClient runs the key exchange for a single control connection.
func (s *awgServer) acceptClient(c net.Conn) (Tunnel, error) {
	// Bound the handshake (same pattern as the smtp protocol): a peer that
	// connects and never sends a line must not stall the accept loop for
	// every other client.
	_ = c.SetDeadline(time.Now().Add(awgControlTimeout))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read client pubkey: %w", err)
	}
	clientPub, err := hex.DecodeString(strings.TrimSpace(line))
	if err != nil {
		return nil, fmt.Errorf("bad client pubkey: %w", err)
	}
	peerHex := hex.EncodeToString(clientPub)

	if s.prevPeer != "" {
		if err := s.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", s.prevPeer)); err != nil {
			return nil, err
		}
	}
	if err := s.dev.IpcSet(fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\n", peerHex, s.params.ClientIP)); err != nil {
		return nil, err
	}
	s.prevPeer = peerHex

	info := wgServerInfo{
		ServerPub:  hex.EncodeToString(s.pub),
		InternalIP: s.params.ServerIP,
		EchoPort:   s.echo.LocalAddr().(*net.UDPAddr).Port,
	}
	if err := json.NewEncoder(c).Encode(info); err != nil {
		return nil, err
	}
	return s.echo.Accept()
}

func (s *awgServer) Close() error {
	s.closeOnce.Do(func() {
		_ = s.ctl.Close()
		_ = s.echo.Close()
		// Closing the device closes the TUN fd, which removes the (non-
		// persistent) interface automatically.
		s.dev.Close()
	})
	return nil
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

type awgClientTunnel struct {
	*datagramTunnel
	dev       *device.Device
	closeOnce sync.Once
}

func (t *awgClientTunnel) Close() error {
	t.closeOnce.Do(func() {
		_ = t.datagramTunnel.Close()
		// Closing the device removes the TUN interface automatically.
		t.dev.Close()
	})
	return nil
}

func (p amneziaProto) Dial(addr string, opts Options) (Tunnel, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ctlPort, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	dataPort := ctlPort + 1

	// 1. Control connection: exchange keys.
	c, err := net.DialTimeout("tcp", addr, awgControlTimeout)
	if err != nil {
		return nil, err
	}
	// Bound the key exchange (same pattern as the smtp protocol): a service
	// squatting on the control port that accepts TCP but never sends the
	// server info would otherwise hang the dial forever (the benchmark's
	// per-protocol budget only starts after Dial returns).
	_ = c.SetDeadline(time.Now().Add(awgControlTimeout))
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

	serverPub, err := hex.DecodeString(info.ServerPub)
	if err != nil {
		return nil, fmt.Errorf("bad server pubkey: %w", err)
	}

	// 2. Bring up the local TUN + device.
	iface := awgIfaceName(p.params.Name)
	tdev, err := tun.CreateTUN(iface, 1420)
	if err != nil {
		return nil, fmt.Errorf("create tun %s: %w (needs root + /dev/net/tun)", iface, err)
	}
	cleanupTun := func() { _ = tdev.Close() }
	if err := runCmd("ip", "addr", "add", p.params.ClientIP+"/24", "dev", iface); err != nil {
		cleanupTun()
		return nil, err
	}
	if err := runCmd("ip", "link", "set", iface, "up"); err != nil {
		cleanupTun()
		return nil, err
	}

	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "awg: "))
	// From here on, dev.Close() owns the TUN fd.
	endpoint := net.JoinHostPort(host, strconv.Itoa(dataPort))
	uapi := p.params.deviceLines(priv, 0)
	uapi += fmt.Sprintf("public_key=%s\nendpoint=%s\nallowed_ip=%s/32\npersistent_keepalive_interval=5\n",
		hex.EncodeToString(serverPub), endpoint, info.InternalIP)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("awg device config: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}

	// 3. Datagram channel into the tunnel.
	ra := &net.UDPAddr{IP: net.ParseIP(info.InternalIP), Port: info.EchoPort}
	uconn, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(p.params.ClientIP), Port: 0}, ra)
	if err != nil {
		dev.Close()
		return nil, err
	}

	return &awgClientTunnel{
		datagramTunnel: &datagramTunnel{c: uconn, label: p.params.Name + "://" + addr},
		dev:            dev,
	}, nil
}
