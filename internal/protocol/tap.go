package protocol

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

// tapProto tunnels datagrams through a real layer-2 TAP interface: each end
// creates an Ethernet TAP device and a userspace relay forwards every L2
// frame between them over UDP, forming a transparent Ethernet bridge. Test
// probes are ordinary IP packets routed through the pair of TAPs.
//
// Requires root + /dev/net/tun (no kernel module needed).
//
// Ports: the protocol's port (base+17) carries the relay UDP socket; base+18
// carries the echo UDP socket bound to the server's internal tunnel address.
type tapProto struct{}

func (tapProto) Name() string    { return "tap" }
func (tapProto) Kind() Kind      { return KindDatagram }
func (tapProto) Overhead() int   { return 42 } // 20 IP + 8 UDP + 14 Ethernet
func (tapProto) NeedsRoot() bool { return true }

const (
	tapServerIP = "10.13.0.1"
	tapClientIP = "10.13.0.2"
)

func tapIfaceName() string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	// 4 + 5 (pid) + 6 (hex) chars — within IFNAMSIZ=15.
	return fmt.Sprintf("tapt%d%x", os.Getpid()%100000, b)
}

// openTap creates a layer-2 TAP device and returns a file handle to it.
// Reads/writes exchange complete Ethernet frames (no PI header).
func openTap(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w (needs root + /dev/net/tun)", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("invalid TAP interface name %q: %w", name, err)
	}
	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF (tap %s): %w", name, err)
	}
	return os.NewFile(uintptr(fd), "tap:"+name), nil
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

type tapServer struct {
	tap         *os.File
	relayPC     *net.UDPConn
	clientRelay net.Addr
	mu          sync.Mutex
	echo        *udpServer
	closeOnce   sync.Once
}

func (tapProto) Listen(addr string, opts Options) (ProtoServer, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	relayPort, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	echoPort := relayPort + 1
	iface := tapIfaceName()

	tap, err := openTap(iface)
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = tap.Close() }
	if err := runCmd("ip", "addr", "add", tapServerIP+"/24", "dev", iface); err != nil {
		cleanup()
		return nil, err
	}
	if err := runCmd("ip", "link", "set", iface, "up"); err != nil {
		cleanup()
		return nil, err
	}

	// Relay endpoint: receives L2 frames from the client and feeds them into
	// our TAP; frames coming out of our TAP are sent back to the client.
	relayPC, err := net.ListenUDP("udp", &net.UDPAddr{Port: relayPort})
	if err != nil {
		cleanup()
		return nil, err
	}

	// Echo socket on the tunnel address (where benchmark probes terminate).
	echoSrv, err := (&udpProto{}).Listen(JoinHostPort(tapServerIP, echoPort), opts)
	if err != nil {
		cleanup()
		_ = relayPC.Close()
		return nil, err
	}

	s := &tapServer{tap: tap, relayPC: relayPC, echo: echoSrv.(*udpServer)}
	go s.relayUDPToTap()
	go s.relayTapToUDP()
	return s, nil
}

// relayUDPToTap forwards frames received from the client into our TAP and
// learns the client's relay address from the first frame.
func (s *tapServer) relayUDPToTap() {
	buf := make([]byte, 1<<16)
	for {
		n, addr, err := s.relayPC.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Last-wins so a second client session (fresh relay socket) replaces
		// the previous one instead of misrouting its echo replies.
		s.mu.Lock()
		s.clientRelay = addr
		s.mu.Unlock()
		if _, err := s.tap.Write(buf[:n]); err != nil {
			return
		}
	}
}

// relayTapToUDP forwards frames coming out of our TAP (echo replies, ARP
// replies, ...) back to the client's relay address.
func (s *tapServer) relayTapToUDP() {
	buf := make([]byte, 1<<16)
	for {
		n, err := s.tap.Read(buf)
		if err != nil {
			return
		}
		s.mu.Lock()
		peer := s.clientRelay
		s.mu.Unlock()
		if peer == nil {
			continue // nothing to send back to yet
		}
		if _, err := s.relayPC.WriteTo(buf[:n], peer); err != nil {
			return
		}
	}
}

func (s *tapServer) Accept() (Tunnel, error) { return s.echo.Accept() }

func (s *tapServer) Close() error {
	s.closeOnce.Do(func() {
		_ = s.relayPC.Close()
		_ = s.echo.Close()
		// Closing the TAP fd destroys the interface automatically.
		_ = s.tap.Close()
	})
	return nil
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

type tapClientTunnel struct {
	*datagramTunnel
	relay     *net.UDPConn
	tap       *os.File
	closeOnce sync.Once
}

func (t *tapClientTunnel) Close() error {
	t.closeOnce.Do(func() {
		_ = t.datagramTunnel.Close()
		_ = t.relay.Close()
		_ = t.tap.Close()
	})
	return nil
}

func (tapProto) Dial(addr string, opts Options) (Tunnel, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	relayPort, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	echoPort := relayPort + 1

	iface := tapIfaceName()
	tap, err := openTap(iface)
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = tap.Close() }
	if err := runCmd("ip", "addr", "add", tapClientIP+"/24", "dev", iface); err != nil {
		cleanup()
		return nil, err
	}
	if err := runCmd("ip", "link", "set", iface, "up"); err != nil {
		cleanup()
		return nil, err
	}

	// Relay to the server: our TAP frames go out over UDP and vice versa.
	relay, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(host), Port: relayPort})
	if err != nil {
		cleanup()
		return nil, err
	}
	go func() {
		buf := make([]byte, 1<<16)
		for {
			n, err := tap.Read(buf)
			if err != nil {
				return
			}
			if _, err := relay.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 1<<16)
		for {
			n, err := relay.Read(buf)
			if err != nil {
				return
			}
			if _, err := tap.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	// Test-data channel: UDP probes to the server's tunnel address, routed
	// through our TAP by the kernel.
	ra := &net.UDPAddr{IP: net.ParseIP(tapServerIP), Port: echoPort}
	conn, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(tapClientIP), Port: 0}, ra)
	if err != nil {
		cleanup()
		_ = relay.Close()
		return nil, err
	}

	return &tapClientTunnel{
		datagramTunnel: &datagramTunnel{c: conn, label: "tap://" + addr},
		relay:          relay,
		tap:            tap,
	}, nil
}
