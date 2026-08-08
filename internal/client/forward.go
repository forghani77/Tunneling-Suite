package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"tunnel-suite/internal/forward"
	"tunnel-suite/internal/protocol"
)

// ForwardConfig configures the client's forwarding mode
// (tunnel-suite client --mode forward|socks). It turns the client into a
// persistent tunnel endpoint: each local TCP connection is wrapped in frames
// and carried through the chosen protocol tunnel to a server running with
// --forward, which dials the destination and relays.
type ForwardConfig struct {
	Server string
	// ProtocolsBasePort is the base for the tunnel dial: the chosen protocol
	// is dialed at ProtocolsBasePort plus its registry offset (must match the
	// server's --protocols-base-port). Ignored when ControlPort is set, since
	// the manifest then reports the exact port the server actually serves.
	ProtocolsBasePort int
	// ControlPort is the server's control/manifest port. When set, the tunnel
	// port is discovered from the manifest instead of computed as
	// ProtocolsBasePort + offset, so the client aligns itself with whatever
	// the server actually reports. Zero keeps the offset-based dial.
	ControlPort int
	Protocol    string // tunnel protocol name (e.g. "tcp", "udp", "ws", ...)
	Password    string
	SSPassword  string
	// Hysteria2Bandwidth requests a fixed Brutal send rate for the hysteria2
	// tunnel protocol in Mbps (0 = adaptive BBR, the real Hysteria2 default).
	Hysteria2Bandwidth int
	Mode               string // "forward" (fixed target) or "socks" (SOCKS5 proxy)
	Bind               string // local bind address, default "127.0.0.1"
	LocalPort          int
	RemoteHost         string // forward mode only
	RemotePort         int    // forward mode only
}

// RunForward runs the forwarding endpoint until killed. It listens on the
// local port and handles each accepted connection on its own tunnel.
func RunForward(cfg ForwardConfig) error {
	if cfg.Bind == "" {
		cfg.Bind = "127.0.0.1"
	}
	switch cfg.Mode {
	case "forward":
		if cfg.RemoteHost == "" || cfg.RemotePort == 0 {
			return fmt.Errorf("forward mode requires --remote-host and --remote-port")
		}
	case "socks":
	default:
		return fmt.Errorf("unknown mode %q (want forward or socks)", cfg.Mode)
	}
	if cfg.LocalPort == 0 {
		return fmt.Errorf("--local-port is required")
	}
	p, ok := protocol.ByName(protocol.NormalizeName(cfg.Protocol))
	if !ok {
		return fmt.Errorf("unknown protocol %q (known: %v)", cfg.Protocol, protocol.Names())
	}
	port, err := forwardDialPort(cfg, p)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(cfg.Server, strconv.Itoa(port))
	opts := protocol.Options{
		Password:           cfg.Password,
		SSPassword:         cfg.SSPassword,
		Hysteria2Bandwidth: cfg.Hysteria2Bandwidth,
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.LocalPort)))
	if err != nil {
		return fmt.Errorf("listen on %s: %w", net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.LocalPort)), err)
	}
	portSrc := "protocols-base-port + offset"
	if cfg.ControlPort != 0 {
		portSrc = "manifest"
	}
	fmt.Printf("tunnel-suite %s → %s via %s on %s (tunnel port %d, %s)\n",
		cfg.Mode, cfg.Server, p.Name(), ln.Addr(), port, portSrc)
	if cfg.Mode == "forward" {
		fmt.Printf("forwarding to %s\n", net.JoinHostPort(cfg.RemoteHost, strconv.Itoa(cfg.RemotePort)))
	} else {
		fmt.Printf("SOCKS5 proxy ready — use it as a local proxy, e.g. curl --socks5-hostname %s\n", ln.Addr())
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleForwardConn(c, p, addr, opts, cfg)
	}
}

// forwardDialPort returns the absolute port to dial for the tunnel protocol.
// With ControlPort set, the port comes from the server's manifest (the client
// aligns itself with what the server actually serves, and fails with a clear
// error if the protocol is missing or unavailable there); otherwise it is
// ProtocolsBasePort plus the protocol's registry offset.
func forwardDialPort(cfg ForwardConfig, p protocol.Protocol) (int, error) {
	if cfg.ControlPort == 0 {
		return cfg.ProtocolsBasePort + protocol.PortOffset(p), nil
	}
	entries, _, err := fetchManifest(Config{
		Server:            cfg.Server,
		ProtocolsBasePort: cfg.ProtocolsBasePort,
		ControlPort:       cfg.ControlPort,
	})
	if err != nil {
		return 0, fmt.Errorf("discover tunnel port from control port: %w", err)
	}
	e, ok := entries[p.Name()]
	if !ok {
		return 0, fmt.Errorf("server does not offer protocol %q (control port %d)", p.Name(), cfg.ControlPort)
	}
	if !e.Available {
		return 0, fmt.Errorf("protocol %q is unavailable on the server: %s", p.Name(), e.Reason)
	}
	return e.Port, nil
}

// handleForwardConn serves one local TCP connection: for SOCKS mode it first
// reads the CONNECT target from the proxy handshake, then it opens a tunnel
// to the server and relays.
func handleForwardConn(local net.Conn, p protocol.Protocol, addr string, opts protocol.Options, cfg ForwardConfig) {
	defer local.Close()

	target := net.JoinHostPort(cfg.RemoteHost, strconv.Itoa(cfg.RemotePort))
	if cfg.Mode == "socks" {
		t, err := socks5Target(local)
		if err != nil {
			return
		}
		target = t
	}

	tun, err := p.Dial(addr, opts)
	if err != nil {
		if cfg.Mode == "socks" {
			socks5Reply(local, false)
		}
		return
	}
	defer tun.Close()
	if cfg.Mode == "socks" {
		socks5Reply(local, true)
	}
	_ = forward.DialAndRelay(tun, local, target, p.Kind())
}

// socks5Target performs the SOCKS5 handshake (no-auth), reads the CONNECT
// request and returns the destination "host:port". It replies to the greeting
// but not to the CONNECT request — the caller sends the success/failure reply
// once the tunnel is up.
func socks5Target(c net.Conn) (string, error) {
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return "", err
	}
	if head[0] != 5 {
		return "", fmt.Errorf("not a SOCKS5 client (version %d)", head[0])
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", err
	}
	if _, err := c.Write([]byte{5, 0}); err != nil { // no-auth
		return "", err
	}

	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return "", err
	}
	if req[0] != 5 {
		return "", fmt.Errorf("bad SOCKS version %d", req[0])
	}
	if req[1] != 1 { // CONNECT only
		return "", fmt.Errorf("unsupported SOCKS command %d (only CONNECT)", req[1])
	}
	var host string
	switch req[3] {
	case 1: // IPv4
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", err
		}
		host = net.IP(b[:]).String()
	case 3: // domain name
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return "", err
		}
		d := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, d); err != nil {
			return "", err
		}
		host = string(d)
	case 4: // IPv6
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", err
		}
		host = net.IP(b[:]).String()
	default:
		return "", fmt.Errorf("unsupported SOCKS address type %d", req[3])
	}
	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

// socks5Reply sends the SOCKS5 CONNECT reply (success or generic failure).
func socks5Reply(c net.Conn, ok bool) {
	code := byte(0x01) // general failure
	if ok {
		code = 0x00 // succeeded
	}
	// VER, REP, RSV, ATYP=IPv4, 0.0.0.0, :0
	_, _ = c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
}
