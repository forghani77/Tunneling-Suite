package protocol

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	hyclient "github.com/apernet/hysteria/core/v2/client"
	hyserver "github.com/apernet/hysteria/core/v2/server"
	hyobfs "github.com/apernet/hysteria/extras/v2/obfs"
)

// hysteria2Proto tunnels bytes over Hysteria2 (apernet/hysteria core/v2): a
// full HTTP/3 session over QUIC — the client authenticates with a POST to a
// fixed URL, then every connection becomes a bidirectional QUIC stream. On
// the wire it is QUIC-shaped (which itself defeats TCP fingerprinting), with
// two extra layers from the Hysteria2 toolkit:
//
//   - Salamander obfuscation: every UDP datagram carries an 8-byte random
//     salt prepended and its payload XORed with BLAKE2b-256(PSK || salt),
//     which removes the QUIC magic-byte fingerprint so the stream does not
//     even look like QUIC. The PSK is derived from --password.
//   - Brutal congestion control: both ends are wired to a fixed-rate sender
//     (hysteria2BrutalRate) that ignores loss signals and paces the tunnel at
//     that rate, the "brutal" congestion control Hysteria2 is known for.
//
// Both ends are keyed purely from --password and there is no separate control
// plane, so like the other QUIC/UDP protocols it works unchanged in --blind
// mode. A wrong password is rejected during the HTTP/3 auth exchange and the
// dial fails fast (the server answers the auth probe with a plain 404, so a
// port scan finds a dead port rather than a service).
type hysteria2Proto struct{}

func (hysteria2Proto) Name() string    { return "hysteria2" }
func (hysteria2Proto) Kind() Kind      { return KindStream }
func (hysteria2Proto) Overhead() int   { return 41 } // 20 IP + 8 UDP + 5 QUIC short header + 8 Salamander salt
func (hysteria2Proto) NeedsRoot() bool { return false }

const (
	// hysteria2IdleTimeout bounds an idle QUIC connection; also the value both
	// configs advertise (the library validates it between 4s and 120s).
	hysteria2IdleTimeout = 30 * time.Second
	// hysteria2DialTimeout is a hard backstop on Dial. The QUIC library's own
	// handshake-idle timeout (~5s) normally fires first and cleans up, so this
	// only catches pathological cases.
	hysteria2DialTimeout = 15 * time.Second
	// hysteria2BrutalRate is the fixed send rate Brutal paces the tunnel at,
	// in bytes per second (200 Mbps). Both the client's upload and the
	// server's echo direction are paced at this rate, so throughput results
	// are bounded by it by design — that is what Brutal does: send at exactly
	// the configured rate regardless of loss.
	hysteria2BrutalRate = 200 * 1000 * 1000 / 8
	// hysteria2SNI is the TLS server name both ends use; the client skips
	// certificate validation (self-signed harness cert), so this is cosmetic.
	hysteria2SNI = "tunnel-suite"
)

func hysteria2Password(opts Options) string {
	if opts.Password != "" {
		return opts.Password
	}
	return defaultPassword
}

// hysteria2PSK derives the Salamander pre-shared key (32 bytes) from the
// shared password.
func hysteria2PSK(opts Options) []byte {
	sum := sha256.Sum256([]byte(hysteria2Password(opts)))
	return sum[:]
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

type hysteria2Server struct {
	srv  hyserver.Server
	conn net.PacketConn // the (obfuscated) UDP socket; exposed for tests
	ch   chan Tunnel
	done chan struct{}
	once sync.Once
}

// hysteria2Auth validates the client's auth payload against the password.
type hysteria2Auth struct{ want string }

func (a *hysteria2Auth) Authenticate(addr net.Addr, auth string, tx uint64) (bool, string) {
	if subtle.ConstantTimeCompare([]byte(auth), []byte(a.want)) == 1 {
		return true, "hysteria2"
	}
	return false, ""
}

// hysteria2Outbound is the harness's hook into the server's proxy plane:
// instead of dialing a real remote for each TCP request, it hands the harness
// one end of a net.Pipe whose other end becomes the tunnel the echo loop (or
// forwarding plane) runs on. The requested address is ignored — the harness
// supplies real destinations in the forwarding plane.
type hysteria2Outbound struct {
	ch   chan Tunnel
	done chan struct{}
}

func (o *hysteria2Outbound) TCP(reqAddr string) (net.Conn, error) {
	srv, cli := net.Pipe()
	select {
	case o.ch <- newStreamTunnel(cli, "hysteria2://"+reqAddr):
	case <-o.done:
		_ = srv.Close()
		_ = cli.Close()
		return nil, errors.New("hysteria2: server closed")
	}
	return srv, nil
}

func (o *hysteria2Outbound) UDP(reqAddr string) (hyserver.UDPConn, error) {
	return nil, errors.New("hysteria2: UDP disabled")
}

func (o *hysteria2Outbound) CheckUDP(reqAddr string) error {
	return errors.New("hysteria2: UDP disabled")
}

func (hysteria2Proto) Listen(addr string, opts Options) (ProtoServer, error) {
	cert, err := loadOrGenerateCert(opts)
	if err != nil {
		return nil, err
	}
	raw, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := hyobfs.WrapPacketConnSalamander(raw, hysteria2PSK(opts))
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	s := &hysteria2Server{
		conn: conn,
		ch:   make(chan Tunnel, 8),
		done: make(chan struct{}),
	}
	srv, err := hyserver.NewServer(&hyserver.Config{
		TLSConfig:       hyserver.TLSConfig{Certificates: []tls.Certificate{cert}},
		QUICConfig:      hyserver.QUICConfig{MaxIdleTimeout: hysteria2IdleTimeout},
		Conn:            conn,
		Authenticator:   &hysteria2Auth{want: hysteria2Password(opts)},
		BandwidthConfig: hyserver.BandwidthConfig{MaxTx: hysteria2BrutalRate, MaxRx: hysteria2BrutalRate},
		DisableUDP:      true,
		Outbound:        &hysteria2Outbound{ch: s.ch, done: s.done},
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	s.srv = srv
	go func() { _ = srv.Serve() }()
	return s, nil
}

func (s *hysteria2Server) Accept() (Tunnel, error) {
	select {
	case t := <-s.ch:
		return t, nil
	case <-s.done:
		return nil, net.ErrClosed
	}
}

func (s *hysteria2Server) Close() error {
	s.once.Do(func() {
		close(s.done)
		_ = s.srv.Close()
	})
	return nil
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

// hysteria2ConnFactory gives every client dial its own UDP socket wrapped in
// the same Salamander obfuscation the server uses, so the wire format matches.
type hysteria2ConnFactory struct{ psk []byte }

func (f *hysteria2ConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	raw, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return hyobfs.WrapPacketConnSalamander(raw, f.psk)
}

// hysteria2Tunnel closes the whole QUIC session (not just the stream) when
// the harness is done with the tunnel, so the client socket and goroutines
// are released promptly instead of lingering until the idle timeout.
type hysteria2Tunnel struct {
	*streamTunnel
	cli hyclient.Client
}

func (t *hysteria2Tunnel) Close() error {
	_ = t.cli.Close()
	return t.streamTunnel.Close()
}

func (hysteria2Proto) Dial(addr string, opts Options) (Tunnel, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	cfg := &hyclient.Config{
		ConnFactory: &hysteria2ConnFactory{psk: hysteria2PSK(opts)},
		ServerAddr:  ua,
		Auth:        hysteria2Password(opts),
		TLSConfig:   hyclient.TLSConfig{ServerName: hysteria2SNI, InsecureSkipVerify: true},
		QUICConfig:  hyclient.QUICConfig{MaxIdleTimeout: hysteria2IdleTimeout},
		BandwidthConfig: hyclient.BandwidthConfig{
			MaxTx: hysteria2BrutalRate,
			MaxRx: hysteria2BrutalRate,
		},
	}
	type dialResult struct {
		cli hyclient.Client
		err error
	}
	rc := make(chan dialResult, 1)
	go func() {
		cli, _, err := hyclient.NewClient(cfg) // QUIC handshake + HTTP/3 auth
		rc <- dialResult{cli, err}
	}()
	var r dialResult
	select {
	case r = <-rc:
	case <-time.After(hysteria2DialTimeout):
		return nil, errors.New("hysteria2: dial timed out")
	}
	if r.err != nil {
		return nil, r.err
	}
	// The server's outbound ignores the dial target, so any placeholder
	// address works; the harness supplies real destinations in the
	// forwarding plane.
	c, err := r.cli.TCP("0.0.0.0:0")
	if err != nil {
		_ = r.cli.Close()
		return nil, err
	}
	return &hysteria2Tunnel{
		streamTunnel: newStreamTunnel(c, "hysteria2://"+addr),
		cli:          r.cli,
	}, nil
}
