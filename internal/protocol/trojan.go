package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// trojanProto tunnels bytes over TLS behind the Trojan protocol (a real
// TLS connection whose first payload is the SHA-224 hash of the shared
// password plus a SOCKS5-style address). On the wire it is indistinguishable
// from ordinary HTTPS: a full TLS handshake followed by application data.
// The server validates the password hash and silently closes on mismatch, so
// a wrong-token peer sees a dead TLS port. Wire-compatible with real Trojan
// clients and servers (the harness only exercises the echo/relay path, which
// is raw bytes after the header).
type trojanProto struct{}

func (trojanProto) Name() string    { return "trojan" }
func (trojanProto) Kind() Kind      { return KindStream }
func (trojanProto) Overhead() int   { return 61 } // 20 IP + 20 TCP + 5 TLS + 16 header
func (trojanProto) NeedsRoot() bool { return false }

const (
	// trojanHandshakeTimeout bounds the TLS handshake + header exchange so a
	// stalled or hostile peer (blind-mode probe) cannot leak a goroutine/fd.
	trojanHandshakeTimeout = 10 * time.Second
	// trojanHashHexLen is the length of the hex-encoded SHA-224 password hash.
	trojanHashHexLen = 56
)

// trojanHeader holds the parsed Trojan request header.
type trojanHeader struct {
	cmd  byte // 0x01 = TCP connect, 0x03 = UDP associate
	addr string
}

// trojanAddresses: SOCKS5-style address types used by the header.
const (
	trojanAtypIPv4   = 0x01
	trojanAtypDomain = 0x03
	trojanAtypIPv6   = 0x04
)

// trojanPassword returns the tunnel secret (--password, or the default).
func trojanPassword(opts Options) string {
	if opts.Password != "" {
		return opts.Password
	}
	return defaultPassword
}

// trojanHashHex returns the hex-encoded SHA-224 hash of the password, the
// first field of the wire header.
func trojanHashHex(secret string) string {
	sum := sha256.Sum224([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Header encoding / decoding
// ---------------------------------------------------------------------------

// trojanEncodeHeader builds the wire header: [56B hex hash]\r\n[cmd][atyp
// address][2B port]\r\n. The harness's client has no dial target of its own
// (the server dials destinations relayed by the forwarding plane), so it
// sends a fixed 0.0.0.0:0 target, which real Trojan servers accept and the
// harness server ignores.
func trojanEncodeHeader(secret string, cmd byte) []byte {
	h := make([]byte, 0, 64)
	h = append(h, trojanHashHex(secret)...)
	h = append(h, '\r', '\n', cmd, trojanAtypIPv4, 0, 0, 0, 0, 0, 0, '\r', '\n')
	return h
}

// trojanDecodeHeader reads and validates the header from a TLS connection.
// It returns the parsed command and address, or an error if the password
// hash is wrong or the header is malformed (the caller then closes silently,
// making the port look dead to scanners).
func trojanDecodeHeader(c net.Conn, secret string) (*trojanHeader, error) {
	var hdr [trojanHashHexLen]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	// The wire carries the *hex-encoded* SHA-224 (that is what real Trojan
	// clients send), so hex-decode it before comparing with the raw hash.
	wireHash, err := hex.DecodeString(string(hdr[:]))
	if err != nil {
		return nil, errors.New("trojan: malformed password hash")
	}
	sum := sha256.Sum224([]byte(secret))
	if !hmac.Equal(wireHash, sum[:]) {
		return nil, errors.New("trojan: bad password hash")
	}
	var rest [2]byte
	if _, err := io.ReadFull(c, rest[:]); err != nil {
		return nil, errors.New("trojan: missing CRLF after hash")
	}
	if rest != [2]byte{'\r', '\n'} {
		return nil, errors.New("trojan: malformed header")
	}
	var cmdBuf [1]byte
	if _, err := io.ReadFull(c, cmdBuf[:]); err != nil {
		return nil, errors.New("trojan: missing command")
	}
	cmd := cmdBuf[0]
	if cmd != 0x01 && cmd != 0x03 {
		return nil, fmt.Errorf("trojan: unknown command %#x", cmd)
	}
	var atyp [1]byte
	if _, err := io.ReadFull(c, atyp[:]); err != nil {
		return nil, errors.New("trojan: missing address type")
	}
	var host string
	switch atyp[0] {
	case trojanAtypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return nil, errors.New("trojan: short IPv4 address")
		}
		host = net.IP(b[:]).String()
	case trojanAtypDomain:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return nil, errors.New("trojan: missing domain length")
		}
		if l[0] == 0 {
			return nil, errors.New("trojan: empty domain")
		}
		d := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, d); err != nil {
			return nil, errors.New("trojan: short domain")
		}
		host = string(d)
	case trojanAtypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return nil, errors.New("trojan: short IPv6 address")
		}
		host = net.IP(b[:]).String()
	default:
		return nil, fmt.Errorf("trojan: unknown address type %#x", atyp[0])
	}
	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return nil, errors.New("trojan: missing port")
	}
	var crlf [2]byte
	if _, err := io.ReadFull(c, crlf[:]); err != nil {
		return nil, errors.New("trojan: missing trailing CRLF")
	}
	if crlf != [2]byte{'\r', '\n'} {
		return nil, errors.New("trojan: malformed header tail")
	}
	return &trojanHeader{cmd: cmd, addr: net.JoinHostPort(host, fmt.Sprintf("%d", binary.BigEndian.Uint16(port[:])))}, nil
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

type trojanServer struct {
	ln     net.Listener
	tlsCfg *tls.Config
	ch     chan Tunnel
	done   chan struct{}
	once   sync.Once
}

func (trojanProto) Listen(addr string, opts Options) (ProtoServer, error) {
	cert, err := loadOrGenerateCert(opts)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &trojanServer{
		ln:     ln,
		tlsCfg: &tls.Config{Certificates: []tls.Certificate{cert}},
		ch:     make(chan Tunnel, 8),
		done:   make(chan struct{}),
	}
	go s.acceptLoop(opts)
	return s, nil
}

func (s *trojanServer) acceptLoop(opts Options) {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(c, opts)
	}
}

func (s *trojanServer) handleConn(c net.Conn, opts Options) {
	// Bound the handshake so a stalled or hostile peer can't leak a
	// goroutine and fd; cleared once the tunnel is live.
	_ = c.SetDeadline(time.Now().Add(trojanHandshakeTimeout))
	tc := tls.Server(c, s.tlsCfg)
	// A peer that never speaks TLS closes at the deadline; a peer with the
	// wrong password fails trojanDecodeHeader below, so the server replies
	// with nothing and the port looks dead.
	if err := tc.Handshake(); err != nil {
		_ = c.Close()
		return
	}
	if _, err := trojanDecodeHeader(tc, trojanPassword(opts)); err != nil {
		_ = c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	select {
	case s.ch <- newStreamTunnel(tc, "trojan://"+s.ln.Addr().String()):
	case <-s.done:
		_ = tc.Close()
	}
}

func (s *trojanServer) Accept() (Tunnel, error) {
	select {
	case t := <-s.ch:
		return t, nil
	case <-s.done:
		return nil, net.ErrClosed
	}
}

func (s *trojanServer) Close() error {
	s.once.Do(func() {
		close(s.done)
		_ = s.ln.Close()
	})
	return nil
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

func (trojanProto) Dial(addr string, opts Options) (Tunnel, error) {
	// Bounded: a firewall that drops SYNs would otherwise hang the dial.
	raw, err := net.DialTimeout("tcp", addr, connTimeout)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(trojanHandshakeTimeout))
	// The harness owns both ends and uses an ephemeral self-signed cert, so
	// the client skips certificate validation, exactly like the other
	// TLS-based protocols (and like real Trojan clients with default config).
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := writeFull(tc, trojanEncodeHeader(trojanPassword(opts), 0x01)); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return newStreamTunnel(tc, "trojan://"+addr), nil
}
