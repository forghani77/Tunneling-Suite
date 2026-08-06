// Package protocol defines the tunneling-protocol abstraction used by the
// tunnel-suit test harness.
//
// Every protocol under test implements the Protocol interface, which provides
// two sides:
//
//   - Listen() starts the server side and returns a ProtoServer that Accepts
//     one Tunnel per test session.
//   - Dial() connects the client side and returns an established Tunnel.
//
// A Tunnel is a message-oriented channel: the benchmark writes one test frame
// at a time and reads one frame at a time. Stream transports (TCP, TLS, QUIC,
// KCP, Shadowsocks, HTTP/3) length-prefix every frame; datagram transports
// (UDP, GRE, IPIP, SIT, WireGuard) deliver exactly one frame per datagram.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Kind describes how a tunnel transports data.
type Kind int

const (
	// KindStream is a reliable, ordered byte stream (TCP-like).
	KindStream Kind = iota
	// KindDatagram is an unreliable, message-oriented channel (UDP-like).
	KindDatagram
)

func (k Kind) String() string {
	if k == KindStream {
		return "stream"
	}
	return "datagram"
}

// defaultPassword is the well-known password for protocols that share a
// secret (anytls, naive) when neither side sets --password.
const defaultPassword = "tunnel-suit"

// Options carries per-run configuration shared by all protocols.
type Options struct {
	// SSPassword is the Shadowsocks AEAD password. Empty means the default.
	SSPassword string
	// Password is the shared secret for anytls, naive, the ipsec static
	// SA, and the l2tp session parameters. Empty means defaultPassword.
	Password string
	// TLSCertFile/TLSKeyFile optionally point at a server certificate pair.
	// When empty the server generates an ephemeral self-signed certificate.
	TLSCertFile string
	TLSKeyFile  string
	// ClientIP is the client's local IP address as observed by the server.
	// Used by raw layer-3 protocols (GRE/IPIP/SIT) when crafting packets.
	ClientIP net.IP
}

// Tunnel is an established data channel between the test client and server.
type Tunnel interface {
	// WriteFrame writes one complete test frame.
	WriteFrame(p []byte) error
	// ReadFrame reads one complete test frame.
	ReadFrame() ([]byte, error)
	// SetReadDeadline bounds the next ReadFrame call.
	SetReadDeadline(t time.Time) error
	Close() error
	// Label is a human-readable description of the tunnel endpoint.
	Label() string
}

// ProtoServer accepts tunnels on the server side.
type ProtoServer interface {
	// Accept blocks until a new tunnel is established, or returns an error
	// when the server is closed.
	Accept() (Tunnel, error)
	Close() error
}

// Protocol is implemented by every tunneling protocol under test.
type Protocol interface {
	// Name is the unique protocol identifier, e.g. "tcp".
	Name() string
	// Kind reports whether the tunnel is stream- or datagram-based.
	Kind() Kind
	// Overhead is the nominal number of header bytes this tunnel adds to each
	// packet on the wire (approximate, no IP options).
	Overhead() int
	// NeedsRoot reports whether the protocol requires root/raw privileges.
	NeedsRoot() bool
	// Listen starts the server side of the tunnel. addr is "host:port" of the
	// protocol's own port; the returned ProtoServer must be ready to Accept
	// immediately.
	Listen(addr string, opts Options) (ProtoServer, error)
	// Dial connects the client side of the tunnel.
	Dial(addr string, opts Options) (Tunnel, error)
}

// ---------------------------------------------------------------------------
// Test-frame format
//
// Every test frame carries a type marker, a sequence number and a nanosecond
// timestamp so the benchmark can pair requests with echoed responses:
//
//	[type 1B][seq 4B BE][ts 8B BE][padding to target size]
// ---------------------------------------------------------------------------

const (
	// FramePing is a client->server latency/loss probe.
	FramePing byte = 1
	// FramePong is the server's echo of a FramePing.
	FramePong byte = 2

	frameHeaderLen = 13
	// MaxFrame bounds frame sizes; the stream length prefix is a uint16.
	MaxFrame = 1 << 16

	// DefaultRTTSize is the default payload size for latency probes.
	DefaultRTTSize = 64
	// DefaultLossSize is the default payload size for loss probes.
	DefaultLossSize = 1200
)

var (
	// ErrFrameTooLarge is returned when a frame exceeds MaxFrame.
	ErrFrameTooLarge = errors.New("frame too large")
	// ErrBadFrame is returned when a frame is malformed.
	ErrBadFrame = errors.New("malformed frame")
)

// EncodeFrame builds a frame of exactly size bytes (zero-padded).
func EncodeFrame(ftype byte, seq uint32, ts time.Time, size int) ([]byte, error) {
	if size < frameHeaderLen {
		size = frameHeaderLen
	}
	if size > MaxFrame {
		return nil, ErrFrameTooLarge
	}
	b := make([]byte, size)
	b[0] = ftype
	binary.BigEndian.PutUint32(b[1:5], seq)
	binary.BigEndian.PutUint64(b[5:13], uint64(ts.UnixNano()))
	return b, nil
}

// DecodeFrame parses a frame header.
func DecodeFrame(b []byte) (ftype byte, seq uint32, ts time.Time, err error) {
	if len(b) < frameHeaderLen {
		return 0, 0, time.Time{}, ErrBadFrame
	}
	ftype = b[0]
	seq = binary.BigEndian.Uint32(b[1:5])
	ts = time.Unix(0, int64(binary.BigEndian.Uint64(b[5:13])))
	return ftype, seq, ts, nil
}

// ---------------------------------------------------------------------------
// Shared tunnel implementations
// ---------------------------------------------------------------------------

// duplex is the minimal byte-stream interface shared by net.Conn,
// quic.Stream, http3.RequestStream, etc.
type duplex interface {
	io.Reader
	io.Writer
	Close() error
	SetDeadline(time.Time) error
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

// streamTunnel wraps a byte-stream connection with 2-byte length framing.
type streamTunnel struct {
	c     duplex
	label string
}

func newStreamTunnel(c duplex, label string) *streamTunnel {
	return &streamTunnel{c: c, label: label}
}

func (t *streamTunnel) WriteFrame(p []byte) error {
	if len(p) > MaxFrame {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(p)))
	copy(buf[2:], p)
	return writeFull(t.c, buf)
}

func (t *streamTunnel) ReadFrame() ([]byte, error) {
	var lh [2]byte
	if _, err := io.ReadFull(t.c, lh[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lh[:])
	if n == 0 {
		return nil, ErrBadFrame
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(t.c, b); err != nil {
		return nil, err
	}
	return b, nil
}

func (t *streamTunnel) SetReadDeadline(d time.Time) error { return t.c.SetDeadline(d) }
func (t *streamTunnel) Close() error                      { return t.c.Close() }
func (t *streamTunnel) Label() string                     { return t.label }

// datagramTunnel wraps a connected datagram connection (net.Conn based);
// every frame is exactly one datagram.
type datagramTunnel struct {
	c       net.Conn
	pending []byte
	label   string
}

func (t *datagramTunnel) WriteFrame(p []byte) error {
	if len(p) > MaxFrame {
		return ErrFrameTooLarge
	}
	_, err := t.c.Write(p)
	return err
}

func (t *datagramTunnel) ReadFrame() ([]byte, error) {
	if len(t.pending) > 0 {
		b := t.pending
		t.pending = nil
		return b, nil
	}
	buf := make([]byte, MaxFrame)
	n, err := t.c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (t *datagramTunnel) SetReadDeadline(d time.Time) error { return t.c.SetDeadline(d) }
func (t *datagramTunnel) Close() error                      { return t.c.Close() }
func (t *datagramTunnel) Label() string                     { return t.label }

// packetTunnel wraps a PacketConn bound to a fixed peer (server side).
type packetTunnel struct {
	pc      net.PacketConn
	peer    net.Addr
	pending []byte
	label   string
}

func (t *packetTunnel) WriteFrame(p []byte) error {
	if len(p) > MaxFrame {
		return ErrFrameTooLarge
	}
	_, err := t.pc.WriteTo(p, t.peer)
	return err
}

func (t *packetTunnel) ReadFrame() ([]byte, error) {
	if len(t.pending) > 0 {
		b := t.pending
		t.pending = nil
		return b, nil
	}
	buf := make([]byte, MaxFrame)
	n, _, err := t.pc.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (t *packetTunnel) SetReadDeadline(d time.Time) error { return t.pc.SetReadDeadline(d) }
func (t *packetTunnel) Close() error                      { return t.pc.Close() }
func (t *packetTunnel) Label() string                     { return t.label }

// streamServer adapts a net.Listener (whose Accept already returns wrapped
// connections, e.g. TLS or KCP) into a ProtoServer.
type streamServer struct {
	ln net.Listener
}

func (s *streamServer) Accept() (Tunnel, error) {
	c, err := s.ln.Accept()
	if err != nil {
		return nil, err
	}
	return newStreamTunnel(c, s.ln.Addr().String()), nil
}

func (s *streamServer) Close() error { return s.ln.Close() }

// EchoLoop reads frames from a tunnel and echoes them back until the tunnel
// fails or is closed. Ping frames are re-marked as Pong so the client can pair
// them by sequence number.
func EchoLoop(t Tunnel) {
	defer t.Close()
	for {
		f, err := t.ReadFrame()
		if err != nil {
			return
		}
		if len(f) == 0 {
			continue
		}
		if f[0] == FramePing {
			f[0] = FramePong
		}
		if err := t.WriteFrame(f); err != nil {
			return
		}
	}
}

// JoinHostPort is a small alias to keep call sites terse.
func JoinHostPort(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}
