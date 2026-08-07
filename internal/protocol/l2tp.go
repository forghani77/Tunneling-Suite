package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"time"
)

// l2tpProto tunnels datagrams through the L2TPv3 (RFC 3931) data-message
// format over UDP (port 1701). The harness implements the data plane only —
// no control connection: the session parameters that real L2TPv3 exchanges
// through its control plane (SCCRQ/ICRQ etc.) are derived from the shared
// secret (--password; defaultPassword when unset), so both ends agree on
// them without signaling. Every datagram carries the RFC 3931 §4.1.2.1
// session header, [flags 16b = T clear, Ver 3][reserved 16b][Session ID
// 32b][Cookie 32b], with the 4-byte cookie validated on receipt exactly as
// the RFC requires — "check the association of a received data message with
// the session identified by the Session ID" — so a wrong password is
// rejected. The test frame stands in for the tunneled L2 frame (the
// pseudowire payload). L2TPv3's other transport, direct over IP (protocol
// 115), would need raw sockets; the UDP variant runs without root.
type l2tpProto struct{}

func l2tpPassword(opts Options) string {
	if opts.Password != "" {
		return opts.Password
	}
	return defaultPassword
}

func (l2tpProto) Name() string    { return "l2tp" }
func (l2tpProto) Kind() Kind      { return KindDatagram }
func (l2tpProto) Overhead() int   { return 40 } // 20 IP + 8 UDP + 12 L2TPv3 header (4 flags/res + 4 session + 4 cookie)
func (l2tpProto) NeedsRoot() bool { return false }

// l2tpSession derives the session parameters — the 32-bit Session ID and the
// 4-byte Cookie — from the shared secret. Real L2TPv3 picks these randomly
// and exchanges them via the control plane; the harness derives them so both
// ends agree without signaling.
func l2tpSession(psk string) (sessionID uint32, cookie []byte) {
	digest := sha256.Sum256([]byte(psk))
	return binary.BigEndian.Uint32(digest[0:4]), digest[4:8]
}

// l2tpEncap builds the RFC 3931 §4.1.2.1 UDP session header followed by the
// frame. The flags word is 0x0003: the T bit is clear (a data message — over
// UDP, T=1 marks control messages) and Ver = 3; the reserved bits are zero.
func l2tpEncap(sessionID uint32, cookie, frame []byte) []byte {
	p := make([]byte, 12+len(frame))
	binary.BigEndian.PutUint16(p[0:2], 0x0003) // T=0 (data), Ver=3
	// bytes 2-3 reserved: zero.
	binary.BigEndian.PutUint32(p[4:8], sessionID)
	copy(p[8:12], cookie)
	copy(p[12:], frame)
	return p
}

// l2tpDecap validates the header and the session association, returning the
// inner frame. A bad flags/version word, a mismatched Session ID, a
// mismatched Cookie, or a truncated datagram all yield ErrBadFrame. The
// flags word must match exactly: RFC 3931 says reserved bits are ignored on
// receipt, but the harness rejects them (as its siblings do) so the
// Accept loop filters strictly.
func l2tpDecap(sessionID uint32, cookie, b []byte) ([]byte, error) {
	if len(b) < 12 || binary.BigEndian.Uint16(b[0:2]) != 0x0003 {
		return nil, ErrBadFrame
	}
	if binary.BigEndian.Uint32(b[4:8]) != sessionID {
		return nil, ErrBadFrame
	}
	if !bytes.Equal(b[8:12], cookie) {
		return nil, ErrBadFrame
	}
	return b[12:], nil
}

// l2tpTunnel wraps a datagram transport (datagramTunnel client side or the
// dispatcher's server-side session transport) with L2TPv3 framing.
type l2tpTunnel struct {
	dt        Tunnel
	sessionID uint32
	cookie    []byte
}

func (t *l2tpTunnel) WriteFrame(p []byte) error {
	return t.dt.WriteFrame(l2tpEncap(t.sessionID, t.cookie, p))
}

func (t *l2tpTunnel) ReadFrame() ([]byte, error) {
	for {
		b, err := t.dt.ReadFrame()
		if err != nil {
			return nil, err
		}
		f, err := l2tpDecap(t.sessionID, t.cookie, b)
		if err != nil {
			// Not a valid datagram for our session: keep waiting.
			continue
		}
		return f, nil
	}
}

func (t *l2tpTunnel) SetReadDeadline(d time.Time) error { return t.dt.SetReadDeadline(d) }
func (t *l2tpTunnel) Close() error                      { return t.dt.Close() }
func (t *l2tpTunnel) Label() string                     { return t.dt.Label() }

type l2tpServer struct {
	d *udpDispatcher
}

func (l2tpProto) Listen(addr string, opts Options) (ProtoServer, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	tuneSocket(conn)
	sessionID, cookie := l2tpSession(l2tpPassword(opts))
	return &l2tpServer{d: newUDPDispatcher(conn, "l2tp", func(tr *udpSessionTransport) Tunnel {
		return &l2tpTunnel{dt: tr, sessionID: sessionID, cookie: cookie}
	})}, nil
}

func (s *l2tpServer) Accept() (Tunnel, error) { return s.d.Accept() }
func (s *l2tpServer) Close() error            { return s.d.Close() }

func (l2tpProto) Dial(addr string, opts Options) (Tunnel, error) {
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		return nil, err
	}
	sessionID, cookie := l2tpSession(l2tpPassword(opts))
	return &l2tpTunnel{
		dt:        &datagramTunnel{c: c, label: "l2tp://" + addr},
		sessionID: sessionID,
		cookie:    cookie,
	}, nil
}
