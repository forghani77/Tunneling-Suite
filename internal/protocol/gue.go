package protocol

import (
	"encoding/binary"
	"math/rand"
	"net"
	"time"
)

// gueProto tunnels datagrams through GUE (Generic UDP Encapsulation,
// draft-ietf-nvo3-gue) over UDP. GUE wraps arbitrary IP protocols in UDP
// with a compact extensible header; the harness uses version 0 with the VNI
// extension: the 4-byte base header [Ver 2b][C 1b][Hlen 5b][Proto/ctype
// 16b][Flags 8b] plus one 32-bit extension word carrying the VNI. The 16-bit
// Proto/ctype field plays the same "what is the inner payload" role as
// GENEVE's Protocol Type, but holds an IANA IP protocol number — the draft's
// own data-message example uses 94 (IPIP) for an encapsulated IP packet, so
// the test frame is stamped the same way. The VNI extension is flagged by
// the first (most significant) flag bit, the group-identifier option of the
// GUE extension drafts (draft-ietf-intarea-gue-extensions). GUE's
// IANA-assigned UDP port is 6080; the harness uses its own base+offset port
// layout so one server can host every protocol. No UDP self-reception issue
// exists, so no per-tunnel id filtering is needed — the VNI is stamped per
// tunnel for wire fidelity. Note: GUE/GUEE are unratified drafts (no RFC);
// this follows draft-ietf-nvo3-gue-05 and the group-identifier extension
// from draft-ietf-intarea-gue-extensions. The VNI-as-first-flag-bit layout
// follows the draft's example; the Linux kernel's GUE implementation instead
// encodes the VNI via the private-flags path, so this is not kernel
// wire-interoperable.
type gueProto struct{}

const (
	// gueProtoIPIP marks the inner payload as an IP packet (IANA protocol
	// number 94, IPIP), exactly as in the GUE draft's data-message
	// example. GUE's IANA UDP port is 6080 (not used here — the harness
	// runs on base+offset).
	gueProtoIPIP = 94

	// gueFlagVNI marks the VNI extension: the first (most significant)
	// flag bit, which the GUE extension drafts allocate to the
	// group-identifier option — a single 32-bit word.
	gueFlagVNI = 0x80
)

func (gueProto) Name() string    { return "gue" }
func (gueProto) Kind() Kind      { return KindDatagram }
func (gueProto) Overhead() int   { return 36 } // 20 IP + 8 UDP + 8 GUE (4 base + 4 VNI)
func (gueProto) NeedsRoot() bool { return false }

// GUE v0 header with the VNI extension, 8 bytes:
//
//	[Ver 2b][C 1b][Hlen 5b][Proto/ctype 16b][Flags 8b][VNI 32b]
func gueEncap(vni uint32, frame []byte) ([]byte, error) {
	p := make([]byte, 8+len(frame))
	p[0] = 0x01 // version 0, data message (C clear), Hlen = 1 extension word
	binary.BigEndian.PutUint16(p[1:3], gueProtoIPIP)
	p[3] = gueFlagVNI
	binary.BigEndian.PutUint32(p[4:8], vni)
	copy(p[8:], frame)
	return p, nil
}

// gueDecap extracts the VNI, proto/ctype, and inner payload from a GUE
// datagram, rejecting malformed headers (non-zero version, control message,
// Hlen != 1, unknown or missing VNI flag).
func gueDecap(b []byte) (uint32, uint16, []byte, error) {
	// Version 0, data message, exactly one extension word, and only the
	// VNI flag set: anything else is a header we do not understand, and
	// the draft requires unknown flags to cause a drop.
	if len(b) < 8 || b[0] != 0x01 || b[3] != gueFlagVNI {
		return 0, 0, nil, ErrBadFrame
	}
	vni := binary.BigEndian.Uint32(b[4:8])
	return vni, binary.BigEndian.Uint16(b[1:3]), b[8:], nil
}

// gueTunnel wraps a datagram transport (datagramTunnel client side or
// packetTunnel server side) with GUE framing.
type gueTunnel struct {
	dt  Tunnel
	vni uint32
}

func (t *gueTunnel) WriteFrame(p []byte) error {
	b, err := gueEncap(t.vni, p)
	if err != nil {
		return err
	}
	return t.dt.WriteFrame(b)
}

func (t *gueTunnel) ReadFrame() ([]byte, error) {
	for {
		b, err := t.dt.ReadFrame()
		if err != nil {
			return nil, err
		}
		_, _, f, err := gueDecap(b)
		if err != nil {
			// Not a well-formed GUE datagram: keep waiting.
			continue
		}
		return f, nil
	}
}

func (t *gueTunnel) SetReadDeadline(d time.Time) error { return t.dt.SetReadDeadline(d) }
func (t *gueTunnel) Close() error                      { return t.dt.Close() }
func (t *gueTunnel) Label() string                     { return t.dt.Label() }

type gueServer struct {
	conn *net.UDPConn
}

func (gueProto) Listen(addr string, opts Options) (ProtoServer, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	return &gueServer{conn: conn}, nil
}

// Accept consumes the first well-formed GUE datagram to learn the client's
// address, then returns a tunnel bound to that peer. Datagrams that fail the
// header check (e.g. stray UDP traffic on the port) are ignored.
func (s *gueServer) Accept() (Tunnel, error) {
	buf := make([]byte, MaxFrame)
	for {
		n, peer, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}
		if _, _, _, err := gueDecap(buf[:n]); err != nil {
			continue
		}
		return &gueTunnel{
			dt: &packetTunnel{
				pc:      s.conn,
				peer:    peer,
				pending: buf[:n],
				label:   "gue@" + peer.String(),
			},
			vni: rand.Uint32(),
		}, nil
	}
}

func (s *gueServer) Close() error { return s.conn.Close() }

func (gueProto) Dial(addr string, opts Options) (Tunnel, error) {
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		return nil, err
	}
	return &gueTunnel{
		dt:  &datagramTunnel{c: c, label: "gue://" + addr},
		vni: rand.Uint32(),
	}, nil
}
