package protocol

import (
	"math/rand"
	"net"
	"time"
)

// vxlanGpeProto tunnels datagrams through VXLAN-GPE (Generic Protocol
// Extension, draft-ietf-nvo3-vxlan-gpe; the NVO3 encapsulation
// considerations in RFC 9638 discuss it as a rejected GENEVE candidate)
// encapsulation over UDP.
// VXLAN-GPE extends VXLAN (RFC 7348) with a Next Protocol field — the same
// role GENEVE's Protocol Type plays in RFC 8926 — so the inner payload is
// self-describing instead of always being an Ethernet frame. The header stays
// 8 bytes: [flags 8b][res 16b][next protocol 8b][VNI 24b][res 8b], with the
// I and P flags set to mark a valid VNI carrying the indicated inner
// protocol. The test frame rides as the inner payload and is stamped as IPv4
// (next protocol 0x01). VXLAN-GPE's IANA-assigned UDP port is 4790; the
// harness uses its own base+offset port layout so one server can host every
// protocol. No UDP self-reception issue exists (unlike raw IP sockets), so no
// per-tunnel id filtering is needed — the VNI is stamped per tunnel for wire
// fidelity.
type vxlanGpeProto struct{}

const (
	// vxlanGpeFlagsIP: the I flag (bit 3, valid VNI) and P flag (bit 2,
	// next protocol present) set. The remaining bits of byte 0 are the
	// 2-bit version (0), the BUM and OAM flags, and two reserved bits —
	// all zero for harness frames.
	vxlanGpeFlagsIP = 0x0C

	// vxlanGpeNextProtoIPv4 marks the inner payload as an IPv4 packet
	// (IANA Next Protocol registry shared with LISP-GPE, value 0x01).
	// VXLAN-GPE's IANA UDP port is 4790 (not used here — the harness runs
	// on base+offset).
	vxlanGpeNextProtoIPv4 = 0x01
)

func (vxlanGpeProto) Name() string    { return "vxlan-gpe" }
func (vxlanGpeProto) Kind() Kind      { return KindDatagram }
func (vxlanGpeProto) Overhead() int   { return 36 } // 20 IP + 8 UDP + 8 VXLAN-GPE header
func (vxlanGpeProto) NeedsRoot() bool { return false }

// VXLAN-GPE header (draft-ietf-nvo3-vxlan-gpe), 8 bytes:
//
//	[flags 8b][res 16b][next protocol 8b][VNI 24b][res 8b]
func vxlanGpeEncap(vni uint32, frame []byte) ([]byte, error) {
	if vni > 0xFFFFFF {
		return nil, ErrBadFrame
	}
	p := make([]byte, 8+len(frame))
	p[0] = vxlanGpeFlagsIP // version 0, I + P flags
	p[3] = vxlanGpeNextProtoIPv4
	p[4] = byte(vni >> 16)
	p[5] = byte(vni >> 8)
	p[6] = byte(vni)
	// bytes 1-2 and 7 reserved: all zero.
	copy(p[8:], frame)
	return p, nil
}

// vxlanGpeDecap extracts the VNI, next protocol, and inner payload from a
// VXLAN-GPE datagram, rejecting malformed headers (I or P flag missing,
// non-zero version, reserved flag bits set, truncated).
func vxlanGpeDecap(b []byte) (uint32, uint8, []byte, error) {
	if len(b) < 8 || b[0] != vxlanGpeFlagsIP {
		return 0, 0, nil, ErrBadFrame
	}
	vni := uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6])
	return vni, b[3], b[8:], nil
}

// vxlanGpeTunnel wraps a datagram transport (datagramTunnel client side or
// packetTunnel server side) with VXLAN-GPE framing.
type vxlanGpeTunnel struct {
	dt  Tunnel
	vni uint32
}

func (t *vxlanGpeTunnel) WriteFrame(p []byte) error {
	b, err := vxlanGpeEncap(t.vni, p)
	if err != nil {
		return err
	}
	return t.dt.WriteFrame(b)
}

func (t *vxlanGpeTunnel) ReadFrame() ([]byte, error) {
	for {
		b, err := t.dt.ReadFrame()
		if err != nil {
			return nil, err
		}
		_, _, f, err := vxlanGpeDecap(b)
		if err != nil {
			// Not a well-formed VXLAN-GPE datagram: keep waiting.
			continue
		}
		return f, nil
	}
}

func (t *vxlanGpeTunnel) SetReadDeadline(d time.Time) error { return t.dt.SetReadDeadline(d) }
func (t *vxlanGpeTunnel) Close() error                      { return t.dt.Close() }
func (t *vxlanGpeTunnel) Label() string                     { return t.dt.Label() }

type vxlanGpeServer struct {
	conn *net.UDPConn
}

func (vxlanGpeProto) Listen(addr string, opts Options) (ProtoServer, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	return &vxlanGpeServer{conn: conn}, nil
}

// Accept consumes the first well-formed VXLAN-GPE datagram to learn the
// client's address, then returns a tunnel bound to that peer. Datagrams that
// fail the header check (e.g. stray UDP traffic on the port) are ignored.
func (s *vxlanGpeServer) Accept() (Tunnel, error) {
	buf := make([]byte, MaxFrame)
	for {
		n, peer, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}
		if _, _, _, err := vxlanGpeDecap(buf[:n]); err != nil {
			continue
		}
		return &vxlanGpeTunnel{
			dt: &packetTunnel{
				pc:      s.conn,
				peer:    peer,
				pending: buf[:n],
				label:   "vxlan-gpe@" + peer.String(),
			},
			vni: uint32(rand.Intn(1 << 24)),
		}, nil
	}
}

func (s *vxlanGpeServer) Close() error { return s.conn.Close() }

func (vxlanGpeProto) Dial(addr string, opts Options) (Tunnel, error) {
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		return nil, err
	}
	return &vxlanGpeTunnel{
		dt:  &datagramTunnel{c: c, label: "vxlan-gpe://" + addr},
		vni: uint32(rand.Intn(1 << 24)),
	}, nil
}
