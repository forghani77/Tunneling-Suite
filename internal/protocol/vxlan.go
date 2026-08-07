package protocol

import (
	"math/rand"
	"net"
	"time"
)

// vxlanProto tunnels datagrams through VXLAN (RFC 7348) encapsulation over
// UDP. VXLAN's IANA-assigned UDP port is 4789; the harness uses its own
// base+offset port layout so one server can host every protocol. Every
// datagram carries the 8-byte VXLAN header (flags + 24-bit VNI); the test
// frame stands in for the inner Ethernet frame a real VXLAN tunnel would
// carry. No UDP self-reception issue exists (unlike raw IP sockets), so no
// per-tunnel id filtering is needed — the VNI is stamped per tunnel for wire
// fidelity.
type vxlanProto struct{}

// vxlanFlagsI marks a valid VNI (RFC 7348: bit 3 is the I flag; the other
// flag bits are reserved and MUST be zero on transmission).
const vxlanFlagsI = 0x08

func (vxlanProto) Name() string    { return "vxlan" }
func (vxlanProto) Kind() Kind      { return KindDatagram }
func (vxlanProto) Overhead() int   { return 36 } // 20 IP + 8 UDP + 8 VXLAN header
func (vxlanProto) NeedsRoot() bool { return false }

// VXLAN header (RFC 7348), 8 bytes:
//
//	[flags 8b][res 24b][VNI 24b][res 8b]
func vxlanEncap(vni uint32, frame []byte) ([]byte, error) {
	if vni > 0xFFFFFF {
		return nil, ErrBadFrame
	}
	p := make([]byte, 8+len(frame))
	p[0] = vxlanFlagsI // I flag set: VNI is valid
	// bytes 1-3 reserved, byte 7 reserved: all zero.
	p[4] = byte(vni >> 16)
	p[5] = byte(vni >> 8)
	p[6] = byte(vni)
	copy(p[8:], frame)
	return p, nil
}

// vxlanDecap extracts the VNI and inner payload from a VXLAN datagram,
// rejecting malformed headers (I flag not set, reserved bits set, truncated).
func vxlanDecap(b []byte) (uint32, []byte, error) {
	if len(b) < 8 || b[0] != vxlanFlagsI {
		return 0, nil, ErrBadFrame
	}
	vni := uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6])
	return vni, b[8:], nil
}

// vxlanTunnel wraps a datagram transport (datagramTunnel client side or the
// dispatcher's server-side session transport) with VXLAN framing.
type vxlanTunnel struct {
	dt  Tunnel
	vni uint32
}

func (t *vxlanTunnel) WriteFrame(p []byte) error {
	b, err := vxlanEncap(t.vni, p)
	if err != nil {
		return err
	}
	return t.dt.WriteFrame(b)
}

func (t *vxlanTunnel) ReadFrame() ([]byte, error) {
	for {
		b, err := t.dt.ReadFrame()
		if err != nil {
			return nil, err
		}
		_, f, err := vxlanDecap(b)
		if err != nil {
			// Not a well-formed VXLAN datagram: keep waiting.
			continue
		}
		return f, nil
	}
}

func (t *vxlanTunnel) SetReadDeadline(d time.Time) error { return t.dt.SetReadDeadline(d) }
func (t *vxlanTunnel) Close() error                      { return t.dt.Close() }
func (t *vxlanTunnel) Label() string                     { return t.dt.Label() }

type vxlanServer struct {
	d *udpDispatcher
}

func (vxlanProto) Listen(addr string, opts Options) (ProtoServer, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	tuneSocket(conn)
	return &vxlanServer{d: newUDPDispatcher(conn, "vxlan", func(tr *udpSessionTransport) Tunnel {
		return &vxlanTunnel{dt: tr, vni: uint32(rand.Intn(1 << 24))}
	})}, nil
}

func (s *vxlanServer) Accept() (Tunnel, error) { return s.d.Accept() }
func (s *vxlanServer) Close() error            { return s.d.Close() }

func (vxlanProto) Dial(addr string, opts Options) (Tunnel, error) {
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		return nil, err
	}
	return &vxlanTunnel{
		dt:  &datagramTunnel{c: c, label: "vxlan://" + addr},
		vni: uint32(rand.Intn(1 << 24)),
	}, nil
}
