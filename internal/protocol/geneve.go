package protocol

import (
	"encoding/binary"
	"math/rand"
	"net"
	"time"
)

// geneveProto tunnels datagrams through GENEVE (RFC 8926) encapsulation over
// UDP. GENEVE's IANA-assigned UDP port is 6081; the harness uses its own
// base+offset port layout so one server can host every protocol. Every
// datagram carries the 8-byte fixed GENEVE header (24-bit VNI + protocol
// type); the test frame rides as the inner payload. No UDP self-reception
// issue exists (unlike raw IP sockets), so no per-tunnel id filtering is
// needed — the VNI is stamped per tunnel for wire fidelity.
type geneveProto struct{}

const (
	// geneveProtoTypeIPv4 marks the inner payload as IPv4 (EtherType
	// 0x0800): the test frame stands in for the inner IP packet a real
	// GENEVE tunnel would carry. GENEVE's IANA UDP port is 6081 (not used
	// here — the harness runs on base+offset).
	geneveProtoTypeIPv4 = 0x0800
)

func (geneveProto) Name() string    { return "geneve" }
func (geneveProto) Kind() Kind      { return KindDatagram }
func (geneveProto) Overhead() int   { return 36 } // 20 IP + 8 UDP + 8 GENEVE header
func (geneveProto) NeedsRoot() bool { return false }

// GENEVE fixed header (RFC 8926), 8 bytes:
//
//	[ver 2b][optlen 6b][O 1b][C 1b][res 6b][proto type 16b][VNI 24b][res 8b]
func geneveEncap(vni uint32, frame []byte) ([]byte, error) {
	if vni > 0xFFFFFF {
		return nil, ErrBadFrame
	}
	p := make([]byte, 8+len(frame))
	// byte 0: ver=0, optlen=0; byte 1: flags/reserved = 0; byte 7: reserved.
	binary.BigEndian.PutUint16(p[2:4], geneveProtoTypeIPv4)
	p[4] = byte(vni >> 16)
	p[5] = byte(vni >> 8)
	p[6] = byte(vni)
	copy(p[8:], frame)
	return p, nil
}

// geneveDecap extracts the VNI and inner payload from a GENEVE datagram,
// rejecting malformed headers (wrong version, options present, truncated).
func geneveDecap(b []byte) (uint32, []byte, error) {
	if len(b) < 8 || b[0]>>6 != 0 || b[0]&0x3F != 0 {
		return 0, nil, ErrBadFrame
	}
	vni := uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6])
	return vni, b[8:], nil
}

// geneveTunnel wraps a datagram transport (datagramTunnel client side or the
// dispatcher's server-side session transport) with GENEVE framing.
type geneveTunnel struct {
	dt  Tunnel
	vni uint32
}

func (t *geneveTunnel) WriteFrame(p []byte) error {
	b, err := geneveEncap(t.vni, p)
	if err != nil {
		return err
	}
	return t.dt.WriteFrame(b)
}

func (t *geneveTunnel) ReadFrame() ([]byte, error) {
	for {
		b, err := t.dt.ReadFrame()
		if err != nil {
			return nil, err
		}
		_, f, err := geneveDecap(b)
		if err != nil {
			// Not a well-formed GENEVE datagram: keep waiting.
			continue
		}
		return f, nil
	}
}

func (t *geneveTunnel) SetReadDeadline(d time.Time) error { return t.dt.SetReadDeadline(d) }
func (t *geneveTunnel) Close() error                      { return t.dt.Close() }
func (t *geneveTunnel) Label() string                     { return t.dt.Label() }

type geneveServer struct {
	d *udpDispatcher
}

func (geneveProto) Listen(addr string, opts Options) (ProtoServer, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	tuneSocket(conn)
	return &geneveServer{d: newUDPDispatcher(conn, "geneve", func(tr *udpSessionTransport) Tunnel {
		return &geneveTunnel{dt: tr, vni: uint32(rand.Intn(1 << 24))}
	})}, nil
}

func (s *geneveServer) Accept() (Tunnel, error) { return s.d.Accept() }
func (s *geneveServer) Close() error            { return s.d.Close() }

func (geneveProto) Dial(addr string, opts Options) (Tunnel, error) {
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		return nil, err
	}
	return &geneveTunnel{
		dt:  &datagramTunnel{c: c, label: "geneve://" + addr},
		vni: uint32(rand.Intn(1 << 24)),
	}, nil
}
