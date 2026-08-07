package protocol

import "net"

// udpProto is a plain UDP datagram tunnel.
type udpProto struct{}

func (udpProto) Name() string    { return "udp" }
func (udpProto) Kind() Kind      { return KindDatagram }
func (udpProto) Overhead() int   { return 28 } // 20 IP + 8 UDP
func (udpProto) NeedsRoot() bool { return false }

type udpServer struct {
	d *udpDispatcher
}

func (udpProto) Listen(addr string, opts Options) (ProtoServer, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	tuneSocket(conn)
	// Plain UDP has no framing: the session transport itself is the tunnel.
	return &udpServer{d: newUDPDispatcher(conn, "udp", func(tr *udpSessionTransport) Tunnel {
		return tr
	})}, nil
}

func (s *udpServer) Accept() (Tunnel, error) { return s.d.Accept() }
func (s *udpServer) Close() error            { return s.d.Close() }

// LocalAddr reports the socket's bound address (used by the WireGuard and
// AmneziaWG protocols to tell clients where the echo listener lives).
func (s *udpServer) LocalAddr() net.Addr { return s.d.conn.LocalAddr() }

func (udpProto) Dial(addr string, opts Options) (Tunnel, error) {
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		return nil, err
	}
	return &datagramTunnel{c: c, label: "udp://" + addr}, nil
}
