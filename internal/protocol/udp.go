package protocol

import "net"

// udpProto is a plain UDP datagram tunnel.
type udpProto struct{}

func (udpProto) Name() string    { return "udp" }
func (udpProto) Kind() Kind      { return KindDatagram }
func (udpProto) Overhead() int   { return 28 } // 20 IP + 8 UDP
func (udpProto) NeedsRoot() bool { return false }

type udpServer struct {
	conn *net.UDPConn
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
	return &udpServer{conn: conn}, nil
}

// Accept consumes the first datagram to learn the client's address, then
// returns a tunnel bound to that peer.
func (s *udpServer) Accept() (Tunnel, error) {
	buf := make([]byte, MaxFrame)
	n, peer, err := s.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	return &packetTunnel{
		pc:      s.conn,
		peer:    peer,
		pending: buf[:n],
		label:   "udp@" + peer.String(),
	}, nil
}

func (s *udpServer) Close() error { return s.conn.Close() }

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
