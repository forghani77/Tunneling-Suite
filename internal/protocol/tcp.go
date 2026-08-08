package protocol

import "net"

// tcpProto is a plain TCP byte-stream tunnel.
type tcpProto struct{}

func (tcpProto) Name() string    { return "tcp" }
func (tcpProto) Kind() Kind      { return KindStream }
func (tcpProto) Overhead() int   { return 40 } // 20 IP + 20 TCP
func (tcpProto) NeedsRoot() bool { return false }

func (tcpProto) Listen(addr string, opts Options) (ProtoServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &streamServer{ln: ln}, nil
}

func (tcpProto) Dial(addr string, opts Options) (Tunnel, error) {
	// Bounded: a firewall that drops SYNs (instead of refusing) would
	// otherwise hang the dial forever.
	c, err := net.DialTimeout("tcp", addr, connTimeout)
	if err != nil {
		return nil, err
	}
	return newStreamTunnel(c, "tcp://"+addr), nil
}
