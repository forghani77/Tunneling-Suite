package protocol

import (
	"math/rand"
	"net"
)

// ipipProto tunnels datagrams through IP-in-IP encapsulation (RFC 2003) using
// a raw socket. Requires root/CAP_NET_RAW.
type ipipProto struct{}

func (ipipProto) Name() string    { return "ipip" }
func (ipipProto) Kind() Kind      { return KindDatagram }
func (ipipProto) Overhead() int   { return 42 } // 20 outer IP + 20 inner IP + 2 tunnel id
func (ipipProto) NeedsRoot() bool { return true }

var ipipCfg = rawConfig{
	name:     "ipip",
	protoNum: ipProtoIPIP,
	encapsulate: func(serverSide bool, self, peer net.IP, id uint16, frame []byte) []byte {
		return craftInnerIPv4(self, peer, id, frame)
	},
	deencapsulate: stripInnerIPv4,
}

func (ipipProto) Listen(addr string, opts Options) (ProtoServer, error) {
	rs, err := listenRawIP(ipProtoIPIP)
	if err != nil {
		return nil, err
	}
	return newRawServer(ipipCfg, rs), nil
}

func (ipipProto) Dial(addr string, opts Options) (Tunnel, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	dst, err := resolveIPv4(host)
	if err != nil {
		return nil, err
	}
	rs, err := listenRawIP(ipProtoIPIP)
	if err != nil {
		return nil, err
	}
	src := opts.ClientIP
	if src == nil || src.IsUnspecified() {
		src = outboundIP(host)
	}
	return &rawTunnel{
		cfg:   ipipCfg,
		rs:    rs,
		id:    uint16(rand.Intn(1 << 16)),
		peer:  dst,
		self:  src,
		label: "ipip://" + host,
	}, nil
}
