package protocol

import (
	"math/rand"
	"net"
)

// sitProto tunnels datagrams through 6in4 (SIT) encapsulation (RFC 4213) using
// a raw socket: IPv6 packets inside IPv4 packets (IP protocol 41). Requires
// root/CAP_NET_RAW. The inner packet is a synthetic IPv6 packet.
//
// Note: this is the protocol commonly referred to as "SIT" (and sometimes
// written "6in4" / "ip6ip"); it is enabled with `ip tunnel add mode sit`.
type sitProto struct{}

func (sitProto) Name() string    { return "sit" }
func (sitProto) Kind() Kind      { return KindDatagram }
func (sitProto) Overhead() int   { return 62 } // 20 outer IPv4 + 40 inner IPv6 + 2 tunnel id
func (sitProto) NeedsRoot() bool { return true }

var sitCfg = rawConfig{
	name:     "sit",
	protoNum: ipProtoSIT,
	encapsulate: func(serverSide bool, self, peer net.IP, id uint16, frame []byte) []byte {
		return craftInnerIPv6(id, frame)
	},
	deencapsulate: stripInnerIPv6,
}

func (sitProto) Listen(addr string, opts Options) (ProtoServer, error) {
	rs, err := listenRawIP(ipProtoSIT)
	if err != nil {
		return nil, err
	}
	return newRawServer(sitCfg, rs), nil
}

func (sitProto) Dial(addr string, opts Options) (Tunnel, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	dst, err := resolveIPv4(host)
	if err != nil {
		return nil, err
	}
	rs, err := listenRawIP(ipProtoSIT)
	if err != nil {
		return nil, err
	}
	src := opts.ClientIP
	if src == nil || src.IsUnspecified() {
		src = outboundIP(host)
	}
	return &rawTunnel{
		cfg:   sitCfg,
		rs:    rs,
		id:    uint16(rand.Intn(1 << 16)),
		peer:  dst,
		self:  src,
		label: "sit://" + host,
	}, nil
}
