package protocol

import (
	"math/rand"
	"net"
)

// sixToFourProto tunnels datagrams through 6to4 (RFC 3056) encapsulation
// using a raw socket: IPv6 packets inside IPv4 packets (IP protocol 41).
// It shares the 6in4 wire format with sit but uses the RFC 3056 addressing
// scheme: the inner source and destination are 2002::/48 addresses derived
// from the tunnel endpoints' IPv4 addresses (2002:V4ADDR::/48), the classic
// automatic-6to4 scheme — as opposed to sit, whose inner addresses are fixed
// RFC 4193 ULA addresses.
type sixToFourProto struct{}

func (sixToFourProto) Name() string        { return "6to4" }
func (sixToFourProto) Kind() Kind          { return KindDatagram }
func (sixToFourProto) Overhead() int       { return 62 } // 20 outer IPv4 + 40 inner IPv6 + 2 tunnel id
func (sixToFourProto) NeedsRoot() bool     { return true }
func (sixToFourProto) IsRawDatagram() bool { return true }

var sixFourCfg = rawConfig{
	name:     "6to4",
	protoNum: ipProtoSIT,
	encapsulate: func(serverSide bool, self, peer net.IP, id uint16, frame []byte) []byte {
		return craftInnerIPv6To4(self, peer, id, frame)
	},
	deencapsulate: stripInnerIPv6,
}

func (sixToFourProto) Listen(addr string, opts Options) (ProtoServer, error) {
	rs, err := listenRawIP(ipProtoSIT)
	if err != nil {
		return nil, err
	}
	return newRawServer(sixFourCfg, rs), nil
}

func (sixToFourProto) Dial(addr string, opts Options) (Tunnel, error) {
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
		cfg:   sixFourCfg,
		rs:    rs,
		id:    uint16(rand.Intn(1 << 16)),
		peer:  dst,
		self:  src,
		label: "6to4://" + host,
	}, nil
}
