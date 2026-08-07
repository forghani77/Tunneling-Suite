package protocol

import (
	"math/rand"
	"net"
)

// greProto tunnels datagrams through GRE (RFC 2784) using a raw socket.
// Requires root/CAP_NET_RAW. The inner packet is a synthetic IPv4 packet so
// the test frames stay valid IP payloads on the wire.
type greProto struct{}

func (greProto) Name() string        { return "gre" }
func (greProto) Kind() Kind          { return KindDatagram }
func (greProto) Overhead() int       { return 46 } // 20 outer IP + 4 GRE + 20 inner IPv4 + 2 tunnel id
func (greProto) NeedsRoot() bool     { return true }
func (greProto) IsRawDatagram() bool { return true }

var greCfg = rawConfig{
	name:     "gre",
	protoNum: ipProtoGRE,
	encapsulate: func(serverSide bool, self, peer net.IP, id uint16, frame []byte) []byte {
		return greEnvelope(craftInnerIPv4(self, peer, id, frame))
	},
	deencapsulate: func(payload []byte) (uint16, []byte, error) {
		inner, err := stripGRE(payload)
		if err != nil {
			return 0, nil, err
		}
		return stripInnerIPv4(inner)
	},
}

func (greProto) Listen(addr string, opts Options) (ProtoServer, error) {
	rs, err := listenRawIP(ipProtoGRE)
	if err != nil {
		return nil, err
	}
	return newRawServer(greCfg, rs), nil
}

func (greProto) Dial(addr string, opts Options) (Tunnel, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	dst, err := resolveIPv4(host)
	if err != nil {
		return nil, err
	}
	rs, err := listenRawIP(ipProtoGRE)
	if err != nil {
		return nil, err
	}
	src := opts.ClientIP
	if src == nil || src.IsUnspecified() {
		src = outboundIP(host)
	}
	return &rawTunnel{
		cfg:   greCfg,
		rs:    rs,
		id:    uint16(rand.Intn(1 << 16)),
		peer:  dst,
		self:  src,
		label: "gre://" + host,
	}, nil
}
