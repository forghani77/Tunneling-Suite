package protocol

import (
	"encoding/binary"
	"math/rand"
	"net"
)

// icmpProto tunnels datagrams through ICMP echo messages (RFC 792) over a
// raw IPv4 socket (IP protocol 1), so the tunnel looks like ordinary ping
// traffic. The client sends echo requests (type 8); the server answers with
// echo replies (type 0).
//
// Two kernel behaviors need handling:
//
//   - On loopback a raw socket receives its own transmissions, so every
//     message carries a per-tunnel id and each end drops its own.
//   - The kernel auto-answers echo requests, so the server treats only echo
//     requests as client probes (echo replies — from the kernel or from other
//     harness servers on the same host — are ignored via clientOK), and the
//     client treats only echo replies as answers (the kernel's reply to the
//     client's own request carries the client's own id and is dropped
//     anyway).
type icmpProto struct{}

const ipProtoICMP = 1

func (icmpProto) Name() string    { return "icmp" }
func (icmpProto) Kind() Kind      { return KindDatagram }
func (icmpProto) Overhead() int   { return 30 } // 20 outer IPv4 + 8 ICMP echo header + 2 tunnel id
func (icmpProto) NeedsRoot() bool { return true }

// ICMP echo message format:
//
//	[type 1B][code 1B][checksum 2B][echo id 2B][echo seq 2B][tunnel id 2B][test frame ...]
const (
	icmpEchoReply   = 0
	icmpEchoRequest = 8
)

// icmp4Encap wraps a test frame in an ICMP echo message. Client probes are
// echo requests; server answers are echo replies. The echo header id/seq are
// cosmetic (the kernel copies them in auto-replies, which both ends ignore);
// the tunnel id travels in the data.
func icmp4Encap(serverSide bool, id uint16, frame []byte) []byte {
	msg := make([]byte, 10+len(frame))
	if serverSide {
		msg[0] = icmpEchoReply
	} else {
		msg[0] = icmpEchoRequest
	}
	binary.BigEndian.PutUint16(msg[4:6], id) // echo id
	binary.BigEndian.PutUint16(msg[8:10], id)
	copy(msg[10:], frame)
	// ipChecksum is the standard one's-complement checksum; the ICMPv4
	// checksum is the same algorithm over the message only (no pseudo-header),
	// with an odd trailing octet padded high.
	binary.BigEndian.PutUint16(msg[2:4], ipChecksum(msg))
	return msg
}

// icmp4Decap extracts the tunnel id and test frame from a received ICMP echo
// message, rejecting everything else (errors, redirects, timestamps, ...).
func icmp4Decap(payload []byte) (uint16, []byte, error) {
	if len(payload) < 10 || (payload[0] != icmpEchoRequest && payload[0] != icmpEchoReply) {
		return 0, nil, ErrBadFrame
	}
	return binary.BigEndian.Uint16(payload[8:10]), payload[10:], nil
}

var icmpCfg = rawConfig{
	protoNum: ipProtoICMP,
	encapsulate: func(serverSide bool, self, peer net.IP, id uint16, frame []byte) []byte {
		return icmp4Encap(serverSide, id, frame)
	},
	deencapsulate: icmp4Decap,
	// The server must ignore echo replies: the kernel auto-replies to echo
	// requests, and other harness servers only emit replies.
	clientOK: func(payload []byte) bool {
		return len(payload) > 0 && payload[0] == icmpEchoRequest
	},
	// The client must ignore echo requests (its own looped-back probes, or a
	// real ping aimed at the machine): only replies carry the server's data.
	serverOK: func(payload []byte) bool {
		return len(payload) > 0 && payload[0] == icmpEchoReply
	},
}

func (icmpProto) Listen(addr string, opts Options) (ProtoServer, error) {
	rs, err := listenRawIP(ipProtoICMP)
	if err != nil {
		return nil, err
	}
	return newRawServer(icmpCfg, rs), nil
}

func (icmpProto) Dial(addr string, opts Options) (Tunnel, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	dst, err := resolveIPv4(host)
	if err != nil {
		return nil, err
	}
	rs, err := listenRawIP(ipProtoICMP)
	if err != nil {
		return nil, err
	}
	src := opts.ClientIP
	if src == nil || src.IsUnspecified() {
		src = outboundIP(host)
	}
	return &rawTunnel{
		cfg:   icmpCfg,
		rs:    rs,
		id:    uint16(rand.Intn(1 << 16)),
		peer:  dst,
		self:  src,
		label: "icmp://" + host,
	}, nil
}
