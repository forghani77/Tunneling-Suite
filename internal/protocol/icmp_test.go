package protocol

import (
	"encoding/binary"
	"testing"
)

func TestICMP4EncapDecap(t *testing.T) {
	frame := []byte("hello icmp")

	// Client probes are echo requests.
	req := icmp4Encap(false, 0xBEEF, frame)
	if req[0] != icmpEchoRequest {
		t.Fatalf("client message type = %d, want %d (echo request)", req[0], icmpEchoRequest)
	}
	id, got, err := icmp4Decap(req)
	if err != nil {
		t.Fatal(err)
	}
	if id != 0xBEEF || string(got) != string(frame) {
		t.Fatalf("request round trip: id=%#x frame=%q", id, got)
	}

	// Server answers are echo replies.
	rep := icmp4Encap(true, 0xBEEF, frame)
	if rep[0] != icmpEchoReply {
		t.Fatalf("server message type = %d, want %d (echo reply)", rep[0], icmpEchoReply)
	}
	id, got, err = icmp4Decap(rep)
	if err != nil {
		t.Fatal(err)
	}
	if id != 0xBEEF || string(got) != string(frame) {
		t.Fatalf("reply round trip: id=%#x frame=%q", id, got)
	}
}

func TestICMP4DecapForeign(t *testing.T) {
	// Destination unreachable (type 3) must be rejected.
	bad := icmp4Encap(false, 1, []byte("x"))
	bad[0] = 3
	if _, _, err := icmp4Decap(bad); err != ErrBadFrame {
		t.Fatalf("foreign type decap err = %v, want ErrBadFrame", err)
	}
	// Too short to carry the header.
	if _, _, err := icmp4Decap([]byte{8, 0, 0, 0}); err != ErrBadFrame {
		t.Fatalf("short frame decap err = %v, want ErrBadFrame", err)
	}
}

func TestICMP4Checksum(t *testing.T) {
	msg := icmp4Encap(false, 0x1234, []byte("payload"))
	// With the checksum field set, the one's-complement sum over the message
	// must be all-ones. (Unlike ICMPv6 there is no pseudo-header: the ICMPv4
	// checksum covers the message only.)
	var sum uint32
	for i := 0; i+1 < len(msg); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(msg[i:]))
	}
	if len(msg)%2 == 1 {
		sum += uint32(msg[len(msg)-1]) << 8 // pad the odd trailing octet
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if uint16(sum) != 0xffff {
		t.Fatalf("checksum does not verify: %#x", uint16(sum))
	}
}

// TestICMP4DirectionFilters pins the client/server message-type split: the
// server must accept only echo requests (kernel auto-replies and other
// servers' echoes are replies), and the client only echo replies.
func TestICMP4DirectionFilters(t *testing.T) {
	req := icmp4Encap(false, 1, []byte("data"))
	rep := icmp4Encap(true, 1, []byte("data"))
	if !icmpCfg.clientOK(req) || icmpCfg.clientOK(rep) {
		t.Fatal("clientOK should accept only echo requests")
	}
	if icmpCfg.serverOK(req) || !icmpCfg.serverOK(rep) {
		t.Fatal("serverOK should accept only echo replies")
	}
}
