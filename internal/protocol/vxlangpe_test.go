package protocol

import (
	"net"
	"testing"
	"time"
)

func TestVxlanGpeEncapDecap(t *testing.T) {
	frame, err := EncodeFrame(FramePing, 3, time.Now(), DefaultRTTSize)
	if err != nil {
		t.Fatal(err)
	}
	b, err := vxlanGpeEncap(0xABCDEF, frame)
	if err != nil {
		t.Fatalf("encap: %v", err)
	}
	if len(b) != 8+len(frame) {
		t.Fatalf("len = %d, want %d", len(b), 8+len(frame))
	}
	vni, np, got, err := vxlanGpeDecap(b)
	if err != nil {
		t.Fatalf("decap: %v", err)
	}
	if vni != 0xABCDEF {
		t.Errorf("vni = %#x, want 0xabcdef", vni)
	}
	if np != vxlanGpeNextProtoIPv4 {
		t.Errorf("next protocol = %#x, want %#x (IPv4)", np, vxlanGpeNextProtoIPv4)
	}
	if string(got) != string(frame) {
		t.Errorf("frame mismatch: got %d bytes, want %d", len(got), len(frame))
	}
	// Fixed header layout: flags 0x0C (version 0, I+P set), reserved bytes
	// 1-2 and 7 zero, next protocol 0x01 at byte 3, VNI in bytes 4-6.
	if b[0] != 0x0C || b[1] != 0x00 || b[2] != 0x00 || b[3] != 0x01 || b[7] != 0x00 {
		t.Errorf("header = % x, want 0c 00 00 01 ab cd ef 00", b[:8])
	}
	if b[4] != 0xAB || b[5] != 0xCD || b[6] != 0xEF {
		t.Errorf("vni bytes = % x, want ab cd ef", b[4:7])
	}

	// VNI must fit in 24 bits.
	if _, err := vxlanGpeEncap(1<<24, frame); err == nil {
		t.Error("vxlanGpeEncap accepted a VNI wider than 24 bits")
	}

	// Malformed headers must be rejected: truncated, I or P flag missing,
	// non-zero version, reserved flag bits set.
	bad := [][]byte{
		{0, 0, 0, 0, 0, 0, 0},
		{0x0C, 0, 0, 0, 0, 0, 0},    // truncated (7 bytes)
		{0x08, 0, 0, 0, 0, 0, 0, 0}, // I only, P flag missing
		{0x04, 0, 0, 0, 0, 0, 0, 0}, // P only, I flag missing
		{0x3C, 0, 0, 0, 0, 0, 0, 0}, // version 1 (bits 4-5)
		{0x0E, 0, 0, 0, 0, 0, 0, 0}, // I+P set, BUM flag set
	}
	for _, b := range bad {
		if _, _, _, err := vxlanGpeDecap(b); err == nil {
			t.Errorf("vxlanGpeDecap accepted malformed header % x", b)
		}
	}
}

// TestVxlanGpeLoopbackTunnel drives a full client/server round trip on
// 127.0.0.1: every ping must come back as a matching pong through the
// VXLAN-GPE framing.
func TestVxlanGpeLoopbackTunnel(t *testing.T) {
	// Reserve a free UDP port, then hand it to the server.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()

	srv, err := vxlanGpeProto{}.Listen(addr, Options{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srv.Close()
	go func() {
		for {
			tun, err := srv.Accept()
			if err != nil {
				return
			}
			go EchoLoop(tun)
		}
	}()

	cli, err := vxlanGpeProto{}.Dial(addr, Options{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()

	for seq := uint32(1); seq <= 10; seq++ {
		frame, err := EncodeFrame(FramePing, seq, time.Now(), DefaultRTTSize)
		if err != nil {
			t.Fatal(err)
		}
		if err := cli.WriteFrame(frame); err != nil {
			t.Fatalf("write %d: %v", seq, err)
		}
		readPong(t, cli, seq, 3*time.Second)
	}
}
