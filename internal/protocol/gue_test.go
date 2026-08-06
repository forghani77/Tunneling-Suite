package protocol

import (
	"net"
	"testing"
	"time"
)

func TestGueEncapDecap(t *testing.T) {
	frame, err := EncodeFrame(FramePing, 3, time.Now(), DefaultRTTSize)
	if err != nil {
		t.Fatal(err)
	}
	// GUE's VNI is a full 32-bit field, unlike the 24-bit VNIs of
	// geneve/vxlan/vxlan-gpe.
	b, err := gueEncap(0xABCDEF12, frame)
	if err != nil {
		t.Fatalf("encap: %v", err)
	}
	if len(b) != 8+len(frame) {
		t.Fatalf("len = %d, want %d", len(b), 8+len(frame))
	}
	vni, proto, got, err := gueDecap(b)
	if err != nil {
		t.Fatalf("decap: %v", err)
	}
	if vni != 0xABCDEF12 {
		t.Errorf("vni = %#x, want 0xabcdef12", vni)
	}
	if proto != gueProtoIPIP {
		t.Errorf("proto = %d, want %d (IPIP)", proto, gueProtoIPIP)
	}
	if string(got) != string(frame) {
		t.Errorf("frame mismatch: got %d bytes, want %d", len(got), len(frame))
	}
	// Fixed header layout: version 0, data message, Hlen = 1, proto/ctype
	// 94 (0x5e), VNI flag 0x80, then the 32-bit VNI.
	if b[0] != 0x01 || b[1] != 0x00 || b[2] != 0x5E || b[3] != 0x80 {
		t.Errorf("header = % x, want 01 00 5e 80 ab cd ef 12", b[:8])
	}
	if b[4] != 0xAB || b[5] != 0xCD || b[6] != 0xEF || b[7] != 0x12 {
		t.Errorf("vni bytes = % x, want ab cd ef 12", b[4:8])
	}

	// Malformed headers must be rejected: truncated, non-zero version,
	// control message, wrong Hlen, missing/unknown flags.
	bad := [][]byte{
		{0x01, 0x00, 0x5E, 0x80, 0, 0, 0},    // truncated (7 bytes)
		{0x41, 0x00, 0x5E, 0x80, 0, 0, 0, 0}, // version 1 (bits 6-7)
		{0x21, 0x00, 0x5E, 0x80, 0, 0, 0, 0}, // control message (C bit)
		{0x02, 0x00, 0x5E, 0x80, 0, 0, 0, 0}, // Hlen = 2, not 1
		{0x01, 0x00, 0x5E, 0x00, 0, 0, 0, 0}, // VNI flag clear
		{0x01, 0x00, 0x5E, 0xC0, 0, 0, 0, 0}, // VNI flag + unknown bit
		{0x01, 0x00, 0x5E, 0x40, 0, 0, 0, 0}, // unknown flag only
	}
	for _, b := range bad {
		if _, _, _, err := gueDecap(b); err == nil {
			t.Errorf("gueDecap accepted malformed header % x", b)
		}
	}
}

// TestGueLoopbackTunnel drives a full client/server round trip on 127.0.0.1:
// every ping must come back as a matching pong through the GUE framing.
func TestGueLoopbackTunnel(t *testing.T) {
	// Reserve a free UDP port, then hand it to the server.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()

	srv, err := gueProto{}.Listen(addr, Options{})
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

	cli, err := gueProto{}.Dial(addr, Options{})
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
