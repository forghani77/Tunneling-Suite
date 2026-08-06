package protocol

import (
	"net"
	"testing"
	"time"
)

func TestVxlanEncapDecap(t *testing.T) {
	frame, err := EncodeFrame(FramePing, 3, time.Now(), DefaultRTTSize)
	if err != nil {
		t.Fatal(err)
	}
	b, err := vxlanEncap(0xABCDEF, frame)
	if err != nil {
		t.Fatalf("encap: %v", err)
	}
	if len(b) != 8+len(frame) {
		t.Fatalf("len = %d, want %d", len(b), 8+len(frame))
	}
	vni, got, err := vxlanDecap(b)
	if err != nil {
		t.Fatalf("decap: %v", err)
	}
	if vni != 0xABCDEF {
		t.Errorf("vni = %#x, want 0xabcdef", vni)
	}
	if string(got) != string(frame) {
		t.Errorf("frame mismatch: got %d bytes, want %d", len(got), len(frame))
	}
	// Fixed header layout: flags 0x08 (I flag), reserved bytes 1-3 and 7
	// zero, VNI in bytes 4-6.
	if b[0] != 0x08 || b[1] != 0x00 || b[2] != 0x00 || b[3] != 0x00 || b[7] != 0x00 {
		t.Errorf("header = % x, want 08 00 00 00 ab cd ef 00", b[:8])
	}
	if b[4] != 0xAB || b[5] != 0xCD || b[6] != 0xEF {
		t.Errorf("vni bytes = % x, want ab cd ef", b[4:7])
	}

	// VNI must fit in 24 bits.
	if _, err := vxlanEncap(1<<24, frame); err == nil {
		t.Error("vxlanEncap accepted a VNI wider than 24 bits")
	}

	// Malformed headers must be rejected: truncated, I flag clear,
	// reserved flag bits set.
	bad := [][]byte{
		{0, 0, 0, 0, 0, 0, 0},
		{0x08, 0, 0, 0, 0, 0, 0},    // truncated (7 bytes)
		{0x00, 0, 0, 0, 0, 0, 0, 0}, // I flag clear
		{0x0C, 0, 0, 0, 0, 0, 0, 0}, // I flag set, reserved R bit also set
	}
	for _, b := range bad {
		if _, _, err := vxlanDecap(b); err == nil {
			t.Errorf("vxlanDecap accepted malformed header % x", b)
		}
	}
}

// TestVxlanLoopbackTunnel drives a full client/server round trip on
// 127.0.0.1: every ping must come back as a matching pong through the VXLAN
// framing.
func TestVxlanLoopbackTunnel(t *testing.T) {
	// Reserve a free UDP port, then hand it to the server.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()

	srv, err := vxlanProto{}.Listen(addr, Options{})
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

	cli, err := vxlanProto{}.Dial(addr, Options{})
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
