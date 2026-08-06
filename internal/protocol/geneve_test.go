package protocol

import (
	"net"
	"testing"
	"time"
)

func TestGeneveEncapDecap(t *testing.T) {
	frame, err := EncodeFrame(FramePing, 3, time.Now(), DefaultRTTSize)
	if err != nil {
		t.Fatal(err)
	}
	b, err := geneveEncap(0xABCDEF, frame)
	if err != nil {
		t.Fatalf("encap: %v", err)
	}
	if len(b) != 8+len(frame) {
		t.Fatalf("len = %d, want %d", len(b), 8+len(frame))
	}
	vni, got, err := geneveDecap(b)
	if err != nil {
		t.Fatalf("decap: %v", err)
	}
	if vni != 0xABCDEF {
		t.Errorf("vni = %#x, want 0xabcdef", vni)
	}
	if string(got) != string(frame) {
		t.Errorf("frame mismatch: got %d bytes, want %d", len(got), len(frame))
	}
	// Fixed header layout: version 0, no options/flags, protocol type
	// 0x0800 (IPv4), VNI in bytes 4-6, byte 7 reserved.
	if b[0] != 0x00 || b[1] != 0x00 || b[2] != 0x08 || b[3] != 0x00 || b[7] != 0x00 {
		t.Errorf("header = % x, want 00 00 08 00 ab cd ef 00", b[:8])
	}
	if b[4] != 0xAB || b[5] != 0xCD || b[6] != 0xEF {
		t.Errorf("vni bytes = % x, want ab cd ef", b[4:7])
	}

	// VNI must fit in 24 bits.
	if _, err := geneveEncap(1<<24, frame); err == nil {
		t.Error("geneveEncap accepted a VNI wider than 24 bits")
	}

	// Malformed headers must be rejected: truncated, wrong version,
	// options present.
	bad := [][]byte{
		{0, 0, 0, 0, 0, 0, 0},
		{0x40, 0, 8, 0, 0, 0, 0, 0}, // version 1
		{0x01, 0, 8, 0, 0, 0, 0, 0}, // opt len 1 (options present)
	}
	for _, b := range bad {
		if _, _, err := geneveDecap(b); err == nil {
			t.Errorf("geneveDecap accepted malformed header % x", b)
		}
	}
}

// TestGeneveLoopbackTunnel drives a full client/server round trip on
// 127.0.0.1: every ping must come back as a matching pong through the GENEVE
// framing.
func TestGeneveLoopbackTunnel(t *testing.T) {
	// Reserve a free UDP port, then hand it to the server.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()

	srv, err := geneveProto{}.Listen(addr, Options{})
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

	cli, err := geneveProto{}.Dial(addr, Options{})
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
