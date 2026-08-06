package protocol

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestL2tpEncapDecap(t *testing.T) {
	sessionID, cookie := l2tpSession("test-secret")
	if sessionID == 0 {
		t.Error("session ID must be non-zero per RFC 3931")
	}
	frame, err := EncodeFrame(FramePing, 3, time.Now(), DefaultRTTSize)
	if err != nil {
		t.Fatal(err)
	}
	b := l2tpEncap(sessionID, cookie, frame)
	if len(b) != 12+len(frame) {
		t.Fatalf("len = %d, want %d", len(b), 12+len(frame))
	}
	got, err := l2tpDecap(sessionID, cookie, b)
	if err != nil {
		t.Fatalf("decap: %v", err)
	}
	if string(got) != string(frame) {
		t.Errorf("frame mismatch: got %d bytes, want %d", len(got), len(frame))
	}
	// Fixed header layout: flags 0x0003 (T clear = data, Ver 3), reserved
	// word zero, Session ID, then the Cookie.
	if b[0] != 0x00 || b[1] != 0x03 || b[2] != 0x00 || b[3] != 0x00 {
		t.Errorf("flags/reserved = % x, want 00 03 00 00", b[0:4])
	}
	if binary.BigEndian.Uint32(b[4:8]) != sessionID {
		t.Errorf("session id = %#x, want %#x", binary.BigEndian.Uint32(b[4:8]), sessionID)
	}
	if string(b[8:12]) != string(cookie) {
		t.Errorf("cookie = % x, want % x", b[8:12], cookie)
	}

	// A mismatched session association must be rejected.
	otherID, otherCookie := l2tpSession("other-secret")
	if _, err := l2tpDecap(otherID, otherCookie, b); err == nil {
		t.Error("decap accepted a datagram for a different session")
	}
	if _, err := l2tpDecap(sessionID, otherCookie, b); err == nil {
		t.Error("decap accepted a datagram with the wrong cookie")
	}
	if _, err := l2tpDecap(otherID, cookie, b); err == nil {
		t.Error("decap accepted a datagram with the wrong session ID")
	}

	// Malformed headers must be rejected: truncated, T bit set (control
	// message), wrong version.
	bad := [][]byte{
		{0, 0, 0, 0},
		{0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0x80, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // T bit set (control)
		{0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},    // Ver 2 (L2TPv2)
	}
	for _, x := range bad {
		if _, err := l2tpDecap(sessionID, cookie, x); err == nil {
			t.Errorf("decap accepted malformed datagram of len %d", len(x))
		}
	}
}

// TestL2tpLoopbackTunnel drives a full client/server round trip on
// 127.0.0.1: every ping must come back as a matching pong through the
// L2TPv3 framing.
func TestL2tpLoopbackTunnel(t *testing.T) {
	// Reserve a free UDP port, then hand it to the server.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()

	opts := Options{Password: "shared-secret"}
	srv, err := l2tpProto{}.Listen(addr, opts)
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

	cli, err := l2tpProto{}.Dial(addr, opts)
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
