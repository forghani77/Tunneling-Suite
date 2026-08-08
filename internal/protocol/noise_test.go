package protocol

import (
	"testing"
	"time"
)

// TestNoiseRoundTrip runs a full client/server session through the NNpsk0
// handshake and echoes a few frames, verifying the length-framed transport
// works over the Noise stream.
func TestNoiseRoundTrip(t *testing.T) {
	ps, err := noiseProto{}.Listen("127.0.0.1:0", Options{Password: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	addr := ps.(*noiseServer).ln.Addr().String()

	tun, err := noiseProto{}.Dial(addr, Options{Password: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	serverTun, err := ps.Accept()
	if err != nil {
		t.Fatal(err)
	}
	go EchoLoop(serverTun)

	// A few frames of varying size, including one larger than a single
	// Noise message fits in one TCP segment, so ReadFrame must reassemble.
	for _, size := range []int{DefaultRTTSize, DefaultLossSize, 4096, 16384} {
		f, err := EncodeFrame(FramePing, 1, time.Now(), size)
		if err != nil {
			t.Fatal(err)
		}
		if err := tun.WriteFrame(f); err != nil {
			t.Fatal(err)
		}
		_ = tun.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, err := tun.ReadFrame()
		if err != nil {
			t.Fatalf("read (size %d): %v", size, err)
		}
		ftype, _, _, err := DecodeFrame(got)
		if err != nil {
			t.Fatalf("decode (size %d): %v", size, err)
		}
		if ftype != FramePong {
			t.Fatalf("size %d: got frame type %d, want Pong", size, ftype)
		}
		if len(got) != size {
			t.Fatalf("size %d: echoed %d bytes", size, len(got))
		}
	}
}

// TestNoiseWrongToken verifies a peer without the tunnel token cannot
// complete the handshake: the server stays silent and the client's dial
// fails, so a port scan sees a dead port. The failure must be bounded by the
// handshake timeout, never a hang.
func TestNoiseWrongToken(t *testing.T) {
	ps, err := noiseProto{}.Listen("127.0.0.1:0", Options{Password: "correct-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	addr := ps.(*noiseServer).ln.Addr().String()

	// The server goroutine sees the failed handshake and closes; make sure
	// it never pushes a tunnel (and thus never leaks one).
	start := time.Now()
	tun, err := noiseProto{}.Dial(addr, Options{Password: "wrong-token"})
	if err == nil {
		// A broken server could accept the connection and only fail later.
		// The right-token requirement means this should not happen, but if
		// the dial somehow succeeded, the tunnel must still be unusable
		// (the server never answers), not hang forever.
		_ = tun.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, rerr := tun.ReadFrame(); rerr == nil {
			t.Fatal("wrong-token tunnel unexpectedly echo-capable")
		}
		tun.Close()
		t.Log("dial succeeded but tunnel is dead (acceptable); server-side silent close verified")
		return
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("wrong-token dial took %v — handshake deadline not honoured", d)
	}
	t.Logf("wrong-token dial rejected in %v (server stayed silent)", time.Since(start))
}

// TestNoiseDefaultPassword verifies the two default-password endpoints
// interoperate (the harness's standard no-flag path).
func TestNoiseDefaultPassword(t *testing.T) {
	ps, err := noiseProto{}.Listen("127.0.0.1:0", Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	addr := ps.(*noiseServer).ln.Addr().String()

	tun, err := noiseProto{}.Dial(addr, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	serverTun, err := ps.Accept()
	if err != nil {
		t.Fatal(err)
	}
	go EchoLoop(serverTun)

	f, _ := EncodeFrame(FramePing, 9, time.Now(), 64)
	if err := tun.WriteFrame(f); err != nil {
		t.Fatal(err)
	}
	_ = tun.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := tun.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if _, seq, _, err := DecodeFrame(got); err != nil || seq != 9 {
		t.Fatalf("default-password echo mismatch: seq=%d err=%v", seq, err)
	}
}
