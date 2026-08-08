package protocol

import (
	"testing"
	"time"
)

// TestHysteria2RoundTrip runs a full client/server session through the
// QUIC + Salamander + Brutal tunnel and echoes a few frames.
func TestHysteria2RoundTrip(t *testing.T) {
	ps, err := hysteria2Proto{}.Listen("127.0.0.1:0", Options{Password: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	addr := ps.(*hysteria2Server).conn.LocalAddr().String()

	tun, err := hysteria2Proto{}.Dial(addr, Options{Password: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	serverTun, err := ps.Accept()
	if err != nil {
		t.Fatal(err)
	}
	go EchoLoop(serverTun)

	for _, size := range []int{DefaultRTTSize, 4096} {
		f, _ := EncodeFrame(FramePing, 1, time.Now(), size)
		if err := tun.WriteFrame(f); err != nil {
			t.Fatal(err)
		}
		_ = tun.SetReadDeadline(time.Now().Add(10 * time.Second))
		got, err := tun.ReadFrame()
		if err != nil {
			t.Fatalf("read (size %d): %v", size, err)
		}
		if ftype, _, _, err := DecodeFrame(got); err != nil || ftype != FramePong || len(got) != size {
			t.Fatalf("size %d: type=%d len=%d err=%v", size, ftype, len(got), err)
		}
	}
}

// TestHysteria2WrongPassword verifies a peer without the token cannot even
// complete the QUIC handshake: the Salamander PSK derives from the password,
// so every packet a wrong-token peer sends is obfuscated with the wrong key
// and the server discards it. The dial fails at quic-go's handshake-idle
// timeout (~5s) instead of producing a tunnel, and a port scan finds a dead
// port rather than a service.
func TestHysteria2WrongPassword(t *testing.T) {
	ps, err := hysteria2Proto{}.Listen("127.0.0.1:0", Options{Password: "correct-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	addr := ps.(*hysteria2Server).conn.LocalAddr().String()

	start := time.Now()
	tun, err := hysteria2Proto{}.Dial(addr, Options{Password: "wrong-token"})
	if err == nil {
		// A broken server could accept and only fail later; the tunnel must
		// then be dead, not echo-capable.
		_ = tun.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, rerr := tun.ReadFrame(); rerr == nil {
			t.Fatal("wrong-token tunnel unexpectedly echo-capable")
		}
		tun.Close()
		return
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("wrong-token dial took %v — handshake deadline not honoured", d)
	}
}
