package protocol

import (
	"bytes"
	"testing"
	"time"
)

// TestShadowTLSRoundTrip runs a full client/server session through the
// greeting + TLS handshake + authenticated record exchange.
func TestShadowTLSRoundTrip(t *testing.T) {
	ps, err := shadowTLSProto{}.Listen("127.0.0.1:0", Options{Password: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	addr := ps.(*shadowTLSServer).ln.Addr().String()

	tun, err := shadowTLSProto{}.Dial(addr, Options{Password: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	serverTun, err := ps.Accept()
	if err != nil {
		t.Fatal(err)
	}
	go EchoLoop(serverTun)

	for _, size := range []int{DefaultRTTSize, 4096, 16384} {
		f, _ := EncodeFrame(FramePing, 1, time.Now(), size)
		if err := tun.WriteFrame(f); err != nil {
			t.Fatal(err)
		}
		_ = tun.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, err := tun.ReadFrame()
		if err != nil {
			t.Fatalf("read (size %d): %v", size, err)
		}
		if ftype, _, _, err := DecodeFrame(got); err != nil || ftype != FramePong || len(got) != size {
			t.Fatalf("size %d: type=%d len=%d err=%v", size, ftype, len(got), err)
		}
	}
}

// TestShadowTLSWrongPassword verifies a peer without the token is rejected:
// the server closes silently on the failed record authentication.
func TestShadowTLSWrongPassword(t *testing.T) {
	ps, err := shadowTLSProto{}.Listen("127.0.0.1:0", Options{Password: "correct-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	addr := ps.(*shadowTLSServer).ln.Addr().String()

	start := time.Now()
	tun, err := shadowTLSProto{}.Dial(addr, Options{Password: "wrong-token"})
	if err == nil {
		_ = tun.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, rerr := tun.ReadFrame(); rerr == nil {
			t.Fatal("wrong-token tunnel unexpectedly echo-capable")
		}
		tun.Close()
		return
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("wrong-token dial took %v — handshake deadline not honoured", d)
	}
}

// TestShadowTLSRecordFormat pins the v3 record framing: application-data
// header, 4-byte HMAC tag, XOR-obfuscated payload, and a tampered record
// must fail verification.
func TestShadowTLSRecordFormat(t *testing.T) {
	secret := "tunnel-suite"
	keys := shadowTLSKeysFor(secret, shadowTLSServerRandom(secret))

	payload := []byte("hello record layer")
	var buf bytes.Buffer
	if err := shadowTLSWriteFrame(&buf, keys.sendMac, keys.xorKey, payload); err != nil {
		t.Fatal(err)
	}
	wire := buf.Bytes()
	if wire[0] != 0x17 {
		t.Fatalf("record type = %#x, want 0x17 (application data)", wire[0])
	}
	if n := int(wire[3])<<8 | int(wire[4]); n != shadowTLSHmacLen+len(payload) {
		t.Fatalf("record length = %d, want %d", n, shadowTLSHmacLen+len(payload))
	}

	got, err := shadowTLSReadFrame(&buf, keys.recvMac, keys.xorKey)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round trip mismatch: %q", got)
	}

	// A flipped bit in the payload must fail the tag.
	tampered := append([]byte(nil), wire...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := shadowTLSReadFrame(bytes.NewReader(tampered), keys.recvMac, keys.xorKey); err == nil {
		t.Fatal("tampered record passed verification")
	}
}
