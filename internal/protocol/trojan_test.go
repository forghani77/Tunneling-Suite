package protocol

import (
	"strings"
	"testing"
	"time"
)

// TestTrojanRoundTrip runs a full client/server session through the TLS +
// header handshake and echoes a few frames.
func TestTrojanRoundTrip(t *testing.T) {
	ps, err := trojanProto{}.Listen("127.0.0.1:0", Options{Password: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	addr := ps.(*trojanServer).ln.Addr().String()

	tun, err := trojanProto{}.Dial(addr, Options{Password: "hunter2"})
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

// TestTrojanWrongPassword verifies a peer without the token cannot complete
// the handshake: the server stays silent and the dial fails, bounded by the
// handshake timeout.
func TestTrojanWrongPassword(t *testing.T) {
	ps, err := trojanProto{}.Listen("127.0.0.1:0", Options{Password: "correct-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	addr := ps.(*trojanServer).ln.Addr().String()

	start := time.Now()
	tun, err := trojanProto{}.Dial(addr, Options{Password: "wrong-token"})
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
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("wrong-token dial took %v — handshake deadline not honoured", d)
	}
}

// TestTrojanHeaderFormat pins the wire-compatible header encoding: a real
// Trojan server must be able to parse it. The first 56 bytes are the
// lowercase hex SHA-224 of the password, followed by CRLF, command 0x01, an
// IPv4 address and the trailing CRLF.
func TestTrojanHeaderFormat(t *testing.T) {
	hdr := trojanEncodeHeader("tunnel-suite", 0x01)
	if len(hdr) < 56+2+1+1+4+2+2 {
		t.Fatalf("header too short: %d bytes", len(hdr))
	}
	hash := string(hdr[:56])
	if len(hash) != 56 || strings.ToLower(hash) != hash {
		t.Fatalf("password hash not lowercase hex: %q", hash)
	}
	if hash != trojanHashHex("tunnel-suite") {
		t.Fatalf("hash mismatch: %q vs %q", hash, trojanHashHex("tunnel-suite"))
	}
	if string(hdr[56:58]) != "\r\n" {
		t.Fatal("missing CRLF after hash")
	}
	if hdr[58] != 0x01 {
		t.Fatalf("command byte = %#x, want 0x01", hdr[58])
	}
	if hdr[59] != trojanAtypIPv4 {
		t.Fatalf("address type = %#x, want IPv4", hdr[59])
	}
	if string(hdr[len(hdr)-2:]) != "\r\n" {
		t.Fatal("missing trailing CRLF")
	}
}
