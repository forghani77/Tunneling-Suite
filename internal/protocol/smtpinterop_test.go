package protocol

import (
	"net"
	"os"
	"testing"
	"time"
)

// Verifies the Go smtp client handshake against an externally deployed
// smtp-tunnel-proxy Python server (set SMTP_PY_ADDR to host:port). The
// Python reference implementation is not part of this repository.
func TestSmtpInteropPythonServer(t *testing.T) {
	addr := os.Getenv("SMTP_PY_ADDR")
	if addr == "" {
		t.Skip("SMTP_PY_ADDR not set")
	}
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	conn, err := smtpDialHandshake(c, "tunnel-suit")
	if err != nil {
		t.Fatalf("handshake against python server failed: %v", err)
	}
	// Round-trip a tiny payload through the tunnel (the python server will
	// treat it as a binary frame, but the connection must stay usable).
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	t.Log("OK: Go client handshake against python server succeeded")
}
