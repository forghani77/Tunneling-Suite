package protocol

import (
	"net"
	"testing"
	"time"
)

// silentListener accepts one TCP connection and holds it open without ever
// sending a byte, mimicking an unrelated service squatting on a protocol's
// control port (exactly what a blind-mode probe of an absent protocol hits).
func silentListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	// Cleanup runs LIFO, so register ln.Close first and close(done) second:
	// the held conn is released before the listener goes away.
	t.Cleanup(func() { _ = ln.Close() })
	t.Cleanup(func() { close(done) })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
		}
	}()
	return ln
}

// TestWireguardDialSilentServer verifies the client key exchange fails
// promptly when the control port accepts TCP but never answers. The exchange
// happens before any interface setup, so no root/TUN is needed.
func TestWireguardDialSilentServer(t *testing.T) {
	if err := checkWGTools(); err != nil {
		t.Skipf("wg/ip tools unavailable: %v", err)
	}
	ln := silentListener(t)
	start := time.Now()
	_, err := (wgProto{}).Dial(ln.Addr().String(), Options{})
	if err == nil {
		t.Fatal("Dial succeeded against a silent control server")
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Fatalf("Dial hung for %v against a silent control server", d)
	}
}

// TestAmneziaDialSilentServer is the same check for the AmneziaWG variants,
// whose key exchange used to hang forever on a silent control port (reported
// as the blind test hanging on amnezia).
func TestAmneziaDialSilentServer(t *testing.T) {
	for _, p := range []amneziaProto{{awgV1}, {awgV2}} {
		t.Run(p.Name(), func(t *testing.T) {
			t.Parallel() // each waits out the 10s key-exchange deadline
			ln := silentListener(t)
			start := time.Now()
			_, err := p.Dial(ln.Addr().String(), Options{})
			if err == nil {
				t.Fatal("Dial succeeded against a silent control server")
			}
			if d := time.Since(start); d > 15*time.Second {
				t.Fatalf("Dial hung for %v against a silent control server", d)
			}
		})
	}
}
