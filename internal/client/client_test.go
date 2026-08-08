package client

import (
	"net"
	"testing"
	"time"

	"tunnel-suite/internal/protocol"
)

func TestBlindEntriesCoversAllProtocols(t *testing.T) {
	entries, ip, err := protocolEntries(Config{Blind: true})
	if err != nil {
		t.Fatalf("protocolEntries(blind): %v", err)
	}
	if ip != nil {
		t.Errorf("blind mode should not report a client IP: got %v", ip)
	}
	all := protocol.All()
	if len(entries) != len(all) {
		t.Errorf("blind entries = %d, want %d (one per registry protocol)", len(entries), len(all))
	}
	for _, p := range all {
		e, ok := entries[p.Name()]
		if !ok {
			t.Errorf("blind entries missing %q", p.Name())
			continue
		}
		if !e.Available {
			t.Errorf("blind entry %q should be marked available", p.Name())
		}
		if e.Port != protocol.PortOffset(p) {
			t.Errorf("blind entry %q port = %d, want offset %d", p.Name(), e.Port, protocol.PortOffset(p))
		}
	}
}

// TestFetchManifestSilentControlPort verifies the manifest fetch fails
// promptly when the control port accepts TCP but never answers (an unrelated
// service squatting on base+0 would otherwise hang the client forever).
func TestFetchManifestSilentControlPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	defer close(done)
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

	start := time.Now()
	_, _, err = fetchManifest(Config{Server: "127.0.0.1", BasePort: ln.Addr().(*net.TCPAddr).Port})
	if err == nil {
		t.Fatal("fetchManifest succeeded against a silent control server")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("fetchManifest hung for %v against a silent control server", d)
	}
}
