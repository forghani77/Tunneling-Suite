package client

import (
	"testing"

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
