package client

import (
	"net"
	"testing"
	"time"

	"tunnel-suite/internal/benchmark"
	"tunnel-suite/internal/protocol"
	"tunnel-suite/internal/report"
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

// TestFetchManifestUsesControlPort verifies the manifest is fetched from the
// --control-port when it differs from the protocols base port: the fetch must
// dial the former, ignoring the latter for the control exchange.
func TestFetchManifestUsesControlPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 64)
		if _, err := c.Read(buf); err != nil {
			return
		}
		_, _ = c.Write([]byte(`{"entries":[{"name":"udp","port":30002,"kind":"datagram","needs_root":false,"available":true}]}`))
	}()

	// Protocols base port 30000 (nothing listens there); control port = ln's
	// port. A config that dialed the base port would fail to connect.
	entries, _, err := fetchManifest(Config{Server: "127.0.0.1", ProtocolsBasePort: 30000, ControlPort: port})
	if err != nil {
		t.Fatalf("fetchManifest with distinct control port: %v", err)
	}
	if _, ok := entries["udp"]; !ok {
		t.Errorf("manifest entries missing udp: %v", entries)
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
	_, _, err = fetchManifest(Config{Server: "127.0.0.1", ProtocolsBasePort: ln.Addr().(*net.TCPAddr).Port})
	if err == nil {
		t.Fatal("fetchManifest succeeded against a silent control server")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("fetchManifest hung for %v against a silent control server", d)
	}
}

// TestBlindThroughputRunSkipsControlPort pins the blind-mode throughput
// plumbing end to end: client.Run with Blind must never touch the TCP control
// port, even for the --throughput speed test. base+0 is a silent TCP
// squatter (accepts and never answers — a non-blind run would hang on the
// manifest fetch and fail), the only listener is a real UDP echo server at
// the protocol's port offset, and yet the throughput-only run must succeed
// quickly. This guards the client plumbing that routes cfg.Blind into both
// the benchmark and the speed test.
func TestBlindThroughputRunSkipsControlPort(t *testing.T) {
	ctl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	base := ctl.Addr().(*net.TCPAddr).Port
	done := make(chan struct{})
	defer close(done)
	go func() {
		c, err := ctl.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
		}
	}()

	udp, ok := protocol.ByName("udp")
	if !ok {
		t.Fatal("udp protocol not registered")
	}
	echoAddr := protocol.JoinHostPort("127.0.0.1", base+protocol.PortOffset(udp))
	srv, err := udp.Listen(echoAddr, protocol.Options{})
	if err != nil {
		t.Skipf("udp echo on %s (rare port collision): %v", echoAddr, err)
	}
	defer srv.Close()
	go func() {
		for {
			tun, err := srv.Accept()
			if err != nil {
				return
			}
			go protocol.EchoLoop(tun)
		}
	}()

	cfg := benchmark.DefaultConfig()
	cfg.ThroughputSec = 0.5
	cfg.ThroughputSize = 1400

	start := time.Now()
	rep, err := Run(Config{
		Server:            "127.0.0.1",
		ProtocolsBasePort: base,
		Blind:             true,
		Throughput:        []string{"udp"},
		ThroughputOnly:    true,
		Config:            cfg,
	})
	if err != nil {
		t.Fatalf("blind throughput run failed (did it dial the control port?): %v", err)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Fatalf("blind throughput run took %v, want < 15s", d)
	}
	if len(rep.Throughput) != 1 {
		t.Fatalf("throughput results = %d, want 1", len(rep.Throughput))
	}
	r := rep.Throughput[0]
	if r.Protocol != "udp" || r.Status != report.StatusOK {
		t.Fatalf("throughput = %s/%s, want udp/ok (error=%q)", r.Protocol, r.Status, r.Error)
	}
	if r.UploadMbps <= 0 || r.DownloadMbps <= 0 {
		t.Fatalf("no throughput: up=%.1f down=%.1f", r.UploadMbps, r.DownloadMbps)
	}
}
