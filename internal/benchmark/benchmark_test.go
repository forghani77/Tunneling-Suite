package benchmark

import (
	"fmt"
	"os"
	"testing"

	"tunnel-suite/internal/protocol"
	"tunnel-suite/internal/report"
)

// TestThroughputEndToEnd runs the throughput speed test against a couple of
// protocols on loopback with a short duration to keep the suite fast.
func TestThroughputEndToEnd(t *testing.T) {
	const base = 22000
	opts := protocol.Options{}
	for _, name := range []string{"tcp", "udp"} {
		p, ok := protocol.ByName(name)
		if !ok {
			t.Fatalf("protocol %s not registered", name)
		}
		t.Run(name, func(t *testing.T) {
			addr := protocol.JoinHostPort("127.0.0.1", base+protocol.PortOffset(p))
			srv, err := p.Listen(addr, opts)
			if err != nil {
				t.Skipf("listen: %v", err)
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

			cfg := DefaultConfig()
			cfg.ThroughputSec = 1
			res := RunThroughput(p, addr, opts, cfg)
			if res.Status != report.StatusOK {
				t.Fatalf("status=%s error=%q", res.Status, res.Error)
			}
			if res.UploadMbps <= 0 || res.DownloadMbps <= 0 {
				t.Fatalf("no throughput: up=%.1f down=%.1f", res.UploadMbps, res.DownloadMbps)
			}
			if res.SentBytes == 0 || res.RecvBytes == 0 || res.SentFrames == 0 {
				t.Fatalf("no data transferred: sent=%d recv=%d frames=%d", res.SentBytes, res.RecvBytes, res.SentFrames)
			}
			if res.DurationSec < 0.9 || res.DurationSec > 1.5 {
				t.Fatalf("duration %.1fs, want ~1s", res.DurationSec)
			}
			if p.Kind() == protocol.KindStream && res.LossPercent != 0 {
				t.Fatalf("stream loss %.2f%%, want 0", res.LossPercent)
			}
			fmt.Printf("%-8s throughput up=%.1f Mbps down=%.1f Mbps frames=%d/%d\n",
				name, res.UploadMbps, res.DownloadMbps, res.SentFrames, res.RecvFrames)
		})
	}
}

// TestMain disables the go-shadowsocks2 salt-replay filter: it is a
// process-global singleton, so with both ends of a test in one process the
// client's outbound salt is falsely flagged as repeated by the server.
// (Real client/server runs are separate processes and are unaffected.)
func TestMain(m *testing.M) {
	_ = os.Setenv("SHADOWSOCKS_SF_CAPACITY", "-1")
	os.Exit(m.Run())
}

// TestProtocolsEndToEnd runs the full benchmark against every protocol on
// loopback, with the server side in the same process.
func TestProtocolsEndToEnd(t *testing.T) {
	const base = 21000
	cfg := DefaultConfig()
	cfg.Pings = 10
	opts := protocol.Options{}

	for _, p := range protocol.All() {
		p := p
		t.Run(p.Name(), func(t *testing.T) {
			if p.NeedsRoot() && os.Geteuid() != 0 {
				t.Skip("requires root privileges")
			}
			addr := protocol.JoinHostPort("127.0.0.1", base+protocol.PortOffset(p))
			srv, err := p.Listen(addr, opts)
			if err != nil {
				t.Skipf("listen: %v", err)
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

			res := Run(p, addr, opts, cfg)
			if res.Status != report.StatusOK {
				t.Fatalf("status=%s note=%q error=%q", res.Status, res.Note, res.Error)
			}
			if res.RTT.Samples == 0 {
				t.Fatalf("no RTT samples")
			}
			if res.RTT.AvgMs < 0 {
				t.Fatalf("negative avg RTT: %v", res.RTT.AvgMs)
			}
			if res.OverheadBytes <= 0 {
				t.Fatalf("missing overhead")
			}
			fmt.Printf("%-12s ok  rtt=%.2fms loss=%.2f%% handshake=%.1fms\n",
				p.Name(), res.RTT.AvgMs, res.LossPercent, res.HandshakeMs)
		})
	}
}
