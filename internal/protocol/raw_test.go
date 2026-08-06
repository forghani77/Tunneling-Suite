package protocol

import (
	"net"
	"os"
	"testing"
	"time"
)

// rawProtocols are the raw layer-3 protocols sharing the rawServer.
var rawProtocols = []Protocol{greProto{}, ipipProto{}, sitProto{}, sixToFourProto{}, icmpProto{}}

// rawCfgFor returns the rawConfig for a raw layer-3 protocol.
func rawCfgFor(p Protocol) rawConfig {
	switch p.Name() {
	case "gre":
		return greCfg
	case "ipip":
		return ipipCfg
	case "sit":
		return sitCfg
	case "6to4":
		return sixFourCfg
	case "icmp":
		return icmpCfg
	}
	panic("not a raw layer-3 protocol: " + p.Name())
}

// skipNoRawIP aborts the test when raw IPv4 sockets are unavailable.
func skipNoRawIP(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root/CAP_NET_RAW for raw IPv4 sockets")
	}
}

// startRawServer runs the accept/echo loops the way the real harness does and
// returns a stop function.
func startRawServer(t *testing.T, p Protocol) func() {
	t.Helper()
	srv, err := p.Listen("0.0.0.0:0", Options{})
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	go func() {
		for {
			tun, err := srv.Accept()
			if err != nil {
				return
			}
			go EchoLoop(tun)
		}
	}()
	return func() { _ = srv.Close() }
}

// TestSixToFourAddr verifies the RFC 3056 address derivation and the
// 6to4 inner-packet round trip.
func TestSixToFourAddr(t *testing.T) {
	cases := []struct {
		v4   string
		want string
	}{
		{"127.0.0.1", "2002:7f00:1::"},
		{"192.168.1.1", "2002:c0a8:101::"},
		{"8.8.8.8", "2002:808:808::"},
		{"10.0.0.1", "2002:a00:1::"},
	}
	for _, c := range cases {
		got := sixToFourAddr(net.ParseIP(c.v4))
		if got.String() != c.want {
			t.Errorf("sixToFourAddr(%s) = %s, want %s", c.v4, got, c.want)
		}
	}

	// Round trip: craft an inner 6to4 packet and strip it back.
	self, peer := net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.2")
	frame, err := EncodeFrame(FramePing, 7, time.Now(), DefaultRTTSize)
	if err != nil {
		t.Fatal(err)
	}
	b := craftInnerIPv6To4(self, peer, 0x1234, frame)
	id, got, err := stripInnerIPv6(b)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if id != 0x1234 {
		t.Errorf("id = %#x, want 0x1234", id)
	}
	if string(got) != string(frame) {
		t.Errorf("frame mismatch: got %d bytes, want %d", len(got), len(frame))
	}
	// The inner source/destination must be the 2002::/48 forms of the
	// outer endpoints, not the fixed ULA addresses sit uses.
	src, dst := net.IP(b[8:24]), net.IP(b[24:40])
	if src.String() != sixToFourAddr(self).String() || dst.String() != sixToFourAddr(peer).String() {
		t.Errorf("inner addrs = %s -> %s, want %s -> %s",
			src, dst, sixToFourAddr(self), sixToFourAddr(peer))
	}
}

// TestRawLoopbackTunnel drives a full client/server round trip on 127.0.0.1
// for every raw layer-3 protocol: the client's pings must be echoed back as
// matching pongs.
func TestRawLoopbackTunnel(t *testing.T) {
	skipNoRawIP(t)
	for _, p := range rawProtocols {
		p := p
		t.Run(p.Name(), func(t *testing.T) {
			stop := startRawServer(t, p)
			defer stop()

			cli, err := p.Dial(net.JoinHostPort("127.0.0.1", "1"), Options{})
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer cli.Close()

			for seq := uint32(1); seq <= 10; seq++ {
				frame, err := EncodeFrame(FramePing, seq, time.Now(), DefaultRTTSize)
				if err != nil {
					t.Fatal(err)
				}
				if err := cli.WriteFrame(frame); err != nil {
					t.Fatalf("write %d: %v", seq, err)
				}
				readPong(t, cli, seq, 3*time.Second)
			}
		})
	}
}

// TestRawServerSessionReuse guards the raw layer-3 servers against the
// loopback self-reception trap and the per-probe goroutine leak, mirroring
// TestICMP6ServerSelfEchoFiltering: a raw socket receives its own
// transmissions (and every other raw socket's), so the server must drop its
// own echoes and route repeat probes to one tunnel per client instead of
// accepting one tunnel per probe.
func TestRawServerSessionReuse(t *testing.T) {
	skipNoRawIP(t)
	for _, p := range rawProtocols {
		p := p
		t.Run(p.Name(), func(t *testing.T) {
			srv, err := p.Listen("0.0.0.0:0", Options{})
			if err != nil {
				t.Skipf("listen: %v", err)
			}
			defer srv.Close()
			is, ok := srv.(*rawServer)
			if !ok {
				t.Fatalf("unexpected server type %T", srv)
			}
			go func() {
				for {
					tun, err := srv.Accept()
					if err != nil {
						return
					}
					go EchoLoop(tun)
				}
			}()

			// Craft the client directly with a fixed tunnel id so the session
			// key is predictable and immune to unrelated raw-socket traffic
			// from other test processes on the same host.
			const cliID = 0x4242
			cfg := rawCfgFor(p)
			key := sessKey{peer: net.IPv4(127, 0, 0, 1).String(), id: cliID}
			sessions := func() int {
				is.mu.Lock()
				defer is.mu.Unlock()
				if _, ok := is.sessions[key]; ok {
					return 1
				}
				return 0
			}

			rs, err := listenRawIP(cfg.protoNum)
			if err != nil {
				t.Fatalf("client socket: %v", err)
			}
			cli := &rawTunnel{
				cfg:   cfg,
				rs:    rs,
				id:    cliID,
				peer:  net.IPv4(127, 0, 0, 1),
				self:  net.IPv4(127, 0, 0, 1),
				label: "test-client",
			}
			defer cli.Close()

			for seq := uint32(1); seq <= 20; seq++ {
				frame, err := EncodeFrame(FramePing, seq, time.Now(), DefaultRTTSize)
				if err != nil {
					t.Fatal(err)
				}
				if err := cli.WriteFrame(frame); err != nil {
					t.Fatalf("write %d: %v", seq, err)
				}
				readPong(t, cli, seq, 3*time.Second)
			}

			// One client session means exactly one tunnel for our key. Before
			// the fix the raw accept loop accepted every packet as a brand-new
			// tunnel (~one per probe).
			if n := sessions(); n != 1 {
				t.Fatalf("server holds %d sessions for one client's 20 pings (expected 1; per-probe tunnel leak)", n)
			}
		})
	}
}
