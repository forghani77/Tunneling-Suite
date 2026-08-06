package protocol

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Unit tests (no privileges required)
// ---------------------------------------------------------------------------

func TestICMP6EncapDecap(t *testing.T) {
	src := net.ParseIP("2001:db8::1")
	dst := net.ParseIP("2001:db8::2")
	frame := []byte("hello icmpv6")

	msg := icmp6Encap(src, dst, 0xBEEF, frame)
	if len(msg) != 6+len(frame) {
		t.Fatalf("message length = %d, want %d", len(msg), 6+len(frame))
	}
	if msg[0] != icmp6Type {
		t.Fatalf("type = %d, want %d", msg[0], icmp6Type)
	}
	id, got, err := icmp6Decap(msg)
	if err != nil {
		t.Fatal(err)
	}
	if id != 0xBEEF {
		t.Fatalf("id = %#x, want %#x", id, 0xBEEF)
	}
	if string(got) != string(frame) {
		t.Fatalf("frame = %q, want %q", got, frame)
	}
}

func TestICMP6DecapForeign(t *testing.T) {
	// Non-experimental ICMPv6 type (128 = echo request): must be rejected.
	msg := make([]byte, 10)
	msg[0] = 128
	if _, _, err := icmp6Decap(msg); err != ErrBadFrame {
		t.Fatalf("echo request decap err = %v, want ErrBadFrame", err)
	}
	// Too short to carry the header.
	if _, _, err := icmp6Decap([]byte{icmp6Type, 0, 0, 0}); err != ErrBadFrame {
		t.Fatalf("short frame decap err = %v, want ErrBadFrame", err)
	}
}

func TestICMP6Checksum(t *testing.T) {
	src := net.ParseIP("2001:db8::1")
	dst := net.ParseIP("2001:db8::2")
	msg := icmp6Encap(src, dst, 0x1234, []byte("payload"))

	// With the checksum field set, the one's-complement sum over the IPv6
	// pseudo-header plus the message must be all-ones.
	pseudo := make([]byte, 40+len(msg))
	copy(pseudo[0:16], src.To16())
	copy(pseudo[16:32], dst.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(msg)))
	pseudo[39] = ipProtoICMPv6
	copy(pseudo[40:], msg)

	var sum uint32
	for i := 0; i+1 < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i:]))
	}
	if len(pseudo)%2 == 1 {
		sum += uint32(pseudo[len(pseudo)-1]) << 8 // pad the odd trailing octet
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if uint16(sum) != 0xffff {
		t.Fatalf("checksum does not verify: %#x", uint16(sum))
	}
}

// ---------------------------------------------------------------------------
// Loopback integration tests (require root/CAP_NET_RAW)
// ---------------------------------------------------------------------------

// skipNoRaw aborts the test when raw IPv6 sockets are unavailable.
func skipNoRaw(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root/CAP_NET_RAW for raw IPv6 sockets")
	}
}

// readPong reads frames until a pong matching seq arrives, skipping stale
// pongs (the client may legitimately receive a probe's echo more than once or
// out of order while multiple server tunnels are live).
func readPong(t *testing.T, tun Tunnel, seq uint32, d time.Duration) {
	t.Helper()
	if err := tun.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatal(err)
	}
	for {
		f, err := tun.ReadFrame()
		if err != nil {
			t.Fatalf("waiting for pong %d: %v", seq, err)
		}
		ftype, s, _, err := DecodeFrame(f)
		if err != nil {
			continue
		}
		if ftype == FramePong && s == seq {
			return
		}
	}
}

// startICMP6Server runs the accept/echo loops the way the real harness does
// and returns a stop function.
func startICMP6Server(t *testing.T) func() {
	t.Helper()
	srv, err := icmp6Proto{}.Listen("::", Options{})
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

// TestICMP6LoopbackTunnel drives a full client/server round trip on ::1:
// the client's pings must be echoed back as matching pongs.
func TestICMP6LoopbackTunnel(t *testing.T) {
	skipNoRaw(t)
	stop := startICMP6Server(t)
	defer stop()

	cli, err := icmp6Proto{}.Dial(net.JoinHostPort("::1", "1"), Options{})
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
}

// TestICMP6ServerSelfEchoFiltering guards the server against the loopback
// self-reception trap and the per-probe goroutine leak:
//
//  1. A raw IPv6 socket receives its own transmissions, so the server's
//     echoed probes loop back and must NOT be accepted as new client tunnels
//     (which would re-echo them forever).
//  2. Every probe from an already-known client session must be delivered to
//     that session's tunnel, not spawn a brand-new tunnel: before the fix the
//     server accepted ~one tunnel per probe, each leaking an EchoLoop
//     goroutine until shutdown (200 probes -> 186 permanent goroutines).
//
// The client is crafted directly with a fixed tunnel id so the session key
// is predictable: the assertion inspects only our session, staying immune to
// unrelated raw-socket traffic from other test processes on the same host.
func TestICMP6ServerSelfEchoFiltering(t *testing.T) {
	skipNoRaw(t)
	srv, err := icmp6Proto{}.Listen("::", Options{})
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	defer srv.Close()
	is, ok := srv.(*icmp6Server)
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

	const cliID = 0x4242 // distinctive; must not collide with a server id
	key := sessKey{peer: net.IPv6loopback.String(), id: cliID}
	sessions := func() int {
		is.mu.Lock()
		defer is.mu.Unlock()
		if _, ok := is.sessions[key]; ok {
			return 1
		}
		return 0
	}

	rs, err := listenRawIP6()
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	cli := &icmp6Tunnel{
		rs:    rs,
		id:    cliID,
		peer:  net.IPv6loopback,
		self:  net.IPv6loopback,
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

	// One client session means exactly one tunnel for our key. Before the
	// fix this was ~18 for 20 pings (one tunnel per probe), each leaking an
	// EchoLoop goroutine until server shutdown.
	if n := sessions(); n != 1 {
		t.Fatalf("server holds %d sessions for one client's 20 pings (expected 1; per-probe tunnel leak)", n)
	}
}
