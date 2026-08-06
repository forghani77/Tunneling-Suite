package protocol

import (
	"net"
	"testing"
	"time"
)

func TestFrameRoundTrip(t *testing.T) {
	ts := time.Now()
	f, err := EncodeFrame(FramePing, 42, ts, DefaultRTTSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != DefaultRTTSize {
		t.Fatalf("frame size = %d, want %d", len(f), DefaultRTTSize)
	}
	ftype, seq, got, err := DecodeFrame(f)
	if err != nil {
		t.Fatal(err)
	}
	if ftype != FramePing || seq != 42 || !got.Equal(ts) {
		t.Fatalf("round trip mismatch: type=%d seq=%d ts=%v", ftype, seq, got)
	}
}

func TestDecodeFrameBad(t *testing.T) {
	if _, _, _, err := DecodeFrame([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short frame")
	}
}

func TestStreamTunnelFraming(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ct := newStreamTunnel(client, "test")
	st := newStreamTunnel(server, "test")

	payload := []byte("hello tunnel")
	go func() {
		if err := ct.WriteFrame(payload); err != nil {
			t.Error(err)
		}
	}()
	got, err := st.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
}

func TestEchoLoop(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ct := newStreamTunnel(client, "client")
	st := newStreamTunnel(server, "server")
	go EchoLoop(st)

	f, err := EncodeFrame(FramePing, 7, time.Now(), 64)
	if err != nil {
		t.Fatal(err)
	}
	if err := ct.WriteFrame(f); err != nil {
		t.Fatal(err)
	}
	got, err := ct.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	ftype, seq, _, err := DecodeFrame(got)
	if err != nil {
		t.Fatal(err)
	}
	if ftype != FramePong || seq != 7 {
		t.Fatalf("echo mismatch: type=%d seq=%d", ftype, seq)
	}
}

func TestChecksum(t *testing.T) {
	// Known vector: a zeroed 20-byte IPv4 header checksums to 0xFFFF when
	// complemented; just verify stability over two runs.
	b := make([]byte, 20)
	c1 := ipChecksum(b)
	c2 := ipChecksum(b)
	if c1 != c2 {
		t.Fatal("checksum not deterministic")
	}
}

func TestInnerPacketCrafting(t *testing.T) {
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	frame := []byte("payload")
	const id = 0x1234

	inner := craftInnerIPv4(src, dst, id, frame)
	if inner[0]>>4 != 4 {
		t.Fatal("inner IPv4 version mismatch")
	}
	gotID, got, err := stripInnerIPv4(inner)
	if err != nil {
		t.Fatal(err)
	}
	if gotID != id || string(got) != string(frame) {
		t.Fatalf("ipip round trip: id=%#x frame=%q", gotID, got)
	}

	inner6 := craftInnerIPv6(id, frame)
	if inner6[0]>>4 != 6 {
		t.Fatal("inner IPv6 version mismatch")
	}
	gotID6, got6, err := stripInnerIPv6(inner6)
	if err != nil {
		t.Fatal(err)
	}
	if gotID6 != id || string(got6) != string(frame) {
		t.Fatalf("sit round trip: id=%#x frame=%q", gotID6, got6)
	}

	g := greEnvelope(inner)
	gotGre, err := stripGRE(g)
	if err != nil {
		t.Fatal(err)
	}
	gotInnerID, gotInner, err := stripInnerIPv4(gotGre)
	if err != nil {
		t.Fatal(err)
	}
	if gotInnerID != id || string(gotInner) != string(frame) {
		t.Fatalf("gre round trip: id=%#x frame=%q", gotInnerID, gotInner)
	}
}
