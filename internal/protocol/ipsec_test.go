package protocol

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestIpsecEncapDecap(t *testing.T) {
	key, salt := ipsecKey("test-secret")
	frame, err := EncodeFrame(FramePing, 7, time.Now(), DefaultRTTSize)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 8)
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	b, err := ipsecEncap(key, salt, 1, iv, frame)
	if err != nil {
		t.Fatalf("encap: %v", err)
	}
	// Structure: marker(4) + SPI(4) + seq(4) + IV(8) + ciphertext + tag.
	if len(b) < 4+8+8+len(frame)+16 {
		t.Fatalf("len = %d, want at least %d", len(b), 4+8+8+len(frame)+16)
	}
	if binary.BigEndian.Uint32(b[0:4]) != 0 {
		t.Errorf("non-IKE marker = %#x, want 0", b[0:4])
	}
	if binary.BigEndian.Uint32(b[4:8]) != ipsecSPI {
		t.Errorf("SPI = %#x, want %#x", binary.BigEndian.Uint32(b[4:8]), ipsecSPI)
	}
	if string(b[12:20]) != string(iv) {
		t.Errorf("IV on the wire does not match the one passed to encap")
	}
	// The payload bytes must be ciphertext: the frame must not appear in
	// cleartext anywhere in the datagram.
	for i := 20; i+len(frame) <= len(b); i++ {
		if string(b[i:i+len(frame)]) == string(frame) {
			t.Fatalf("frame appears in cleartext at offset %d", i)
		}
	}

	got, err := ipsecDecap(key, salt, b)
	if err != nil {
		t.Fatalf("decap: %v", err)
	}
	if string(got) != string(frame) {
		t.Errorf("frame mismatch: got %d bytes, want %d", len(got), len(frame))
	}

	// A different SA (wrong password) must fail authentication.
	otherKey, otherSalt := ipsecKey("other-secret")
	if _, err := ipsecDecap(otherKey, otherSalt, b); err == nil {
		t.Error("decap accepted a packet encrypted under a different SA")
	}

	// Tampering with the ciphertext must fail GCM authentication.
	tampered := append([]byte(nil), b...)
	tampered[30] ^= 0xFF
	if _, err := ipsecDecap(key, salt, tampered); err == nil {
		t.Error("decap accepted a tampered ciphertext")
	}

	// Tampering with the ESP header (SPI) must fail, since it is AAD.
	badSpi := append([]byte(nil), b...)
	badSpi[4] ^= 0xFF
	if _, err := ipsecDecap(key, salt, badSpi); err == nil {
		t.Error("decap accepted a tampered SPI")
	}

	// Malformed datagrams must be rejected: truncated, missing marker.
	bad := [][]byte{
		{0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		b[4:], // valid ESP minus the non-IKE marker
	}
	for _, x := range bad {
		if _, err := ipsecDecap(key, salt, x); err == nil {
			t.Errorf("decap accepted malformed datagram of len %d", len(x))
		}
	}
}

// TestIpsecLoopbackTunnel drives a full client/server round trip on
// 127.0.0.1: every ping must come back as a matching pong, encrypted under
// the shared SA on the way out and authenticated on the way in.
func TestIpsecLoopbackTunnel(t *testing.T) {
	// Reserve a free UDP port, then hand it to the server.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()

	opts := Options{Password: "shared-secret"}
	srv, err := ipsecProto{}.Listen(addr, opts)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srv.Close()
	go func() {
		for {
			tun, err := srv.Accept()
			if err != nil {
				return
			}
			go EchoLoop(tun)
		}
	}()

	cli, err := ipsecProto{}.Dial(addr, opts)
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
