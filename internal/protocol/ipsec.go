package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"
)

// ipsecProto tunnels datagrams through IPsec ESP (RFC 4303) with the AES-GCM
// transform (RFC 4106), encapsulated in UDP per the IPsec NAT-Traversal
// scheme (RFC 3948): a 4-byte non-IKE marker precedes each ESP packet, the
// way real IPsec tunnels run over UDP port 4500. Every datagram carries a
// genuine ESP packet — SPI, sequence number, 8-byte IV, and an
// authenticated ciphertext whose GCM tag serves as the ICV — making this the
// only encrypted and integrity-protected tunnel in the harness. Both ends
// share one static SA: the AES-128 key and 4-byte GCM salt are derived from
// the shared secret (--password; defaultPassword when unset), and the SPI is
// a fixed constant, mirroring the harness's other secret-based protocols
// (anytls, naive, smtp). No IKE handshake is performed. Runs without root:
// the UDP encapsulation avoids raw sockets and the kernel's XFRM/IPsec
// stack, which would otherwise intercept raw protocol-50 ESP traffic.
type ipsecProto struct{}

const (
	// ipsecSPI is the fixed Security Parameters Index of the harness's
	// single static SA. Real IPsec assigns SPIs per SA via IKE; the
	// harness uses one shared SA with a static secret.
	ipsecSPI = 0x12345678

	// ipsecNextHeaderIPv4 marks the inner payload as an IPv4 packet (IANA
	// protocol number 4), the encapsulated protocol of a tunnel-mode ESP
	// SA carrying an IP packet.
	ipsecNextHeaderIPv4 = 4

	// ipsecNonIkeMarker is the 4-byte zero prefix that RFC 3948 places
	// before ESP packets in UDP (IKE packets instead start with the
	// nonzero initiator cookie).
	ipsecNonIkeMarker = 0
)

func ipsecPassword(opts Options) string {
	if opts.Password != "" {
		return opts.Password
	}
	return defaultPassword
}

func (ipsecProto) Name() string    { return "ipsec" }
func (ipsecProto) Kind() Kind      { return KindDatagram }
func (ipsecProto) Overhead() int   { return 68 } // 20 IP + 8 UDP + 4 marker + 8 SPI/Seq + 8 IV + 16 ICV + 2 padlen/next + 0-3 pad: 66-69, 68 for the default 64B frame
func (ipsecProto) NeedsRoot() bool { return false }

// ipsecKey derives the AES-128 key and 4-byte GCM salt for the shared SA
// from the secret.
func ipsecKey(psk string) (key, salt []byte) {
	digest := sha256.Sum256([]byte(psk))
	return digest[:16], digest[16:20]
}

// ipsecEncap builds the RFC 3948 UDP payload: the non-IKE marker followed by
// the ESP packet. The plaintext is the frame, zero padding, the Pad Length,
// and the Next Header byte; it is encrypted with AES-GCM whose additional
// authenticated data is the ESP header (SPI || sequence), per RFC 4106.
func ipsecEncap(key, salt []byte, seq uint32, iv, frame []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Pad so the encrypted portion (frame + pad + padlen + nexthdr) is a
	// multiple of 4, per RFC 4303.
	pad := (4 - (len(frame)+2)%4) % 4
	pt := make([]byte, 0, len(frame)+pad+2)
	pt = append(pt, frame...)
	pt = append(pt, make([]byte, pad)...)
	pt = append(pt, byte(pad), ipsecNextHeaderIPv4)

	var esp [8]byte
	binary.BigEndian.PutUint32(esp[0:4], ipsecSPI)
	binary.BigEndian.PutUint32(esp[4:8], seq)

	nonce := make([]byte, 12)
	copy(nonce, salt)
	copy(nonce[4:], iv)

	out := make([]byte, 4+8+8+len(pt)+gcm.Overhead())
	binary.BigEndian.PutUint32(out[0:4], ipsecNonIkeMarker)
	copy(out[4:12], esp[:])
	copy(out[12:20], iv)
	gcm.Seal(out[20:20], nonce, pt, esp[:])
	return out, nil
}

// ipsecDecap validates the marker and SPI, then decrypts and authenticates
// the ESP packet, returning the inner frame. Any failure — bad marker, wrong
// SPI, truncated packet, or failed GCM authentication — yields ErrBadFrame.
func ipsecDecap(key, salt []byte, b []byte) ([]byte, error) {
	if len(b) < 4+8+8+2+16 || binary.BigEndian.Uint32(b[0:4]) != ipsecNonIkeMarker {
		return nil, ErrBadFrame
	}
	if binary.BigEndian.Uint32(b[4:8]) != ipsecSPI {
		return nil, ErrBadFrame
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	copy(nonce, salt)
	copy(nonce[4:], b[12:20])
	pt, err := gcm.Open(nil, nonce, b[20:], b[4:12]) // AAD = SPI || sequence
	if err != nil {
		return nil, ErrBadFrame
	}
	if len(pt) < 2 || pt[len(pt)-1] != ipsecNextHeaderIPv4 {
		return nil, ErrBadFrame
	}
	padLen := int(pt[len(pt)-2])
	if padLen > len(pt)-2 {
		return nil, ErrBadFrame
	}
	return pt[:len(pt)-2-padLen], nil
}

// ipsecTunnel wraps a datagram transport with ESP framing: every outgoing
// frame is encrypted under the shared SA, and every incoming datagram is
// authenticated before its payload is released.
type ipsecTunnel struct {
	dt   Tunnel
	key  []byte
	salt []byte
	seq  uint32
}

func (t *ipsecTunnel) WriteFrame(p []byte) error {
	iv := make([]byte, 8)
	if _, err := rand.Read(iv); err != nil {
		return err
	}
	seq := atomic.AddUint32(&t.seq, 1)
	b, err := ipsecEncap(t.key, t.salt, seq, iv, p)
	if err != nil {
		return err
	}
	return t.dt.WriteFrame(b)
}

func (t *ipsecTunnel) ReadFrame() ([]byte, error) {
	for {
		b, err := t.dt.ReadFrame()
		if err != nil {
			return nil, err
		}
		f, err := ipsecDecap(t.key, t.salt, b)
		if err != nil {
			// Not a valid ESP datagram for our SA: keep waiting.
			continue
		}
		return f, nil
	}
}

func (t *ipsecTunnel) SetReadDeadline(d time.Time) error { return t.dt.SetReadDeadline(d) }
func (t *ipsecTunnel) Close() error                      { return t.dt.Close() }
func (t *ipsecTunnel) Label() string                     { return t.dt.Label() }

type ipsecServer struct {
	conn *net.UDPConn
	key  []byte
	salt []byte
}

func (ipsecProto) Listen(addr string, opts Options) (ProtoServer, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	key, salt := ipsecKey(ipsecPassword(opts))
	return &ipsecServer{conn: conn, key: key, salt: salt}, nil
}

// Accept authenticates the first datagram against the shared SA; only a
// valid ESP packet for our SPI passes, so stray or hostile UDP traffic is
// rejected rather than merely structurally skipped.
func (s *ipsecServer) Accept() (Tunnel, error) {
	buf := make([]byte, MaxFrame)
	for {
		n, peer, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}
		if _, err := ipsecDecap(s.key, s.salt, buf[:n]); err != nil {
			continue
		}
		return &ipsecTunnel{
			dt: &packetTunnel{
				pc:      s.conn,
				peer:    peer,
				pending: buf[:n],
				label:   "ipsec@" + peer.String(),
			},
			key:  s.key,
			salt: s.salt,
		}, nil
	}
}

func (s *ipsecServer) Close() error { return s.conn.Close() }

func (ipsecProto) Dial(addr string, opts Options) (Tunnel, error) {
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		return nil, err
	}
	key, salt := ipsecKey(ipsecPassword(opts))
	return &ipsecTunnel{
		dt:   &datagramTunnel{c: c, label: "ipsec://" + addr},
		key:  key,
		salt: salt,
	}, nil
}
