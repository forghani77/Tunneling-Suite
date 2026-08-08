package protocol

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// shadowTLSProto tunnels bytes over TLS behind a ShadowTLS-style record
// layer (v3 wire format): a real TLS handshake followed by TLS application
// data records, each carrying a 4-byte HMAC-SHA1 tag and a payload XORed
// with a password-derived keystream. On the wire it is indistinguishable
// from ordinary HTTPS — no extra handshake, no recognisable protocol bytes —
// and a peer without the shared token fails the HMAC on the very first
// record, so the server closes silently and a port scan finds a dead port.
//
// The harness implements the v3 framing (the sing-shadowtls/ihciah shadow-tls
// record format) without the decoy-site TLS splice: the "server random" the
// v3 key derivation feeds on is a 32-byte password-derived greeting the
// server sends before the TLS handshake, so both ends agree on it without a
// decoy. Every post-handshake record is authenticated, so a wrong password
// is detected on the first exchange and the connection dies silently.
type shadowTLSProto struct{}

func (shadowTLSProto) Name() string    { return "shadowtls" }
func (shadowTLSProto) Kind() Kind      { return KindStream }
func (shadowTLSProto) Overhead() int   { return 69 } // 20 IP + 20 TCP + 5 TLS + 4 HMAC + 20 XOR record
func (shadowTLSProto) NeedsRoot() bool { return false }

const (
	// shadowTLSHandshakeTimeout bounds the greeting + TLS handshake + auth
	// exchange so a stalled or hostile peer (blind-mode probe) cannot leak a
	// goroutine and fd.
	shadowTLSHandshakeTimeout = 10 * time.Second
	// shadowTLSGreetingLen is the size of the pre-TLS server greeting (the
	// v3 key-derivation seed).
	shadowTLSGreetingLen = 32
	// shadowTLSHmacLen is the per-record authentication tag length (HMAC-SHA1
	// truncated to 4 bytes, exactly as shadow-tls v3 does).
	shadowTLSHmacLen = 4
	// shadowTLSTLSHeaderLen is the length of the TLS record header.
	shadowTLSTLSHeaderLen = 5
	// shadowTLSFrameOverhead is header + HMAC tag.
	shadowTLSFrameOverhead = shadowTLSTLSHeaderLen + shadowTLSHmacLen
)

func shadowTLSPassword(opts Options) string {
	if opts.Password != "" {
		return opts.Password
	}
	return defaultPassword
}

// shadowTLSServerRandom derives the v3 key-derivation seed. In the real
// shadow-tls it is the decoy TLS ServerHello random; the harness fixes it as
// a password-derived value sent up front, so the whole key material derives
// from the shared token and no decoy is needed.
func shadowTLSServerRandom(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// shadowTLSKeys bundles the per-session key material, all derived from the
// password and the server random, mirroring shadow-tls v3.
type shadowTLSKeys struct {
	sendMac   []byte // HMAC key: password
	recvMac   []byte // HMAC key: password
	xorKey    []byte // XOR keystream seed: SHA-256(password || server_random)
	serverRnd []byte
}

func shadowTLSKeysFor(secret string, serverRnd []byte) *shadowTLSKeys {
	x := sha256.New()
	x.Write([]byte(secret))
	x.Write(serverRnd)
	return &shadowTLSKeys{
		sendMac:   []byte(secret),
		recvMac:   []byte(secret),
		xorKey:    x.Sum(nil),
		serverRnd: serverRnd,
	}
}

// shadowTLSHmac computes the 4-byte record tag: the first 4 bytes of
// HMAC-SHA1(key, xorPayload), matching shadow-tls v3's frame authentication.
func shadowTLSHmac(key, xorPayload []byte) [shadowTLSHmacLen]byte {
	m := hmac.New(sha1.New, key)
	m.Write(xorPayload)
	var tag [shadowTLSHmacLen]byte
	copy(tag[:], m.Sum(nil)[:shadowTLSHmacLen])
	return tag
}

// shadowTLSXor applies the keystream (XOR of SHA-256(password||rnd), cycled)
// in place, exactly like shadow-tls v3's xor_slice.
func shadowTLSXor(data, key []byte) {
	for i := range data {
		data[i] ^= key[i%len(key)]
	}
}

// ---------------------------------------------------------------------------
// Record framing
// ---------------------------------------------------------------------------

// shadowTLSWriteFrame writes one authenticated application-data record:
//
//	[17 03 03][2B len][4B HMAC-SHA1 tag][XOR'd payload]
//
// where len covers the tag plus the payload. This is byte-for-byte the
// shadow-tls v3 record format (a TLS application data record whose payload is
// tagged and XOR-obfuscated).
func shadowTLSWriteFrame(w io.Writer, macKey, xorKey []byte, payload []byte) error {
	body := make([]byte, shadowTLSHmacLen+len(payload))
	copy(body[shadowTLSHmacLen:], payload)
	shadowTLSXor(body[shadowTLSHmacLen:], xorKey)
	tag := shadowTLSHmac(macKey, body[shadowTLSHmacLen:])
	copy(body[:shadowTLSHmacLen], tag[:])

	frame := make([]byte, shadowTLSFrameOverhead+len(payload))
	frame[0] = 0x17 // application data
	frame[1] = 0x03
	frame[2] = 0x03
	binary.BigEndian.PutUint16(frame[3:5], uint16(shadowTLSHmacLen+len(payload)))
	copy(frame[shadowTLSTLSHeaderLen:], body)
	return writeFull(w, frame)
}

// shadowTLSReadFrame reads one authenticated record, verifies its tag, and
// returns the decrypted payload. A wrong tag means the peer does not share
// the token — the caller closes the connection.
func shadowTLSReadFrame(r io.Reader, macKey, xorKey []byte) ([]byte, error) {
	var hdr [shadowTLSTLSHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x17 {
		return nil, errors.New("shadowtls: not an application-data record")
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n < shadowTLSHmacLen || n > MaxFrame+shadowTLSHmacLen {
		return nil, errors.New("shadowtls: bad record length")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	tag := shadowTLSHmac(macKey, body[shadowTLSHmacLen:])
	if !hmac.Equal(tag[:], body[:shadowTLSHmacLen]) {
		return nil, errors.New("shadowtls: record authentication failed")
	}
	payload := body[shadowTLSHmacLen:]
	shadowTLSXor(payload, xorKey)
	return payload, nil
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

type shadowTLSServer struct {
	ln     net.Listener
	tlsCfg *tls.Config
	ch     chan Tunnel
	done   chan struct{}
	once   sync.Once
}

func (shadowTLSProto) Listen(addr string, opts Options) (ProtoServer, error) {
	cert, err := loadOrGenerateCert(opts)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &shadowTLSServer{
		ln:     ln,
		tlsCfg: &tls.Config{Certificates: []tls.Certificate{cert}},
		ch:     make(chan Tunnel, 8),
		done:   make(chan struct{}),
	}
	go s.acceptLoop(opts)
	return s, nil
}

func (s *shadowTLSServer) acceptLoop(opts Options) {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(c, opts)
	}
}

func (s *shadowTLSServer) handleConn(c net.Conn, opts Options) {
	_ = c.SetDeadline(time.Now().Add(shadowTLSHandshakeTimeout))
	secret := shadowTLSPassword(opts)

	// Stage 1: the password-derived server random greeting (the v3 key seed).
	serverRnd := shadowTLSServerRandom(secret)
	if err := writeFull(c, serverRnd); err != nil {
		_ = c.Close()
		return
	}
	keys := shadowTLSKeysFor(secret, serverRnd)

	// Stage 2: a real TLS handshake (looks like plain HTTPS).
	tc := tls.Server(c, s.tlsCfg)
	if err := tc.Handshake(); err != nil {
		_ = c.Close()
		return
	}

	// Stage 3: authenticate the client on its first record. The client's
	// first write is an empty authenticated frame; the tag only matches if
	// both ends share the token. On failure the server closes without
	// replying, so the port looks dead.
	first, err := shadowTLSReadFrame(tc, keys.recvMac, keys.xorKey)
	if err != nil || len(first) != 0 {
		_ = c.Close()
		return
	}
	// Confirm authorization: the server's own authenticated empty frame (the
	// client verifies it; a hijacked/probed connection gets no usable reply).
	if err := shadowTLSWriteFrame(tc, keys.sendMac, keys.xorKey, nil); err != nil {
		_ = c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})

	stream := &shadowTLSStream{c: tc, keys: keys}
	select {
	case s.ch <- newStreamTunnel(stream, "shadowtls://"+s.ln.Addr().String()):
	case <-s.done:
		_ = tc.Close()
	}
}

func (s *shadowTLSServer) Accept() (Tunnel, error) {
	select {
	case t := <-s.ch:
		return t, nil
	case <-s.done:
		return nil, net.ErrClosed
	}
}

func (s *shadowTLSServer) Close() error {
	s.once.Do(func() {
		close(s.done)
		_ = s.ln.Close()
	})
	return nil
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

// shadowTLSStream adapts the authenticated record layer to the byte-stream
// interface the stream framing rides on: every Write becomes one tagged
// record, every Read consumes one record and serves its plaintext from an
// internal buffer.
type shadowTLSStream struct {
	c    net.Conn
	keys *shadowTLSKeys
	buf  []byte
	mu   sync.Mutex
}

func (s *shadowTLSStream) Read(p []byte) (int, error) {
	if len(s.buf) > 0 {
		n := copy(p, s.buf)
		s.buf = s.buf[n:]
		return n, nil
	}
	pt, err := shadowTLSReadFrame(s.c, s.keys.recvMac, s.keys.xorKey)
	if err != nil {
		return 0, err
	}
	n := copy(p, pt)
	s.buf = pt[n:]
	return n, nil
}

func (s *shadowTLSStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := shadowTLSWriteFrame(s.c, s.keys.sendMac, s.keys.xorKey, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *shadowTLSStream) Close() error                  { return s.c.Close() }
func (s *shadowTLSStream) SetDeadline(t time.Time) error { return s.c.SetDeadline(t) }

func (shadowTLSProto) Dial(addr string, opts Options) (Tunnel, error) {
	// Bounded: a firewall that drops SYNs would otherwise hang the dial.
	raw, err := net.DialTimeout("tcp", addr, connTimeout)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(shadowTLSHandshakeTimeout))
	secret := shadowTLSPassword(opts)
	serverRnd := shadowTLSServerRandom(secret)

	// Stage 1: read the server's greeting (the v3 key seed).
	greeting := make([]byte, shadowTLSGreetingLen)
	if _, err := io.ReadFull(raw, greeting); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if !hmac.Equal(greeting, serverRnd) {
		_ = raw.Close()
		return nil, errors.New("shadowtls: wrong server greeting (password mismatch?)")
	}
	keys := shadowTLSKeysFor(secret, serverRnd)

	// Stage 2: a real TLS handshake (self-signed cert, validation skipped).
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}

	// Stage 3: prove the token and confirm the server. The empty first
	// record authenticates us; the server's empty reply confirms it is a
	// real shadow-tls server (a probed TLS endpoint cannot produce a valid
	// tag, so the handshake dies here instead of silently relaying).
	if err := shadowTLSWriteFrame(tc, keys.sendMac, keys.xorKey, nil); err != nil {
		_ = raw.Close()
		return nil, err
	}
	reply, err := shadowTLSReadFrame(tc, keys.recvMac, keys.xorKey)
	if err != nil || len(reply) != 0 {
		_ = raw.Close()
		return nil, errors.New("shadowtls: server authentication failed")
	}
	_ = raw.SetDeadline(time.Time{})

	return newStreamTunnel(&shadowTLSStream{c: tc, keys: keys}, "shadowtls://"+addr), nil
}
