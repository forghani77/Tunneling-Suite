package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
)

// noiseProto tunnels bytes over TCP through a Noise NNpsk0 record layer.
//
// On the wire the session is two short bursts of random-looking bytes (the
// client's 32-byte ephemeral public key, then the server's 48-byte
// key-and-payload message) followed by an encrypted byte stream that looks
// the same — no TLS ClientHello, no recognisable protocol, nothing for deep
// packet inspection to fingerprint. The pre-shared key is derived from the
// shared tunnel token (--password; defaultPassword when unset), so the
// transport carries no key material of its own: the token is mixed into the
// handshake from the first message, and a peer without it cannot even
// complete the handshake — the server replies with nothing, so a port scan
// finds a dead port rather than a service.
//
// Because the whole tunnel runs over plain TCP with no separate key-exchange
// plane, it works unchanged in the client's --blind mode (probe every
// protocol directly, skipping the TCP control port): a blind probe dials the
// protocol's port offset and runs this same handshake.
type noiseProto struct{}

func (noiseProto) Name() string    { return "noise" }
func (noiseProto) Kind() Kind      { return KindStream }
func (noiseProto) Overhead() int   { return 58 } // 20 IP + 20 TCP + 16 AEAD tag + 2 length
func (noiseProto) NeedsRoot() bool { return false }

const (
	// noiseHandshakeTimeout bounds the full client/server handshake so a
	// stalled peer or a service squatting on the port (blind-mode probe)
	// cannot leak a goroutine and fd.
	noiseHandshakeTimeout = 10 * time.Second
)

// noiseConfig builds the Noise handshake configuration for one side. The
// 32-byte PSK is derived from the tunnel token and the prologue pins the
// protocol identity, so a client and server only interoperate when they share
// the token AND both speak tunnel-suite's noise transport.
func noiseConfig(opts Options, initiator bool) (*noise.HandshakeState, error) {
	secret := opts.Password
	if secret == "" {
		secret = defaultPassword
	}
	digest := sha256.Sum256([]byte(secret))
	// HandshakeNN with a PresharedKey and the default placement (0) is
	// NNpsk0: the PSK token is mixed into the first message, so a peer
	// without the token cannot even complete the handshake.
	cfg := noise.Config{
		CipherSuite:  noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:      noise.HandshakeNN,
		Initiator:    initiator,
		Prologue:     []byte("tunnel-suite-noise-nnpsk0"),
		PresharedKey: digest[:],
	}
	return noise.NewHandshakeState(cfg)
}

// noiseHandshake drives one side of the wire handshake, framed with the same
// 2-byte length prefix the transport uses, so each phase is exactly one
// length-framed message:
//
//	client → [02][00 30] e(32) + psk-token(16)          (msg 1)
//	server → [02][00 30] e(32) + psk-encrypted(16)      (msg 2)
//	client → [02][len]   transport-ciphertext            (transport starts)
//
// NNpsk0 (HandshakeNN with PresharedKeyPlacement 0) has exactly two pattern
// messages, and each peer's single WriteMessage/ReadMessage completes the
// handshake: the client's WriteMessage produces msg 1, its ReadMessage of
// msg 2 completes the transcript and hands out the transport CipherStates;
// the server's ReadMessage of msg 1 and WriteMessage of msg 2 do the same.
// No third pattern message exists, so there is nothing to run off the end of
// the pattern. (flynn/noise tracks one shared message index for read and
// write, so a peer can never write a third message anyway — the canonical
// two-message flow is the only one the library supports.)
//
// The transport starts on the frame the client sends immediately after
// reading msg 2, so there is no read race: the server is in transport mode
// the moment it has written msg 2, and the client's first transport frame
// only arrives after it has read msg 2. A wrong-token client fails to
// decrypt msg 2 and aborts; the server, likewise unable to decrypt anything
// it receives from such a client, closes silently — a port scan finds a dead
// port rather than a service.
func noiseHandshake(c net.Conn, hs *noise.HandshakeState, initiator bool) (send, recv *noise.CipherState, err error) {
	readMsg := func() ([]byte, error) {
		var lh [2]byte
		if _, err := io.ReadFull(c, lh[:]); err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint16(lh[:])
		if n == 0 {
			return nil, errors.New("noise: empty handshake message")
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(c, b); err != nil {
			return nil, err
		}
		return b, nil
	}
	writeMsg := func(p []byte) error {
		if len(p) > MaxFrame {
			return ErrFrameTooLarge
		}
		buf := make([]byte, 2+len(p))
		binary.BigEndian.PutUint16(buf[:2], uint16(len(p)))
		copy(buf[2:], p)
		return writeFull(c, buf)
	}

	if initiator {
		// msg 1: client's ephemeral public key (with the PSK token mixed in
		// by the pattern — NNpsk0 places the PSK on the first message, so a
		// peer without the token cannot even form a valid msg 1... and here
		// cannot decrypt msg 2 either).
		m1, _, _, err := hs.WriteMessage(nil, nil)
		if err != nil {
			return nil, nil, err
		}
		if err := writeMsg(m1); err != nil {
			return nil, nil, err
		}
		// msg 2: server's ephemeral key + psk-encrypted payload. Reading it
		// completes the client's transcript and returns the transport pair.
		m2, err := readMsg()
		if err != nil {
			return nil, nil, err
		}
		_, send, recv, err = hs.ReadMessage(nil, m2)
		if err != nil {
			return nil, nil, err
		}
		return send, recv, nil
	}

	// Server side: read msg 1, respond with msg 2 (empty payload — the
	// secret rides the pattern's PSK mix, not the payload). Writing msg 2
	// completes the server's transcript and returns the transport pair.
	m1, err := readMsg()
	if err != nil {
		return nil, nil, err
	}
	if _, _, _, err := hs.ReadMessage(nil, m1); err != nil {
		return nil, nil, err
	}
	m2, cs1, cs2, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := writeMsg(m2); err != nil {
		return nil, nil, err
	}
	// The completing call's first state decrypts the initiator's transport
	// traffic and the second encrypts to the initiator (the reverse of the
	// client's assignment), so swap them into send/recv order.
	return cs2, cs1, nil
}

// noiseStream presents the Noise transport as a byte stream, owning its own
// ciphertext framing so a TCP read boundary never splits a Noise message:
// every Write encrypts one message and emits [2B ciphertext length][ct];
// every Read consumes exactly one such frame and serves the decrypted
// plaintext from an internal buffer. This is the stream the length-framed
// test frames ride over (streamTunnel nests its 2-byte plaintext-length
// prefix inside one Noise message).
type noiseStream struct {
	c    net.Conn
	send *noise.CipherState
	recv *noise.CipherState
	buf  []byte
	mu   sync.Mutex // guards send (nonce increments)
}

func newNoiseStream(c net.Conn, send, recv *noise.CipherState) *noiseStream {
	return &noiseStream{c: c, send: send, recv: recv}
}

func (s *noiseStream) Read(p []byte) (int, error) {
	if len(s.buf) > 0 {
		n := copy(p, s.buf)
		s.buf = s.buf[n:]
		return n, nil
	}
	// One transport message at a time: [2B ct len][ciphertext]. The write
	// side caps plaintext at MaxFrame, so the ciphertext is at most
	// MaxFrame+16 and the length prefix fits a uint16.
	var lh [2]byte
	if _, err := io.ReadFull(s.c, lh[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(lh[:]))
	if n == 0 || n > MaxFrame+16 {
		return 0, ErrBadFrame
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(s.c, ct); err != nil {
		return 0, err
	}
	pt, err := s.recv.Decrypt(nil, nil, ct)
	if err != nil {
		return 0, err
	}
	if len(p) < len(pt) {
		// streamTunnel always passes a fresh buffer sized to the expected
		// frame, so this is defensive only.
		n = copy(p, pt)
		s.buf = pt[n:]
		return n, nil
	}
	return copy(p, pt), nil
}

func (s *noiseStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ct, err := s.send.Encrypt(nil, nil, p)
	if err != nil {
		return 0, err
	}
	buf := make([]byte, 2+len(ct))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(ct)))
	copy(buf[2:], ct)
	if err := writeFull(s.c, buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *noiseStream) Close() error                  { return s.c.Close() }
func (s *noiseStream) SetDeadline(t time.Time) error { return s.c.SetDeadline(t) }

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

type noiseServer struct {
	ln   net.Listener
	ch   chan Tunnel
	done chan struct{}
	once sync.Once
}

func (noiseProto) Listen(addr string, opts Options) (ProtoServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &noiseServer{
		ln:   ln,
		ch:   make(chan Tunnel, 8),
		done: make(chan struct{}),
	}
	go s.acceptLoop(opts)
	return s, nil
}

func (s *noiseServer) acceptLoop(opts Options) {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(c, opts)
	}
}

func (s *noiseServer) handleConn(c net.Conn, opts Options) {
	// Bound the handshake so a stalled or hostile peer can't leak a
	// goroutine and fd; cleared once the tunnel is live. A client without
	// the token fails ReadMessage below, so the server just closes and the
	// port looks dead.
	_ = c.SetDeadline(time.Now().Add(noiseHandshakeTimeout))
	hs, err := noiseConfig(opts, false)
	if err != nil {
		_ = c.Close()
		return
	}
	send, recv, err := noiseHandshake(c, hs, false)
	if err != nil {
		_ = c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	select {
	case s.ch <- newStreamTunnel(newNoiseStream(c, send, recv), "noise://"+s.ln.Addr().String()):
	case <-s.done:
		_ = c.Close()
	}
}

func (s *noiseServer) Accept() (Tunnel, error) {
	select {
	case t := <-s.ch:
		return t, nil
	case <-s.done:
		return nil, net.ErrClosed
	}
}

func (s *noiseServer) Close() error {
	s.once.Do(func() {
		close(s.done)
		_ = s.ln.Close()
	})
	return nil
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

func (noiseProto) Dial(addr string, opts Options) (Tunnel, error) {
	// Bounded: a firewall that drops SYNs (instead of refusing) would
	// otherwise hang the dial forever.
	c, err := net.DialTimeout("tcp", addr, connTimeout)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(noiseHandshakeTimeout))
	hs, err := noiseConfig(opts, true)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	send, recv, err := noiseHandshake(c, hs, true)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return newStreamTunnel(newNoiseStream(c, send, recv), "noise://"+addr), nil
}
