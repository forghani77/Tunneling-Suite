package protocol

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// smtpHostname is advertised in the SMTP greeting and EHLO capabilities;
	// it matches the reference Python implementation's default so the
	// handshake is indistinguishable from a real Postfix submission server.
	smtpHostname = "mail.example.com"
	// smtpUser is the harness's fixed tunnel user; the shared --password is
	// the secret. A real smtp-tunnel-proxy client configured with the same
	// username/secret can authenticate against this server and vice versa.
	smtpUser = "tunnel"
	// smtpMaxAuthAge bounds how old an auth timestamp may be (replay
	// protection; mirrors the Python server's 300s window).
	smtpMaxAuthAge = 5 * time.Minute
	// smtpHandshakeTimeout bounds the full client/server handshake so a
	// stalled or hostile peer can't leak a goroutine and fd.
	smtpHandshakeTimeout = 10 * time.Second
	// smtpMaxLine caps a single SMTP response line (same convention as the
	// HTTP tunnels' maxHeaderLine) to prevent a memory DoS from an
	// unbounded greeting/capability reply.
	smtpMaxLine = 8 * 1024
)

// smtpProto tunnels bytes through a fake SMTP session. The handshake mimics
// a real mail submission server — greeting, EHLO capabilities, STARTTLS,
// AUTH PLAIN with an HMAC token, then a "BINARY" upgrade — after which the
// connection becomes a raw byte stream. This is a Go port of the
// smtp-tunnel-proxy Python implementation (wire-compatible handshake); the
// harness only needs the echo path, not the Python side's multiplexed
// CONNECT/DATA/CLOSE proxying frames.
type smtpProto struct{}

func (smtpProto) Name() string    { return "smtp" }
func (smtpProto) Kind() Kind      { return KindStream }
func (smtpProto) Overhead() int   { return 50 } // 20 IP + 20 TCP + 5 TLS + ~5 SMTP
func (smtpProto) NeedsRoot() bool { return false }

func smtpSecret(opts Options) string {
	if opts.Password != "" {
		return opts.Password
	}
	return defaultPassword
}

// ---------------------------------------------------------------------------
// Authentication (HMAC-SHA256 token, same format as the Python TunnelCrypto)
// ---------------------------------------------------------------------------

// smtpAuthTokenFor builds base64(username:timestamp:base64(hmac)) where
// hmac = HMAC-SHA256(secret, "smtp-tunnel-auth:"+username+":"+timestamp).
func smtpAuthTokenFor(secret, username string, ts int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "smtp-tunnel-auth:%s:%d", username, ts)
	macB64 := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	raw := fmt.Sprintf("%s:%d:%s", username, ts, macB64)
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

// smtpVerifyAuthToken validates a token against a user->secret map,
// enforcing the timestamp freshness window. The full-token comparison
// mirrors the Python server's hmac.compare_digest(token, expected).
func smtpVerifyAuthToken(token string, users map[string]string, now time.Time) (string, bool) {
	dec, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", false
	}
	parts := strings.Split(string(dec), ":")
	if len(parts) != 3 {
		return "", false
	}
	username, tsStr := parts[0], parts[1]
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return "", false
	}
	maxAge := int64(smtpMaxAuthAge / time.Second)
	if age := now.Unix() - ts; age > maxAge || age < -maxAge {
		return "", false
	}
	secret, ok := users[username]
	if !ok {
		return "", false
	}
	expected := smtpAuthTokenFor(secret, username, ts)
	if hmac.Equal([]byte(token), []byte(expected)) {
		return username, true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// SMTP handshake helpers
// ---------------------------------------------------------------------------

// readSMTPLine reads one SMTP response line, enforcing smtpMaxLine so a
// broken peer can't stream an unbounded reply. A final line without a
// trailing newline (clean EOF) is still returned.
func readSMTPLine(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		part, err := br.ReadSlice('\n')
		sb.Write(part)
		if sb.Len() > smtpMaxLine {
			return "", fmt.Errorf("smtp: response line exceeds %d bytes", smtpMaxLine)
		}
		switch {
		case err == nil:
			return strings.TrimRight(sb.String(), "\r\n"), nil
		case err == bufio.ErrBufferFull:
			continue
		case sb.Len() > 0 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)):
			return strings.TrimRight(sb.String(), "\r\n"), nil
		default:
			return "", err
		}
	}
}

func isEHLO(l string) bool {
	u := strings.ToUpper(strings.TrimSpace(l))
	return strings.HasPrefix(u, "EHLO") || strings.HasPrefix(u, "HELO")
}

// smtpSendCloser bundles the current connection and a buffered reader so the
// handshake can swap in the TLS layer mid-session.
type smtpConn struct {
	conn net.Conn
	br   *bufio.Reader
}

func (s *smtpConn) send(line string) error {
	_, err := s.conn.Write([]byte(line + "\r\n"))
	return err
}

func (s *smtpConn) read() (string, error) { return readSMTPLine(s.br) }

// bufferedConn serves bytes already buffered by a bufio.Reader before falling
// through to the underlying connection. It lets the STARTTLS upgrade survive
// a peer that pipelines bytes (e.g. a ClientHello sent immediately after
// STARTTLS without waiting for the 220) without losing them.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (bc *bufferedConn) Read(p []byte) (int, error) { return bc.r.Read(p) }

func (s *smtpConn) wrapTLS(tlsCfg *tls.Config, isServer bool) error {
	upstream := net.Conn(s.conn)
	if s.br.Buffered() > 0 {
		upstream = &bufferedConn{Conn: s.conn, r: s.br}
	}
	var tc *tls.Conn
	if isServer {
		tc = tls.Server(upstream, tlsCfg)
	} else {
		tc = tls.Client(upstream, tlsCfg)
	}
	if err := tc.Handshake(); err != nil {
		return err
	}
	s.conn = tc
	s.br = bufio.NewReader(tc)
	return nil
}

// expect250 consumes a multiline 250 response (lines with "250-" continue,
// the line with "250 " terminates it), like the Python client's _expect_250.
func (s *smtpConn) expect250() error {
	for {
		l, err := s.read()
		if err != nil {
			return err
		}
		if strings.HasPrefix(l, "250 ") {
			return nil
		}
		if !strings.HasPrefix(l, "250-") {
			return fmt.Errorf("smtp: expected 250, got %q", l)
		}
	}
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

type smtpServer struct {
	ln     net.Listener
	tlsCfg *tls.Config
	users  map[string]string
	ch     chan Tunnel
	done   chan struct{}
	once   sync.Once
}

func (smtpProto) Listen(addr string, opts Options) (ProtoServer, error) {
	cert, err := loadOrGenerateCert(opts)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &smtpServer{
		ln:     ln,
		tlsCfg: &tls.Config{Certificates: []tls.Certificate{cert}},
		users:  map[string]string{smtpUser: smtpSecret(opts)},
		ch:     make(chan Tunnel, 8),
		done:   make(chan struct{}),
	}
	go s.acceptLoop()
	return s, nil
}

func (s *smtpServer) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(c)
	}
}

func (s *smtpServer) handleConn(c net.Conn) {
	// Bound the handshake so a stalled or hostile client can't leak a
	// goroutine and fd; the deadline is cleared once the tunnel is live.
	_ = c.SetDeadline(time.Now().Add(smtpHandshakeTimeout))
	conn, err := smtpServeHandshake(c, s.tlsCfg, s.users)
	if err != nil {
		_ = c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	// Hand the tunnel off; EchoLoop owns it from here and closes it when the
	// client disconnects.
	select {
	case s.ch <- newStreamTunnel(conn, "smtp://"+s.ln.Addr().String()):
	case <-s.done:
		_ = conn.Close()
	}
}

func (s *smtpServer) Accept() (Tunnel, error) {
	select {
	case t := <-s.ch:
		return t, nil
	case <-s.done:
		return nil, net.ErrClosed
	}
}

func (s *smtpServer) Close() error {
	s.once.Do(func() {
		close(s.done)
		_ = s.ln.Close()
	})
	return nil
}

// smtpServeHandshake performs the server side of the SMTP handshake and
// returns the upgraded, buffered connection.
func smtpServeHandshake(c net.Conn, tlsCfg *tls.Config, users map[string]string) (net.Conn, error) {
	sc := &smtpConn{conn: c, br: bufio.NewReader(c)}

	if err := sc.send("220 " + smtpHostname + " ESMTP Postfix (Ubuntu)"); err != nil {
		return nil, err
	}
	l, err := sc.read()
	if err != nil || !isEHLO(l) {
		return nil, fmt.Errorf("smtp: expected EHLO, got %q", l)
	}
	for _, capLine := range []string{"250-" + smtpHostname, "250-STARTTLS", "250-AUTH PLAIN LOGIN", "250 8BITMIME"} {
		if err := sc.send(capLine); err != nil {
			return nil, err
		}
	}

	l, err = sc.read()
	if err != nil || strings.ToUpper(strings.TrimSpace(l)) != "STARTTLS" {
		return nil, fmt.Errorf("smtp: expected STARTTLS, got %q", l)
	}
	if err := sc.send("220 2.0.0 Ready to start TLS"); err != nil {
		return nil, err
	}
	if err := sc.wrapTLS(tlsCfg, true); err != nil {
		return nil, err
	}

	// Post-TLS EHLO.
	l, err = sc.read()
	if err != nil || !isEHLO(l) {
		return nil, fmt.Errorf("smtp: expected EHLO after TLS, got %q", l)
	}
	for _, capLine := range []string{"250-" + smtpHostname, "250-AUTH PLAIN LOGIN", "250 8BITMIME"} {
		if err := sc.send(capLine); err != nil {
			return nil, err
		}
	}

	// AUTH PLAIN <token>
	l, err = sc.read()
	if err != nil || !strings.HasPrefix(strings.ToUpper(l), "AUTH") {
		return nil, fmt.Errorf("smtp: expected AUTH, got %q", l)
	}
	parts := strings.Fields(l)
	if len(parts) < 3 {
		_ = sc.send("535 5.7.8 Authentication failed")
		return nil, fmt.Errorf("smtp: AUTH missing token")
	}
	if _, ok := smtpVerifyAuthToken(parts[2], users, time.Now()); !ok {
		_ = sc.send("535 5.7.8 Authentication failed")
		return nil, fmt.Errorf("smtp: authentication failed")
	}
	if err := sc.send("235 2.7.0 Authentication successful"); err != nil {
		return nil, err
	}

	// BINARY upgrade.
	l, err = sc.read()
	if err != nil || strings.TrimSpace(l) != "BINARY" {
		return nil, fmt.Errorf("smtp: expected BINARY, got %q", l)
	}
	if err := sc.send("299 Binary mode activated"); err != nil {
		return nil, err
	}

	return &readWrapped{Conn: sc.conn, br: sc.br}, nil
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

func (smtpProto) Dial(addr string, opts Options) (Tunnel, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	// Bound the handshake (mirror of the server side) so a dead or
	// non-speaking server can't hang the dial; cleared once the tunnel is up.
	_ = c.SetDeadline(time.Now().Add(smtpHandshakeTimeout))
	conn, err := smtpDialHandshake(c, smtpSecret(opts))
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return newStreamTunnel(conn, "smtp://"+addr), nil
}

// smtpDialHandshake performs the client side of the SMTP handshake,
// mirroring the Python client exactly (EHLO, STARTTLS, AUTH PLAIN, BINARY).
func smtpDialHandshake(c net.Conn, secret string) (net.Conn, error) {
	sc := &smtpConn{conn: c, br: bufio.NewReader(c)}

	l, err := sc.read()
	if err != nil || !strings.HasPrefix(l, "220") {
		return nil, fmt.Errorf("smtp: expected greeting, got %q", l)
	}
	if err := sc.send("EHLO tunnel-client.local"); err != nil {
		return nil, err
	}
	if err := sc.expect250(); err != nil {
		return nil, err
	}
	if err := sc.send("STARTTLS"); err != nil {
		return nil, err
	}
	l, err = sc.read()
	if err != nil || !strings.HasPrefix(l, "220") {
		return nil, fmt.Errorf("smtp: STARTTLS refused: %q", l)
	}
	// The harness owns both ends; the client skips certificate validation.
	if err := sc.wrapTLS(&tls.Config{InsecureSkipVerify: true}, false); err != nil {
		return nil, err
	}

	if err := sc.send("EHLO tunnel-client.local"); err != nil {
		return nil, err
	}
	if err := sc.expect250(); err != nil {
		return nil, err
	}

	token := smtpAuthTokenFor(secret, smtpUser, time.Now().Unix())
	if err := sc.send("AUTH PLAIN " + token); err != nil {
		return nil, err
	}
	l, err = sc.read()
	if err != nil || !strings.HasPrefix(l, "235") {
		return nil, fmt.Errorf("smtp: auth failed: %q", l)
	}

	if err := sc.send("BINARY"); err != nil {
		return nil, err
	}
	l, err = sc.read()
	if err != nil || !strings.HasPrefix(l, "299") {
		return nil, fmt.Errorf("smtp: binary mode refused: %q", l)
	}

	return &readWrapped{Conn: sc.conn, br: sc.br}, nil
}
