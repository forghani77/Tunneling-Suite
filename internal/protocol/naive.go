package protocol

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// naiveUser is the fixed Basic-auth username for the naive tunnel; the
// password comes from --password (defaulting to the shared default).
const naiveUser = "naive"

// naivePaddingChunks is the number of initial chunks in each direction that
// carry the naive padding scheme (NumFirstPaddings in the reference server).
const naivePaddingChunks = 8

// naiveProto implements the NaiveProxy protocol in pure Go. Naive is a
// TLS + HTTP/2 CONNECT forward proxy with Basic auth whose distinguishing
// feature is padding: the first few chunks in each direction are prefixed
// with [2-byte length][1-byte pad size][data][pad bytes] to break up packet
// size fingerprinting. This is a faithful, wire-compatible reimplementation
// of the naive server (caddy forwardproxy, "naive" branch) and client.
type naiveProto struct{}

func (naiveProto) Name() string    { return "naive" }
func (naiveProto) Kind() Kind      { return KindStream }
func (naiveProto) Overhead() int   { return 54 } // 20 IP + 20 TCP + 5 TLS + ~9 h2
func (naiveProto) NeedsRoot() bool { return false }

func naivePassword(opts Options) string {
	if opts.Password != "" {
		return opts.Password
	}
	return defaultPassword
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

type naiveServer struct {
	srv       *http.Server
	ln        net.Listener
	opts      Options
	ch        chan Tunnel
	done      chan struct{}
	closeOnce sync.Once
}

func (naiveProto) Listen(addr string, opts Options) (ProtoServer, error) {
	cert, err := loadOrGenerateCert(opts)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &naiveServer{
		opts: opts,
		ln:   ln,
		ch:   make(chan Tunnel, 8),
		done: make(chan struct{}),
	}
	protos := &http.Protocols{}
	protos.SetHTTP1(true)
	// Use x/net/http2 exclusively (registered via TLSNextProto); the
	// native Go 1.24+ http2 path is disabled to avoid double setup.
	protos.SetHTTP2(false)
	s.srv = &http.Server{
		Handler:   http.HandlerFunc(s.handle),
		Protocols: protos,
	}
	if err := http2.ConfigureServer(s.srv, &http2.Server{}); err != nil {
		_ = ln.Close()
		return nil, err
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	go func() { _ = s.srv.Serve(tlsLn) }()
	return s, nil
}

func (s *naiveServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, pass := naiveUser, naivePassword(s.opts)
	if !checkBasicAuth(r.Header.Get("Proxy-Authorization"), user, pass) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="naive"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

	// Naive mode is signalled by the client's Padding header; we always
	// answer with our own Padding header (like the reference server) and pad
	// both directions when the client announced padding.
	padded := r.Header.Get("Padding") != ""
	w.Header().Set("Padding", naivePaddingHeader())
	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex() // http/1.1 fallback: allow concurrent read/write
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()

	var rd io.Reader = r.Body
	var wr io.Writer = flushWriter{w: w}
	if padded {
		rd = newPadReader(rd)
		wr = newPadWriter(wr)
	}
	st := &naiveStream{rd: rd, wr: wr, body: r.Body, done: make(chan struct{})}
	select {
	case s.ch <- newStreamTunnel(st, "naive"):
	case <-s.done:
		_ = r.Body.Close()
		return
	}
	// Keep the handler alive until the tunnel closes so the HTTP/2 stream
	// (and its response body) stays open.
	select {
	case <-st.done:
	case <-s.done:
	}
}

func (s *naiveServer) Accept() (Tunnel, error) {
	select {
	case t := <-s.ch:
		return t, nil
	case <-s.done:
		return nil, net.ErrClosed
	}
}

func (s *naiveServer) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.srv.Close()
		_ = s.ln.Close()
	})
	return nil
}

// naiveStream adapts an HTTP request/response body pair into a duplex byte
// stream (client->server via the request body, server->client via the
// response body, both possibly wrapped in the naive padding scheme).
type naiveStream struct {
	rd        io.Reader
	wr        io.Writer
	body      io.ReadCloser
	done      chan struct{}
	closeOnce sync.Once
}

func (s *naiveStream) Read(p []byte) (int, error)  { return s.rd.Read(p) }
func (s *naiveStream) Write(p []byte) (int, error) { return s.wr.Write(p) }
func (s *naiveStream) SetDeadline(time.Time) error { return nil } // server side needs no deadlines
func (s *naiveStream) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.body.Close()
	})
	return nil
}

// flushWriter flushes after every write so tunneled bytes reach the client
// promptly (HTTP/2 and buffered http/1.1 would otherwise hold them).
type flushWriter struct{ w http.ResponseWriter }

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if err == nil {
		if fl, ok := f.w.(http.Flusher); ok {
			fl.Flush()
		}
	}
	return n, err
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

func (naiveProto) Dial(addr string, opts Options) (Tunnel, error) {
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}},
	}
	pr, pw := io.Pipe()
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: addr},
		Host:   addr,
		Header: make(http.Header),
		Body:   pr,
	}
	user, pass := naiveUser, naivePassword(opts)
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	req.Header.Set("Padding", naivePaddingHeader())

	res, err := tr.RoundTrip(req)
	if err != nil {
		_ = pw.Close()
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		_ = pw.Close()
		_ = res.Body.Close()
		return nil, fmt.Errorf("naive CONNECT failed: %s", res.Status)
	}
	padded := res.Header.Get("Padding") != ""
	var rd io.Reader = res.Body
	var wr io.Writer = pw
	if padded {
		rd = newPadReader(rd)
		wr = newPadWriter(wr)
	}
	cc := &naiveClientConn{
		rd: rd,
		wr: wr,
		closeFn: func() {
			_ = pw.Close()
			_ = res.Body.Close()
		},
	}
	return newStreamTunnel(cc, "naive://"+addr), nil
}

// naiveClientConn is the client-side duplex over the h2 request/response
// bodies; SetDeadline is emulated with a timer that tears the stream down,
// so a silent tunnel can't hang the benchmark forever.
type naiveClientConn struct {
	rd      io.Reader
	wr      io.Writer
	closeFn func()
	mu      sync.Mutex
	timer   *time.Timer
}

func (c *naiveClientConn) Read(p []byte) (int, error)  { return c.rd.Read(p) }
func (c *naiveClientConn) Write(p []byte) (int, error) { return c.wr.Write(p) }
func (c *naiveClientConn) Close() error                { c.closeFn(); return nil }

func (c *naiveClientConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
	}
	if t.IsZero() {
		return nil
	}
	if d := time.Until(t); d <= 0 {
		go c.closeFn()
	} else {
		c.timer = time.AfterFunc(d, c.closeFn)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Shared naive helpers
// ---------------------------------------------------------------------------

// checkBasicAuth verifies a Proxy-Authorization Basic header.
func checkBasicAuth(header, user, pass string) bool {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return false
	}
	return string(dec) == user+":"+pass
}

// naivePaddingHeader builds a random header like the reference server:
// length in [30, 62), first 16 chars from a set that Huffman codes poorly,
// the rest '~'.
func naivePaddingHeader() string {
	n := rand.Intn(32) + 30
	b := make([]byte, n)
	const charset = "!#$()+<>?@[]^`{}"
	for i := 0; i < 16; i++ {
		b[i] = charset[rand.Intn(len(charset))]
	}
	for i := 16; i < n; i++ {
		b[i] = '~'
	}
	return string(b)
}

// padWriter prepends the naive chunk header [2-byte length][1-byte pad size]
// and padSize zero bytes to the first 8 chunks written, mirroring the
// reference server's AddPadding.
type padWriter struct {
	w   io.Writer
	rem int
}

func newPadWriter(w io.Writer) *padWriter { return &padWriter{w: w, rem: naivePaddingChunks} }

func (p *padWriter) Write(b []byte) (int, error) {
	if p.rem <= 0 {
		return p.w.Write(b)
	}
	p.rem--
	padSize := rand.Intn(256)
	out := make([]byte, 0, 3+len(b)+padSize)
	out = append(out, byte(len(b)>>8), byte(len(b)), byte(padSize))
	out = append(out, b...)
	out = append(out, make([]byte, padSize)...)
	if _, err := p.w.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

// padReader strips the naive chunk header and junk bytes from the first 8
// chunks read, mirroring the reference server's RemovePadding. Oversized
// chunks are buffered so callers can read in small pieces.
type padReader struct {
	r   io.Reader
	rem int
	buf []byte
}

func newPadReader(r io.Reader) *padReader { return &padReader{r: r, rem: naivePaddingChunks} }

func (p *padReader) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	if p.rem <= 0 {
		return p.r.Read(b)
	}
	p.rem--
	var hdr [3]byte
	if _, err := io.ReadFull(p.r, hdr[:]); err != nil {
		return 0, err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	padSize := int(hdr[2])
	data := make([]byte, n)
	if _, err := io.ReadFull(p.r, data); err != nil {
		return 0, err
	}
	if padSize > 0 {
		if _, err := io.CopyN(io.Discard, p.r, int64(padSize)); err != nil {
			return 0, err
		}
	}
	p.buf = data
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return 0, nil
}
