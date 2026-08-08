package protocol

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// httpProto tunnels bytes through an HTTP CONNECT handshake (RFC 7231 §4.3.6)
// over plain TCP: the client sends "CONNECT host:port HTTP/1.1", the server
// answers "200 Connection Established", and the raw TCP byte stream becomes
// the tunnel. This is the classic HTTP proxy tunnel.
type httpProto struct{}

func (httpProto) Name() string    { return "http" }
func (httpProto) Kind() Kind      { return KindStream }
func (httpProto) Overhead() int   { return 44 } // 20 IP + 20 TCP + ~4 HTTP
func (httpProto) NeedsRoot() bool { return false }

func (httpProto) Listen(addr string, opts Options) (ProtoServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &connectServer{ln: ln}, nil
}

func (httpProto) Dial(addr string, opts Options) (Tunnel, error) {
	c, err := net.DialTimeout("tcp", addr, connTimeout)
	if err != nil {
		return nil, err
	}
	// Bound the CONNECT handshake read: a service squatting on the port that
	// accepts TCP but never answers would otherwise hang the dial forever
	// (the benchmark's per-protocol budget only starts after Dial returns).
	// Cleared once the handshake is done — the benchmark owns the tunnel's
	// deadlines from there on.
	_ = c.SetDeadline(time.Now().Add(connTimeout))
	wrapped, err := doConnectHandshake(c, addr)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("http handshake failed (is another service on this port?): %w", err)
	}
	_ = c.SetDeadline(time.Time{})
	return newStreamTunnel(wrapped, "http://"+addr), nil
}

// httpsProto is the same CONNECT tunnel, but the CONNECT handshake itself
// happens inside a TLS connection, so the tunnel looks like HTTPS.
type httpsProto struct{}

func (httpsProto) Name() string    { return "https" }
func (httpsProto) Kind() Kind      { return KindStream }
func (httpsProto) Overhead() int   { return 49 } // 20 IP + 20 TCP + 5 TLS + ~4 HTTP
func (httpsProto) NeedsRoot() bool { return false }

func (httpsProto) Listen(addr string, opts Options) (ProtoServer, error) {
	cert, err := loadOrGenerateCert(opts)
	if err != nil {
		return nil, err
	}
	ln, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		return nil, err
	}
	return &connectServer{ln: ln}, nil
}

func (httpsProto) Dial(addr string, opts Options) (Tunnel, error) {
	// The harness owns both ends and uses an ephemeral self-signed cert, so
	// the client deliberately skips certificate validation. DialWithDialer
	// bounds the connect + TLS handshake; the deadline below bounds the
	// CONNECT handshake read (see httpProto.Dial).
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: connTimeout}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(connTimeout))
	wrapped, err := doConnectHandshake(c, addr)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("https handshake failed (is another service on this port?): %w", err)
	}
	_ = c.SetDeadline(time.Time{})
	return newStreamTunnel(wrapped, "https://"+addr), nil
}

// connectServer is the shared server for http/https: it performs the CONNECT
// handshake per accepted connection and hands over the raw byte stream.
// Handshake failures close that connection and are retried with the next
// one instead of killing the accept loop.
type connectServer struct {
	ln net.Listener
}

func (s *connectServer) Accept() (Tunnel, error) {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return nil, err
		}
		// Bound the handshake read: a peer that connects and never sends a
		// request must not stall the accept loop for every other client.
		// Cleared once the tunnel is handed over — the benchmark owns its
		// deadlines from there on.
		_ = c.SetDeadline(time.Now().Add(connTimeout))
		wrapped, err := serveConnect(c)
		if err != nil {
			_ = c.Close()
			continue
		}
		_ = c.SetDeadline(time.Time{})
		return newStreamTunnel(wrapped, "connect://"+s.ln.Addr().String()), nil
	}
}

func (s *connectServer) Close() error { return s.ln.Close() }

// maxHeaderLine bounds a single HTTP header line so a broken or malicious
// peer can't stream headers forever (memory DoS).
const maxHeaderLine = 8 * 1024

// connectTarget is the dummy host the client asks the proxy to CONNECT to.
// The harness server never dials it (it echoes), but using a plausible
// target keeps the handshake indistinguishable from real browser traffic.
const connectTarget = "www.google.com:443"

// chromeUserAgent is the User-Agent a current Chrome build sends on proxy
// CONNECT requests, so the tunnel looks like ordinary browser traffic.
const chromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// readWrapped routes reads through a bufio.Reader so any bytes buffered
// beyond the CONNECT header are preserved instead of lost.
type readWrapped struct {
	net.Conn
	br *bufio.Reader
}

func (r *readWrapped) Read(p []byte) (int, error) { return r.br.Read(p) }

// serveConnect performs the server side of an HTTP CONNECT handshake. It
// answers the way a real forward proxy (e.g. Squid) does: a bare
// "200 Connection established" status line and nothing else.
func serveConnect(c net.Conn) (net.Conn, error) {
	br := bufio.NewReader(c)
	first, err := readHeaderLine(br)
	if err != nil {
		return nil, err
	}
	if err := drainHeaders(br); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(first, "CONNECT ") {
		return nil, errors.New("not an HTTP CONNECT request")
	}
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return nil, err
	}
	return &readWrapped{Conn: c, br: br}, nil
}

// doConnectHandshake performs the client side of an HTTP CONNECT handshake,
// emitting the same header set a Chrome browser sends through an HTTP proxy.
func doConnectHandshake(c net.Conn, addr string) (net.Conn, error) {
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Proxy-Connection: keep-alive\r\n"+
		"User-Agent: %s\r\n\r\n", connectTarget, connectTarget, chromeUserAgent)
	if _, err := c.Write([]byte(req)); err != nil {
		return nil, err
	}
	br := bufio.NewReader(c)
	status, err := readHeaderLine(br)
	if err != nil {
		return nil, err
	}
	if err := drainHeaders(br); err != nil {
		return nil, err
	}
	if !strings.Contains(status, " 200 ") {
		return nil, fmt.Errorf("CONNECT rejected: %s", strings.TrimSpace(status))
	}
	return &readWrapped{Conn: c, br: br}, nil
}

// readHeaderLine reads one header line, enforcing maxHeaderLine.
func readHeaderLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > maxHeaderLine {
		return "", errors.New("HTTP header line too long")
	}
	return line, nil
}

// drainHeaders consumes header lines until the empty line that terminates
// the header block.
func drainHeaders(br *bufio.Reader) error {
	for {
		line, err := readHeaderLine(br)
		if err != nil {
			return err
		}
		if line == "\r\n" || line == "\n" {
			return nil
		}
	}
}
