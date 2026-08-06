package protocol

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// h3Proto tunnels bytes over HTTP/3 using the extended CONNECT method
// (RFC 9220): the client opens a bidirectional stream with a CONNECT request
// carrying a custom :protocol token, and the server hijacks it.
type h3Proto struct{}

func (h3Proto) Name() string    { return "http3" }
func (h3Proto) Kind() Kind      { return KindStream }
func (h3Proto) Overhead() int   { return 51 } // QUIC ~48 + HTTP/3 frame header
func (h3Proto) NeedsRoot() bool { return false }

const h3ALPN = "h3"

func (h3Proto) Listen(addr string, opts Options) (ProtoServer, error) {
	cert, err := loadOrGenerateCert(opts)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{h3ALPN}}

	done := make(chan struct{})
	tunnels := make(chan Tunnel, 16)
	srv := &http3.Server{
		TLSConfig: tlsCfg,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			streamer, ok := w.(http3.HTTPStreamer)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			str := streamer.HTTPStream()
			select {
			case tunnels <- newStreamTunnel(str, addr):
			case <-done:
				// Server shutting down; abandon the stream.
				_ = str.Close()
			}
		}),
	}

	ln, err := quic.ListenAddr(addr, tlsCfg, nil)
	if err != nil {
		return nil, err
	}
	go func() { _ = srv.ServeListener(ln) }()

	return &h3Server{ln: ln, tunnels: tunnels, done: done}, nil
}

type h3Server struct {
	ln        *quic.Listener
	tunnels   chan Tunnel
	closeOnce sync.Once
	done      chan struct{}
}

func (s *h3Server) Accept() (Tunnel, error) {
	select {
	case t := <-s.tunnels:
		return t, nil
	case <-s.done:
		return nil, fmt.Errorf("http3 server closed")
	}
}

func (s *h3Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.done)
		err = s.ln.Close()
	})
	return err
}

func (h3Proto) Dial(addr string, opts Options) (Tunnel, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tlsCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{h3ALPN}}
	conn, err := quic.DialAddr(ctx, addr, tlsCfg, nil)
	if err != nil {
		return nil, err
	}

	tr := &http3.Transport{}
	cc := tr.NewClientConn(conn)

	u := &url.URL{Scheme: "https", Host: addr, Path: "/tunnel"}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    u,
		Host:   addr,
		// :protocol pseudo-header (RFC 9220); must be a valid HTTP token.
		Proto:  "tunnel-suit",
		Header: http.Header{},
	}

	rs, err := cc.OpenRequestStream(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "dial failed")
		return nil, err
	}
	if err := rs.SendRequestHeader(req); err != nil {
		return nil, err
	}
	resp, err := rs.ReadResponse()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http3 CONNECT status %d", resp.StatusCode)
	}
	return newStreamTunnel(rs, "http3://"+addr), nil
}
