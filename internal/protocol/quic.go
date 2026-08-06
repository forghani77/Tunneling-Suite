package protocol

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/quic-go/quic-go"
)

// quicProto tunnels bytes over a raw QUIC bidirectional stream.
type quicProto struct{}

func (quicProto) Name() string    { return "quic" }
func (quicProto) Kind() Kind      { return KindStream }
func (quicProto) Overhead() int   { return 48 } // 20 IP + 8 UDP + ~20 QUIC short header
func (quicProto) NeedsRoot() bool { return false }

const quicALPN = "tunnel-suit"

func quicClientTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, NextProtos: []string{quicALPN}}
}

func (quicProto) Listen(addr string, opts Options) (ProtoServer, error) {
	cert, err := loadOrGenerateCert(opts)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{quicALPN}}
	ln, err := quic.ListenAddr(addr, tlsCfg, nil)
	if err != nil {
		return nil, err
	}
	return &quicServer{ln: ln}, nil
}

type quicServer struct {
	ln *quic.Listener
}

func (s *quicServer) Accept() (Tunnel, error) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, err := s.ln.Accept(ctx)
		cancel()
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				continue
			}
			return nil, err
		}
		stream, err := c.AcceptStream(context.Background())
		if err != nil {
			_ = c.CloseWithError(0, "no stream")
			continue
		}
		return newStreamTunnel(stream, s.ln.Addr().String()), nil
	}
}

func (s *quicServer) Close() error { return s.ln.Close() }

func (quicProto) Dial(addr string, opts Options) (Tunnel, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := quic.DialAddr(ctx, addr, quicClientTLS(), nil)
	if err != nil {
		return nil, err
	}
	stream, err := c.OpenStreamSync(ctx)
	if err != nil {
		_ = c.CloseWithError(0, "dial failed")
		return nil, err
	}
	return newStreamTunnel(stream, "quic://"+addr), nil
}
