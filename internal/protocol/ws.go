package protocol

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// wsProto tunnels a byte stream through a WebSocket connection (RFC 6455):
// the server upgrades plain HTTP to a WebSocket and every stream write
// becomes one binary message. This is the "tunnel over a socket" trick used
// by many real-world proxies (it passes through HTTP-filtering middleboxes).
type wsProto struct{}

func (wsProto) Name() string    { return "ws" }
func (wsProto) Kind() Kind      { return KindStream }
func (wsProto) Overhead() int   { return 46 } // 20 IP + 20 TCP + 2 frame + 4 mask
func (wsProto) NeedsRoot() bool { return false }

func (wsProto) Listen(addr string, opts Options) (ProtoServer, error) {
	return newWSServer(addr, opts, false)
}

func (wsProto) Dial(addr string, opts Options) (Tunnel, error) {
	return dialWS(addr, false)
}

// wssProto is the WebSocket tunnel inside TLS, i.e. "wss://". It is the
// same protocol with TLS added, which is how most browsers-based tunnels
// actually run in production.
type wssProto struct{}

func (wssProto) Name() string    { return "wss" }
func (wssProto) Kind() Kind      { return KindStream }
func (wssProto) Overhead() int   { return 51 } // 20 IP + 20 TCP + 5 TLS + 2 + 4
func (wssProto) NeedsRoot() bool { return false }

func (wssProto) Listen(addr string, opts Options) (ProtoServer, error) {
	return newWSServer(addr, opts, true)
}

func (wssProto) Dial(addr string, opts Options) (Tunnel, error) {
	return dialWS(addr, true)
}

// wsServer upgrades incoming HTTP requests to WebSockets and hands the
// resulting byte stream to the harness.
type wsServer struct {
	srv       *http.Server
	ln        net.Listener
	ch        chan Tunnel
	done      chan struct{}
	closeOnce sync.Once
}

func newWSServer(addr string, opts Options, tlsMode bool) (*wsServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &wsServer{ln: ln, ch: make(chan Tunnel, 8), done: make(chan struct{})}
	s.srv = &http.Server{Handler: http.HandlerFunc(s.handle)}
	if tlsMode {
		cert, err := loadOrGenerateCert(opts)
		if err != nil {
			_ = ln.Close()
			return nil, err
		}
		tlsLn := tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"http/1.1"},
		})
		go func() { _ = s.srv.Serve(tlsLn) }()
	} else {
		go func() { _ = s.srv.Serve(ln) }()
	}
	return s, nil
}

func (s *wsServer) handle(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	// NetConn needs a long-lived context: cancelling it would kill the
	// tunnel. The tunnel is closed explicitly by the harness instead.
	nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	select {
	case s.ch <- newStreamTunnel(nc, "ws://"):
	case <-s.done:
		_ = nc.Close()
	}
}

func (s *wsServer) Accept() (Tunnel, error) {
	select {
	case t := <-s.ch:
		return t, nil
	case <-s.done:
		return nil, net.ErrClosed
	}
}

func (s *wsServer) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.srv.Close()
		_ = s.ln.Close()
	})
	return nil
}

func dialWS(addr string, tlsMode bool) (Tunnel, error) {
	scheme := "ws"
	dopts := &websocket.DialOptions{}
	if tlsMode {
		scheme = "wss"
		dopts.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, scheme+"://"+addr+"/", dopts)
	if err != nil {
		return nil, err
	}
	nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	return newStreamTunnel(nc, scheme+"://"+addr), nil
}
