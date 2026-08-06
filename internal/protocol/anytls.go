package protocol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"anytls/proxy/padding"
	"anytls/proxy/session"
	M "github.com/sagernet/sing/common/metadata"
)

func anytlsPassword(opts Options) string {
	if opts.Password != "" {
		return opts.Password
	}
	return defaultPassword
}

// anytlsProto tunnels bytes through AnyTLS: a TLS connection carrying a
// custom framed session protocol (github.com/anytls/anytls-go) whose wire
// traffic is deliberately indistinguishable from ordinary HTTPS. Both ends
// run the library in-process, exactly like the reference anytls server/client
// binaries. The server authenticates clients with a shared password.
type anytlsProto struct{}

func (anytlsProto) Name() string    { return "anytls" }
func (anytlsProto) Kind() Kind      { return KindStream }
func (anytlsProto) Overhead() int   { return 55 } // 20 IP + 20 TCP + 5 TLS + ~10 frames
func (anytlsProto) NeedsRoot() bool { return false }

func (anytlsProto) Listen(addr string, opts Options) (ProtoServer, error) {
	cert, err := loadOrGenerateCert(opts)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(anytlsPassword(opts)))
	s := &anytlsServer{
		ln:      ln,
		tlsCfg:  &tls.Config{Certificates: []tls.Certificate{cert}},
		passSum: sum[:],
		ch:      make(chan Tunnel, 8),
		done:    make(chan struct{}),
	}
	go s.acceptLoop()
	return s, nil
}

type anytlsServer struct {
	ln      net.Listener
	tlsCfg  *tls.Config
	passSum []byte
	ch      chan Tunnel
	done    chan struct{}
	once    sync.Once
}

func (s *anytlsServer) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(c)
	}
}

func (s *anytlsServer) handleConn(c net.Conn) {
	tc := tls.Server(c, s.tlsCfg)
	defer tc.Close()
	if err := tc.Handshake(); err != nil {
		return
	}
	// Password block (same as the reference server): 32B SHA-256 of the
	// password, 2B padding length, then that many padding bytes.
	hdr := make([]byte, 34)
	if _, err := io.ReadFull(tc, hdr); err != nil {
		return
	}
	if !bytes.Equal(hdr[:32], s.passSum) {
		return
	}
	if padLen := int(binary.BigEndian.Uint16(hdr[32:34])); padLen > 0 {
		if _, err := io.CopyN(io.Discard, tc, int64(padLen)); err != nil {
			return
		}
	}
	sess := session.NewServerSession(tc, func(st *session.Stream) {
		// The client flushes its session handshake by writing a destination
		// address; we don't dial it, so parse and discard it.
		if _, err := M.SocksaddrSerializer.ReadAddrPort(st); err != nil {
			_ = st.Close()
			return
		}
		// Note: the tunnel's own Close() (via EchoLoop) closes the stream;
		// this callback must NOT close it here or the tunnel dies instantly.
		t := newStreamTunnel(st, "anytls")
		select {
		case s.ch <- t:
		case <-s.done:
			_ = st.Close()
		}
	}, &padding.DefaultPaddingFactory)
	sess.Run()
	sess.Close()
}

func (s *anytlsServer) Accept() (Tunnel, error) {
	select {
	case t := <-s.ch:
		return t, nil
	case <-s.done:
		return nil, net.ErrClosed
	}
}

func (s *anytlsServer) Close() error {
	s.once.Do(func() {
		close(s.done)
		_ = s.ln.Close()
	})
	return nil
}

func (anytlsProto) Dial(addr string, opts Options) (Tunnel, error) {
	sum := sha256.Sum256([]byte(anytlsPassword(opts)))
	ctx := context.Background()
	cli := session.NewClient(ctx, func(ctx context.Context) (net.Conn, error) {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, err
		}
		block := make([]byte, 34)
		copy(block, sum[:])
		binary.BigEndian.PutUint16(block[32:34], 0) // no padding in our block
		if _, err := c.Write(block); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	}, &padding.DefaultPaddingFactory, 30*time.Second, 30*time.Second, 0, true)
	conn, err := cli.CreateStream(ctx)
	if err != nil {
		_ = cli.Close()
		return nil, err
	}
	// The client buffers its session handshake (settings + SYN) and only
	// flushes on the next write — the reference client writes the proxy
	// destination there. We write a dummy address that the server discards.
	if err := M.SocksaddrSerializer.WriteAddrPort(conn, M.ParseSocksaddr("0.0.0.0:1")); err != nil {
		_ = conn.Close()
		_ = cli.Close()
		return nil, err
	}
	return newStreamTunnel(conn, "anytls://"+addr), nil
}
