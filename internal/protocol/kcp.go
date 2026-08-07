package protocol

import (
	"github.com/xtaci/kcp-go/v5"
)

// kcpProto tunnels bytes over KCP (a reliable ARQ protocol over UDP).
type kcpProto struct{}

func (kcpProto) Name() string    { return "kcp" }
func (kcpProto) Kind() Kind      { return KindStream }
func (kcpProto) Overhead() int   { return 52 } // 20 IP + 8 UDP + 24 KCP header
func (kcpProto) NeedsRoot() bool { return false }

func (kcpProto) Listen(addr string, opts Options) (ProtoServer, error) {
	ln, err := kcp.ListenWithOptions(addr, nil, 0, 0)
	if err != nil {
		return nil, err
	}
	return &kcpServer{ln: ln}, nil
}

func (kcpProto) Dial(addr string, opts Options) (Tunnel, error) {
	sess, err := kcp.DialWithOptions(addr, nil, 0, 0)
	if err != nil {
		return nil, err
	}
	tuneKCPSession(sess)
	return newStreamTunnel(sess, "kcp://"+addr), nil
}

// tuneKCPSession applies the fast-mode settings both ends of the tunnel need:
// nodelay with a 10ms interval, fast resend, no congestion control, and a
// 4096-segment window. kcp-go's defaults are the opposite — a 32-segment
// window and 40ms interval with nodelay off — which throttle a session to a
// few Mbps on a real WAN and cannot even hold one 60000-byte test frame (43
// segments) in flight.
func tuneKCPSession(sess *kcp.UDPSession) {
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(4096, 4096)
	sess.SetMtu(1400)
}

// kcpServer accepts KCP sessions like the client dials them. The plain
// streamServer wrapper would leave every accepted session at kcp-go's default
// tuning (32-segment window, 40ms interval, nodelay off), capping the echo
// direction to a fraction of the client's send rate.
type kcpServer struct {
	ln *kcp.Listener
}

func (s *kcpServer) Accept() (Tunnel, error) {
	sess, err := s.ln.AcceptKCP()
	if err != nil {
		return nil, err
	}
	tuneKCPSession(sess)
	return newStreamTunnel(sess, s.ln.Addr().String()), nil
}

func (s *kcpServer) Close() error { return s.ln.Close() }
