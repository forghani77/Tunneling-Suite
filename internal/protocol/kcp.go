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
	return &streamServer{ln: ln}, nil
}

func (kcpProto) Dial(addr string, opts Options) (Tunnel, error) {
	sess, err := kcp.DialWithOptions(addr, nil, 0, 0)
	if err != nil {
		return nil, err
	}
	// Low-latency tuning: nodelay, 10ms interval, fast resend, no congestion
	// control — appropriate for a loopback test harness.
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(256, 256)
	sess.SetMtu(1400)
	return newStreamTunnel(sess, "kcp://"+addr), nil
}
