// Package forward implements the data plane for real tunnelling: a client
// wraps TCP connections in test frames and sends them through a tunnel-suite
// protocol tunnel; a server started with --forward unwraps them and dials the
// requested destination, then relays bytes in both directions.
//
// A forwarding session uses two frame types:
//
//	FrameForwardDial  the first frame; payload = "host:port" to dial
//	FrameForwardData  subsequent frames; payload = relayed bytes
//
// One tunnel carries exactly one TCP connection (the tunnel IS the
// connection). Stream protocols carry large frames efficiently; datagram
// protocols use small frames that fit a single unfragmented UDP packet.
package forward

import (
	"io"
	"net"

	"tunnel-suite/internal/protocol"
)

// MaxStreamFrame bounds relay frames on stream transports.
const MaxStreamFrame = 16 << 10

// MaxDatagramFrame bounds relay frames on datagram transports: small enough
// that the frame plus protocol overhead stays under the path MTU, so it
// survives real networks without IP fragmentation.
const MaxDatagramFrame = 1200

// MaxFrameFor returns the relay frame payload budget for a tunnel kind.
func MaxFrameFor(k protocol.Kind) int {
	if k == protocol.KindStream {
		return MaxStreamFrame
	}
	return MaxDatagramFrame
}

// Serve runs the server side of a forwarding tunnel: it peeks at the first
// frame. A FrameForwardDial switches the session into relay mode (dials the
// requested target and relays); anything else is treated as a benchmark
// session and echoed back, so a --forward server keeps serving the test
// harness unchanged.
func Serve(t protocol.Tunnel, kind protocol.Kind) error {
	f, err := t.ReadFrame()
	if err != nil {
		return err
	}
	if len(f) == 0 {
		return io.ErrUnexpectedEOF
	}
	if f[0] == protocol.FrameForwardDial {
		return serveForward(t, string(f[1:]), kind)
	}
	// Benchmark session: echo this first frame, then keep echoing.
	if f[0] == protocol.FramePing {
		f[0] = protocol.FramePong
	}
	if err := t.WriteFrame(f); err != nil {
		return err
	}
	protocol.EchoLoop(t)
	return nil
}

// DialAndRelay is the client side of a forwarding tunnel: it tells the server
// to dial target, then relays the local connection through the tunnel in both
// directions until either side closes.
func DialAndRelay(t protocol.Tunnel, local net.Conn, target string, kind protocol.Kind) error {
	dial := make([]byte, 0, 1+len(target))
	dial = append(dial, protocol.FrameForwardDial)
	dial = append(dial, target...)
	if err := t.WriteFrame(dial); err != nil {
		return err
	}
	return relay(t, local, kind)
}

// serveForward relays a forwarding session whose dial target is already known.
func serveForward(t protocol.Tunnel, target string, kind protocol.Kind) error {
	rc, err := net.Dial("tcp", target)
	if err != nil {
		// Target unreachable: closing the tunnel makes the client's relay
		// wake with an error and drop the local connection.
		_ = t.Close()
		return err
	}
	defer rc.Close()
	return relay(t, rc, kind)
}

// relay copies bytes between the local TCP connection and the tunnel in both
// directions until either side closes, then tears both down. The frame size
// is chosen from the tunnel's transport kind: datagram tunnels must stay
// under the path MTU, stream tunnels can use large frames.
func relay(t protocol.Tunnel, c net.Conn, kind protocol.Kind) error {
	maxFrame := MaxFrameFor(kind)

	// c -> tunnel. Exits when the local side closes or a tunnel write fails;
	// closing the tunnel wakes the reader below so the whole session unwinds.
	go func() {
		defer t.Close()
		buf := make([]byte, maxFrame)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				frame := make([]byte, 1+n)
				frame[0] = protocol.FrameForwardData
				copy(frame[1:], buf[:n])
				if werr := t.WriteFrame(frame); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// tunnel -> c.
	defer c.Close()
	for {
		f, err := t.ReadFrame()
		if err != nil {
			return err
		}
		if len(f) > 0 && f[0] == protocol.FrameForwardData {
			if _, err := c.Write(f[1:]); err != nil {
				return err
			}
		}
	}
}
