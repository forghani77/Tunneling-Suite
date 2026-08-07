// Package benchmark runs the protocol test suite: connection overhead,
// round-trip latency (with jitter) and packet loss.
package benchmark

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"tunnel-suite/internal/protocol"
	"tunnel-suite/internal/report"
)

// Config tunes the benchmark.
type Config struct {
	Pings       int           // probes per phase
	RTTSize     int           // latency probe payload size (bytes)
	LossSize    int           // loss probe payload size (bytes)
	Gap         time.Duration // pause between probes
	Timeout     time.Duration // overall budget per protocol
	ReadTimeout time.Duration // per-read budget

	// ThroughputSec is the duration of the throughput blast; ThroughputSize
	// is the payload size of each throughput frame. Zero means default.
	ThroughputSec  float64
	ThroughputSize int
}

// DefaultThroughputSize is the default throughput frame payload size: large
// enough to measure real bandwidth, small enough that no tunnel's framing
// (16-bit length fields, UDP/raw payload limits) overflows.
const DefaultThroughputSize = 60000

// drainGrace is how long the reader keeps counting echoed frames after the
// blast deadline. Frames that were still in flight when the writer stopped
// (socket buffers, the server's echo queue, the wire) arrive during this
// window and are counted, so they are not misreported as loss.
const drainGrace = 300 * time.Millisecond

// DefaultConfig returns sensible defaults for a local/loopback run.
func DefaultConfig() Config {
	return Config{
		Pings:          50,
		RTTSize:        protocol.DefaultRTTSize,
		LossSize:       protocol.DefaultLossSize,
		Gap:            5 * time.Millisecond,
		Timeout:        20 * time.Second,
		ReadTimeout:    2 * time.Second,
		ThroughputSec:  5,
		ThroughputSize: DefaultThroughputSize,
	}
}

// Note: individual reads wait for the remaining overall budget rather than
// ReadTimeout. This deliberately avoids misreporting loss on tunnels that are
// merely slow: a probe is only counted as lost once the whole protocol budget
// is exhausted, which also bounds how long a dead datagram tunnel can stall
// the suite.

// ReportConfig converts a benchmark Config into its report representation.
func ReportConfig(c Config) report.Config {
	return report.Config{
		Pings:          c.Pings,
		RTTSize:        c.RTTSize,
		LossSize:       c.LossSize,
		GapMs:          float64(c.Gap.Microseconds()) / 1000,
		TimeoutSec:     c.Timeout.Seconds(),
		ReadTimeoutMs:  float64(c.ReadTimeout.Microseconds()) / 1000,
		ThroughputSec:  c.ThroughputSec,
		ThroughputSize: c.ThroughputSize,
	}
}

func ms(t time.Time) float64 { return float64(time.Since(t).Microseconds()) / 1000 }

// Run executes the full benchmark against one protocol. The server side is
// assumed to be listening already (see the server package).
//
// The returned Result carries every metric plus any error/note; failures are
// reported as skipped (dial stage) or failed (measurement stage) so the
// report stays complete.
func Run(p protocol.Protocol, addr string, opts protocol.Options, cfg Config) report.Result {
	res := report.Result{
		Protocol:      p.Name(),
		Kind:          p.Kind().String(),
		OverheadBytes: p.Overhead(),
	}

	start := time.Now()
	tun, err := p.Dial(addr, opts)
	res.ConnectMs = ms(start)
	if err != nil {
		res.Status = report.StatusSkipped
		res.Note = "dial failed"
		res.Error = err.Error()
		return res
	}
	defer tun.Close()

	deadline := time.Now().Add(cfg.Timeout)
	remaining := func() time.Duration { return time.Until(deadline) }
	rtts := make([]float64, 0, cfg.Pings+1)

	// --- handshake + latency phase -----------------------------------------
	// The first ping/pong doubles as the handshake measurement: for TLS/QUIC
	// it includes the full transport handshake; for WireGuard it includes the
	// handshake ratchet; for raw datagrams it is the first full round trip.
	hsStart := time.Now()
	var probeSeq uint32
	for probeSeq = 0; probeSeq < uint32(cfg.Pings); probeSeq++ {
		if remaining() <= 0 {
			res.Note = "timeout during latency phase"
			break
		}
		sendAt := time.Now()
		f, err := protocol.EncodeFrame(protocol.FramePing, probeSeq, sendAt, cfg.RTTSize)
		if err != nil {
			res.Status = report.StatusFailed
			res.Error = err.Error()
			return res
		}
		if err := tun.WriteFrame(f); err != nil {
			res.Status = report.StatusFailed
			res.Error = "write: " + err.Error()
			return res
		}
		if _, err := readSeq(tun, probeSeq, remaining()); err != nil {
			// A stream transport failing mid-test is fatal; for datagrams a
			// single missed probe is just loss (counted in the loss phase).
			if p.Kind() == protocol.KindStream {
				res.Status = report.StatusFailed
				res.Error = "read: " + err.Error()
				break
			}
		} else {
			rtts = append(rtts, ms(sendAt))
			if probeSeq == 0 {
				// Only report a handshake time if the first round trip succeeded;
				// otherwise the metric would just reflect the read timeout.
				res.HandshakeMs = ms(hsStart)
			}
		}
		time.Sleep(cfg.Gap)
	}
	if res.Status != report.StatusFailed {
		res.RTT = report.ComputeRTT(rtts)
	}

	// --- loss phase (datagram transports only) -----------------------------
	// Reliable streams reorder nothing and lose nothing by design: report 0%.
	if p.Kind() == protocol.KindDatagram && res.Status != report.StatusFailed {
		sent, recv := 0, 0
		base := uint32(1 << 30) // distinct sequence space
		for i := 0; i < cfg.Pings; i++ {
			if remaining() <= 0 {
				break
			}
			f, err := protocol.EncodeFrame(protocol.FramePing, base+uint32(i), time.Now(), cfg.LossSize)
			if err != nil {
				break
			}
			if err := tun.WriteFrame(f); err != nil {
				break
			}
			sent++
			if _, err := readSeq(tun, base+uint32(i), remaining()); err == nil {
				recv++
			}
			time.Sleep(cfg.Gap)
		}
		res.Sent, res.Received = sent, recv
		if sent > 0 {
			res.LossPercent = float64(sent-recv) / float64(sent) * 100
		}
	} else if res.Status == report.StatusOK || res.Status == "" {
		res.LossPercent = 0
		res.Note = "reliable transport: loss is 0% by design"
	}

	if res.Status == "" {
		res.Status = report.StatusOK
	}
	if res.Status == report.StatusOK && len(rtts) == 0 {
		res.Status = report.StatusFailed
		res.Error = "no successful round trips"
	}
	return res
}

// RunThroughput measures how fast one protocol can push data. The client
// blasts large frames at the server for the configured duration while the
// server's echo loop returns them, so both directions are exercised at once:
// Upload is the achieved client→server byte rate and Download the achieved
// server→client (echo) byte rate. Write pacing comes from the socket buffers
// and the tunnel's own flow control, so the rates reflect what the tunnel can
// actually carry.
func RunThroughput(p protocol.Protocol, addr string, opts protocol.Options, cfg Config) report.ThroughputResult {
	res := report.ThroughputResult{
		Protocol:  p.Name(),
		Kind:      p.Kind().String(),
		FrameSize: cfg.ThroughputSize,
	}

	dur := cfg.ThroughputSec
	if dur <= 0 {
		dur = 5
	}
	size := cfg.ThroughputSize
	if size <= 0 {
		size = DefaultThroughputSize
	}
	// Raw layer-3 protocols (gre/ipip/sit/6to4/icmp/icmpv6) send each frame as
	// one unfragmented raw IP packet: the kernel refuses writes larger than
	// the path MTU (EMSGSIZE, "message too long"), which used to fail the
	// default 60000-byte blast even though the protocol itself was fine. Clamp
	// to a frame that fits in the standard 1500-byte MTU (including each
	// protocol's own encapsulation overhead) and say so, instead of failing
	// with a cryptic sendmsg error.
	if size > protocol.RawDatagramMaxFrame && protocol.IsRawDatagram(p) {
		size = protocol.RawDatagramMaxFrame
		res.Note = fmt.Sprintf("frame clamped to %dB: raw sockets cannot exceed the path MTU", size)
	}
	res.FrameSize = size

	tun, err := p.Dial(addr, opts)
	if err != nil {
		res.Status = report.StatusSkipped
		res.Note = "dial failed"
		res.Error = err.Error()
		return res
	}
	defer tun.Close()

	frame, err := protocol.EncodeFrame(protocol.FramePing, 0, time.Now(), size)
	if err != nil {
		res.Status = report.StatusFailed
		res.Error = err.Error()
		return res
	}

	// Warm up: the first frame establishes the session (raw protocols create
	// it on the first probe), so a short blast isn't dominated by session
	// setup. The echo, if any, is drained before the clock starts; a lost
	// warm-up echo on a lossy datagram tunnel is not fatal.
	if err := tun.WriteFrame(frame); err != nil {
		res.Status = report.StatusFailed
		res.Error = "warm-up write: " + err.Error()
		return res
	}
	_ = tun.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = tun.ReadFrame()

	blastStart := time.Now()
	deadline := blastStart.Add(time.Duration(dur * float64(time.Second)))
	var sentBytes, recvBytes, sentFrames, recvFrames atomic.Int64

	// Reader: counts echoed frames back from the server until shortly after
	// the blast deadline (the absolute read deadline persists across reads).
	// The extra drainGrace lets frames that were still in flight when the
	// writer stopped arrive and be counted instead of being misreported as
	// loss.
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		if err := tun.SetReadDeadline(deadline.Add(drainGrace)); err != nil {
			return
		}
		for {
			f, err := tun.ReadFrame()
			if err != nil {
				return
			}
			recvBytes.Add(int64(len(f)))
			recvFrames.Add(1)
		}
	}()

	// Writer: blasts frames until the deadline. Stream tunnels set one
	// combined read+write deadline, so a write that blocks past it returns a
	// deadline error — that is the normal end of the blast, not a failure.
	// Tunnels that can only emulate deadlines (e.g. HTTP/2-stream based
	// protocols) tear the connection down when the window ends, so an
	// in-flight write wakes with a closed-connection error at/after the
	// deadline; that is equally the normal end of the blast.
	for time.Now().Before(deadline) {
		if err := tun.WriteFrame(frame); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || !time.Now().Before(deadline) {
				break
			}
			res.Status = report.StatusFailed
			res.Error = "write: " + err.Error()
			break
		}
		sentBytes.Add(int64(len(frame)))
		sentFrames.Add(1)
	}
	// The blast window ends when the writer stops; the drain grace period
	// after it is not part of the measured duration, so the rates reflect
	// exactly the window the frames were blasted over. For stream tunnels
	// the read deadline is combined (read+write), so a write blocked across
	// the blast boundary could wake as late as deadline+drainGrace; clamp to
	// the nominal window so that teardown time never inflates the duration
	// (early failures, which stop short of the window, are unaffected).
	elapsed := time.Since(blastStart).Seconds()
	if elapsed <= 0 {
		elapsed = 0.001
	}
	if elapsed > dur {
		elapsed = dur
	}
	<-readDone
	sent := sentBytes.Load()
	recv := recvBytes.Load()
	sf := sentFrames.Load()
	rf := recvFrames.Load()

	res.DurationSec = elapsed
	res.SentBytes = sent
	res.RecvBytes = recv
	res.SentFrames = sf
	res.RecvFrames = rf
	res.UploadMbps = float64(sent) * 8 / 1e6 / elapsed
	res.DownloadMbps = float64(recv) * 8 / 1e6 / elapsed
	if sf > 0 {
		if p.Kind() == protocol.KindStream {
			// Reliable transports cannot lose data; any sent/recv gap is just
			// frames still in flight when the blast deadline hit.
			res.LossPercent = 0
		} else {
			res.LossPercent = float64(sf-rf) / float64(sf) * 100
		}
	}
	if res.Status == "" {
		res.Status = report.StatusOK
	}
	return res
}

// readSeq reads frames until a pong matching seq arrives, respecting the
// deadline (which is refreshed per attempt).
func readSeq(tun protocol.Tunnel, seq uint32, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	if err := tun.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	for {
		f, err := tun.ReadFrame()
		if err != nil {
			return nil, err
		}
		ftype, s, _, err := protocol.DecodeFrame(f)
		if err != nil {
			continue
		}
		if ftype == protocol.FramePong && s == seq {
			return f, nil
		}
		// Ignore stale/out-of-order pongs.
	}
}
