package protocol

import (
	"net"
	"os"
	"sync"
	"time"
)

// udpSessionIdle bounds how long a server-side session stays alive with no
// traffic. When it fires, the session's EchoLoop exits and the session is
// reaped, so a long-lived server does not accumulate sessions for clients
// that have gone away.
const udpSessionIdle = 60 * time.Second

// udpSession is one accepted client session on a udpDispatcher: the raw
// datagrams for its source address, delivered by the dispatcher, and the
// protocol tunnel handed to Accept.
type udpSession struct {
	key  string
	tun  Tunnel
	in   chan []byte
	done <-chan struct{}
}

// udpSessionTransport is the shared server-side transport for UDP-family
// protocols. The dispatcher (the socket's only reader) delivers the raw
// datagrams for this session's peer through in, and writes go straight to
// the peer over the shared socket. SetReadDeadline is a no-op because
// delivery is channel-based, mirroring the raw/icmp6 server tunnels.
type udpSessionTransport struct {
	conn   *net.UDPConn
	peer   net.Addr
	in     <-chan []byte
	done   <-chan struct{}
	label  string
	remove func()
}

func newUDPSessionTransport(conn *net.UDPConn, peer net.Addr, in <-chan []byte, done <-chan struct{}, label string, remove func()) *udpSessionTransport {
	return &udpSessionTransport{conn: conn, peer: peer, in: in, done: done, label: label, remove: remove}
}

func (t *udpSessionTransport) WriteFrame(p []byte) error {
	_, err := t.conn.WriteTo(p, t.peer)
	return err
}

func (t *udpSessionTransport) ReadFrame() ([]byte, error) {
	select {
	case f := <-t.in:
		return f, nil
	case <-t.done:
		return nil, net.ErrClosed
	case <-time.After(udpSessionIdle):
		return nil, os.ErrDeadlineExceeded
	}
}

func (t *udpSessionTransport) SetReadDeadline(d time.Time) error { return nil }
func (t *udpSessionTransport) Close() error {
	if t.remove != nil {
		t.remove()
	}
	return nil
}
func (t *udpSessionTransport) Label() string { return t.label }

// udpDispatcher is a single-reader server for UDP-based datagram protocols
// (udp, vxlan, vxlan-gpe, geneve, gue, ipsec, l2tp). One goroutine owns the
// socket and routes every datagram to the session for its source address,
// creating sessions on demand and handing them to Accept. Per-protocol wrap
// builds each session's tunnel around the shared transport (adding the
// protocol's encapsulation and per-session header parameters).
//
// This replaces the old design where Accept() itself blocked on the socket
// and every session's echo loop read the shared conn directly. With that
// design each datagram woke one of many readers, sessions never ended, and a
// throughput blast spawned thousands of zombie readers that stole later
// clients' frames — reproduced as "no successful round trips" on the second
// test run against the same server.
//
// Note: a session is created for any datagram from a new source address; the
// protocol tunnel's own ReadFrame decap filter rejects malformed or foreign
// datagrams (matching how the plain-udp server always behaved), and stray
// sessions idle out after udpSessionIdle.
type udpDispatcher struct {
	conn        *net.UDPConn
	label       string
	wrap        func(tr *udpSessionTransport) Tunnel
	mu          sync.Mutex
	sessions    map[string]*udpSession
	newSessions chan *udpSession
	done        chan struct{}
	closeOnce   sync.Once
}

func newUDPDispatcher(conn *net.UDPConn, label string, wrap func(*udpSessionTransport) Tunnel) *udpDispatcher {
	d := &udpDispatcher{
		conn:        conn,
		label:       label,
		wrap:        wrap,
		sessions:    make(map[string]*udpSession),
		newSessions: make(chan *udpSession, 16),
		done:        make(chan struct{}),
	}
	go d.dispatchLoop()
	return d
}

// dispatchLoop is the socket's only reader.
func (d *udpDispatcher) dispatchLoop() {
	buf := make([]byte, MaxFrame) // reused read buffer
	for {
		n, peer, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed
		}
		key := peer.String()
		d.mu.Lock()
		s := d.sessions[key]
		d.mu.Unlock()
		if s == nil {
			// Brand-new client session.
			s = &udpSession{
				key:  key,
				in:   make(chan []byte, 64),
				done: d.done,
			}
			tr := newUDPSessionTransport(d.conn, peer, s.in, s.done, d.label+"@"+peer.String(), func() { d.removeSession(s) })
			s.tun = d.wrap(tr)
			d.mu.Lock()
			d.sessions[key] = s
			d.mu.Unlock()
			select {
			case d.newSessions <- s:
			case <-d.done:
				return
			}
		}
		// The read buffer is reused, so copy the datagram before queueing.
		frame := append([]byte(nil), buf[:n]...)
		select {
		case s.in <- frame:
		default:
			// Session buffer full (slow echo loop): drop, the same as any
			// datagram loss. Never stall the socket's only reader.
		}
	}
}

func (d *udpDispatcher) removeSession(s *udpSession) {
	d.mu.Lock()
	delete(d.sessions, s.key)
	d.mu.Unlock()
}

// Accept waits for a new client session and hands over its tunnel.
func (d *udpDispatcher) Accept() (Tunnel, error) {
	select {
	case s := <-d.newSessions:
		return s.tun, nil
	case <-d.done:
		return nil, net.ErrClosed
	}
}

func (d *udpDispatcher) Close() error {
	d.closeOnce.Do(func() {
		close(d.done)
		_ = d.conn.Close()
	})
	return nil
}
