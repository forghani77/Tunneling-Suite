package protocol

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/ipv6"
)

// ICMPv6 (RFC 4443) tunneling. Test frames travel inside ICMPv6 messages of
// a private type over a raw IPv6 socket (next header 58), so the tunnel
// looks like ordinary ICMPv6 control traffic. RFC 4443 §2.1 reserves types
// 200–254 for private experimentation, and the kernel never auto-responds to
// them (unlike echo/NDP), so they are safe to reuse.
//
// Unlike the IPv4 raw protocols, a raw IPv6 socket on loopback also receives
// its own transmissions, so every message carries a per-tunnel id: the
// client drops its own pings, and the server drops its own echoes.
const (
	ipProtoICMPv6 = 58
	// icmp6Type is the ICMPv6 message type used for the harness's test
	// traffic (reserved for private experimentation).
	icmp6Type = 200

	// serverTunnelIdle bounds how long a server-side session tunnel stays
	// alive with no traffic. When it fires the EchoLoop exits and the
	// session is reaped, so a long-lived server does not accumulate
	// goroutines for clients that have gone away.
	serverTunnelIdle = 60 * time.Second
)

type icmp6Proto struct{}

func (icmp6Proto) Name() string        { return "icmpv6" }
func (icmp6Proto) Kind() Kind          { return KindDatagram }
func (icmp6Proto) Overhead() int       { return 46 } // 40 outer IPv6 + 6 ICMPv6 (type/code/checksum/id)
func (icmp6Proto) NeedsRoot() bool     { return true }
func (icmp6Proto) IsRawDatagram() bool { return true }

// ---------------------------------------------------------------------------
// Raw IPv6 socket
// ---------------------------------------------------------------------------

// icmp6Socket wraps a raw IPv6 socket for protocol 58. The kernel builds the
// outer IPv6 header; the payload passed to the kernel is the ICMPv6 message
// itself (header included).
type icmp6Socket struct {
	pc  net.PacketConn
	rc  *ipv6.PacketConn
	buf []byte // reused read buffer (payload aliases it until the next read)
}

func listenRawIP6() (*icmp6Socket, error) {
	pc, err := net.ListenPacket("ip6:58", "::")
	if err != nil {
		return nil, fmt.Errorf("raw socket ip6:58: %w (needs CAP_NET_RAW / root)", err)
	}
	rc := ipv6.NewPacketConn(pc)
	// Request the destination address so the server can tell which local
	// address a probe arrived at (matters off-loopback).
	if err := rc.SetControlMessage(ipv6.FlagDst, true); err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("ipv6 pktinfo: %w", err)
	}
	tuneSocket(pc)
	return &icmp6Socket{pc: pc, rc: rc}, nil
}

// ReadPacket returns the source, destination and ICMPv6 message of the next
// received raw IPv6 packet. The payload aliases the socket's reused buffer
// and is only valid until the next ReadPacket call.
func (s *icmp6Socket) ReadPacket() (src, dst net.IP, payload []byte, err error) {
	if s.buf == nil {
		s.buf = make([]byte, 1<<16)
	}
	n, cm, raddr, err := s.rc.ReadFrom(s.buf)
	if err != nil {
		return nil, nil, nil, err
	}
	src = raddr.(*net.IPAddr).IP
	if cm != nil {
		dst = cm.Dst
	}
	if dst == nil {
		dst = net.IPv6unspecified
	}
	return src, dst, s.buf[:n], nil
}

// WritePacket sends an ICMPv6 message to dst, stamping src as the source
// address via pktinfo so the kernel uses exactly the address the checksum
// was computed over (off-loopback the routing-chosen source would otherwise
// differ and the checksum would be rejected).
func (s *icmp6Socket) WritePacket(src, dst net.IP, payload []byte) error {
	var cm *ipv6.ControlMessage
	if src != nil && !src.IsUnspecified() {
		cm = &ipv6.ControlMessage{Src: src}
	}
	_, err := s.rc.WriteTo(payload, cm, &net.IPAddr{IP: dst})
	return err
}

// ---------------------------------------------------------------------------
// Message format
//
//	[type 1B][code 1B][checksum 2B][tunnel id 2B][test frame ...]
// ---------------------------------------------------------------------------

// icmp6Encap wraps a test frame in an ICMPv6 message. The checksum covers
// the whole message including the IPv6 pseudo-header.
func icmp6Encap(src, dst net.IP, id uint16, frame []byte) []byte {
	msg := make([]byte, 6+len(frame))
	msg[0] = icmp6Type
	binary.BigEndian.PutUint16(msg[4:6], id)
	copy(msg[6:], frame)
	binary.BigEndian.PutUint16(msg[2:4], icmp6Checksum(src, dst, msg))
	return msg
}

// icmp6Decap extracts the tunnel id and test frame from a received ICMPv6
// message, rejecting foreign ICMPv6 traffic (NDP, router solicitations,
// pings, ...).
func icmp6Decap(payload []byte) (id uint16, frame []byte, err error) {
	if len(payload) < 6 || payload[0] != icmp6Type {
		return 0, nil, ErrBadFrame
	}
	return binary.BigEndian.Uint16(payload[4:6]), payload[6:], nil
}

// icmp6Checksum computes the ICMPv6 checksum including the IPv6 pseudo-header.
// An odd-length message is padded with one zero octet (RFC 4443 §2.3) so the
// checksum matches what the peer's kernel expects.
func icmp6Checksum(src, dst net.IP, msg []byte) uint16 {
	pseudo := make([]byte, 40+len(msg))
	copy(pseudo[0:16], src.To16())
	copy(pseudo[16:32], dst.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(msg)))
	pseudo[39] = ipProtoICMPv6
	copy(pseudo[40:], msg)
	var sum uint32
	for i := 0; i+1 < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i:]))
	}
	if len(pseudo)%2 == 1 {
		sum += uint32(pseudo[len(pseudo)-1]) << 8 // pad the odd trailing octet
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ---------------------------------------------------------------------------
// Tunnel
// ---------------------------------------------------------------------------

type icmp6Tunnel struct {
	rs   *icmp6Socket
	srv  *icmp6Server    // non-nil for server-side sessions
	in   chan []byte     // server side: frames delivered by the dispatcher
	done <-chan struct{} // server side: closed when the server shuts down
	key  *sessKey        // server side: session identity, used when reaping
	id   uint16          // this endpoint's tunnel id (drops our own echoes)
	peer net.IP
	self net.IP
	// label is a human-readable description of the tunnel endpoint.
	label string
}

func (t *icmp6Tunnel) WriteFrame(p []byte) error {
	if len(p) > MaxFrame {
		return ErrFrameTooLarge
	}
	return t.rs.WritePacket(t.self, t.peer, icmp6Encap(t.self, t.peer, t.id, p))
}

func (t *icmp6Tunnel) ReadFrame() ([]byte, error) {
	if t.in != nil {
		// Server side: the dispatcher is the only socket reader and pushes
		// this session's frames here. The idle timeout lets the EchoLoop
		// exit (and the session be reaped) once the client goes away; done
		// wakes it promptly when the server shuts down.
		select {
		case f := <-t.in:
			return f, nil
		case <-t.done:
			return nil, net.ErrClosed
		case <-time.After(serverTunnelIdle):
			return nil, os.ErrDeadlineExceeded
		}
	}
	for {
		_, _, payload, err := t.rs.ReadPacket()
		if err != nil {
			return nil, err
		}
		id, frame, err := icmp6Decap(payload)
		if err != nil || id == t.id {
			// Foreign ICMPv6, or our own transmission looped back by the
			// kernel: keep waiting.
			continue
		}
		return frame, nil
	}
}

func (t *icmp6Tunnel) SetReadDeadline(d time.Time) error {
	if t.in != nil {
		// Server side: delivery is channel-based; nothing to arm.
		return nil
	}
	return t.rs.pc.SetReadDeadline(d)
}

// Close releases the tunnel. Server-side sessions share the server's socket,
// so they only remove themselves from the session table.
func (t *icmp6Tunnel) Close() error {
	if t.srv != nil {
		t.srv.removeSession(t)
		return nil
	}
	if t.rs != nil {
		return t.rs.pc.Close()
	}
	return nil
}

func (t *icmp6Tunnel) Label() string { return t.label }

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

// sessKey identifies one client session on the wire: the client's address
// and the tunnel id it chose. On loopback every client shares the ::1 source
// address, so the id is what separates concurrent sessions. The id space is
// only 16 bits: a fresh client's random id can collide with a live server id
// (its probes would be dropped as self-echoes) or with another loopback
// client's id (sessions merge) — each roughly 1/65536, acceptable for a test
// harness.
type sessKey struct {
	peer string
	id   uint16
}

// icmp6Server demultiplexes the shared raw socket through a single
// dispatchLoop. This matters on loopback, where the socket receives the
// server's own echoes: a naive accept loop would re-accept every echoed
// probe as a brand-new client and leak one tunnel (and one EchoLoop
// goroutine) per probe, eventually taking the server down. Instead:
//
//   - packets carrying an id this server handed out are its own echoes and
//     are dropped;
//   - probes from a known session are routed to that session's tunnel;
//   - only genuinely new sessions reach Accept.
type icmp6Server struct {
	rs *icmp6Socket
	mu sync.Mutex
	// used holds the ids of live server-side tunnels.
	used map[uint16]struct{}
	// sessions maps a client session to the tunnel serving it.
	sessions map[sessKey]*icmp6Tunnel
	// newSessions hands freshly-created tunnels to Accept.
	newSessions chan *icmp6Tunnel
	done        chan struct{}
	closeOnce   sync.Once
}

func newICMP6Server(rs *icmp6Socket) *icmp6Server {
	s := &icmp6Server{
		rs:          rs,
		used:        make(map[uint16]struct{}),
		sessions:    make(map[sessKey]*icmp6Tunnel),
		newSessions: make(chan *icmp6Tunnel, 16),
		done:        make(chan struct{}),
	}
	go s.dispatchLoop()
	return s
}

func (s *icmp6Server) known(id uint16) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.used[id]
	return ok
}

func (s *icmp6Server) register(id uint16) {
	s.mu.Lock()
	s.used[id] = struct{}{}
	s.mu.Unlock()
}

// removeSession drops a reaped session and its tunnel id. Once a tunnel is
// gone nothing echoes with its id again, so the id no longer needs to be
// filtered, which keeps the used set bounded (no growing risk of colliding
// with a fresh client's random id).
func (s *icmp6Server) removeSession(t *icmp6Tunnel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.key != nil {
		delete(s.sessions, *t.key)
		delete(s.used, t.id)
	}
}

// isClientProbe reports whether a decapsulated frame is a client-originated
// probe that can OPEN a new session: either a benchmark Ping (the server
// re-marks it Pong when echoing) or a ForwardDial that starts a forwarding
// tunnel. Any other frame — in particular Pongs echoed by OTHER harness
// servers, which every raw socket on the host also receives — is never treated
// as a new client session. Without this, two servers on one host echo each
// other's echoes forever. Once a session exists, every frame from that peer is
// routed to it (forward data frames are not probes but still belong to the
// session).
func isClientProbe(frame []byte) bool {
	return len(frame) > 0 && (frame[0] == FramePing || frame[0] == FrameForwardDial)
}

// dispatchLoop is the server's single socket reader.
func (s *icmp6Server) dispatchLoop() {
	for {
		src, dst, payload, err := s.rs.ReadPacket()
		if err != nil {
			return // socket closed
		}
		id, frame, err := icmp6Decap(payload)
		if err != nil || s.known(id) {
			// Foreign ICMPv6 (NDP, pings, ...) or one of our own echoes
			// looped back by the kernel: keep waiting.
			continue
		}
		// The socket read buffer is reused, so the frame aliases it; copy it
		// before queueing, or later reads would clobber queued frames.
		frame = append([]byte(nil), frame...)
		self := dst
		if self == nil || self.IsUnspecified() {
			self = src
		}
		key := sessKey{peer: src.String(), id: id}
		s.mu.Lock()
		t := s.sessions[key]
		s.mu.Unlock()
		if t != nil {
			// Known session: route every frame from this peer — benchmark
			// pings AND forward data frames alike. The send is non-blocking:
			// a full session buffer must never stall the dispatcher, the
			// socket's only reader (a dropped frame is just loss, the same as
			// any datagram drop).
			select {
			case t.in <- frame:
			default:
			}
			continue
		}
		// Brand-new client session: only a genuine client probe opens one
		// (a Ping benchmark probe or a ForwardDial that starts a forwarding
		// tunnel). Pongs echoed by other harness servers never qualify.
		if !isClientProbe(frame) {
			continue
		}
		var tid uint16
		for {
			tid = uint16(rand.Intn(1 << 16))
			if !s.known(tid) {
				break
			}
		}
		s.register(tid)
		t = &icmp6Tunnel{
			rs:    s.rs,
			srv:   s,
			in:    make(chan []byte, 64),
			done:  s.done,
			key:   &key,
			id:    tid,
			peer:  src,
			self:  self,
			label: fmt.Sprintf("icmpv6@%s<->%s", src, self),
		}
		s.mu.Lock()
		s.sessions[key] = t
		s.mu.Unlock()
		select {
		case s.newSessions <- t:
		case <-s.done:
			return
		}
		select {
		case t.in <- frame:
		case <-s.done:
			return
		}
	}
}

// Accept waits for a new client session and hands over its tunnel.
func (s *icmp6Server) Accept() (Tunnel, error) {
	select {
	case t := <-s.newSessions:
		return t, nil
	case <-s.done:
		return nil, net.ErrClosed
	}
}

func (s *icmp6Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.rs.pc.Close()
	})
	return nil
}

func (icmp6Proto) Listen(addr string, opts Options) (ProtoServer, error) {
	rs, err := listenRawIP6()
	if err != nil {
		return nil, err
	}
	return newICMP6Server(rs), nil
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

func (icmp6Proto) Dial(addr string, opts Options) (Tunnel, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	dst, err := resolveIPv6(host)
	if err != nil {
		return nil, err
	}
	rs, err := listenRawIP6()
	if err != nil {
		return nil, err
	}
	// ClientIP (learned over the IPv4 control connection) is useless here;
	// derive the source address from the route to the destination instead.
	src := net.IP(nil)
	if opts.ClientIP != nil && opts.ClientIP.To4() == nil {
		src = opts.ClientIP
	}
	if src == nil || src.IsUnspecified() {
		src = outboundIP6(dst)
	}
	return &icmp6Tunnel{
		rs:    rs,
		id:    uint16(rand.Intn(1 << 16)),
		peer:  dst,
		self:  src,
		label: "icmpv6://" + host,
	}, nil
}

// resolveIPv6 resolves a host to an IPv6 address. A loopback IPv4 (or the
// "localhost" name) is mapped to ::1 so the harness works out of the box
// when --server is 127.0.0.1; any other IPv4-only address is rejected.
func resolveIPv6(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			if v4.IsLoopback() {
				return net.IPv6loopback, nil
			}
			return nil, fmt.Errorf("icmpv6: %s is an IPv4 address; use an IPv6 address (e.g. ::1)", host)
		}
		return ip, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if ip.To4() == nil {
			return ip.To16(), nil
		}
	}
	if host == "localhost" {
		return net.IPv6loopback, nil
	}
	return nil, fmt.Errorf("icmpv6: no IPv6 address for %s", host)
}

// outboundIP6 determines the local IPv6 address used to reach dst, falling
// back to ::1 (loopback).
func outboundIP6(dst net.IP) net.IP {
	if c, err := net.Dial("udp6", net.JoinHostPort(dst.String(), "9")); err == nil {
		defer c.Close()
		if ua, ok := c.LocalAddr().(*net.UDPAddr); ok && ua.IP.To4() == nil && !ua.IP.IsUnspecified() {
			return ua.IP.To16()
		}
	}
	return net.IPv6loopback
}
