package protocol

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

// IP protocol numbers used by the layer-3 tunnels.
const (
	ipProtoGRE  = 47 // GRE
	ipProtoIPIP = 4  // IP-in-IP
	ipProtoSIT  = 41 // IPv6-in-IPv4 (6in4)

	// innerProto is the IP protocol number stamped on the synthetic inner
	// IPv4 packets (RFC 3692 experimental range).
	innerProto = 253
)

// rawSocket wraps a raw IPv4 socket with full header control. The read
// buffer is reused across ReadPacket calls (the returned payload is only
// valid until the next call), so a throughput blast does not allocate 64 KiB
// per packet.
type rawSocket struct {
	pc  net.PacketConn
	rc  *ipv4.RawConn
	buf []byte
}

// listenRawIP opens a raw IPv4 socket for the given IP protocol number.
func listenRawIP(protoNum int) (*rawSocket, error) {
	pc, err := net.ListenPacket(fmt.Sprintf("ip4:%d", protoNum), "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("raw socket ip4:%d: %w (needs CAP_NET_RAW / root)", protoNum, err)
	}
	rc, err := ipv4.NewRawConn(pc)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	tuneSocket(pc)
	return &rawSocket{pc: pc, rc: rc}, nil
}

func (r *rawSocket) Close() error { return r.pc.Close() }

// ReadPacket returns the source, destination and payload of the next
// received raw IP packet. The payload aliases the socket's reused buffer and
// is only valid until the next ReadPacket call.
func (r *rawSocket) ReadPacket() (src, dst net.IP, payload []byte, err error) {
	if r.buf == nil {
		r.buf = make([]byte, 1<<16)
	}
	h, p, _, err := r.rc.ReadFrom(r.buf)
	if err != nil {
		return nil, nil, nil, err
	}
	return h.Src, h.Dst, p, nil
}

// WritePacket crafts and sends a raw IPv4 packet (kernel computes the header
// checksum when the field is zero).
func (r *rawSocket) WritePacket(protoNum int, src, dst net.IP, payload []byte) error {
	h := &ipv4.Header{
		Version:  4,
		Len:      20,
		TOS:      0,
		TotalLen: 20 + len(payload),
		ID:       rand.Intn(1 << 16),
		Flags:    0,
		FragOff:  0,
		TTL:      64,
		Protocol: protoNum,
		Checksum: 0,
		Src:      src,
		Dst:      dst,
	}
	return r.rc.WriteTo(h, payload, nil)
}

// ipChecksum computes the standard one's-complement IPv4 header checksum.
func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// craftInnerIPv4 builds a synthetic inner IPv4 packet carrying the tunnel id
// and test frame. The kernel will not touch this payload, so the checksum is
// computed here. The id lets the receiving end tell its own transmissions
// (looped back by the kernel on loopback) apart from the peer's.
func craftInnerIPv4(src, dst net.IP, id uint16, frame []byte) []byte {
	payload := make([]byte, 2+len(frame))
	binary.BigEndian.PutUint16(payload[:2], id)
	copy(payload[2:], frame)
	b := make([]byte, 20+len(payload))
	b[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[4:6], uint16(rand.Intn(1<<16)))
	b[8] = 64         // TTL
	b[9] = innerProto // protocol
	copy(b[12:16], src.To4())
	copy(b[16:20], dst.To4())
	binary.BigEndian.PutUint16(b[10:12], ipChecksum(b[:20]))
	copy(b[20:], payload)
	return b
}

// stripInnerIPv4 extracts the tunnel id and test frame from a synthetic
// inner IPv4 packet.
func stripInnerIPv4(b []byte) (uint16, []byte, error) {
	if len(b) < 22 { // 20 header + 2 id
		return 0, nil, ErrBadFrame
	}
	return binary.BigEndian.Uint16(b[20:22]), b[22:], nil
}

// craftInnerIPv6Addr builds a synthetic inner IPv6 packet with explicit
// source/destination addresses, carrying the tunnel id and test frame.
func craftInnerIPv6Addr(src, dst net.IP, id uint16, frame []byte) []byte {
	payload := make([]byte, 2+len(frame))
	binary.BigEndian.PutUint16(payload[:2], id)
	copy(payload[2:], frame)
	b := make([]byte, 40+len(payload))
	b[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(b[4:6], uint16(len(payload)))
	b[6] = 59 // next header: no next header
	b[7] = 64 // hop limit
	copy(b[8:24], src.To16())
	copy(b[24:40], dst.To16())
	copy(b[40:], payload)
	return b
}

// craftInnerIPv6 builds a synthetic inner IPv6 packet (used by 6in4) carrying
// the tunnel id and test frame. The addresses are RFC 4193 ULA addresses
// reserved for the harness.
func craftInnerIPv6(id uint16, frame []byte) []byte {
	return craftInnerIPv6Addr(net.ParseIP("fd00::1"), net.ParseIP("fd00::2"), id, frame)
}

// sixToFourAddr maps an IPv4 address to its RFC 3056 6to4 address
// (2002:V4ADDR::/48): the well-known 2002::/16 prefix followed by the
// IPv4 address split into two 16-bit groups. E.g. 127.0.0.1 → 2002:7f00:1::.
func sixToFourAddr(v4 net.IP) net.IP {
	v4 = v4.To4()
	if v4 == nil {
		return nil
	}
	b := make(net.IP, 16)
	binary.BigEndian.PutUint16(b[0:2], 0x2002)
	binary.BigEndian.PutUint16(b[2:4], binary.BigEndian.Uint16(v4[0:2]))
	binary.BigEndian.PutUint16(b[4:6], binary.BigEndian.Uint16(v4[2:4]))
	return b
}

// craftInnerIPv6To4 builds the inner IPv6 packet for the 6to4 (RFC 3056)
// protocol: the inner source and destination are the 2002::/48 addresses
// derived from the tunnel endpoints' IPv4 addresses, the classic
// automatic-6to4 addressing scheme.
func craftInnerIPv6To4(self, peer net.IP, id uint16, frame []byte) []byte {
	return craftInnerIPv6Addr(sixToFourAddr(self), sixToFourAddr(peer), id, frame)
}

// stripInnerIPv6 extracts the tunnel id and test frame from a synthetic
// inner IPv6 packet.
func stripInnerIPv6(b []byte) (uint16, []byte, error) {
	if len(b) < 42 { // 40 header + 2 id
		return 0, nil, ErrBadFrame
	}
	return binary.BigEndian.Uint16(b[40:42]), b[42:], nil
}

// greEnvelope wraps an inner IPv4 packet in a minimal GRE header.
func greEnvelope(inner []byte) []byte {
	h := make([]byte, 4+len(inner))
	// flags=0, protocol type=0x0800 (IPv4)
	binary.BigEndian.PutUint16(h[2:4], 0x0800)
	copy(h[4:], inner)
	return h
}

func stripGRE(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, ErrBadFrame
	}
	if binary.BigEndian.Uint16(b[2:4]) != 0x0800 {
		return nil, ErrBadFrame
	}
	return b[4:], nil
}

// ---------------------------------------------------------------------------
// Shared server/tunnel for all raw layer-3 protocols
// ---------------------------------------------------------------------------

// rawConfig describes how one layer-3 protocol wraps a test frame.
type rawConfig struct {
	// name is the protocol name, used in session labels.
	name     string
	protoNum int
	// encapsulate builds the raw payload (after the outer IP header) for a
	// frame travelling from self to peer under tunnel id. serverSide reports
	// which end of the tunnel is sending, so protocols whose message type is
	// directional (e.g. ICMP echo request vs reply) can stamp the right one.
	encapsulate func(serverSide bool, self, peer net.IP, id uint16, frame []byte) []byte
	// deencapsulate extracts the tunnel id and test frame from a received
	// raw payload.
	deencapsulate func(payload []byte) (uint16, []byte, error)
	// clientOK, when non-nil, further restricts which received payloads the
	// server treats as client probes (e.g. only ICMP echo requests). This
	// stops the server from reacting to kernel auto-replies and to echoes
	// from other harness servers on the same host.
	clientOK func(payload []byte) bool
	// serverOK, when non-nil, further restricts which received payloads the
	// client treats as the server's answers (e.g. only ICMP echo replies).
	serverOK func(payload []byte) bool
}

// rawTunnel is one direction of a raw layer-3 tunnel.
type rawTunnel struct {
	cfg  rawConfig
	rs   *rawSocket
	srv  *rawServer      // non-nil for server-side sessions
	in   chan []byte     // server side: frames delivered by the dispatcher
	done <-chan struct{} // server side: closed when the server shuts down
	key  *sessKey        // server side: session identity, used when reaping
	id   uint16          // this endpoint's tunnel id (drops our own echoes)
	peer net.IP
	self net.IP
	// label is a human-readable description of the tunnel endpoint.
	label string
}

func (t *rawTunnel) WriteFrame(p []byte) error {
	if len(p) > MaxFrame {
		return ErrFrameTooLarge
	}
	payload := t.cfg.encapsulate(t.srv != nil, t.self, t.peer, t.id, p)
	return t.rs.WritePacket(t.cfg.protoNum, t.self, t.peer, payload)
}

func (t *rawTunnel) ReadFrame() ([]byte, error) {
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
		id, frame, err := t.cfg.deencapsulate(payload)
		if err != nil || id == t.id {
			// Foreign traffic, or our own transmission looped back by the
			// kernel: keep waiting.
			continue
		}
		if t.cfg.serverOK != nil && !t.cfg.serverOK(payload) {
			// Not a message this tunnel's peer would send (e.g. an ICMP echo
			// request when the server only answers with replies).
			continue
		}
		return frame, nil
	}
}

func (t *rawTunnel) SetReadDeadline(d time.Time) error {
	if t.in != nil {
		// Server side: delivery is channel-based; nothing to arm.
		return nil
	}
	return t.rs.pc.SetReadDeadline(d)
}

// Close releases the tunnel. Server-side sessions share the server's socket,
// so they only remove themselves from the session table.
func (t *rawTunnel) Close() error {
	if t.srv != nil {
		t.srv.removeSession(t)
		return nil
	}
	if t.rs != nil {
		return t.rs.pc.Close()
	}
	return nil
}

func (t *rawTunnel) Label() string { return t.label }

// rawServer demultiplexes the shared raw socket through a single
// dispatchLoop. On loopback the socket receives the server's own echoes, and
// every raw socket on a host receives the other servers' echoes too; a naive
// accept loop would re-accept all of them as brand-new clients and leak one
// tunnel (and one EchoLoop goroutine) per probe, eventually taking the server
// down. Instead:
//
//   - packets carrying an id this server handed out are its own echoes and
//     are dropped;
//   - frames that are not client Pings (in particular Pongs echoed by other
//     harness servers) are never treated as a client session;
//   - probes from a known session are routed to that session's tunnel;
//   - only genuinely new sessions reach Accept.
//
// This mirrors the icmp6Server design.
type rawServer struct {
	cfg rawConfig
	rs  *rawSocket
	mu  sync.Mutex
	// used holds the ids of live server-side tunnels.
	used map[uint16]struct{}
	// sessions maps a client session to the tunnel serving it.
	sessions map[sessKey]*rawTunnel
	// newSessions hands freshly-created tunnels to Accept.
	newSessions chan *rawTunnel
	done        chan struct{}
	closeOnce   sync.Once
}

func newRawServer(cfg rawConfig, rs *rawSocket) *rawServer {
	s := &rawServer{
		cfg:         cfg,
		rs:          rs,
		used:        make(map[uint16]struct{}),
		sessions:    make(map[sessKey]*rawTunnel),
		newSessions: make(chan *rawTunnel, 16),
		done:        make(chan struct{}),
	}
	go s.dispatchLoop()
	return s
}

func (s *rawServer) known(id uint16) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.used[id]
	return ok
}

func (s *rawServer) register(id uint16) {
	s.mu.Lock()
	s.used[id] = struct{}{}
	s.mu.Unlock()
}

// removeSession drops a reaped session and its tunnel id, keeping the used
// set bounded (see icmp6Server.removeSession).
func (s *rawServer) removeSession(t *rawTunnel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.key != nil {
		delete(s.sessions, *t.key)
		delete(s.used, t.id)
	}
}

// dispatchLoop is the server's single socket reader.
func (s *rawServer) dispatchLoop() {
	for {
		src, dst, payload, err := s.rs.ReadPacket()
		if err != nil {
			return // socket closed
		}
		id, frame, err := s.cfg.deencapsulate(payload)
		if err != nil || s.known(id) || (s.cfg.clientOK != nil && !s.cfg.clientOK(payload)) {
			// Foreign traffic for this protocol number, one of our own echoes
			// looped back by the kernel, or a message type a client would
			// never send (e.g. an ICMP echo reply auto-answered by the
			// kernel): keep waiting.
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
		// tunnel). Pongs echoed by other harness servers on the same host, or
		// a message type a client would never send, never qualify.
		if !isClientProbe(frame) || (s.cfg.clientOK != nil && !s.cfg.clientOK(payload)) {
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
		t = &rawTunnel{
			cfg:   s.cfg,
			rs:    s.rs,
			srv:   s,
			in:    make(chan []byte, 64),
			done:  s.done,
			key:   &key,
			id:    tid,
			peer:  src,
			self:  self,
			label: fmt.Sprintf("%s@%s<->%s", s.cfg.name, src, self),
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
func (s *rawServer) Accept() (Tunnel, error) {
	select {
	case t := <-s.newSessions:
		return t, nil
	case <-s.done:
		return nil, net.ErrClosed
	}
}

func (s *rawServer) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.rs.pc.Close()
	})
	return nil
}

// resolveIPv4 resolves a host to an IPv4 address (falling back to the first
// resolved address).
func resolveIPv4(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, fmt.Errorf("not an IPv4 address: %s", host)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address for %s", host)
}

// outboundIP determines the local IP used to reach dstHost, falling back to
// 127.0.0.1. Used as the source address for raw protocol packets.
func outboundIP(dstHost string) net.IP {
	if dstHost != "" && dstHost != "0.0.0.0" && dstHost != "::" {
		if c, err := net.Dial("udp", net.JoinHostPort(dstHost, "9")); err == nil {
			defer c.Close()
			if ua, ok := c.LocalAddr().(*net.UDPAddr); ok && !ua.IP.IsUnspecified() {
				return ua.IP.To4()
			}
		}
	}
	return net.IPv4(127, 0, 0, 1)
}
