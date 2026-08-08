// Package server runs the server side of the tunnel-suite harness: it starts
// every configured protocol listener, echoes probes back to clients, and
// serves a small JSON manifest on the control port.
package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"tunnel-suite/internal/forward"
	"tunnel-suite/internal/protocol"
)

// Config configures the server.
type Config struct {
	Listen string // bind host, default "0.0.0.0"
	// ProtocolsBasePort is the base for protocol listeners: each protocol
	// binds ProtocolsBasePort plus its registry offset.
	ProtocolsBasePort int
	// ControlPort is the control/manifest (TCP) port. Zero means the
	// protocols base port, preserving the classic layout where the manifest
	// sits at base+0 and the protocols start at base+1.
	ControlPort int
	Protocols   []string // empty means all
	TLSCertFile string
	TLSKeyFile  string
	SSPassword  string
	Password    string // shared secret for anytls / naive
	// Hysteria2Bandwidth caps the hysteria2 protocol's Brutal send rate in
	// Mbps (0 = no cap: the client's requested rate, or the BBR default).
	Hysteria2Bandwidth int
	// Forward enables relay sessions: a client sending a FrameForwardDial is
	// dialed out to the requested target and its bytes relayed (the data
	// plane used by "tunnel-suite client --mode forward|socks"). Without it
	// every session is echo-only and the server can never be used as an open
	// relay. Benchmark sessions always keep working either way.
	Forward bool
}

// controlPort returns the effective control/manifest port.
func (c Config) controlPort() int {
	return protocol.EffectiveControlPort(c.ControlPort, c.ProtocolsBasePort)
}

type entry struct {
	Proto     protocol.Protocol
	Server    protocol.ProtoServer
	Available bool
	Reason    string
}

// Run starts the server and blocks until SIGINT/SIGTERM.
func Run(cfg Config) error {
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0"
	}
	opts := protocol.Options{
		SSPassword:         cfg.SSPassword,
		Password:           cfg.Password,
		TLSCertFile:        cfg.TLSCertFile,
		TLSKeyFile:         cfg.TLSKeyFile,
		Hysteria2Bandwidth: cfg.Hysteria2Bandwidth,
	}

	protos, err := selectProtocols(cfg.Protocols)
	if err != nil {
		return err
	}

	// The control listener is TCP, so it can only collide with a protocol
	// that binds TCP at the same port (stream protocols and the wg-family
	// control plane; UDP protocol offsets live in a separate namespace and
	// cannot conflict). Catch that up front with a clear message instead of
	// an opaque "address already in use" from the bind.
	ctlPort := cfg.controlPort()
	if name, ok := usedTCPPorts(cfg.ProtocolsBasePort, protos)[ctlPort]; ok {
		return fmt.Errorf("control port %d collides with the %s protocol listener (protocols base port %d) — pick a free --control-port or shift --protocols-base-port", ctlPort, name, cfg.ProtocolsBasePort)
	}

	// Ordered map of name -> entry (mirrors registry order).
	names := make([]string, 0, len(protos))
	entries := make(map[string]*entry)
	for _, p := range protos {
		addr := protocol.JoinHostPort(cfg.Listen, cfg.ProtocolsBasePort+protocol.PortOffset(p))
		ps, err := p.Listen(addr, opts)
		if err != nil {
			log.Printf("protocol %-12s unavailable: %v", p.Name(), err)
			entries[p.Name()] = &entry{Proto: p, Reason: err.Error()}
			names = append(names, p.Name())
			continue
		}
		log.Printf("protocol %-12s listening on %s", p.Name(), addr)
		entries[p.Name()] = &entry{Proto: p, Server: ps, Available: true}
		names = append(names, p.Name())
		go acceptLoop(ps, p, cfg.Forward)
	}

	// Control/manifest listener.
	ctlAddr := protocol.JoinHostPort(cfg.Listen, ctlPort)
	ctl, err := net.Listen("tcp", ctlAddr)
	if err != nil {
		for _, e := range entries {
			if e.Server != nil {
				_ = e.Server.Close()
			}
		}
		return fmt.Errorf("control listener: %w", err)
	}
	log.Printf("control       listening on %s (manifest)", ctlAddr)

	go func() {
		for {
			c, err := ctl.Accept()
			if err != nil {
				return
			}
			go handleControl(c, cfg, entries, names)
		}
	}()

	log.Printf("tunnel-suite server ready on %s (protocols base port %d, control port %d)", cfg.Listen, cfg.ProtocolsBasePort, ctlPort)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down...")
	for _, e := range entries {
		if e.Server != nil {
			_ = e.Server.Close()
		}
	}
	_ = ctl.Close()
	return nil
}

func acceptLoop(ps protocol.ProtoServer, p protocol.Protocol, enableForward bool) {
	for {
		t, err := ps.Accept()
		if err != nil {
			return
		}
		if enableForward {
			go forward.Serve(t, p.Kind())
		} else {
			go protocol.EchoLoop(t)
		}
	}
}

func handleControl(c net.Conn, cfg Config, entries map[string]*entry, names []string) {
	defer c.Close()
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	var req map[string]string
	if err := json.Unmarshal([]byte(line), &req); err != nil {
		return
	}
	if req["op"] != "manifest" {
		return
	}
	out := make([]map[string]any, 0, len(names))
	for _, name := range names {
		e := entries[name]
		if e == nil {
			continue
		}
		out = append(out, map[string]any{
			"name":       e.Proto.Name(),
			"port":       cfg.ProtocolsBasePort + protocol.PortOffset(e.Proto),
			"kind":       e.Proto.Kind().String(),
			"needs_root": e.Proto.NeedsRoot(),
			"available":  e.Available,
			"reason":     e.Reason,
		})
	}
	_ = json.NewEncoder(c).Encode(map[string]any{"entries": out})
}

// usedTCPPorts returns the absolute ports the enabled protocols bind TCP
// listeners on (the only ones that can collide with the TCP control port):
// stream protocols at their offset and the wg-family's control-plane
// listener. UDP protocol offsets are deliberately absent — a TCP listener and
// a UDP listener on the same port coexist fine in the kernel.
//
// Keep this list in sync with the registry: any protocol whose Listen binds a
// TCP socket at its port offset must be added here, or a control-port
// collision with it would surface as an opaque "address already in use"
// instead of this clear error.
func usedTCPPorts(base int, protos []protocol.Protocol) map[int]string {
	used := make(map[int]string)
	for _, p := range protos {
		switch p.Name() {
		case "tcp", "tls", "shadowsocks", "http", "https", "ws", "wss", "anytls", "naive", "smtp", "noise",
			"shadowtls", "trojan",
			"wireguard", "amnezia", "amnezia2":
			used[base+protocol.PortOffset(p)] = p.Name()
		}
	}
	return used
}

// selectProtocols resolves requested protocol names against the registry.
func selectProtocols(requested []string) ([]protocol.Protocol, error) {
	all := protocol.All()
	if len(requested) == 0 {
		return all, nil
	}
	want := make(map[string]bool)
	for _, r := range requested {
		n := protocol.NormalizeName(r)
		if _, ok := protocol.ByName(n); !ok {
			return nil, fmt.Errorf("unknown protocol %q", r)
		}
		want[n] = true
	}
	var out []protocol.Protocol
	for _, p := range all {
		if want[p.Name()] {
			out = append(out, p)
		}
	}
	return out, nil
}
