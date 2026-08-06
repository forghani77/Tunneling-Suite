// Package server runs the server side of the tunnel-suit harness: it starts
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

	"tunnel-suit/internal/protocol"
)

// Config configures the server.
type Config struct {
	Listen      string // bind host, default "0.0.0.0"
	BasePort    int
	Protocols   []string // empty means all
	TLSCertFile string
	TLSKeyFile  string
	SSPassword  string
	Password    string // shared secret for anytls / naive
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
		SSPassword:  cfg.SSPassword,
		Password:    cfg.Password,
		TLSCertFile: cfg.TLSCertFile,
		TLSKeyFile:  cfg.TLSKeyFile,
	}

	protos, err := selectProtocols(cfg.Protocols)
	if err != nil {
		return err
	}

	// Ordered map of name -> entry (mirrors registry order).
	names := make([]string, 0, len(protos))
	entries := make(map[string]*entry)
	for _, p := range protos {
		addr := protocol.JoinHostPort(cfg.Listen, cfg.BasePort+protocol.PortOffset(p))
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
		go acceptLoop(ps)
	}

	// Control/manifest listener.
	ctlAddr := protocol.JoinHostPort(cfg.Listen, cfg.BasePort+protocol.PortControl)
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

	log.Printf("tunnel-suit server ready on %s, base port %d", cfg.Listen, cfg.BasePort)

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

func acceptLoop(ps protocol.ProtoServer) {
	for {
		t, err := ps.Accept()
		if err != nil {
			return
		}
		go protocol.EchoLoop(t)
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
			"port":       cfg.BasePort + protocol.PortOffset(e.Proto),
			"kind":       e.Proto.Kind().String(),
			"needs_root": e.Proto.NeedsRoot(),
			"available":  e.Available,
			"reason":     e.Reason,
		})
	}
	_ = json.NewEncoder(c).Encode(map[string]any{"entries": out})
}

// selectProtocols resolves the requested protocol names against the registry.
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
