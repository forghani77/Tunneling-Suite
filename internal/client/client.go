// Package client drives the benchmark from the client side: it fetches the
// server's protocol manifest, then runs the benchmark suite against every
// requested protocol.
package client

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"tunnel-suite/internal/benchmark"
	"tunnel-suite/internal/protocol"
	"tunnel-suite/internal/report"
)

// Config configures the client run.
type Config struct {
	Server     string
	BasePort   int
	Protocols  []string // empty means every protocol the server offers
	SSPassword string
	Password   string // shared secret for anytls / naive
	// Throughput lists the protocols to run an additional throughput speed
	// test against (empty means no speed test). ThroughputOnly skips the
	// standard benchmark and runs only those speed tests.
	Throughput     []string
	ThroughputOnly bool
	benchmark.Config
}

type manifestEntry struct {
	Name      string
	Port      int
	Kind      string
	NeedsRoot bool
	Available bool
	Reason    string
}

// Run executes the benchmark suite and returns the full report.
func Run(cfg Config) (*report.Report, error) {
	entries, clientIP, err := fetchManifest(cfg)
	if err != nil {
		return nil, err
	}

	protos, err := selectProtocols(entries, cfg.Protocols)
	if err != nil {
		return nil, err
	}
	// Resolve the throughput list up front so unknown names fail before any
	// testing runs.
	var tp []protocol.Protocol
	if len(cfg.Throughput) > 0 {
		tp, err = selectProtocols(entries, cfg.Throughput)
		if err != nil {
			return nil, err
		}
	}

	opts := protocol.Options{
		SSPassword: cfg.SSPassword,
		Password:   cfg.Password,
		ClientIP:   clientIP,
	}

	results := make([]report.Result, 0, len(protos))
	if cfg.ThroughputOnly {
		protos = nil // skip the standard benchmark
	}
	for _, p := range protos {
		me := entries[p.Name()]
		if !me.Available {
			results = append(results, report.Result{
				Protocol:      p.Name(),
				Kind:          p.Kind().String(),
				Status:        report.StatusSkipped,
				OverheadBytes: p.Overhead(),
				Note:          "not offered by server",
				Error:         me.Reason,
			})
			continue
		}
		addr := net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.BasePort+protocol.PortOffset(p)))
		started := time.Now()
		fmt.Printf("testing %-12s... ", p.Name())
		r := benchmark.Run(p, addr, opts, cfg.Config)
		fmt.Printf("%s (%.1fs)\n", r.Status, time.Since(started).Seconds())
		results = append(results, r)
	}

	rep := &report.Report{
		GeneratedAt: time.Now(),
		Server:      cfg.Server,
		BasePort:    cfg.BasePort,
		ClientIP:    ipString(clientIP),
		Config:      benchmark.ReportConfig(cfg.Config),
		Results:     results,
	}
	for _, r := range results {
		rep.Summary.Total++
		switch r.Status {
		case report.StatusOK:
			rep.Summary.OK++
		case report.StatusSkipped:
			rep.Summary.Skipped++
		default:
			rep.Summary.Failed++
		}
	}

	// --- throughput speed tests (only for explicitly requested protocols) ---
	if len(tp) > 0 {
		for _, p := range tp {
			me := entries[p.Name()]
			if !me.Available {
				rep.Throughput = append(rep.Throughput, report.ThroughputResult{
					Protocol: p.Name(),
					Kind:     p.Kind().String(),
					Status:   report.StatusSkipped,
					Note:     "not offered by server",
					Error:    me.Reason,
				})
				continue
			}
			addr := net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.BasePort+protocol.PortOffset(p)))
			started := time.Now()
			fmt.Printf("throughput %-10s... ", p.Name())
			r := benchmark.RunThroughput(p, addr, opts, cfg.Config)
			fmt.Printf("%s (%.1fs)\n", r.Status, time.Since(started).Seconds())
			rep.Throughput = append(rep.Throughput, r)
		}
		for _, r := range rep.Throughput {
			rep.ThroughputSummary.Total++
			switch r.Status {
			case report.StatusOK:
				rep.ThroughputSummary.OK++
			case report.StatusSkipped:
				rep.ThroughputSummary.Skipped++
			default:
				rep.ThroughputSummary.Failed++
			}
		}
	}

	return rep, nil
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// fetchManifest queries the server's control port for its protocol manifest
// and returns the client's observed IP address.
func fetchManifest(cfg Config) (map[string]manifestEntry, net.IP, error) {
	addr := net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.BasePort+protocol.PortControl))
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot reach server control port %s: %w (is the server running?)", addr, err)
	}
	defer c.Close()
	clientIP := c.LocalAddr().(*net.TCPAddr).IP

	if _, err := fmt.Fprintf(c, "{\"op\":\"manifest\"}\n"); err != nil {
		return nil, nil, err
	}
	var resp struct {
		Entries []manifestEntry `json:"entries"`
	}
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return nil, nil, fmt.Errorf("bad manifest: %w", err)
	}
	m := make(map[string]manifestEntry, len(resp.Entries))
	for _, e := range resp.Entries {
		m[e.Name] = e
	}
	return m, clientIP, nil
}

// selectProtocols resolves the requested names against the manifest, in
// registry order. Names unknown to the client are rejected; names the server
// does not advertise are reported as unavailable.
func selectProtocols(entries map[string]manifestEntry, requested []string) ([]protocol.Protocol, error) {
	all := protocol.All()
	if len(requested) == 0 {
		var out []protocol.Protocol
		for _, p := range all {
			if _, ok := entries[p.Name()]; ok {
				out = append(out, p)
			}
		}
		return out, nil
	}
	want := make(map[string]bool)
	for _, r := range requested {
		n := protocol.NormalizeName(r)
		if _, ok := protocol.ByName(n); !ok {
			return nil, fmt.Errorf("unknown protocol %q (known: %v)", r, protocol.Names())
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
