// Command tunnel-suit is a tunneling-protocol test harness.
//
// Usage:
//
//	tunnel-suit server [flags]   # listen for tests on every protocol
//	tunnel-suit client [flags]   # run the benchmark suite against a server
//
// The server and client are the same binary; run one of each on the machines
// you want to test connectivity between.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"tunnel-suit/internal/benchmark"
	"tunnel-suit/internal/client"
	"tunnel-suit/internal/protocol"
	"tunnel-suit/internal/report"
	"tunnel-suit/internal/server"
)

const usageText = `tunnel-suit — tunneling protocol test harness

Usage:
  tunnel-suit server [flags]   run the server (listens for tests)
  tunnel-suit client [flags]   run the client (drives the tests)

Protocols tested: tcp, udp, tls, quic, http3 (QUIC), kcp, shadowsocks,
                  gre, ipip, sit, 6to4, icmp, icmpv6 (layer-3, needs root),
                  geneve (UDP, RFC 8926), vxlan (UDP, RFC 7348),
                  vxlan-gpe (UDP, next-protocol field), gue (UDP, generic
                  encapsulation), ipsec (ESP-AES-GCM over UDP, NAT-T),
                  wireguard, amnezia, amnezia2, tap (layer-2, needs root),
                  http, https, ws, wss, anytls, naive, smtp

Examples:
  tunnel-suit server --listen 0.0.0.0 --base-port 10000
  tunnel-suit client --server 203.0.113.10 --base-port 10000
  tunnel-suit client --server 203.0.113.10 --protocols tcp,tls,quic --pings 100

Run "tunnel-suit server --help" or "tunnel-suit client --help" for options.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		os.Exit(runServer(os.Args[2:]))
	case "client":
		os.Exit(runClient(os.Args[2:]))
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usageText)
		os.Exit(2)
	}
}

// splitCSV splits a comma-separated flag value, trimming empties.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func runServer(args []string) int {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", "0.0.0.0", "address to bind")
	basePort := fs.Int("base-port", 10000, "base port; each protocol uses base+offset")
	protocols := fs.String("protocols", "", "comma-separated subset (default: all)")
	cert := fs.String("cert", "", "TLS certificate file (default: ephemeral self-signed)")
	key := fs.String("key", "", "TLS key file")
	ssPass := fs.String("ss-password", "", "Shadowsocks password (must match client)")
	password := fs.String("password", "", "shared secret for anytls/naive/ipsec (must match client)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "tunnel-suit server — listen for tunneling tests\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := server.Run(server.Config{
		Listen:      *listen,
		BasePort:    *basePort,
		Protocols:   splitCSV(*protocols),
		TLSCertFile: *cert,
		TLSKeyFile:  *key,
		SSPassword:  *ssPass,
		Password:    *password,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func runClient(args []string) int {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	serverHost := fs.String("server", "", "server host or IP (required)")
	basePort := fs.Int("base-port", 10000, "base port (must match server)")
	protocols := fs.String("protocols", "", "comma-separated subset (default: everything the server offers)")
	pings := fs.Int("pings", 50, "probes per phase per protocol")
	rttSize := fs.Int("rtt-size", protocol.DefaultRTTSize, "latency probe size (bytes)")
	lossSize := fs.Int("loss-size", protocol.DefaultLossSize, "loss probe size (bytes)")
	gapMs := fs.Float64("gap-ms", 5, "pause between probes (ms)")
	timeoutSec := fs.Float64("timeout", 20, "per-protocol budget (s)")
	jsonOut := fs.String("json", "", "JSON report path (default: report-<timestamp>.json)")
	noColor := fs.Bool("no-color", false, "disable ANSI colors")
	ssPass := fs.String("ss-password", "", "Shadowsocks password (must match server)")
	password := fs.String("password", "", "shared secret for anytls/naive/ipsec (must match server)")
	throughput := fs.String("throughput", "", "comma-separated protocols to run a throughput speed test against (default: none)")
	throughputOnly := fs.Bool("throughput-only", false, "run only the throughput speed tests (skip the standard benchmark)")
	throughputSec := fs.Float64("throughput-time", 5, "throughput test duration (s)")
	throughputSize := fs.Int("throughput-size", benchmark.DefaultThroughputSize, "throughput frame size (bytes)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "tunnel-suit client — run the tunneling test suite against a server\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *serverHost == "" {
		fmt.Fprintln(os.Stderr, "error: --server is required")
		fs.Usage()
		return 2
	}

	cfg := client.Config{
		Server:         *serverHost,
		BasePort:       *basePort,
		Protocols:      splitCSV(*protocols),
		Throughput:     splitCSV(*throughput),
		ThroughputOnly: *throughputOnly,
		SSPassword:     *ssPass,
		Password:       *password,
		Config: benchmark.Config{
			Pings:          *pings,
			RTTSize:        *rttSize,
			LossSize:       *lossSize,
			Gap:            time.Duration(*gapMs * float64(time.Millisecond)),
			Timeout:        time.Duration(*timeoutSec * float64(time.Second)),
			ReadTimeout:    2 * time.Second,
			ThroughputSec:  *throughputSec,
			ThroughputSize: *throughputSize,
		},
	}

	fmt.Printf("tunnel-suit client → server %s (base port %d)\n", *serverHost, *basePort)
	fmt.Printf("testing: %s\n", strings.Join(protocol.Names(), ", "))

	rep, err := client.Run(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	report.PrintTable(os.Stdout, rep.Results, !*noColor)
	report.PrintSummary(os.Stdout, rep.Summary, !*noColor)

	if len(rep.Throughput) > 0 {
		report.PrintThroughputTable(os.Stdout, rep.Throughput, *throughputSec, *throughputSize, !*noColor)
		report.PrintSummary(os.Stdout, rep.ThroughputSummary, !*noColor)
	}

	jsonPath := *jsonOut
	if jsonPath == "" {
		jsonPath = fmt.Sprintf("report-%s.json", time.Now().Format("20060102-150405"))
	}
	if err := writeJSON(jsonPath, rep); err != nil {
		fmt.Fprintln(os.Stderr, "error writing report:", err)
		return 1
	}
	fmt.Printf("\nJSON report written to %s\n", jsonPath)
	if rep.Summary.Failed > 0 || rep.ThroughputSummary.Failed > 0 {
		// Non-zero exit when any protocol test failed (CI-friendly).
		return 1
	}
	return 0
}
