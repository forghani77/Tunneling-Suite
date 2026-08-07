// Command tunnel-suite is a tunneling-protocol test harness.
//
// The server and client are the same binary; run one of each on the machines
// you want to test connectivity between.
//
// The CLI is built on Cobra, so every subcommand supports --help and shell
// autocomplete ("tunnel-suite completion bash", then source the output).
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"tunnel-suite/internal/benchmark"
	"tunnel-suite/internal/client"
	"tunnel-suite/internal/protocol"
	"tunnel-suite/internal/report"
	"tunnel-suite/internal/server"
)

const protocolList = `Protocols tested:
  stream   tcp, tls, quic, http3, kcp, shadowsocks, http, https, ws, wss,
           anytls, naive, smtp
  datagram udp, gre, ipip, sit, 6to4, icmp, icmpv6, geneve, vxlan, vxlan-gpe,
           gue, ipsec, l2tp, wireguard, amnezia, amnezia2, tap`

var rootCmd = &cobra.Command{
	Use:   "tunnel-suite",
	Short: "Tunneling protocol test harness",
	Long: `tunnel-suite — tunneling protocol test harness

One binary, two roles:
  server    listen for test sessions on every supported protocol
  client    connect to a server and benchmark each protocol

` + protocolList + `

Each protocol is measured for handshake time, round-trip latency (min/avg/max
plus jitter), packet loss and header overhead. The client can additionally
run throughput speed tests (upload + download echo) with --throughput, or
only the speed tests with --throughput-only.

Examples:
  tunnel-suite server --listen 0.0.0.0 --base-port 10000
  tunnel-suite client --server 203.0.113.10 --base-port 10000
  tunnel-suite client --server 203.0.113.10 --throughput tcp,udp,kcp --throughput-time 10
  tunnel-suite client --server 203.0.113.10 --throughput-only gre,kcp --throughput-size 1400

Shell autocomplete: run "tunnel-suite completion install" to auto-detect your
shell and enable tab-completion (commands, flags and protocol names).
`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

// errSilent makes RunE exit non-zero without main printing an error line: the
// friendly message was already printed (missing --server) or the exit code is
// a result, not a failure (some protocol tests failed, report already
// written).
var errSilent = errors.New("silent exit")

func main() {
	// Legacy syntax --throughput-only <list> (space-separated list after the
	// flag). Cobra/pflag, like the previous flag package, stops parsing at the
	// first non-flag token, so rewrite the list into the =value form before
	// parsing: --throughput-only udp , gre  →  --throughput-only=udp,gre.
	// (Note: this rewrite runs for the real invocation only, not for the
	// completion machinery, so the space-separated form tab-completes via the
	// --throughput-only=<list> = form.)
	if len(os.Args) >= 2 && os.Args[1] == "client" {
		os.Args = append(os.Args[:2], expandThroughputOnlyList(os.Args[2:])...)
	}
	if err := rootCmd.Execute(); err != nil {
		if err != errSilent {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
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

// expandThroughputOnlyList rewrites a space-separated protocol list that
// follows a bare --throughput-only into the =value form, so flag parsing can
// continue past the list. For example
//
//	--throughput-only udp , gre --throughput-time 2
//
// becomes
//
//	--throughput-only=udp,gre --throughput-time 2
//
// A bare --throughput-only with no following list is rewritten to
// --throughput-only=, preserving the legacy "reuse the --throughput list"
// behavior.
func expandThroughputOnlyList(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-throughput-only" || a == "--throughput-only" {
			var list []string
			for i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				list = append(list, args[i])
			}
			out = append(out, "--throughput-only="+strings.Join(list, ","))
			continue
		}
		out = append(out, a)
	}
	return out
}

// throughputOnlyFlag implements the --throughput-only flag. It accepts a
// comma-separated protocol list (--throughput-only=tcp,amnezia, or the
// space-separated legacy form rewritten by expandThroughputOnlyList) or the
// bare form (--throughput-only), which reuses the --throughput list.
type throughputOnlyFlag struct {
	enabled bool
	list    string
}

func (f *throughputOnlyFlag) String() string { return f.list }
func (f *throughputOnlyFlag) Type() string   { return "string" }

func (f *throughputOnlyFlag) Set(v string) error {
	switch strings.ToLower(v) {
	case "true":
		f.enabled = true
	case "false":
		f.enabled = false
	default:
		f.enabled = true
		f.list = v
	}
	return nil
}

// completeProtocol tab-completes protocol names for --protocols and the
// throughput protocol-list flags.
func completeProtocol(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var out []string
	for _, n := range protocol.Names() {
		if strings.HasPrefix(n, toComplete) {
			out = append(out, n)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// flagUsage prints the command's usage when flag parsing fails (unknown flag,
// bad value, missing required flag) — runtime errors returned by RunE are
// printed by main without the usage dump.
func flagUsage(cmd *cobra.Command, err error) error {
	_ = cmd.Usage()
	return err
}

func init() {
	rootCmd.AddCommand(serverCmd())
	rootCmd.AddCommand(clientCmd())
	// Custom completion command: defines an `install` subcommand and replaces
	// cobra's default one (cobra skips its default when a command named
	// "completion" already exists, and the hidden __complete commands are
	// registered independently, so dynamic completion keeps working).
	rootCmd.AddCommand(completionCmd())
}

func serverCmd() *cobra.Command {
	var (
		listen    string
		basePort  int
		protocols string
		cert      string
		key       string
		ssPass    string
		password  string
	)
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Listen for tunneling tests on every supported protocol",
		Long: `Listen for test sessions on every supported protocol.

Binds the control port at --base-port plus one port per protocol. The client
discovers the offered protocols from the manifest. Pass --protocols to serve
a subset, and keep --password / --ss-password in sync with the client for the
protocols that share a secret (ipsec, l2tp, anytls, naive, shadowsocks).`,
		Example: `  tunnel-suite server --listen 0.0.0.0 --base-port 10000
  tunnel-suite server --protocols tcp,udp,vxlan,kcp --base-port 20000`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return server.Run(server.Config{
				Listen:      listen,
				BasePort:    basePort,
				Protocols:   splitCSV(protocols),
				TLSCertFile: cert,
				TLSKeyFile:  key,
				SSPassword:  ssPass,
				Password:    password,
			})
		},
	}
	cmd.SetFlagErrorFunc(flagUsage)
	f := cmd.Flags()
	f.StringVar(&listen, "listen", "0.0.0.0", "address to bind")
	f.IntVar(&basePort, "base-port", 10000, "base port; each protocol uses base+offset")
	f.StringVar(&protocols, "protocols", "", "comma-separated subset (default: all)")
	f.StringVar(&cert, "cert", "", "TLS certificate file (default: ephemeral self-signed)")
	f.StringVar(&key, "key", "", "TLS key file")
	f.StringVar(&ssPass, "ss-password", "", "Shadowsocks password (must match client)")
	f.StringVar(&password, "password", "", "shared secret for anytls/naive/ipsec/l2tp (must match client)")
	_ = cmd.RegisterFlagCompletionFunc("protocols", completeProtocol)
	return cmd
}

func clientCmd() *cobra.Command {
	var (
		serverHost     string
		basePort       int
		protocols      string
		pings          int
		rttSize        int
		lossSize       int
		gapMs          float64
		timeoutSec     float64
		jsonOut        string
		noColor        bool
		ssPass         string
		password       string
		throughput     string
		throughputOnly = &throughputOnlyFlag{}
		throughputSec  float64
		throughputSize int
	)
	cmd := &cobra.Command{
		Use:   "client",
		Short: "Run the tunneling test suite against a server",
		Long: `Run the benchmark suite against a running server.

Measures every requested protocol for handshake time, round-trip latency
(min/avg/max + jitter), packet loss and header overhead. Add throughput speed
tests (upload + download echo) with --throughput, or run nothing but the
speed tests with --throughput-only:

  tunnel-suite client --server HOST --throughput tcp,udp --throughput-time 10
  tunnel-suite client --server HOST --throughput-only gre,kcp --throughput-size 1400

--throughput-only accepts the protocol list directly, either as a value
(--throughput-only=tcp,udp) or space-separated (--throughput-only tcp,udp);
bare --throughput-only reuses the --throughput list.`,
		Example: `  tunnel-suite client --server 203.0.113.10 --base-port 10000
  tunnel-suite client --server 203.0.113.10 --protocols tcp,tls,quic --pings 100
  tunnel-suite client --server 203.0.113.10 --throughput tcp,udp,kcp --throughput-time 10
  tunnel-suite client --server 203.0.113.10 --throughput-only vxlan-gpe --throughput-size 1400`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if serverHost == "" {
				fmt.Fprintln(os.Stderr, "error: --server is required")
				_ = cmd.Usage()
				return errSilent
			}
			// Effective throughput list: --throughput-only's own list wins;
			// otherwise the --throughput list is used.
			throughputList := splitCSV(throughput)
			if throughputOnly.list != "" {
				throughputList = splitCSV(throughputOnly.list)
			}

			cfg := client.Config{
				Server:         serverHost,
				BasePort:       basePort,
				Protocols:      splitCSV(protocols),
				Throughput:     throughputList,
				ThroughputOnly: throughputOnly.enabled,
				SSPassword:     ssPass,
				Password:       password,
				Config: benchmark.Config{
					Pings:          pings,
					RTTSize:        rttSize,
					LossSize:       lossSize,
					Gap:            time.Duration(gapMs * float64(time.Millisecond)),
					Timeout:        time.Duration(timeoutSec * float64(time.Second)),
					ReadTimeout:    2 * time.Second,
					ThroughputSec:  throughputSec,
					ThroughputSize: throughputSize,
				},
			}

			fmt.Printf("tunnel-suite client → server %s (base port %d)\n", serverHost, basePort)
			// Banner lists only what this run will actually test.
			if throughputOnly.enabled {
				if len(throughputList) == 0 {
					fmt.Println("throughput only: (no protocols — pass a list, e.g. --throughput-only tcp,udp)")
				} else {
					fmt.Printf("throughput only: %s\n", strings.Join(throughputList, ", "))
				}
			} else if requested := splitCSV(protocols); len(requested) > 0 {
				fmt.Printf("testing: %s\n", strings.Join(requested, ", "))
			} else {
				fmt.Printf("testing: %s\n", strings.Join(protocol.Names(), ", "))
			}

			rep, err := client.Run(cfg)
			if err != nil {
				return err
			}

			if len(rep.Results) > 0 {
				// In throughput-only mode the standard benchmark is skipped
				// entirely, so there is no table to render.
				report.PrintTable(os.Stdout, rep.Results, !noColor)
				report.PrintSummary(os.Stdout, rep.Summary, !noColor)
			}

			if len(rep.Throughput) > 0 {
				// Frame size as actually used: raw layer-3 protocols clamp it
				// to the path MTU, so the configured value may not match what
				// ran. With mixed raw + non-raw protocols the sizes differ;
				// report the largest actual size, falling back to the
				// configured value only if none ran.
				effSize := 0
				for _, r := range rep.Throughput {
					if r.FrameSize > effSize {
						effSize = r.FrameSize
					}
				}
				if effSize == 0 {
					effSize = throughputSize
				}
				report.PrintThroughputTable(os.Stdout, rep.Throughput, throughputSec, effSize, !noColor)
				report.PrintSummary(os.Stdout, rep.ThroughputSummary, !noColor)
			}

			jsonPath := jsonOut
			if jsonPath == "" {
				jsonPath = fmt.Sprintf("report-%s.json", time.Now().Format("20060102-150405"))
			}
			if err := writeJSON(jsonPath, rep); err != nil {
				return err
			}
			fmt.Printf("\nJSON report written to %s\n", jsonPath)
			if rep.Summary.Failed > 0 || rep.ThroughputSummary.Failed > 0 {
				// Non-zero exit when any protocol test failed (CI-friendly);
				// the report is already written, so exit silently.
				return errSilent
			}
			return nil
		},
	}
	cmd.SetFlagErrorFunc(flagUsage)
	f := cmd.Flags()
	f.StringVar(&serverHost, "server", "", "server host or IP (required)")
	f.IntVar(&basePort, "base-port", 10000, "base port (must match server)")
	f.StringVar(&protocols, "protocols", "", "comma-separated subset (default: everything the server offers)")
	f.IntVar(&pings, "pings", 50, "probes per phase per protocol")
	f.IntVar(&rttSize, "rtt-size", protocol.DefaultRTTSize, "latency probe size (bytes)")
	f.IntVar(&lossSize, "loss-size", protocol.DefaultLossSize, "loss probe size (bytes)")
	f.Float64Var(&gapMs, "gap-ms", 5, "pause between probes (ms)")
	f.Float64Var(&timeoutSec, "timeout", 20, "per-protocol budget (s)")
	f.StringVar(&jsonOut, "json", "", "JSON report path (default: report-<timestamp>.json)")
	f.BoolVar(&noColor, "no-color", false, "disable ANSI colors")
	f.StringVar(&ssPass, "ss-password", "", "Shadowsocks password (must match server)")
	f.StringVar(&password, "password", "", "shared secret for anytls/naive/ipsec/l2tp (must match server)")
	f.StringVar(&throughput, "throughput", "", "comma-separated protocols to run a throughput speed test against (default: none)")
	f.Var(throughputOnly, "throughput-only", "run only the throughput speed tests against the given protocols (skip the standard benchmark); accepts a list (--throughput-only=tcp,udp or --throughput-only tcp,udp) or bare to reuse the --throughput list")
	f.Lookup("throughput-only").NoOptDefVal = "true"
	f.Float64Var(&throughputSec, "throughput-time", 5, "throughput test duration (s)")
	f.IntVar(&throughputSize, "throughput-size", benchmark.DefaultThroughputSize, "throughput frame size (bytes)")

	for _, name := range []string{"protocols", "throughput", "throughput-only"} {
		_ = cmd.RegisterFlagCompletionFunc(name, completeProtocol)
	}
	return cmd
}
