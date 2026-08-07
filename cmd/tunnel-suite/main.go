// Command tunnel-suite is a tunneling-protocol test harness.
//
// The server and client are the same binary; run one of each on the machines
// you want to test connectivity between.
//
// The CLI is built on Cobra, so every subcommand supports --help and shell
// autocomplete ("tunnel-suite completion bash", then source the output).
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

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
	// The token being completed, if this is a shell completion request — must
	// be captured before normalizeArgs rewrites it, so the completion output
	// can be rendered in the same dash style the user typed.
	token := completionToken(os.Args)
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
	// Single-dash long flags: rewrite -install → --install (and friends) so
	// pflag accepts them; the previous flag package used single dashes, and
	// some users still write them. Double-dash flags keep working as usual.
	os.Args = normalizeArgs(os.Args)
	if token != "" {
		// Shell completion: render flag candidates in the dash style the user
		// typed (-ins<TAB> offers -install; --ins<TAB> keeps offering
		// --install), then exit without the normal error handling.
		if err := runCompletion(token, os.Stdout); err != nil {
			os.Exit(1)
		}
		return
	}
	if err := rootCmd.Execute(); err != nil {
		if err != errSilent {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

// completionToken reports the token a shell completion request is completing
// (the last argument of a __complete / __completeNoDesc invocation), or ""
// for ordinary invocations. Only argv[1] is considered the completion
// command, matching how the shell scripts invoke it ("tunnel-suite
// __complete <cmd-line>"), so a flag value that happens to be the string
// "__complete" is never mistaken for a completion request.
func completionToken(argv []string) string {
	if len(argv) >= 3 && (argv[1] == cobra.ShellCompRequestCmd || argv[1] == cobra.ShellCompNoDescRequestCmd) {
		return argv[len(argv)-1]
	}
	return ""
}

// runCompletion services a shell completion request. cobra always renders
// flag candidates as "--flag"; rewriteCompletionFlags switches them to the
// single-dash style when the token being completed uses one, so tab
// completion offers the same style the user is typing. The completion output
// (candidates + ":<directive>") goes to w; cobra's diagnostic line goes to
// stderr, which the shell scripts ignore.
func runCompletion(token string, w io.Writer) error {
	prevOut := rootCmd.OutOrStdout()
	defer rootCmd.SetOut(prevOut)
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	err := rootCmd.Execute()
	if _, werr := w.Write(rewriteCompletionFlags(out.Bytes(), singleDashToken(token))); werr != nil && err == nil {
		err = werr
	}
	return err
}

// singleDashToken reports whether the token being completed uses the
// single-dash style ("-", "-ins"): it starts with a dash but not with "--".
func singleDashToken(token string) bool {
	return len(token) > 0 && token[0] == '-' && (len(token) == 1 || token[1] != '-')
}

// rewriteCompletionFlags converts flag candidates in a completion response to
// the single-dash style ("--install" → "-install") when the user is
// completing a single-dash token. Shells filter candidates against the typed
// token (bash's compgen -W ... -- "$cur", zsh's _describe prefix matching)
// or insert them verbatim (fish), so candidates must carry the same dash
// style the user typed: -ins<TAB> must offer -install, and --ins<TAB> must
// keep offering --install. Each candidate is a line; the trailing
// ":<directive>" line and non-flag candidates (commands, protocol names,
// values) never start with "--" and pass through unchanged.
func rewriteCompletionFlags(b []byte, singleDash bool) []byte {
	if !singleDash {
		return b
	}
	lines := bytes.SplitAfter(b, []byte("\n"))
	out := make([]byte, 0, len(b))
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("--")) {
			out = append(out, '-')
			out = append(out, line[2:]...)
			continue
		}
		out = append(out, line...)
	}
	return out
}

// normalizeArgs rewrites single-dash long flags into their double-dash form
// for the invoked command (and its subcommands), so "-install", "-server H"
// and "-protocol=tcp" work exactly like their "--" equivalents. pflag reads
// a single dash as shorthand clusters, so a bare "-install" would otherwise
// be rejected as an unknown shorthand. Tokens are rewritten only when the
// text after "-" matches a known flag name, which leaves flag values alone
// (e.g. "-0.5", "-1"). Double-dash flags keep working as usual.
func normalizeArgs(argv []string) []string {
	if len(argv) < 2 {
		return argv
	}
	rest := argv[1:]
	target := rootCmd
	prefixMatch := false
	// Cobra's completion requests (__complete / __completeNoDesc) are hidden
	// commands cobra registers only at Execute time, so detect them by name
	// and resolve the command being completed from the following argument.
	if rest[0] == cobra.ShellCompRequestCmd || rest[0] == cobra.ShellCompNoDescRequestCmd {
		prefixMatch = true
		if len(rest) >= 2 {
			if c, _, err := rootCmd.Find(rest[1:]); err == nil && c != nil {
				target = c
			}
		}
	} else if c, _, err := rootCmd.Find(rest); err == nil && c != nil {
		target = c
	}
	out := append([]string(nil), argv[:1]...)
	out = append(out, normalizeSingleDash(rest, target, prefixMatch)...)
	return out
}

// normalizeSingleDash rewrites "-<flag>" tokens of cmd (or any of its
// subcommands) to "--<flag>"; everything else is passed through unchanged.
// The token right after a value-taking flag is that flag's value and is never
// rewritten (so "--password -install" keeps "-install" as the password).
// With prefixMatch (used for cobra's completion requests) a single-dash token
// that prefixes a known flag name is rewritten too, so "-pr<TAB>" completes
// like "--protocol".
func normalizeSingleDash(args []string, cmd *cobra.Command, prefixMatch bool) []string {
	known := knownFlagNames(cmd)
	valueFlags := flagTakesValue(cmd)
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		// len(a) > 2: ordinary long flags. In completion mode a 2-char token
		// like "-p" is also rewritten (cobra only completes long flag names
		// for "--"-prefixed tokens, so "-p<TAB>" would otherwise find
		// nothing) — but only when it is the token being completed (the last
		// argument), never a completed argument like "-h " in "-h ''".
		last := i == len(args)-1
		if len(a) >= 2 && a[0] == '-' && a[1] != '-' && (len(a) > 2 || (prefixMatch && last)) {
			name := a[1:]
			eq := strings.IndexByte(name, '=')
			if eq >= 0 {
				name = name[:eq]
			}
			if known[name] || (prefixMatch && name != "" && flagNameHasPrefix(known, name)) {
				out = append(out, "--"+name+strings.TrimPrefix(a, "-"+name))
				if eq < 0 && valueFlags[name] && i+1 < len(args) {
					// This flag consumes the next token as its value.
					i++
					out = append(out, args[i])
				}
				continue
			}
		} else if len(a) > 2 && strings.HasPrefix(a, "--") {
			// Double-dash value-taking flag: protect its value token from
			// single-dash rewriting (e.g. "--password -install").
			name := a[2:]
			eq := strings.IndexByte(name, '=')
			if eq >= 0 {
				name = name[:eq]
			}
			if eq < 0 && known[name] && valueFlags[name] && i+1 < len(args) {
				out = append(out, a)
				i++
				out = append(out, args[i])
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

// knownFlagNames returns every flag name defined on cmd and all its
// subcommands, recursively (local and inherited persistent flags), so the
// single-dash rewriter knows which tokens are flags.
func knownFlagNames(cmd *cobra.Command) map[string]bool {
	names := make(map[string]bool)
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if c == nil {
			return
		}
		c.Flags().VisitAll(func(f *pflag.Flag) { names[f.Name] = true })
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(cmd)
	return names
}

// flagTakesValue reports, per flag name, whether the flag consumes a separate
// value token. pflag leaves NoOptDefVal empty on value-taking flags and sets
// it on booleans (and optional-value flags like --throughput-only), so
// NoOptDefVal == "" is the value-taking test.
func flagTakesValue(cmd *cobra.Command) map[string]bool {
	out := make(map[string]bool)
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if c == nil {
			return
		}
		c.Flags().VisitAll(func(f *pflag.Flag) { out[f.Name] = f.NoOptDefVal == "" })
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(cmd)
	return out
}

// flagNameHasPrefix reports whether any known flag name starts with prefix.
func flagNameHasPrefix(known map[string]bool, prefix string) bool {
	for name := range known {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
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

// completeMode tab-completes the forwarding-mode values for --mode.
func completeMode(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var out []string
	for _, m := range []string{"forward", "socks"} {
		if strings.HasPrefix(m, toComplete) {
			out = append(out, m)
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
	rootCmd.AddCommand(installCmd())
	// Render help/usage with single-dash long flags (-install, -server H),
	// matching the input style the CLI accepts (--flag stays valid too).
	installSingleDashHelp(rootCmd)
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
		forward   bool

		// Install mode: write a systemd unit for this command line and exit
		// (the full-featured form is `tunnel-suite install server`).
		install   bool
		uninstall bool
		user      bool
		dryRun    bool
	)
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Listen for tunneling tests on every supported protocol",
		Long: `Listen for test sessions on every supported protocol.

Binds the control port at --base-port plus one port per protocol. The client
discovers the offered protocols from the manifest. Pass --protocols to serve
a subset, and keep --password / --ss-password in sync with the client for the
protocols that share a secret (ipsec, l2tp, anytls, naive, shadowsocks).

Relay is on by default: the server also relays real TCP traffic for
"tunnel-suite client --mode forward|socks" (echo testing keeps working). Pass
-forward=false to run a pure test/echo server. Add --install to instead write
a systemd unit for this command line and start it.`,
		Example: `  tunnel-suite server --listen 0.0.0.0 --base-port 10000
  tunnel-suite server --protocols tcp,udp,vxlan,kcp --base-port 20000
  tunnel-suite server --forward --install`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Install mode: build the unit from the very flags on this command
			// line (minus --install) and let writeUnit handle --user / --dry-run
			// / --uninstall, then exit without running.
			if install || uninstall {
				o := installOpts{user: user, dryRun: dryRun, uninstall: uninstall, name: "tunnel-suite-server", overall: "server"}
				if err := validateServerProtocols(protocols); err != nil {
					return err
				}
				// Installed servers enable relay by default, matching
				// `install server`; --forward=false opts out explicitly.
				fwd := true
				if cmd.Flags().Changed("forward") {
					fwd = forward
				}
				exe, err := os.Executable()
				if err != nil || exe == "" {
					return fmt.Errorf("cannot determine the binary path (os.Executable)")
				}
				argsStr := serverExecArgs(exe, listen, basePort, fwd, protocols, password, ssPass, cert, key)
				unit := unitTemplate("tunnel-suite server (test + forwarding server)", strings.Join(argsStr, " "), user)
				return writeUnit(o, unit)
			}
			return server.Run(server.Config{
				Listen:      listen,
				BasePort:    basePort,
				Protocols:   splitCSV(protocols),
				TLSCertFile: cert,
				TLSKeyFile:  key,
				SSPassword:  ssPass,
				Password:    password,
				Forward:     forward,
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
	f.BoolVar(&forward, "forward", true, "enable relay sessions for 'tunnel-suite client --mode forward|socks' (on by default; -forward=false disables)")
	f.BoolVar(&install, "install", false, "write a systemd unit for this command line, enable it and exit (needs root unless --user; the installed server enables relay by default)")
	f.BoolVar(&uninstall, "uninstall", false, "stop and remove the installed systemd unit for this command")
	f.BoolVar(&user, "user", false, "with --install/--uninstall: use the per-user systemd scope (no root, starts at login)")
	f.BoolVar(&dryRun, "dry-run", false, "with --install/--uninstall: print the unit and commands without changing anything")
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

		// Forwarding mode (tunnel-suite client --mode ...): instead of running
		// the benchmark, the client becomes a persistent tunnel endpoint.
		fwdMode       string
		fwdBind       string
		fwdLocalPort  int
		fwdRemoteHost string
		fwdRemotePort int
		fwdProtocol   string

		// Install mode: write a systemd unit for the forwarding endpoint and
		// exit (the full-featured form is `tunnel-suite install client`).
		install   bool
		uninstall bool
		user      bool
		dryRun    bool
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
bare --throughput-only reuses the --throughput list.

With --mode the client becomes a persistent tunnel endpoint instead of
running the benchmark (see --mode forward|socks). Add --install to write a
systemd unit for the endpoint and start it at boot.`,
		Example: `  tunnel-suite client --server 203.0.113.10 --base-port 10000
  tunnel-suite client --server 203.0.113.10 --protocols tcp,tls,quic --pings 100
  tunnel-suite client --server 203.0.113.10 --throughput tcp,udp,kcp --throughput-time 10
  tunnel-suite client --server 203.0.113.10 --throughput-only vxlan-gpe --throughput-size 1400
  tunnel-suite client --server HOST --protocol tcp --mode forward \
    --local-port 8080 --remote-host 10.0.0.5 --remote-port 80 --install`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Install mode: build the unit from the very forwarding flags on
			// this command line (minus --install) and let writeUnit handle
			// --user / --dry-run / --uninstall, then exit without running.
			// Runs before the --server check so `client --uninstall` works
			// without re-supplying any endpoint flags.
			if install || uninstall {
				o := installOpts{user: user, dryRun: dryRun, uninstall: uninstall, name: "tunnel-suite-client", overall: "client"}
				if !uninstall {
					if err := validateClientInstall(serverHost, fwdProtocol, fwdMode, fwdLocalPort, fwdRemoteHost, fwdRemotePort); err != nil {
						fmt.Fprintln(os.Stderr, "error:", err)
						_ = cmd.Usage()
						return errSilent
					}
				}
				exe, err := os.Executable()
				if err != nil || exe == "" {
					return fmt.Errorf("cannot determine the binary path (os.Executable)")
				}
				argsStr := clientExecArgs(exe, serverHost, basePort, fwdProtocol, fwdMode, fwdBind, fwdLocalPort, fwdRemoteHost, fwdRemotePort, password, ssPass)
				desc := "tunnel-suite client"
				if !uninstall {
					desc = fmt.Sprintf("tunnel-suite %s client (%s tunnel)", fwdMode, fwdProtocol)
				} else {
					// --uninstall ignores the unit content; render a clean one for
					// --dry-run instead of one full of empty flag values.
					argsStr = []string{quoteArg(exe), "client"}
				}
				unit := unitTemplate(desc, strings.Join(argsStr, " "), user)
				return writeUnit(o, unit)
			}
			// Forwarding mode: the client becomes a tunnel endpoint (port
			// forward or SOCKS5 proxy) instead of running the benchmark.
			if fwdMode != "" {
				if fwdProtocol == "" {
					fmt.Fprintln(os.Stderr, "error: -protocol is required in forward mode (the tunnel protocol, e.g. -protocol anytls)")
					_ = cmd.Usage()
					return errSilent
				}
				if serverHost == "" {
					fmt.Fprintln(os.Stderr, "error: -server is required (the tunnel-suite server running with -forward)")
					_ = cmd.Usage()
					return errSilent
				}
				return client.RunForward(client.ForwardConfig{
					Server:     serverHost,
					BasePort:   basePort,
					Protocol:   fwdProtocol,
					Password:   password,
					SSPassword: ssPass,
					Mode:       fwdMode,
					Bind:       fwdBind,
					LocalPort:  fwdLocalPort,
					RemoteHost: fwdRemoteHost,
					RemotePort: fwdRemotePort,
				})
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

			if serverHost == "" {
				fmt.Fprintln(os.Stderr, "error: -server is required (the tunnel-suite server host or IP)")
				_ = cmd.Usage()
				return errSilent
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
	f.Float64Var(&throughputSec, "throughput-time", 5, "throughput test duration (s)")
	f.IntVar(&throughputSize, "throughput-size", benchmark.DefaultThroughputSize, "throughput frame size (bytes)")

	// Forwarding mode flags (used when --mode is set; the client then runs a
	// persistent tunnel endpoint instead of the benchmark).
	f.StringVar(&fwdMode, "mode", "", "forwarding mode: 'forward' (fixed remote target) or 'socks' (local SOCKS5 proxy); setting it runs the client as a persistent tunnel endpoint")
	f.StringVar(&fwdProtocol, "protocol", "", "tunnel protocol for forwarding mode (e.g. tcp, udp, ws, ...)")
	f.StringVar(&fwdBind, "bind", "127.0.0.1", "local bind address for forwarding mode")
	f.IntVar(&fwdLocalPort, "local-port", 0, "local listen port for forwarding mode")
	f.StringVar(&fwdRemoteHost, "remote-host", "", "remote destination host for 'forward' mode")
	f.IntVar(&fwdRemotePort, "remote-port", 0, "remote destination port for 'forward' mode")

	// Install mode flags (used with --install; the endpoint then runs as a
	// systemd service instead of in the foreground).
	f.BoolVar(&install, "install", false, "write a systemd unit for this forwarding endpoint, enable it and exit (needs root unless --user)")
	f.BoolVar(&uninstall, "uninstall", false, "stop and remove the installed systemd unit for this command")
	f.BoolVar(&user, "user", false, "with --install/--uninstall: use the per-user systemd scope (no root, starts at login)")
	f.BoolVar(&dryRun, "dry-run", false, "with --install/--uninstall: print the unit and commands without changing anything")

	for _, name := range []string{"protocols", "throughput", "throughput-only"} {
		_ = cmd.RegisterFlagCompletionFunc(name, completeProtocol)
	}
	_ = cmd.RegisterFlagCompletionFunc("protocol", completeProtocol)
	_ = cmd.RegisterFlagCompletionFunc("mode", completeMode)
	return cmd
}
