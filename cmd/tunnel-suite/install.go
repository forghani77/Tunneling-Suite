package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"tunnel-suite/internal/protocol"
)

// installCmd builds the `tunnel-suite install` subcommand, which writes a
// systemd unit for the server or for a persistent forwarding client and
// enables it. --dry-run prints everything without touching the system;
// --user installs into the per-user systemd scope; --uninstall removes the
// unit again.
func installCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install tunnel-suite as a systemd service (server or forwarding client)",
		Long: fmt.Sprintf(`Install tunnel-suite as a systemd service.

  tunnel-suite install server [flags]   install the server (with --forward)
  tunnel-suite install client [flags]   install a persistent forwarding client

The client install writes a unit that runs the tunnel endpoint at boot: pick
the tunnel protocol (any of the %d supported protocols), the mode ('forward'
for a fixed remote destination, 'socks' for a local SOCKS5 proxy) and the
local listen port.

System units need root; pass --user for a per-user service (no root, starts
at login). Add --dry-run to print the unit and commands without changing
anything. Add --name for a custom systemd unit name; --uninstall then only
needs that name.`, len(protocol.Names())),
	}
	cmd.AddCommand(installServerCmd())
	cmd.AddCommand(installClientCmd())
	return cmd
}

// unitNameRe validates service names (systemd allows [a-zA-Z0-9:_.-]).
var unitNameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

type installOpts struct {
	user      bool
	dryRun    bool
	uninstall bool
	name      string
	overall   string // "server" or "client"
}

// systemdPrefix returns the systemctl --user prefix when installing per-user.
func systemdPrefix(o installOpts) []string {
	if o.user {
		return []string{"--user"}
	}
	return nil
}

// unitPath returns the unit file path for the chosen scope.
func unitPath(o installOpts) (string, error) {
	dir := "/etc/systemd/system"
	if o.user {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", fmt.Errorf("cannot find your home directory (is $HOME set?)")
		}
		dir = filepath.Join(home, ".config", "systemd", "user")
	}
	if !o.dryRun {
		if _, err := exec.LookPath("systemctl"); err != nil {
			return "", fmt.Errorf("systemctl not found on PATH — is this a systemd host? (use --dry-run to just print the unit)")
		}
		if !o.user && os.Geteuid() != 0 {
			return "", fmt.Errorf("installing a system service needs root — rerun with sudo, or pass --user for a per-user service")
		}
	}
	return filepath.Join(dir, o.name+".service"), nil
}

// runSystemctl runs one systemctl invocation (dry-run prints it only).
func runSystemctl(o installOpts, args ...string) error {
	argv := append([]string{"systemctl"}, append(systemdPrefix(o), args...)...)
	fmt.Printf("$ %s\n", strings.Join(argv, " "))
	if o.dryRun {
		return nil
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// writeUnit writes (or with --dry-run, prints) the unit file and enables or
// disables the service.
func writeUnit(o installOpts, unit string) error {
	path, err := unitPath(o)
	if err != nil {
		return err
	}
	action := "install"
	if o.uninstall {
		action = "uninstall"
	}
	fmt.Printf("%s %s service %q\n", action, o.overall, o.name)

	if o.dryRun {
		fmt.Printf("\n--- would write %s ---\n", path)
		fmt.Print(unit)
		fmt.Println("--- would run ---")
		if o.uninstall {
			_ = runSystemctl(o, "disable", "--now", o.name+".service")
		} else {
			_ = runSystemctl(o, "daemon-reload")
			_ = runSystemctl(o, "enable", "--now", o.name+".service")
		}
		return nil
	}

	if o.uninstall {
		if err := runSystemctl(o, "disable", "--now", o.name+".service"); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
		if err := runSystemctl(o, "daemon-reload"); err != nil {
			return err
		}
		fmt.Printf("removed %s\n", path)
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("wrote %s\n", path)
	if err := runSystemctl(o, "daemon-reload"); err != nil {
		return err
	}
	if err := runSystemctl(o, "enable", "--now", o.name+".service"); err != nil {
		return err
	}
	fmt.Printf("%s service %q started and enabled\n", o.overall, o.name)
	return nil
}

// unitTemplate renders a systemd unit file.
func unitTemplate(desc, execStart string, user bool) string {
	wantedBy := "multi-user.target"
	if user {
		wantedBy = "default.target"
	}
	return fmt.Sprintf(`[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=5

[Install]
WantedBy=%s
`, desc, execStart, wantedBy)
}

// quoteArg wraps a value in double quotes when it contains characters systemd
// ExecStart would split on (spaces, tabs).
func quoteArg(s string) string {
	if strings.ContainsAny(s, " \t") {
		return `"` + s + `"`
	}
	return s
}

// serverExecArgs builds the ExecStart argv for the server from its flags.
// Used by `install server`.
func serverExecArgs(exe, listen string, basePort int, forward bool, protocols, password, ssPass, cert, key string) []string {
	args := []string{quoteArg(exe), "server",
		"--listen", quoteArg(listen),
		"--base-port", fmt.Sprintf("%d", basePort)}
	if forward {
		args = append(args, "--forward")
	}
	if protocols != "" {
		args = append(args, "--protocols", quoteArg(protocols))
	}
	if password != "" {
		args = append(args, "--password", quoteArg(password))
	}
	if ssPass != "" {
		args = append(args, "--ss-password", quoteArg(ssPass))
	}
	if cert != "" {
		args = append(args, "--cert", quoteArg(cert), "--key", quoteArg(key))
	}
	return args
}

// clientExecArgs builds the ExecStart argv for a forwarding client from its
// flags. Used by `install client`.
func clientExecArgs(exe, server string, basePort int, protocol, mode, bind string, localPort int, remoteHost string, remotePort int, password, ssPass string) []string {
	args := []string{quoteArg(exe), "client",
		"--server", quoteArg(server),
		"--base-port", fmt.Sprintf("%d", basePort),
		"--protocol", protocol,
		"--mode", mode,
		"--bind", quoteArg(bind),
		"--local-port", fmt.Sprintf("%d", localPort)}
	if mode == "forward" {
		args = append(args, "--remote-host", quoteArg(remoteHost), "--remote-port", fmt.Sprintf("%d", remotePort))
	}
	if password != "" {
		args = append(args, "--password", quoteArg(password))
	}
	if ssPass != "" {
		args = append(args, "--ss-password", quoteArg(ssPass))
	}
	return args
}

// validateClientInstall checks the forwarding-client install parameters,
// mirroring what the forwarding endpoint itself enforces at runtime: a
// supported tunnel protocol (any of the registered ones, aliases accepted),
// a tunnel mode and the local listen port.
func validateClientInstall(server, proto, mode string, localPort int, remoteHost string, remotePort int) error {
	if server == "" {
		return fmt.Errorf("-server is required (the tunnel-suite server running with -forward)")
	}
	if proto == "" {
		return fmt.Errorf("-protocol is required (the tunnel protocol)")
	}
	if _, ok := protocol.ByName(protocol.NormalizeName(proto)); !ok {
		return fmt.Errorf("unknown protocol %q (supported: %s)", proto, strings.Join(protocol.Names(), ", "))
	}
	if mode != "forward" && mode != "socks" {
		return fmt.Errorf("-mode must be 'forward' or 'socks' (tab-complete to pick one)")
	}
	if localPort == 0 {
		return fmt.Errorf("-local-port is required")
	}
	if mode == "forward" && (remoteHost == "" || remotePort == 0) {
		return fmt.Errorf("-mode forward requires -remote-host and -remote-port")
	}
	return nil
}

// validateServerProtocols checks a comma-separated --protocols value against
// the registry, so an install never writes a unit whose server fails to boot.
func validateServerProtocols(protocols string) error {
	for _, name := range splitCSV(protocols) {
		if _, ok := protocol.ByName(protocol.NormalizeName(name)); !ok {
			return fmt.Errorf("unknown protocol %q", name)
		}
	}
	return nil
}

func installServerCmd() *cobra.Command {
	var (
		o         installOpts
		listen    string
		basePort  int
		forward   bool
		password  string
		ssPass    string
		cert      string
		key       string
		protocols string
	)
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Install the tunnel-suite server as a systemd service",
		Example: `  sudo tunnel-suite install server --base-port 10000
  tunnel-suite install server --user --base-port 20000 --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.overall = "server"
			if !unitNameRe.MatchString(o.name) {
				return fmt.Errorf("invalid unit name %q", o.name)
			}
			if err := validateServerProtocols(protocols); err != nil {
				return err
			}
			exe, err := os.Executable()
			if err != nil || exe == "" {
				return fmt.Errorf("cannot determine the binary path (os.Executable)")
			}
			argsStr := serverExecArgs(exe, listen, basePort, forward, protocols, password, ssPass, cert, key)
			unit := unitTemplate("tunnel-suite server (test + forwarding server)",
				strings.Join(argsStr, " "), o.user)
			return writeUnit(o, unit)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&o.user, "user", false, "install a per-user service (no root, starts at login)")
	f.BoolVar(&o.dryRun, "dry-run", false, "print the unit and commands without changing anything")
	f.BoolVar(&o.uninstall, "uninstall", false, "remove the installed service")
	f.StringVar(&o.name, "name", "tunnel-suite-server", "systemd unit name")
	f.StringVar(&listen, "listen", "0.0.0.0", "address the server binds")
	f.IntVar(&basePort, "base-port", 10000, "base port for the server")
	f.BoolVar(&forward, "forward", true, "enable forwarding (relay) sessions on the server")
	f.StringVar(&protocols, "protocols", "", "comma-separated protocol subset to serve (default: all)")
	f.StringVar(&password, "password", "", "shared secret for anytls/naive/ipsec/l2tp")
	f.StringVar(&ssPass, "ss-password", "", "Shadowsocks password")
	f.StringVar(&cert, "cert", "", "TLS certificate file")
	f.StringVar(&key, "key", "", "TLS key file")
	_ = cmd.RegisterFlagCompletionFunc("protocols", completeProtocol)
	return cmd
}

func installClientCmd() *cobra.Command {
	var (
		o          installOpts
		server     string
		basePort   int
		protocol   string
		mode       string
		bind       string
		localPort  int
		remoteHost string
		remotePort int
		password   string
		ssPass     string
	)
	cmd := &cobra.Command{
		Use:   "client",
		Short: "Install a persistent forwarding client as a systemd service",
		Long: `Install a persistent forwarding client as a systemd service.

The service runs "tunnel-suite client --mode ..." at boot, carrying local TCP
connections through the chosen tunnel protocol to a server running with
--forward:

  --mode forward  forward --local-port to a fixed --remote-host:--remote-port
  --mode socks    run a local SOCKS5 proxy on --local-port

--uninstall only needs the unit name; the endpoint flags are not required to
remove the service again.`,
		Example: `  sudo tunnel-suite install client --server 203.0.113.10 --protocol tcp \
    --mode forward --local-port 8080 --remote-host 10.0.0.5 --remote-port 80
  tunnel-suite install client --server HOST --protocol udp --mode socks \
    --local-port 1080 --user`,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.overall = "client"
			if !unitNameRe.MatchString(o.name) {
				return fmt.Errorf("invalid unit name %q", o.name)
			}
			// --uninstall only needs the unit name: skip the endpoint flags.
			if !o.uninstall {
				if err := validateClientInstall(server, protocol, mode, localPort, remoteHost, remotePort); err != nil {
					return err
				}
			}
			exe, err := os.Executable()
			if err != nil || exe == "" {
				return fmt.Errorf("cannot determine the binary path (os.Executable)")
			}
			argsStr := clientExecArgs(exe, server, basePort, protocol, mode, bind, localPort, remoteHost, remotePort, password, ssPass)
			desc := fmt.Sprintf("tunnel-suite %s client (%s tunnel)", mode, protocol)
			if o.uninstall {
				// --uninstall ignores the unit content; render a clean one for
				// --dry-run instead of one full of empty flag values.
				argsStr = []string{quoteArg(exe), "client"}
				desc = "tunnel-suite client"
			}
			unit := unitTemplate(desc, strings.Join(argsStr, " "), o.user)
			return writeUnit(o, unit)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&o.user, "user", false, "install a per-user service (no root, starts at login)")
	f.BoolVar(&o.dryRun, "dry-run", false, "print the unit and commands without changing anything")
	f.BoolVar(&o.uninstall, "uninstall", false, "remove the installed service")
	f.StringVar(&o.name, "name", "tunnel-suite-client", "systemd unit name")
	f.StringVar(&server, "server", "", "server host or IP (required)")
	f.IntVar(&basePort, "base-port", 10000, "base port (must match server)")
	f.StringVar(&protocol, "protocol", "", "tunnel protocol, e.g. tcp, udp, ws (required)")
	f.StringVar(&mode, "mode", "", "forward or socks (required)")
	f.StringVar(&bind, "bind", "127.0.0.1", "local bind address")
	f.IntVar(&localPort, "local-port", 0, "local listen port (required)")
	f.StringVar(&remoteHost, "remote-host", "", "remote destination host (forward mode)")
	f.IntVar(&remotePort, "remote-port", 0, "remote destination port (forward mode)")
	f.StringVar(&password, "password", "", "shared secret for anytls/naive/ipsec/l2tp")
	f.StringVar(&ssPass, "ss-password", "", "Shadowsocks password")
	_ = cmd.RegisterFlagCompletionFunc("protocol", completeProtocol)
	_ = cmd.RegisterFlagCompletionFunc("mode", completeMode)
	return cmd
}
