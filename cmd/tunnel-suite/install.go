package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
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
	yes       bool
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

// unitDir returns the systemd unit directory for the chosen scope.
func unitDir(o installOpts) (string, error) {
	if !o.user {
		return "/etc/systemd/system", nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("cannot find your home directory (is $HOME set?)")
	}
	return filepath.Join(home, ".config", "systemd", "user"), nil
}

// unitPath returns the unit file path for the chosen scope.
func unitPath(o installOpts) (string, error) {
	dir, err := unitDir(o)
	if err != nil {
		return "", err
	}
	if err := requireSystemdEnv(o, "just print the unit"); err != nil {
		return "", err
	}
	return filepath.Join(dir, o.name+".service"), nil
}

// requireSystemdEnv verifies the host can manage systemd units in the chosen
// scope: systemctl must exist, and system services need root. dry-run mode
// never touches the system, so both checks are skipped there. dryRunHint
// explains what --dry-run offers instead ("just print the unit").
func requireSystemdEnv(o installOpts, dryRunHint string) error {
	if o.dryRun {
		return nil
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl not found on PATH — is this a systemd host? (use --dry-run to %s)", dryRunHint)
	}
	if !o.user && os.Geteuid() != 0 {
		return fmt.Errorf("this needs root for system services — rerun with sudo, or pass --user for per-user services")
	}
	return nil
}

// uninstallCmd builds the `tunnel-suite uninstall` subcommand, which removes
// tunnel-suite systemd services. With no arguments it removes every one it
// can find; with service names it removes exactly those. Discovery is by
// content: every unit written by `install` is self-identifying (its
// Description and ExecStart reference tunnel-suite), so a scan of the unit
// directory finds them all — default names, custom --name units, even a
// renamed binary. Units belonging to other software are never touched.
func uninstallCmd() *cobra.Command {
	var (
		user   bool
		dryRun bool
		yes    bool
	)
	cmd := &cobra.Command{
		Use:   "uninstall [name...]",
		Short: "Remove tunnel-suite systemd services",
		Long: `Remove tunnel-suite systemd services.

Scans the systemd unit directory (or, with --user, your per-user unit
directory) for unit files that reference tunnel-suite. With no service names
it removes them all: default names, custom --name units and renamed binaries
alike. With names it removes only those — each must be an installed
tunnel-suite service (tab-complete to pick from the installed ones); the
.service suffix is optional. Other services are never touched.

Every removal is confirmed first (the services to be removed are listed and
you answer y/N). Pass --yes to skip the prompt in scripts; add --dry-run to
list what would be removed without changing anything. When stdin is not a
terminal the command fails closed and asks for --yes instead of removing
anything unattended.`,
		Example: `  sudo tunnel-suite uninstall
  sudo tunnel-suite uninstall tunnel-suite-server my-custom-tunnel
  sudo tunnel-suite uninstall --yes
  tunnel-suite uninstall --user
  sudo tunnel-suite uninstall --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return uninstallAll(installOpts{user: user, dryRun: dryRun, yes: yes}, args)
		},
		// Tab-complete the names of the installed tunnel-suite services in
		// the requested scope, so `uninstall tunnel-s<TAB>` offers the units
		// this machine actually has.
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			dir, err := unitDir(installOpts{user: user})
			if err != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			installed, err := findTunnelSuiteUnits(dir)
			if err != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return completeInstalledUnits(installed, toComplete), cobra.ShellCompDirectiveNoFileComp
		},
	}
	f := cmd.Flags()
	f.BoolVar(&user, "user", false, "remove per-user tunnel-suite services (no root)")
	f.BoolVar(&dryRun, "dry-run", false, "list what would be removed without changing anything")
	f.BoolVarP(&yes, "yes", "y", false, "remove without confirmation (for scripts)")
	return cmd
}

// completeInstalledUnits filters the installed unit names by the token being
// completed, in a stable order.
func completeInstalledUnits(installed []string, toComplete string) []string {
	var out []string
	for _, n := range installed {
		if strings.HasPrefix(n, toComplete) {
			out = append(out, n)
		}
	}
	return out
}

// findTunnelSuiteUnits lists the unit names (without the .service suffix) in
// dir whose content references tunnel-suite — the marker every installed unit
// carries in its Description and ExecStart — sorted for stable output.
func findTunnelSuiteUnits(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".service") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			// Unreadable unit files — dangling symlinks and symlinked
			// directories are common in /etc/systemd/system — are not ours;
			// skip rather than abort the whole scan.
			continue
		}
		if bytes.Contains(b, []byte("tunnel-suite")) {
			names = append(names, strings.TrimSuffix(e.Name(), ".service"))
		}
	}
	sort.Strings(names)
	return names, nil
}

// uninstallAll removes the requested tunnel-suite services — every one found
// when no names are given, exactly those otherwise. A destructive removal is
// confirmed first (see confirm): it never runs unattended without --yes.
func uninstallAll(o installOpts, names []string) error {
	dir, units, err := resolveUninstallUnits(o, names)
	if err != nil {
		return err
	}
	if len(units) == 0 {
		fmt.Printf("no tunnel-suite systemd services installed in %s\n", dir)
		return nil
	}
	if err := confirm(o, units); err != nil {
		return err
	}
	// Only after confirmation: systemctl must exist, and removing system
	// services needs root (dry-run already passed through confirm, so the
	// checks are skipped there as before).
	if err := requireSystemdEnv(o, "just list the units"); err != nil {
		return err
	}
	return removeAllUnits(o, dir, units)
}

// resolveUninstallUnits resolves the unit directory for the chosen scope and
// the final list of units to remove: every tunnel-suite unit found, or — when
// names are given — exactly those, each validated against what is installed
// (the .service suffix is tolerated and duplicates collapse).
func resolveUninstallUnits(o installOpts, names []string) (string, []string, error) {
	dir, err := unitDir(o)
	if err != nil {
		return "", nil, err
	}
	units, err := resolveUninstallUnitsIn(dir, names)
	return dir, units, err
}

// resolveUninstallUnitsIn is resolveUninstallUnits against a known directory.
func resolveUninstallUnitsIn(dir string, names []string) ([]string, error) {
	installed, err := findTunnelSuiteUnits(dir)
	if err != nil {
		return nil, err
	}
	if len(names) > 0 {
		var want []string
		for _, n := range names {
			n = strings.TrimSuffix(n, ".service")
			if !slices.Contains(installed, n) {
				return nil, fmt.Errorf("no tunnel-suite service %q installed in %s%s", n, dir, installedHint(installed))
			}
			if !slices.Contains(want, n) {
				want = append(want, n)
			}
		}
		installed = want
	}
	return installed, nil
}

// removeAllUnits prints what will be removed and removes them.
func removeAllUnits(o installOpts, dir string, units []string) error {
	action := "uninstall"
	if o.dryRun {
		action = "would uninstall"
	}
	fmt.Printf("%s %d tunnel-suite service(s): %s\n", action, len(units), strings.Join(units, ", "))
	return removeUnits(o, dir, units)
}

// stdinReadLine and stdinIsTerminal are injectable for tests.
var (
	stdinReadLine   = func() (string, error) { return bufio.NewReader(os.Stdin).ReadString('\n') }
	stdinIsTerminal = func() bool {
		fi, err := os.Stdin.Stat()
		return err == nil && fi.Mode()&os.ModeCharDevice != 0
	}
)

// confirm asks the user to confirm a destructive removal. --dry-run (nothing
// would change) and --yes skip it. When stdin is not a terminal and no --yes
// was given, the run fails closed: an unattended removal must not proceed
// without explicit consent. Any answer other than y/yes aborts the run.
func confirm(o installOpts, units []string) error {
	if o.dryRun || o.yes {
		return nil
	}
	if !stdinIsTerminal() {
		return fmt.Errorf("stdin is not a terminal — pass --yes to remove %d service(s) without prompting", len(units))
	}
	fmt.Printf("Remove %d tunnel-suite service(s): %s? [y/N] ", len(units), strings.Join(units, ", "))
	line, err := stdinReadLine()
	if err != nil {
		return fmt.Errorf("no answer received — aborting (nothing removed)")
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	}
	return fmt.Errorf("aborted — nothing removed")
}

// installedHint renders the list of installed service names for an error
// message ("(installed: a, b)"), or an empty string when nothing is
// installed.
func installedHint(installed []string) string {
	if len(installed) == 0 {
		return ""
	}
	return " (installed: " + strings.Join(installed, ", ") + ")"
}

// removeUnits disables and deletes the given unit files, then reloads systemd
// once. With dry-run it prints the commands and leaves everything alone. A
// failure on one unit does not stop the others: every unit is attempted and
// all errors are reported together.
func removeUnits(o installOpts, dir string, names []string) error {
	var errs []error
	for _, name := range names {
		if err := runSystemctl(o, "disable", "--now", name+".service"); err != nil {
			errs = append(errs, fmt.Errorf("disable %s: %w", name, err))
			continue
		}
		if o.dryRun {
			continue
		}
		path := filepath.Join(dir, name+".service")
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove %s: %w", path, err))
			continue
		}
		fmt.Printf("removed %s\n", path)
	}
	if !o.dryRun {
		if err := runSystemctl(o, "daemon-reload"); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
// Used by `install server`. The control port is only written when set (the
// server's zero default is the protocols base port).
func serverExecArgs(exe, listen string, protocolsBasePort, controlPort, hysteria2Bandwidth int, forward bool, protocols, password, ssPass, cert, key string) []string {
	args := []string{quoteArg(exe), "server",
		"--listen", quoteArg(listen),
		"--protocols-base-port", fmt.Sprintf("%d", protocolsBasePort)}
	if controlPort != 0 {
		args = append(args, "--control-port", fmt.Sprintf("%d", controlPort))
	}
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
	if hysteria2Bandwidth > 0 {
		args = append(args, "--hysteria2-bandwidth", fmt.Sprintf("%d", hysteria2Bandwidth))
	}
	if cert != "" {
		args = append(args, "--cert", quoteArg(cert), "--key", quoteArg(key))
	}
	return args
}

// clientExecArgs builds the ExecStart argv for a forwarding client from its
// flags. Used by `install client`. The control port is only written when set:
// it makes the client discover the tunnel port from the server's manifest
// instead of computing protocols-base-port + offset.
func clientExecArgs(exe, server string, protocolsBasePort, controlPort, hysteria2Bandwidth int, protocol, mode, bind string, localPort int, remoteHost string, remotePort int, password, ssPass string) []string {
	args := []string{quoteArg(exe), "client",
		"--server", quoteArg(server),
		"--protocols-base-port", fmt.Sprintf("%d", protocolsBasePort)}
	if controlPort != 0 {
		args = append(args, "--control-port", fmt.Sprintf("%d", controlPort))
	}
	args = append(args,
		"--tunnel-protocol", protocol,
		"--mode", mode,
		"--bind", quoteArg(bind),
		"--local-port", fmt.Sprintf("%d", localPort))
	if mode == "forward" {
		args = append(args, "--remote-host", quoteArg(remoteHost), "--remote-port", fmt.Sprintf("%d", remotePort))
	}
	if password != "" {
		args = append(args, "--password", quoteArg(password))
	}
	if ssPass != "" {
		args = append(args, "--ss-password", quoteArg(ssPass))
	}
	if hysteria2Bandwidth > 0 {
		args = append(args, "--hysteria2-bandwidth", fmt.Sprintf("%d", hysteria2Bandwidth))
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
		return fmt.Errorf("-tunnel-protocol is required (the tunnel protocol)")
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
		o                 installOpts
		listen            string
		protocolsBasePort int
		controlPort       int
		forward           bool
		password          string
		ssPass            string
		hy2Bandwidth      int
		cert              string
		key               string
		protocols         string
	)
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Install the tunnel-suite server as a systemd service",
		Example: `  sudo tunnel-suite install server --protocols-base-port 10000
  tunnel-suite install server --user --protocols-base-port 20000 --dry-run
  sudo tunnel-suite install server --protocols-base-port 30000 --control-port 10000`,
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
			argsStr := serverExecArgs(exe, listen, protocolsBasePort, controlPort, hy2Bandwidth, forward, protocols, password, ssPass, cert, key)
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
	f.IntVar(&protocolsBasePort, "protocols-base-port", 10000, "base port for protocol listeners")
	f.IntVar(&controlPort, "control-port", 0, "control/manifest port (default: the protocols base port)")
	f.BoolVar(&forward, "forward", true, "enable forwarding (relay) sessions on the server")
	f.StringVar(&protocols, "protocols", "", "comma-separated protocol subset to serve (default: all)")
	f.StringVar(&password, "password", "", "shared secret for anytls/naive/ipsec/l2tp/noise/trojan/shadowtls/hysteria2")
	f.StringVar(&ssPass, "ss-password", "", "Shadowsocks password")
	f.IntVar(&hy2Bandwidth, "hysteria2-bandwidth", 0, "fixed Brutal send rate for hysteria2 in Mbps (0 = adaptive BBR)")
	f.StringVar(&cert, "cert", "", "TLS certificate file")
	f.StringVar(&key, "key", "", "TLS key file")
	_ = cmd.RegisterFlagCompletionFunc("protocols", completeProtocol)
	return cmd
}

func installClientCmd() *cobra.Command {
	var (
		o                 installOpts
		server            string
		protocolsBasePort int
		controlPort       int
		protocol          string
		mode              string
		bind              string
		localPort         int
		remoteHost        string
		remotePort        int
		password          string
		ssPass            string
		hy2Bandwidth      int
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

Add --control-port to discover the tunnel port from the server's manifest
instead of computing --protocols-base-port + offset — handy when the server's
layout was configured differently (e.g. its own --control-port).

--uninstall only needs the unit name; the endpoint flags are not required to
remove the service again.`,
		Example: `  sudo tunnel-suite install client --server 203.0.113.10 --tunnel-protocol tcp \
    --mode forward --local-port 8080 --remote-host 10.0.0.5 --remote-port 80
  tunnel-suite install client --server HOST --tunnel-protocol udp --mode socks \
    --local-port 1080 --user
  sudo tunnel-suite install client --server HOST --tunnel-protocol smtp \
    --protocols-base-port 11580 --control-port 11606 --mode forward \
    --local-port 2060 --remote-host 127.0.0.1 --remote-port 11612`,
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
			argsStr := clientExecArgs(exe, server, protocolsBasePort, controlPort, hy2Bandwidth, protocol, mode, bind, localPort, remoteHost, remotePort, password, ssPass)
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
	f.IntVar(&protocolsBasePort, "protocols-base-port", 10000, "protocols base port (must match server)")
	f.IntVar(&controlPort, "control-port", 0, "server control/manifest port; when set, the tunnel port is discovered from the manifest instead of protocols-base-port + offset")
	f.StringVar(&protocol, "tunnel-protocol", "", "tunnel protocol, e.g. tcp, udp, ws (required)")
	f.StringVar(&mode, "mode", "", "forward or socks (required)")
	f.StringVar(&bind, "bind", "127.0.0.1", "local bind address")
	f.IntVar(&localPort, "local-port", 0, "local listen port (required)")
	f.StringVar(&remoteHost, "remote-host", "", "remote destination host (forward mode)")
	f.IntVar(&remotePort, "remote-port", 0, "remote destination port (forward mode)")
	f.StringVar(&password, "password", "", "shared secret for anytls/naive/ipsec/l2tp/noise/trojan/shadowtls/hysteria2")
	f.StringVar(&ssPass, "ss-password", "", "Shadowsocks password")
	f.IntVar(&hy2Bandwidth, "hysteria2-bandwidth", 0, "fixed Brutal send rate for hysteria2 in Mbps (0 = adaptive BBR)")
	_ = cmd.RegisterFlagCompletionFunc("tunnel-protocol", completeProtocol)
	_ = cmd.RegisterFlagCompletionFunc("mode", completeMode)
	return cmd
}
