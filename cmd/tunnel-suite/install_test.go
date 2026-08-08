package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQuoteArg(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"plain", "plain"},
		{"127.0.0.1", "127.0.0.1"},
		{"hello world", `"hello world"`},
		{"a\tb", `"a	b"`},
	}
	for _, c := range cases {
		if got := quoteArg(c.in); got != c.want {
			t.Errorf("quoteArg(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestServerExecArgs(t *testing.T) {
	cases := []struct {
		name                string
		listen              string
		protocolsBasePort   int
		controlPort         int
		forward             bool
		protocols, password string
		ss, cert, key       string
		hy2Bw               int
		want                string
	}{{
		name:              "defaults with relay on",
		listen:            "0.0.0.0",
		protocolsBasePort: 10000,
		forward:           true,
		want:              "/opt/bin/tunnel-suite server --listen 0.0.0.0 --protocols-base-port 10000 --forward",
	},
		{
			name:              "relay off omits --forward",
			forward:           false,
			listen:            "127.0.0.1",
			protocolsBasePort: 20000,
			want:              "/opt/bin/tunnel-suite server --listen 127.0.0.1 --protocols-base-port 20000",
		},
		{
			name:              "protocols and secrets",
			forward:           true,
			listen:            "127.0.0.1",
			protocolsBasePort: 20000,
			protocols:         "tcp,udp",
			password:          "s3cret",
			ss:                "ss-pass",
			want:              "/opt/bin/tunnel-suite server --listen 127.0.0.1 --protocols-base-port 20000 --forward --protocols tcp,udp --password s3cret --ss-password ss-pass",
		},
		{
			name:              "distinct control port",
			listen:            "0.0.0.0",
			protocolsBasePort: 30000,
			controlPort:       10000,
			forward:           true,
			want:              "/opt/bin/tunnel-suite server --listen 0.0.0.0 --protocols-base-port 30000 --control-port 10000 --forward",
		},
		{
			name:              "cert/key pair",
			listen:            "0.0.0.0",
			protocolsBasePort: 10000,
			forward:           true,
			cert:              "/etc/tls/server.crt",
			key:               "/etc/tls/server.key",
			want:              "/opt/bin/tunnel-suite server --listen 0.0.0.0 --protocols-base-port 10000 --forward --cert /etc/tls/server.crt --key /etc/tls/server.key",
		},
		{
			name:              "quoted values",
			listen:            "0.0.0.0",
			protocolsBasePort: 10000,
			forward:           true,
			password:          "with space",
			want:              `/opt/bin/tunnel-suite server --listen 0.0.0.0 --protocols-base-port 10000 --forward --password "with space"`,
		},
		{
			name:              "hysteria2 bandwidth cap",
			listen:            "0.0.0.0",
			protocolsBasePort: 10000,
			forward:           true,
			hy2Bw:             500,
			want:              "/opt/bin/tunnel-suite server --listen 0.0.0.0 --protocols-base-port 10000 --forward --hysteria2-bandwidth 500",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(serverExecArgs("/opt/bin/tunnel-suite", c.listen, c.protocolsBasePort, c.controlPort, c.hy2Bw, c.forward, c.protocols, c.password, c.ss, c.cert, c.key), " ")
			if got != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}

func TestClientExecArgs(t *testing.T) {
	cases := []struct {
		name                 string
		server               string
		protocolsBasePort    int
		controlPort          int
		protocol, mode, bind string
		localPort            int
		remoteHost           string
		remotePort           int
		password, ss         string
		hy2Bw                int
		want                 string
	}{
		{
			name:              "forward mode",
			server:            "203.0.113.10",
			protocolsBasePort: 10000,
			protocol:          "tcp",
			mode:              "forward",
			bind:              "127.0.0.1",
			localPort:         8080,
			remoteHost:        "10.0.0.5",
			remotePort:        80,
			want:              "/opt/bin/tunnel-suite client --server 203.0.113.10 --protocols-base-port 10000 --tunnel-protocol tcp --mode forward --bind 127.0.0.1 --local-port 8080 --remote-host 10.0.0.5 --remote-port 80",
		},
		{
			name:              "socks mode omits remote flags",
			server:            "HOST",
			protocolsBasePort: 10000,
			protocol:          "udp",
			mode:              "socks",
			bind:              "127.0.0.1",
			localPort:         1080,
			want:              "/opt/bin/tunnel-suite client --server HOST --protocols-base-port 10000 --tunnel-protocol udp --mode socks --bind 127.0.0.1 --local-port 1080",
		},
		{
			name:              "secrets and quoted server",
			server:            "my host",
			protocolsBasePort: 10000,
			protocol:          "ws",
			mode:              "socks",
			bind:              "127.0.0.1",
			localPort:         1080,
			password:          "p w",
			ss:                "ss",
			want:              `/opt/bin/tunnel-suite client --server "my host" --protocols-base-port 10000 --tunnel-protocol ws --mode socks --bind 127.0.0.1 --local-port 1080 --password "p w" --ss-password ss`,
		},
		{
			name:              "control port discovers tunnel port",
			server:            "HOST",
			protocolsBasePort: 11580,
			controlPort:       11606,
			protocol:          "smtp",
			mode:              "forward",
			bind:              "0.0.0.0",
			localPort:         2060,
			remoteHost:        "127.0.0.1",
			remotePort:        11612,
			want:              "/opt/bin/tunnel-suite client --server HOST --protocols-base-port 11580 --control-port 11606 --tunnel-protocol smtp --mode forward --bind 0.0.0.0 --local-port 2060 --remote-host 127.0.0.1 --remote-port 11612",
		},
		{
			name:              "hysteria2 brutal rate",
			server:            "HOST",
			protocolsBasePort: 10000,
			protocol:          "hysteria2",
			mode:              "socks",
			bind:              "127.0.0.1",
			localPort:         1080,
			hy2Bw:             300,
			want:              "/opt/bin/tunnel-suite client --server HOST --protocols-base-port 10000 --tunnel-protocol hysteria2 --mode socks --bind 127.0.0.1 --local-port 1080 --hysteria2-bandwidth 300",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(clientExecArgs("/opt/bin/tunnel-suite", c.server, c.protocolsBasePort, c.controlPort, c.hy2Bw, c.protocol, c.mode, c.bind, c.localPort, c.remoteHost, c.remotePort, c.password, c.ss), " ")
			if got != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}

func TestValidateClientInstall(t *testing.T) {
	cases := []struct {
		name                string
		server, proto, mode string
		localPort           int
		remoteHost          string
		remotePort          int
		wantErr             bool
	}{
		{name: "missing server", mode: "socks", localPort: 1080, proto: "tcp", wantErr: true},
		{name: "missing protocol", server: "H", mode: "socks", localPort: 1080, wantErr: true},
		{name: "unknown protocol", server: "H", proto: "bogus", mode: "socks", localPort: 1080, wantErr: true},
		{name: "alias protocol", server: "H", proto: "awg", mode: "socks", localPort: 1080},
		{name: "missing mode", server: "H", proto: "tcp", localPort: 1080, wantErr: true},
		{name: "bad mode", server: "H", proto: "tcp", mode: "banana", localPort: 1080, wantErr: true},
		{name: "missing local port", server: "H", proto: "tcp", mode: "socks", wantErr: true},
		{name: "forward missing remote host", server: "H", proto: "tcp", mode: "forward", localPort: 8080, remotePort: 80, wantErr: true},
		{name: "forward missing remote port", server: "H", proto: "tcp", mode: "forward", localPort: 8080, remoteHost: "10.0.0.5", wantErr: true},
		{name: "valid forward", server: "H", proto: "tcp", mode: "forward", localPort: 8080, remoteHost: "10.0.0.5", remotePort: 80},
		{name: "valid socks", server: "H", proto: "udp", mode: "socks", localPort: 1080},
		{name: "datagram protocol valid", server: "H", proto: "vxlan-gpe", mode: "socks", localPort: 1080},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateClientInstall(c.server, c.proto, c.mode, c.localPort, c.remoteHost, c.remotePort)
			if (err != nil) != c.wantErr {
				t.Errorf("validateClientInstall() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestValidateServerProtocols(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{in: ""},
		{in: "tcp,udp"},
		{in: "tcp, vxlan-gpe"},
		{in: "awg,awg2"}, // aliases resolve
		{in: "tcp,bogus", wantErr: true},
		{in: "bogus", wantErr: true},
	}
	for _, c := range cases {
		err := validateServerProtocols(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("validateServerProtocols(%q) error = %v, wantErr %v", c.in, err, c.wantErr)
		}
	}
	// splitCSV trims whitespace, so padded lists are fine.
	if err := validateServerProtocols(" tcp , udp "); err != nil {
		t.Errorf("validateServerProtocols padded list: %v", err)
	}
}

func TestFindTunnelSuiteUnits(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Two self-identifying units (default + custom --name) and one unit that
	// belongs to other software and must never be touched.
	write("tunnel-suite-server.service", "[Unit]\nDescription=tunnel-suite server (test + forwarding server)\nExecStart=/opt/bin/tunnel-suite server --forward\n")
	write("my-custom-tunnel.service", "[Unit]\nDescription=tunnel-suite client (ws tunnel)\nExecStart=/opt/bin/tunnel-suite client --mode socks\n")
	write("backhaul-kharej1234.service", "[Unit]\nDescription=backhaul tunnel\nExecStart=/opt/backhaul/backhaul\n")
	write("unrelated.service", "[Unit]\nDescription=asset monitor\nExecStart=/usr/bin/assetmonitor\n")
	// A renamed binary is still found: the Description marker stays.
	write("renamed-bin.service", "[Unit]\nDescription=tunnel-suite server\nExecStart=/opt/ts/server\n")

	got, err := findTunnelSuiteUnits(dir)
	if err != nil {
		t.Fatalf("findTunnelSuiteUnits: %v", err)
	}
	want := []string{"my-custom-tunnel", "renamed-bin", "tunnel-suite-server"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("found %v, want %v", got, want)
	}

	// A missing directory is not an error — nothing installed.
	none, err := findTunnelSuiteUnits(filepath.Join(t.TempDir(), "nope"))
	if err != nil || none != nil {
		t.Errorf("missing dir: units = %v, err = %v, want nil, nil", none, err)
	}
}

func TestFindTunnelSuiteUnitsSkipsDanglingSymlinks(t *testing.T) {
	// /etc/systemd/system is full of dangling symlinks (units pointing at
	// not-yet-installed files); the scan must skip them, not abort.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tunnel-suite-server.service"), []byte("tunnel-suite"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "gone.service"), filepath.Join(dir, "dangling.service")); err != nil {
		t.Fatal(err)
	}

	got, err := findTunnelSuiteUnits(dir)
	if err != nil {
		t.Fatalf("findTunnelSuiteUnits with dangling symlink: %v", err)
	}
	if len(got) != 1 || got[0] != "tunnel-suite-server" {
		t.Errorf("units = %v, want just [tunnel-suite-server]", got)
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what
// was written, restoring the original stdout afterwards.
func captureStdout(fn func()) string {
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	w.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}

func TestResolveUninstallUnitsIn(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(dir, name+".service"), []byte("Description=tunnel-suite\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("tunnel-suite-server")
	write("my-custom-tunnel")
	write("renamed-bin")

	// No names: every tunnel-suite unit, sorted; other services untouched.
	if err := os.WriteFile(filepath.Join(dir, "backhaul.service"), []byte("Description=backhaul\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	units, err := resolveUninstallUnitsIn(dir, nil)
	if err != nil {
		t.Fatalf("resolve all: %v", err)
	}
	if strings.Join(units, ",") != "my-custom-tunnel,renamed-bin,tunnel-suite-server" {
		t.Errorf("all units = %v", units)
	}

	// Named with .service suffix tolerated and duplicates collapsed.
	units, err = resolveUninstallUnitsIn(dir, []string{"my-custom-tunnel.service", "my-custom-tunnel"})
	if err != nil {
		t.Fatalf("resolve named: %v", err)
	}
	if strings.Join(units, ",") != "my-custom-tunnel" {
		t.Errorf("named units = %v", units)
	}

	// An unknown name is rejected with a hint listing what is installed.
	_, err = resolveUninstallUnitsIn(dir, []string{"nope"})
	if err == nil || !strings.Contains(err.Error(), "no tunnel-suite service \"nope\" installed") || !strings.Contains(err.Error(), "installed: ") {
		t.Errorf("unknown-name error = %v, want a hint about installed services", err)
	}
}

func TestRemoveAllUnitsDryRun(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tunnel-suite-server.service"), []byte("tunnel-suite"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(func() {
		if err := removeAllUnits(installOpts{dryRun: true}, dir, []string{"tunnel-suite-server"}); err != nil {
			t.Fatalf("removeAllUnits dry-run: %v", err)
		}
	})
	if !strings.Contains(out, "would uninstall 1 tunnel-suite service(s): tunnel-suite-server") ||
		!strings.Contains(out, "systemctl disable --now tunnel-suite-server.service") {
		t.Errorf("dry-run output wrong:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "tunnel-suite-server.service")); err != nil {
		t.Errorf("dry-run removed the unit file: %v", err)
	}
}

func TestConfirm(t *testing.T) {
	origRead, origTTY := stdinReadLine, stdinIsTerminal
	defer func() { stdinReadLine, stdinIsTerminal = origRead, origTTY }()

	// --dry-run and --yes skip the prompt entirely.
	if err := confirm(installOpts{dryRun: true}, []string{"a"}); err != nil {
		t.Errorf("dry-run confirm: %v", err)
	}
	if err := confirm(installOpts{yes: true}, []string{"a"}); err != nil {
		t.Errorf("--yes confirm: %v", err)
	}

	// Non-terminal stdin without --yes fails closed instead of removing
	// something unattended.
	stdinIsTerminal = func() bool { return false }
	if err := confirm(installOpts{}, []string{"a"}); err == nil || !strings.Contains(err.Error(), "not a terminal") {
		t.Errorf("non-terminal confirm error = %v, want a 'not a terminal' hint", err)
	}

	// Interactive: y/yes (any case) proceed; anything else and EOF abort.
	stdinIsTerminal = func() bool { return true }
	for _, yes := range []string{"y\n", "yes\n", "Y\n"} {
		stdinReadLine = func() (string, error) { return yes, nil }
		if err := confirm(installOpts{}, []string{"a"}); err != nil {
			t.Errorf("answer %q: %v", yes, err)
		}
	}
	for _, no := range []string{"n\n", "\n", "maybe\n"} {
		stdinReadLine = func() (string, error) { return no, nil }
		if err := confirm(installOpts{}, []string{"a"}); err == nil {
			t.Errorf("answer %q should abort", no)
		}
	}
	stdinReadLine = func() (string, error) { return "", io.EOF }
	if err := confirm(installOpts{}, []string{"a"}); err == nil {
		t.Error("EOF should abort")
	}
}

func TestCompleteInstalledUnits(t *testing.T) {
	installed := []string{"my-custom-tunnel", "renamed-bin", "tunnel-suite-server"}
	cases := []struct {
		prefix string
		want   []string
	}{
		{"", []string{"my-custom-tunnel", "renamed-bin", "tunnel-suite-server"}},
		{"tunnel-s", []string{"tunnel-suite-server"}},
		{"my-", []string{"my-custom-tunnel"}},
		{"zzz", nil},
	}
	for _, c := range cases {
		got := completeInstalledUnits(installed, c.prefix)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("completeInstalledUnits(%q) = %v, want %v", c.prefix, got, c.want)
		}
	}
}

func TestInstalledHint(t *testing.T) {
	if got := installedHint(nil); got != "" {
		t.Errorf("installedHint(nil) = %q, want empty", got)
	}
	if got := installedHint([]string{"a", "b"}); got != " (installed: a, b)" {
		t.Errorf("installedHint([a b]) = %q", got)
	}
}

func TestRemoveUnitsDryRun(t *testing.T) {
	dir := t.TempDir()
	name := "tunnel-suite-server"
	path := filepath.Join(dir, name+".service")
	if err := os.WriteFile(path, []byte("tunnel-suite"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Dry-run prints the disable command and leaves the file alone.
	var runErr error
	out := captureStdout(func() {
		runErr = removeUnits(installOpts{user: true, dryRun: true}, dir, []string{name})
	})
	if runErr != nil {
		t.Fatalf("removeUnits dry-run: %v", runErr)
	}
	if !strings.Contains(out, "systemctl --user disable --now tunnel-suite-server.service") {
		t.Errorf("dry-run output missing the systemctl command:\n%s", out)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("dry-run removed the unit file: %v", err)
	}
}

func TestUnitTemplate(t *testing.T) {
	sys := unitTemplate("tunnel-suite server (test + forwarding server)", "/opt/bin/tunnel-suite server --forward", false)
	for _, want := range []string{
		"Description=tunnel-suite server (test + forwarding server)",
		"ExecStart=/opt/bin/tunnel-suite server --forward",
		"After=network-online.target",
		"Wants=network-online.target",
		"Type=simple",
		"Restart=always",
		"RestartSec=5",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(sys, want) {
			t.Errorf("system unit missing %q:\n%s", want, sys)
		}
	}
	usr := unitTemplate("tunnel-suite socks client (udp tunnel)", "/opt/bin/tunnel-suite client --mode socks", true)
	for _, want := range []string{
		"ExecStart=/opt/bin/tunnel-suite client --mode socks",
		"After=network-online.target",
		"WantedBy=default.target",
	} {
		if !strings.Contains(usr, want) {
			t.Errorf("user unit missing %q:\n%s", want, usr)
		}
	}
}
