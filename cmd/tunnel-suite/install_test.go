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
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(serverExecArgs("/opt/bin/tunnel-suite", c.listen, c.protocolsBasePort, c.controlPort, c.forward, c.protocols, c.password, c.ss, c.cert, c.key), " ")
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
		protocol, mode, bind string
		localPort            int
		remoteHost           string
		remotePort           int
		password, ss         string
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
			want:              "/opt/bin/tunnel-suite client --server 203.0.113.10 --protocols-base-port 10000 --protocol tcp --mode forward --bind 127.0.0.1 --local-port 8080 --remote-host 10.0.0.5 --remote-port 80",
		},
		{
			name:              "socks mode omits remote flags",
			server:            "HOST",
			protocolsBasePort: 10000,
			protocol:          "udp",
			mode:              "socks",
			bind:              "127.0.0.1",
			localPort:         1080,
			want:              "/opt/bin/tunnel-suite client --server HOST --protocols-base-port 10000 --protocol udp --mode socks --bind 127.0.0.1 --local-port 1080",
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
			want:              `/opt/bin/tunnel-suite client --server "my host" --protocols-base-port 10000 --protocol ws --mode socks --bind 127.0.0.1 --local-port 1080 --password "p w" --ss-password ss`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(clientExecArgs("/opt/bin/tunnel-suite", c.server, c.protocolsBasePort, c.protocol, c.mode, c.bind, c.localPort, c.remoteHost, c.remotePort, c.password, c.ss), " ")
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

func TestUninstallAllInNames(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(dir, name+".service"), []byte("Description=tunnel-suite\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("tunnel-suite-server")
	write("my-custom-tunnel")
	write("renamed-bin")

	// Dry-run with a specific name lists only that unit; the .service suffix
	// is tolerated and duplicates collapse.
	var runErr error
	out := captureStdout(func() {
		runErr = uninstallAllIn(installOpts{dryRun: true}, dir, []string{"my-custom-tunnel.service", "my-custom-tunnel"})
	})
	if runErr != nil {
		t.Fatalf("uninstallAllIn: %v", runErr)
	}
	if !strings.Contains(out, "would uninstall 1 tunnel-suite service(s): my-custom-tunnel") {
		t.Errorf("dry-run output wrong:\n%s", out)
	}

	// An unknown name is rejected with a hint listing what is installed.
	err := uninstallAllIn(installOpts{dryRun: true}, dir, []string{"nope"})
	if err == nil || !strings.Contains(err.Error(), "no tunnel-suite service \"nope\" installed") || !strings.Contains(err.Error(), "installed: ") {
		t.Errorf("unknown-name error = %v, want a hint about installed services", err)
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
