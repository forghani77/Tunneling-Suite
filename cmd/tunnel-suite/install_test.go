package main

import (
	"io"
	"os"
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
		name                               string
		listen                             string
		basePort                           int
		forward                            bool
		protocols, password, ss, cert, key string
		want                               string
	}{{
		name:     "defaults with relay on",
		listen:   "0.0.0.0",
		basePort: 10000,
		forward:  true,
		want:     "/opt/bin/tunnel-suite server --listen 0.0.0.0 --base-port 10000 --forward",
	},
		{
			name:     "relay off omits --forward",
			forward:  false,
			listen:   "127.0.0.1",
			basePort: 20000,
			want:     "/opt/bin/tunnel-suite server --listen 127.0.0.1 --base-port 20000",
		},
		{
			name:      "protocols and secrets",
			forward:   true,
			listen:    "127.0.0.1",
			basePort:  20000,
			protocols: "tcp,udp",
			password:  "s3cret",
			ss:        "ss-pass",
			want:      "/opt/bin/tunnel-suite server --listen 127.0.0.1 --base-port 20000 --forward --protocols tcp,udp --password s3cret --ss-password ss-pass",
		},
		{
			name:     "cert/key pair",
			listen:   "0.0.0.0",
			basePort: 10000,
			forward:  true,
			cert:     "/etc/tls/server.crt",
			key:      "/etc/tls/server.key",
			want:     "/opt/bin/tunnel-suite server --listen 0.0.0.0 --base-port 10000 --forward --cert /etc/tls/server.crt --key /etc/tls/server.key",
		},
		{
			name:     "quoted values",
			listen:   "0.0.0.0",
			basePort: 10000,
			forward:  true,
			password: "with space",
			want:     `/opt/bin/tunnel-suite server --listen 0.0.0.0 --base-port 10000 --forward --password "with space"`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(serverExecArgs("/opt/bin/tunnel-suite", c.listen, c.basePort, c.forward, c.protocols, c.password, c.ss, c.cert, c.key), " ")
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
		basePort             int
		protocol, mode, bind string
		localPort            int
		remoteHost           string
		remotePort           int
		password, ss         string
		want                 string
	}{
		{
			name:       "forward mode",
			server:     "203.0.113.10",
			basePort:   10000,
			protocol:   "tcp",
			mode:       "forward",
			bind:       "127.0.0.1",
			localPort:  8080,
			remoteHost: "10.0.0.5",
			remotePort: 80,
			want:       "/opt/bin/tunnel-suite client --server 203.0.113.10 --base-port 10000 --protocol tcp --mode forward --bind 127.0.0.1 --local-port 8080 --remote-host 10.0.0.5 --remote-port 80",
		},
		{
			name:      "socks mode omits remote flags",
			server:    "HOST",
			basePort:  10000,
			protocol:  "udp",
			mode:      "socks",
			bind:      "127.0.0.1",
			localPort: 1080,
			want:      "/opt/bin/tunnel-suite client --server HOST --base-port 10000 --protocol udp --mode socks --bind 127.0.0.1 --local-port 1080",
		},
		{
			name:      "secrets and quoted server",
			server:    "my host",
			basePort:  10000,
			protocol:  "ws",
			mode:      "socks",
			bind:      "127.0.0.1",
			localPort: 1080,
			password:  "p w",
			ss:        "ss",
			want:      `/opt/bin/tunnel-suite client --server "my host" --base-port 10000 --protocol ws --mode socks --bind 127.0.0.1 --local-port 1080 --password "p w" --ss-password ss`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(clientExecArgs("/opt/bin/tunnel-suite", c.server, c.basePort, c.protocol, c.mode, c.bind, c.localPort, c.remoteHost, c.remotePort, c.password, c.ss), " ")
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

// captureStdout runs fn with os.Stdout swapped for a pipe and returns what
// was written. Needed because writeUnit/runSystemctl print via fmt.Printf
// (to the process stdout), not through cmd.SetOut.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = old
		_ = w.Close()
	}()
	fn()
	_ = w.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestServerInstallRunE exercises the install-mode branch of `server` via
// --dry-run, which prints the unit without touching the system: the default
// relay-on behavior (matching `install server`), explicit --forward=false,
// and flag-free --uninstall.
func TestServerInstallRunE(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		wantHas    []string
		wantNotHas []string
	}{
		{
			name:    "install defaults relay on",
			args:    []string{"--install", "--dry-run"},
			wantHas: []string{"install server service", "ExecStart=", " --forward"},
		},
		{
			name:       "install with relay explicitly off",
			args:       []string{"--install", "--dry-run", "--forward=false"},
			wantHas:    []string{"install server service", "ExecStart=", "--listen 0.0.0.0 --base-port 10000"},
			wantNotHas: []string{" --forward"},
		},
		{
			name:    "install carries flags into the unit",
			args:    []string{"--install", "--dry-run", "--listen", "127.0.0.1", "--base-port", "20000", "--protocols", "tcp,udp"},
			wantHas: []string{"ExecStart=", "--listen 127.0.0.1", "--base-port 20000", "--protocols tcp,udp"},
		},
		{
			name:    "uninstall needs no flags",
			args:    []string{"--uninstall", "--dry-run"},
			wantHas: []string{"uninstall server service", "systemctl disable"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := serverCmd()
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			cmd.SetArgs(c.args)
			out := captureStdout(t, func() {
				if err := cmd.Execute(); err != nil {
					t.Errorf("Execute() error = %v", err)
				}
			})
			for _, s := range c.wantHas {
				if !strings.Contains(out, s) {
					t.Errorf("output missing %q:\n%s", s, out)
				}
			}
			for _, s := range c.wantNotHas {
				if strings.Contains(out, s) {
					t.Errorf("output must not contain %q:\n%s", s, out)
				}
			}
		})
	}
}

// TestClientInstallRunE exercises the install-mode branch of `client` via
// --dry-run: required endpoint flags are validated, validation errors are
// returned, and --uninstall works without re-supplying any flags.
func TestClientInstallRunE(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantHas []string
		wantErr bool
	}{
		{
			name:    "forward install",
			args:    []string{"--server", "H", "--protocol", "tcp", "--mode", "forward", "--local-port", "8080", "--remote-host", "10.0.0.5", "--remote-port", "80", "--install", "--dry-run"},
			wantHas: []string{"install client service", "ExecStart=", "--protocol tcp --mode forward --bind 127.0.0.1 --local-port 8080 --remote-host 10.0.0.5 --remote-port 80"},
		},
		{
			name:    "socks install",
			args:    []string{"--server", "H", "--protocol", "udp", "--mode", "socks", "--local-port", "1080", "--install", "--dry-run"},
			wantHas: []string{"ExecStart=", "--protocol udp --mode socks --bind 127.0.0.1 --local-port 1080"},
		},
		{
			name:    "missing protocol errors",
			args:    []string{"--server", "H", "--install", "--dry-run"},
			wantErr: true,
		},
		{
			name:    "missing server errors",
			args:    []string{"--protocol", "tcp", "--mode", "socks", "--local-port", "1080", "--install", "--dry-run"},
			wantErr: true,
		},
		{
			name:    "unknown protocol errors",
			args:    []string{"--server", "H", "--protocol", "bogus", "--mode", "socks", "--local-port", "1080", "--install", "--dry-run"},
			wantErr: true,
		},
		{
			name:    "forward mode without remote port errors",
			args:    []string{"--server", "H", "--protocol", "tcp", "--mode", "forward", "--local-port", "8080", "--remote-host", "10.0.0.5", "--install", "--dry-run"},
			wantErr: true,
		},
		{
			name:    "uninstall without server works",
			args:    []string{"--uninstall", "--dry-run"},
			wantHas: []string{"uninstall client service", "systemctl disable"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := clientCmd()
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			cmd.SetArgs(c.args)
			var execErr error
			out := captureStdout(t, func() {
				execErr = cmd.Execute()
			})
			if (execErr != nil) != c.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", execErr, c.wantErr)
			}
			for _, s := range c.wantHas {
				if !strings.Contains(out, s) {
					t.Errorf("output missing %q:\n%s", s, out)
				}
			}
		})
	}
}
