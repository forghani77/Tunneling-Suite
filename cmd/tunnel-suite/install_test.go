package main

import (
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

