package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// resolveCmd resolves a space-separated subcommand path ("" = root).
func resolveCmd(t *testing.T, path string) *cobra.Command {
	t.Helper()
	if path == "" {
		return rootCmd
	}
	cmd, _, err := rootCmd.Find(strings.Fields(path))
	if err != nil {
		t.Fatalf("resolve %q: %v", path, err)
	}
	return cmd
}

func TestNormalizeSingleDash(t *testing.T) {
	cases := []struct {
		name string
		path string // subcommand path whose flags apply, e.g. "client"
		args []string
		want []string
	}{
		{
			name: "client flags",
			path: "client",
			args: []string{"client", "-server", "H", "-protocol", "tcp", "-mode", "forward", "-local-port", "8080"},
			want: []string{"client", "--server", "H", "--protocol", "tcp", "--mode", "forward", "--local-port", "8080"},
		},
		{
			name: "server flags",
			path: "server",
			args: []string{"server", "-listen", "127.0.0.1", "-forward"},
			want: []string{"server", "--listen", "127.0.0.1", "--forward"},
		},
		{
			name: "equals form",
			path: "client",
			args: []string{"client", "-protocol=tcp", "-protocols-base-port=20000"},
			want: []string{"client", "--protocol=tcp", "--protocols-base-port=20000"},
		},
		{
			name: "double dash untouched",
			path: "client",
			args: []string{"client", "--server", "H", "--json"},
			want: []string{"client", "--server", "H", "--json"},
		},
		{
			name: "short help flag untouched",
			path: "client",
			args: []string{"client", "-h"},
			want: []string{"client", "-h"},
		},
		{
			name: "values that look like flags untouched",
			path: "client",
			args: []string{"client", "--gap-ms", "-0.5", "--pings", "-5"},
			want: []string{"client", "--gap-ms", "-0.5", "--pings", "-5"},
		},
		{
			name: "install subcommand flags",
			path: "install client",
			args: []string{"install", "client", "-uninstall", "-dry-run"},
			want: []string{"install", "client", "--uninstall", "--dry-run"},
		},
		{
			name: "install client endpoint flags",
			path: "install client",
			args: []string{"install", "client", "-server", "H", "-protocol", "tcp"},
			want: []string{"install", "client", "--server", "H", "--protocol", "tcp"},
		},
		{
			name: "unknown single-dash token untouched",
			path: "client",
			args: []string{"client", "-bogus", "x"},
			want: []string{"client", "-bogus", "x"},
		},
		{
			name: "value after double-dash flag is protected",
			path: "client",
			args: []string{"client", "--password", "-blind", "--blind"},
			want: []string{"client", "--password", "-blind", "--blind"},
		},
		{
			name: "value after single-dash flag is protected",
			path: "client",
			args: []string{"client", "-server", "-blind"},
			want: []string{"client", "--server", "-blind"},
		},
		{
			name: "equals form needs no value token",
			path: "client",
			args: []string{"client", "-server=H", "-blind"},
			want: []string{"client", "--server=H", "--blind"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := normalizeSingleDash(c.args, resolveCmd(t, c.path), false)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got  %v\nwant %v", got, c.want)
			}
		})
	}
}

// TestNormalizeSingleDashPrefix exercises the completion path (prefixMatch),
// where a single-dash token that prefixes a known flag is rewritten too.
func TestNormalizeSingleDashPrefix(t *testing.T) {
	cases := []struct {
		name string
		path string
		args []string
		want []string
	}{
		{
			name: "partial flag rewritten in completion",
			path: "client",
			args: []string{"__complete", "client", "-pr", ""},
			want: []string{"__complete", "client", "--pr", ""},
		},
		{
			name: "exact flag still rewritten and value protected",
			path: "client",
			args: []string{"__complete", "client", "-server", "-"},
			want: []string{"__complete", "client", "--server", "-"},
		},
		{
			name: "unknown token untouched even in completion",
			path: "client",
			args: []string{"__complete", "client", "-zzz", ""},
			want: []string{"__complete", "client", "-zzz", ""},
		},
		{
			name: "short completed arg untouched (token is the empty arg)",
			path: "client",
			args: []string{"__complete", "client", "-h", ""},
			want: []string{"__complete", "client", "-h", ""},
		},
		{
			name: "1-char prefix token rewritten so long flags complete",
			path: "client",
			args: []string{"__complete", "client", "-p"},
			want: []string{"__complete", "client", "--p"},
		},
		{
			name: "2-char value token untouched",
			path: "client",
			args: []string{"__complete", "client", "-1", ""},
			want: []string{"__complete", "client", "-1", ""},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := normalizeSingleDash(c.args, resolveCmd(t, c.path), true)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got  %v\nwant %v", got, c.want)
			}
		})
	}
}

func TestNormalizeArgs(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want []string
	}{
		{
			name: "client invocation",
			argv: []string{"tunnel-suite", "client", "-server", "H", "-protocol", "tcp"},
			want: []string{"tunnel-suite", "client", "--server", "H", "--protocol", "tcp"},
		},
		{
			name: "server invocation",
			argv: []string{"tunnel-suite", "server", "-listen", "127.0.0.1", "-forward"},
			want: []string{"tunnel-suite", "server", "--listen", "127.0.0.1", "--forward"},
		},
		{
			name: "bare invocation untouched",
			argv: []string{"tunnel-suite"},
			want: []string{"tunnel-suite"},
		},
		{
			name: "completion request resolves the command being completed",
			argv: []string{"tunnel-suite", "__complete", "client", "-protocol", ""},
			want: []string{"tunnel-suite", "__complete", "client", "--protocol", ""},
		},
		{
			name: "completion partial token rewritten to enable flag completion",
			argv: []string{"tunnel-suite", "__complete", "client", "-pro", ""},
			want: []string{"tunnel-suite", "__complete", "client", "--pro", ""},
		},
		{
			name: "completion nested subcommand path",
			argv: []string{"tunnel-suite", "__complete", "install", "client", "-server", ""},
			want: []string{"tunnel-suite", "__complete", "install", "client", "--server", ""},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := normalizeArgs(c.argv)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got  %v\nwant %v", got, c.want)
			}
		})
	}
}
