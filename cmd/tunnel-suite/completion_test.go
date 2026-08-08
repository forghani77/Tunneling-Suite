package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompletionToken(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "completion request", argv: []string{"tunnel-suite", "__complete", "client", "-pr"}, want: "-pr"},
		{name: "no-desc completion request", argv: []string{"tunnel-suite", "__completeNoDesc", "server", "-for"}, want: "-for"},
		{name: "completion with trailing empty arg", argv: []string{"tunnel-suite", "__complete", "client", "-pr", ""}, want: ""},
		{name: "bare completion request with no args", argv: []string{"tunnel-suite", "__complete"}, want: ""},
		{name: "ordinary invocation", argv: []string{"tunnel-suite", "client", "-server", "H"}, want: ""},
		{name: "flag value named like the completion cmd", argv: []string{"tunnel-suite", "client", "-password", "__complete"}, want: ""},
		{name: "bare invocation", argv: []string{"tunnel-suite"}, want: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := completionToken(c.argv); got != c.want {
				t.Errorf("completionToken(%v) = %q, want %q", c.argv, got, c.want)
			}
		})
	}
}

func TestRewriteCompletionFlags(t *testing.T) {
	const resp = "--server\tvalue\n--blind\tbool flag\ntcp\tstream protocol\n:4\n"
	cases := []struct {
		name  string
		input string
		sd    bool
		want  string
	}{
		{
			name:  "single-dash token rewrites flag candidates only",
			input: resp,
			sd:    true,
			want:  "-server\tvalue\n-blind\tbool flag\ntcp\tstream protocol\n:4\n",
		},
		{
			name:  "double-dash token leaves output untouched",
			input: resp,
			sd:    false,
			want:  resp,
		},
		{
			name:  "no trailing newline still rewritten",
			input: "--server",
			sd:    true,
			want:  "-server",
		},
		{
			name:  "empty input",
			input: "",
			sd:    true,
			want:  "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := string(rewriteCompletionFlags([]byte(c.input), c.sd)); got != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}

// TestBashCompletionHasFallbacks verifies the generated bash script is
// self-contained: cobra's script calls _get_comp_words_by_ref and _filedir
// from the external bash-completion package unconditionally, so on systems
// without that package completion fails with "command not found". The fallback
// definitions are injected right after the header, guarded so the real package
// still wins when present.
func TestBashCompletionHasFallbacks(t *testing.T) {
	var buf bytes.Buffer
	if err := genCompletionScript(rootCmd, "bash", &buf); err != nil {
		t.Fatalf("genCompletionScript(bash) error = %v", err)
	}
	out := buf.String()
	// The fallback block must be present, guarded, and placed before any use.
	if !strings.Contains(out, "if ! declare -F _get_comp_words_by_ref >/dev/null 2>&1; then") {
		t.Error("bash script missing guarded _get_comp_words_by_ref fallback")
	}
	if !strings.Contains(out, "if ! declare -F _filedir >/dev/null 2>&1; then") {
		t.Error("bash script missing guarded _filedir fallback")
	}
	fallbackPos := strings.Index(out, "if ! declare -F _get_comp_words_by_ref")
	usePos := strings.Index(out, `_get_comp_words_by_ref "$@" cur prev words cword`)
	if fallbackPos < 0 || usePos < 0 || fallbackPos > usePos {
		t.Errorf("fallback must be defined before its use (fallback %d, use %d)", fallbackPos, usePos)
	}
}

// TestRunCompletion exercises the full completion path the way main() runs it:
// argv normalized (single-dash token → --form so cobra's flag completion
// matches), then execute the hidden __complete command with stdout captured,
// then the output rewrite applied. A single-dash token must yield single-dash
// candidates; a double-dash token must keep the double-dash candidates.
func TestRunCompletion(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		wantHas string
		wantNot string
	}{
		{name: "single dash token offers single dash", argv: []string{"tunnel-suite", "__complete", "client", "-pr"}, wantHas: "-protocol\t", wantNot: "--protocol\t"},
		{name: "double dash token keeps double dash", argv: []string{"tunnel-suite", "__complete", "client", "--pr"}, wantHas: "--protocol\t", wantNot: "-protocol\t"},
		{name: "single dash forward flag", argv: []string{"tunnel-suite", "__complete", "server", "-for"}, wantHas: "-forward\t", wantNot: "--forward\t"},
		{name: "bare single dash offers every flag single-dash", argv: []string{"tunnel-suite", "__complete", "client", "-"}, wantHas: "-base-port\t", wantNot: "--base-port\t"},
		{name: "no-desc request also single-dash", argv: []string{"tunnel-suite", "__completeNoDesc", "client", "-pr"}, wantHas: "-protocol", wantNot: "--protocol"},
		{name: "throughput-only completes protocol values", argv: []string{"tunnel-suite", "__complete", "client", "-throughput-only", "any"}, wantHas: "anytls"},
		{name: "throughput-only = form completes protocol values", argv: []string{"tunnel-suite", "__complete", "client", "-throughput-only=gr"}, wantHas: "gre"},
		{name: "mode completes forward and socks", argv: []string{"tunnel-suite", "__complete", "client", "-mode", "f"}, wantHas: "forward"},
		{name: "protocol completes protocol values", argv: []string{"tunnel-suite", "__complete", "client", "-protocol", "qu"}, wantHas: "quic"},
	}
	// Silence cobra's "Completion ended with directive" stderr diagnostic.
	prevErr := rootCmd.ErrOrStderr()
	rootCmd.SetErr(io.Discard)
	defer rootCmd.SetErr(prevErr)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			argv := normalizeArgs(c.argv)
			rootCmd.SetArgs(argv[1:])
			defer rootCmd.SetArgs(nil)
			var buf bytes.Buffer
			if err := runCompletion(c.argv[len(c.argv)-1], &buf); err != nil {
				t.Fatalf("runCompletion() error = %v", err)
			}
			out := buf.String()
			// Check per candidate line: -protocol must not match the line
			// --protocol\t... (a plain substring check would false-positive).
			lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
			found, bad := false, false
			for _, l := range lines {
				if c.wantHas != "" && strings.HasPrefix(l, c.wantHas) {
					found = true
				}
				if c.wantNot != "" && strings.HasPrefix(l, c.wantNot) {
					bad = true
				}
			}
			if c.wantHas != "" && !found {
				t.Errorf("output missing candidate %q:\n%s", c.wantHas, out)
			}
			if bad {
				t.Errorf("output must not contain candidate %q:\n%s", c.wantNot, out)
			}
		})
	}
}

// TestRenameCompletionName verifies that generated scripts register completion
// under the running executable's basename rather than the compiled-in command
// name. cobra hardcodes the "Use" name (tunnel-suite) in the registration
// line, so a binary installed as e.g. "tunnel-suit" would otherwise get no
// completion for the name the user actually types.
func TestRenameCompletionName(t *testing.T) {
	const script = "#compdef tunnel-suite\ncompdef _tunnel-suite tunnel-suite\ncomplete -o default -F __start_tunnel-suite tunnel-suite\n"
	cases := []struct {
		name    string
		oldName string
		newName string
		want    string
	}{
		{name: "renamed binary registers new name", oldName: "tunnel-suite", newName: "tunnel-suit", want: "#compdef tunnel-suit\ncompdef _tunnel-suit tunnel-suit\ncomplete -o default -F __start_tunnel-suit tunnel-suit\n"},
		{name: "no-op when name matches", oldName: "tunnel-suite", newName: "tunnel-suite", want: script},
		{name: "no-op when new name empty", oldName: "tunnel-suite", newName: "", want: script},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := renameCompletionName(script, c.oldName, c.newName); got != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}

// TestGenCompletionScriptRegistersExecName builds the real binary name into
// the completion: renameCompletionCmd substitutes the running executable's
// basename for the compiled-in command name in every generated shell script.
func TestGenCompletionScriptRegistersExecName(t *testing.T) {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		t.Skip("cannot determine test binary name")
	}
	base := filepath.Base(exe)
	// The registration line must reference the actual binary basename, not the
	// compiled-in name. (The basename contains "tunnel-suite" as a substring
	// for the .test binary, so match the full registration line instead.)
	wantLines := []string{
		"complete -o default -F __start_" + base + " " + base,
		"#compdef " + base,
		"complete -c " + base,
		"-CommandName '" + base + "'",
	}
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			var buf bytes.Buffer
			if err := genCompletionScript(rootCmd, shell, &buf); err != nil {
				t.Fatalf("genCompletionScript(%s) error = %v", shell, err)
			}
			out := buf.String()
			// The exact registration marker per shell, e.g. the bash
			// "complete -F __start_<base> <base>" line.
			if !strings.Contains(out, wantLines[map[string]int{"bash": 0, "zsh": 1, "fish": 2, "powershell": 3}[shell]]) {
				t.Errorf("generated %s script does not register %q:\n%s", shell, base, out[:200])
			}
		})
	}
}
