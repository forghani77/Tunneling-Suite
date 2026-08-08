package main

import (
	"bytes"
	"strings"
	"testing"
)

// renderHelp renders the help output for the given subcommand path through
// the inherited (root-level) help func, returning the output.
func renderHelp(t *testing.T, path string) string {
	t.Helper()
	cmd, _, err := rootCmd.Find(strings.Fields(path))
	if err != nil {
		t.Fatalf("resolve %q: %v", path, err)
	}
	origOut := cmd.OutOrStdout()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	defer cmd.SetOut(origOut)
	cmd.HelpFunc()(cmd, nil)
	return buf.String()
}

// renderUsage renders the usage output (as shown on flag errors) for the
// given subcommand path, returning the output. Usage is routed through the
// command's OUT writer (cobra's OutOrStderr uses getOut), hence SetOut.
func renderUsage(t *testing.T, path string) string {
	t.Helper()
	cmd, _, err := rootCmd.Find(strings.Fields(path))
	if err != nil {
		t.Fatalf("resolve %q: %v", path, err)
	}
	origOut := cmd.OutOrStderr()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	defer cmd.SetOut(origOut)
	if err := cmd.UsageFunc()(cmd); err != nil {
		t.Fatalf("usage func: %v", err)
	}
	return buf.String()
}

func TestHelpRendersSingleDash(t *testing.T) {
	// Flags each command actually defines; the "install" command itself has
	// no flags (they live on its subcommands), so only the no-double-dash
	// assertion applies there.
	perCommandFlags := map[string][]string{
		"client":         {"-server", "-blind", "-protocols-base-port", "-control-port", "-local-port"},
		"server":         {"-listen", "-protocols-base-port", "-control-port", "-forward"},
		"install":        nil,
		"install client": {"-server", "-mode", "-local-port", "-uninstall"},
		"uninstall":      {"-user", "-dry-run"},
	}
	for path, flags := range perCommandFlags {
		t.Run(path, func(t *testing.T) {
			out := renderHelp(t, path)
			if strings.Contains(out, "--") {
				t.Errorf("help for %q still contains '--':\n%s", path, out)
			}
			for _, flag := range flags {
				if !strings.Contains(out, flag) {
					t.Errorf("help for %q missing %q:\n%s", path, flag, out)
				}
			}
		})
	}
}

func TestUsageRendersSingleDash(t *testing.T) {
	for _, path := range []string{"client", "server"} {
		t.Run(path, func(t *testing.T) {
			out := renderUsage(t, path)
			if strings.Contains(out, "--") {
				t.Errorf("usage for %q still contains '--':\n%s", path, out)
			}
			if !strings.Contains(out, "-protocols-base-port") {
				t.Errorf("usage for %q missing '-protocols-base-port':\n%s", path, out)
			}
		})
	}
}

func TestHelpIsRestorableOutput(t *testing.T) {
	// The override must not leak its buffer: after help the command's out
	// writer is restored (checked by renderHelp's defer) and the transformed
	// output is written to the caller's writer, with the Long text intact.
	out := renderHelp(t, "server")
	if !strings.Contains(out, "Listen for test sessions on every supported protocol.") {
		t.Errorf("help for server lost its Long text:\n%s", out)
	}
}
