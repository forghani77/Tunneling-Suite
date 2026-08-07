package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// completionCmd replaces cobra's built-in completion command: besides
// generating the script for a shell (tunnel-suite completion <shell>), it
// offers "install", which detects the current shell and appends the source
// line to the shell's rc file (~/.bashrc, ~/.zshrc, fish config, PowerShell
// profile) so autocomplete just works in every new shell.
func completionCmd() *cobra.Command {
	install := &cobra.Command{
		Use:   "install [shell]",
		Short: "Enable autocomplete for your shell by editing its rc file",
		Long: `Enable autocomplete for your shell by appending the completion source line
to the shell's rc file (bash -> ~/.bashrc, zsh -> ~/.zshrc, fish ->
~/.config/fish/config.fish, powershell -> PowerShell profile).

The shell is auto-detected from $SHELL (falling back to the process that
launched tunnel-suite); pass it explicitly to override. The block is
idempotent: re-running install only rewrites the block in place, and
--uninstall removes it.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			shell := ""
			if len(args) == 1 {
				shell = args[0]
			}
			uninstall, _ := cmd.Flags().GetBool("uninstall")
			return installCompletion(cmd.OutOrStdout(), shell, uninstall)
		},
	}
	install.Flags().Bool("uninstall", false, "remove the completion block from the rc file instead of adding it")
	gen := &cobra.Command{
		Use:   "completion",
		Short: "Generate or install shell autocompletion",
		Long: `Generate the autocompletion script for tunnel-suite for the specified shell.

Print the script and source it, or run "tunnel-suite completion install" to
add the sourcing line to your shell's rc file automatically.

  tunnel-suite completion bash | source
  tunnel-suite completion zsh  | source
  tunnel-suite completion fish | source
  tunnel-suite completion powershell | Out-String | Invoke-Expression`,
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			return genCompletionScript(rootCmd, args[0], cmd.OutOrStdout())
		},
	}
	gen.AddCommand(install)
	return gen
}

// genCompletionScript writes the cobra completion script for shell to w.
func genCompletionScript(cmd *cobra.Command, shell string, w io.Writer) error {
	switch shell {
	case "bash":
		return cmd.GenBashCompletionV2(w, true)
	case "zsh":
		return cmd.GenZshCompletion(w)
	case "fish":
		return cmd.GenFishCompletion(w, true)
	case "powershell":
		return cmd.GenPowerShellCompletion(w)
	default:
		return fmt.Errorf("unsupported shell %q (want bash, zsh, fish or powershell)", shell)
	}
}

const (
	// compBlockStart/compBlockEnd delimit the managed block inside an rc file
	// so install is idempotent and --uninstall can remove exactly what it added.
	compBlockStart = "# >>> tunnel-suite completion >>>\n"
	compBlockEnd   = "# <<< tunnel-suite completion <<<\n"
)

// shellSourceLine returns the line that loads the generated completion script
// for the given shell, referencing this binary by its absolute path so it
// works even when the binary is not on PATH.
func shellSourceLine(shell string) string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = "tunnel-suite"
	}
	switch shell {
	case "bash":
		return fmt.Sprintf("source <(%s completion bash)", exe)
	case "zsh":
		return fmt.Sprintf("source <(%s completion zsh)", exe)
	case "fish":
		return fmt.Sprintf("%s completion fish | source", exe)
	case "powershell":
		return fmt.Sprintf("%s completion powershell | Out-String | Invoke-Expression", exe)
	}
	return ""
}

// rcFile returns the rc file to edit for the given shell.
func rcFile(shell string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	switch shell {
	case "bash":
		return filepath.Join(home, ".bashrc")
	case "zsh":
		return filepath.Join(home, ".zshrc")
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish")
	case "powershell":
		return filepath.Join(home, ".config", "powershell", "Microsoft.PowerShell_profile.ps1")
	}
	return ""
}

// canonicalShell maps a shell name or path fragment to the canonical name
// (bash/zsh/fish/powershell), or "" when unrecognized.
func canonicalShell(raw string) string {
	base := strings.ToLower(strings.TrimSuffix(raw, ".exe"))
	switch {
	case strings.Contains(base, "bash"):
		return "bash"
	case strings.Contains(base, "zsh"):
		return "zsh"
	case strings.Contains(base, "fish"):
		return "fish"
	case strings.Contains(base, "pwsh"), strings.Contains(base, "powershell"):
		return "powershell"
	}
	return ""
}

// detectShell picks the user's shell, in order of reliability:
//
//  1. the running shell's own environment markers ($BASH_VERSION,
//     $ZSH_VERSION, $FISH_VERSION, $PSModulePath) — these are set only by the
//     shell currently executing, so they beat $SHELL, which can point at a
//     different (login) shell or be missing entirely under sudo/ssh/containers;
//  2. $SHELL (the login shell);
//  3. the parent process name (Linux only, e.g. when launched from a script).
func detectShell() (string, error) {
	switch {
	case os.Getenv("BASH_VERSION") != "":
		return "bash", nil
	case os.Getenv("ZSH_VERSION") != "":
		return "zsh", nil
	case os.Getenv("FISH_VERSION") != "":
		return "fish", nil
	case os.Getenv("PSModulePath") != "":
		return "powershell", nil
	}
	if sh := os.Getenv("SHELL"); sh != "" {
		if name := canonicalShell(sh); name != "" {
			return name, nil
		}
		// $SHELL is set but unrecognized (e.g. /bin/sh): fail loudly instead
		// of guessing a different shell from the parent process.
		return "", fmt.Errorf("cannot recognize $SHELL=%q (want bash, zsh, fish or powershell); pass the shell name explicitly, e.g. 'tunnel-suite completion install bash'", sh)
	}
	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", os.Getppid())); err == nil {
			if name := canonicalShell(strings.TrimSpace(string(b))); name != "" {
				return name, nil
			}
		}
	}
	return "", fmt.Errorf("cannot detect your shell (ran from a non-shell parent); pass the shell name explicitly: tunnel-suite completion install bash|zsh|fish|powershell")
}

// applyCompBlock replaces the managed completion block in content with the
// block built from sourceLine; when sourceLine is empty the block is removed.
// Returns the new content, and whether a block was found in content.
func applyCompBlock(content, sourceLine string) (string, bool) {
	start := strings.Index(content, compBlockStart)
	if start < 0 {
		return content, false
	}
	// Find the end marker after the start marker; tolerate a truncated block.
	endRel := strings.Index(content[start+len(compBlockStart):], compBlockEnd)
	var end int
	if endRel < 0 {
		end = len(content)
	} else {
		end = start + len(compBlockStart) + endRel + len(compBlockEnd)
	}
	if sourceLine == "" {
		// Remove the block and the blank lines that surrounded it, so the
		// file is left as close to its original shape as possible.
		before := strings.TrimRight(content[:start], "\n")
		rest := strings.TrimLeft(content[end:], "\n")
		switch {
		case before == "" && rest == "":
			return "", true
		case before == "":
			return rest, true
		case rest == "":
			return before, true
		default:
			return before + "\n" + rest, true
		}
	}
	return content[:start] + compBlockStart + sourceLine + "\n" + compBlockEnd + content[end:], true
}

// installCompletion appends (or removes, when uninstall) the completion block
// to the rc file for the given shell ("" = auto-detect).
func installCompletion(out io.Writer, shell string, uninstall bool) error {
	if shell == "" {
		detected, err := detectShell()
		if err != nil {
			return err
		}
		shell = detected
		fmt.Fprintf(out, "detected shell: %s\n", shell)
	} else {
		raw := shell
		shell = canonicalShell(shell)
		if shell == "" {
			return fmt.Errorf("unsupported shell %q (want bash, zsh, fish or powershell)", raw)
		}
	}

	rc := rcFile(shell)
	if rc == "" {
		return fmt.Errorf("cannot determine the rc file for %s (is $HOME set?)", shell)
	}

	var content []byte
	if b, err := os.ReadFile(rc); err == nil {
		content = b
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", rc, err)
	}

	sourceLine := ""
	if !uninstall {
		sourceLine = shellSourceLine(shell)
	}
	newContent, found := applyCompBlock(string(content), sourceLine)

	switch {
	case uninstall && !found:
		fmt.Fprintf(out, "no completion block found in %s — nothing to remove\n", rc)
		return nil
	case !uninstall && found:
		if newContent == string(content) {
			fmt.Fprintf(out, "completion already installed in %s (block up to date)\n", rc)
			return nil
		}
	case !uninstall && !found:
		// Append a new block at the end of the file (no leading blank line
		// when the file is empty or already ends with a newline).
		if newContent != "" && !strings.HasSuffix(newContent, "\n") {
			newContent += "\n"
		}
		if newContent != "" {
			newContent += "\n"
		}
		newContent += compBlockStart + sourceLine + "\n" + compBlockEnd
	}

	if err := os.MkdirAll(filepath.Dir(rc), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(rc), err)
	}
	if err := os.WriteFile(rc, []byte(newContent), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", rc, err)
	}

	if uninstall {
		fmt.Fprintf(out, "removed tunnel-suite completion from %s\n", rc)
	} else {
		fmt.Fprintf(out, "added tunnel-suite completion to %s\n", rc)
		fmt.Fprintf(out, "restart your shell, or run: source %s\n", rc)
	}
	return nil
}
