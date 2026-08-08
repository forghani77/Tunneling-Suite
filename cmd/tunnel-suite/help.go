package main

import (
	"bytes"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

// installSingleDashHelp makes help and usage output render long flags with a
// single dash (-forward, -server H) instead of the "--flag" spelling pflag
// always emits. Both styles remain valid on the command line — this only
// changes what the help menu shows, for consistency with the input style.
//
// The override must capture the default HelpFunc/UsageFunc first and render
// through them into a buffer, because cobra's UsageString() calls Usage() and
// would otherwise recurse into the overrides.
//
// Note: cobra routes usage output through the command's OUT writer
// (OutOrStderr returns getOut(os.Stderr)), so the usage override swaps
// SetOut, not SetErr, to capture the rendering.
func installSingleDashHelp(root *cobra.Command) {
	origHelp := root.HelpFunc()
	origUsage := root.UsageFunc()

	root.SetUsageFunc(func(c *cobra.Command) error {
		real := c.OutOrStderr()
		var buf bytes.Buffer
		c.SetOut(&buf)
		err := origUsage(c)
		c.SetOut(real)
		if err != nil {
			return err
		}
		_, err = io.WriteString(real, strings.ReplaceAll(buf.String(), "--", "-"))
		return err
	})

	root.SetHelpFunc(func(c *cobra.Command, args []string) {
		real := c.OutOrStdout()
		var buf bytes.Buffer
		c.SetOut(&buf)
		origHelp(c, args)
		c.SetOut(real)
		_, _ = io.WriteString(real, strings.ReplaceAll(buf.String(), "--", "-"))
	})
}
