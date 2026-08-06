package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

const (
	ansiReset  = "\x1b[0m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiCyan   = "\x1b[36m"
	ansiBold   = "\x1b[1m"
)

func statusColor(s Status) string {
	switch s {
	case StatusOK:
		return ansiGreen
	case StatusSkipped:
		return ansiYellow
	default:
		return ansiRed
	}
}

// PrintTable renders the results to w using a fixed-width aligned table.
func PrintTable(w io.Writer, results []Result, color bool) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	c := func(s string) string { return s }
	if color {
		c = func(s string) string { return ansiCyan + s + ansiReset }
	}

	header := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s",
		c("PROTOCOL"), c("KIND"), c("STATUS"),
		c("RTT min"), c("RTT avg"), c("RTT max"), c("JITTER"),
		c("LOSS"), c("HANDSHAKE"), c("OVERHEAD"))
	fmt.Fprintln(tw, header)
	fmt.Fprintln(tw, strings.Repeat("-", 96))

	for _, r := range results {
		var status string
		if color {
			status = statusColor(r.Status) + string(r.Status) + ansiReset
		} else {
			status = string(r.Status)
		}
		rttMin := fmt.Sprintf("%.2fms", r.RTT.MinMs)
		rttAvg := fmt.Sprintf("%.2fms", r.RTT.AvgMs)
		rttMax := fmt.Sprintf("%.2fms", r.RTT.MaxMs)
		jit := fmt.Sprintf("%.2fms", r.RTT.JitterMs)
		loss := fmt.Sprintf("%.2f%%", r.LossPercent)
		hs := fmt.Sprintf("%.1fms", r.HandshakeMs)
		overhead := fmt.Sprintf("%dB", r.OverheadBytes)
		if r.Status != StatusOK {
			rttMin, rttAvg, rttMax, jit, loss, hs = "-", "-", "-", "-", "-", "-"
			overhead = fmt.Sprintf("%dB", r.OverheadBytes)
		}
		note := r.Note
		if r.Error != "" {
			note = r.Error
		}
		if len(note) > 60 {
			note = note[:57] + "..."
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Protocol, r.Kind, status,
			rttMin, rttAvg, rttMax, jit, loss, hs, overhead)
		if note != "" && r.Status != StatusOK {
			fmt.Fprintf(tw, "  └ %s\n", note)
		}
	}
	tw.Flush()
}

// humanBytes renders a byte count in a compact human-readable form.
func humanBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}

// PrintThroughputTable renders the throughput speed-test results.
func PrintThroughputTable(w io.Writer, results []ThroughputResult, sec float64, frameSize int, color bool) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	c := func(s string) string { return s }
	if color {
		c = func(s string) string { return ansiCyan + s + ansiReset }
	}

	bold, reset := "", ""
	if color {
		bold, reset = ansiBold, ansiReset
	}
	fmt.Fprintf(w, "\n%sTHROUGHPUT%s — echo test, %.1fs @ %dB frames\n", bold, reset, sec, frameSize)
	header := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s",
		c("PROTOCOL"), c("KIND"), c("STATUS"),
		c("UPLOAD"), c("DOWNLOAD"), c("LOSS"), c("DATA"))
	fmt.Fprintln(tw, header)
	fmt.Fprintln(tw, strings.Repeat("-", 72))

	for _, r := range results {
		var status string
		if color {
			status = statusColor(r.Status) + string(r.Status) + ansiReset
		} else {
			status = string(r.Status)
		}
		up := fmt.Sprintf("%.1f Mbps", r.UploadMbps)
		down := fmt.Sprintf("%.1f Mbps", r.DownloadMbps)
		loss := fmt.Sprintf("%.2f%%", r.LossPercent)
		data := humanBytes(r.SentBytes) + " up / " + humanBytes(r.RecvBytes) + " down"
		if r.Status != StatusOK {
			up, down, loss, data = "-", "-", "-", "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Protocol, r.Kind, status, up, down, loss, data)
		if r.Error != "" || (r.Note != "" && r.Status != StatusOK) {
			note := r.Error
			if note == "" {
				note = r.Note
			}
			if len(note) > 60 {
				note = note[:57] + "..."
			}
			fmt.Fprintf(tw, "  └ %s\n", note)
		}
	}
	tw.Flush()
}

// PrintSummary renders the overall pass/skip/fail counts.
func PrintSummary(w io.Writer, s Summary, color bool) {
	green, yellow, red, reset := "", "", "", ""
	if color {
		green, yellow, red, reset = ansiGreen, ansiYellow, ansiRed, ansiReset
	}
	fmt.Fprintf(w, "\n%sTotal: %d%s   %sOK: %d%s   %sSkipped: %d%s   %sFailed: %d%s\n",
		ansiBold, s.Total, reset,
		green, s.OK, reset,
		yellow, s.Skipped, reset,
		red, s.Failed, reset)
}
