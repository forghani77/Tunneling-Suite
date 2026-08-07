package report

import (
	"fmt"
	"io"
	"strings"
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

// stripANSI removes ANSI SGR escape sequences (ESC [ ... m) from s. Their
// bytes are zero-width on a terminal, so they must not count toward column
// widths; tabwriter (which counts them) was the source of header/row
// misalignment when color was enabled.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && !(s[j] >= '@' && s[j] <= '~') {
				j++
			}
			if j < len(s) {
				j++ // skip the final byte of the CSI sequence
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// visibleWidth returns the display width of s, ignoring ANSI escape codes.
func visibleWidth(s string) int { return len(stripANSI(s)) }

// renderTable writes an aligned table to w: a header line, a full-width
// dashed separator, then the rows with optional per-row notes (printed under
// their row). Column widths are the maximum visible width over the header and
// every row, so colored headers line up with plain rows and a table with a
// single row still aligns under its header.
func renderTable(w io.Writer, header []string, rows [][]string, notes []string) {
	cols := len(header)
	widths := make([]int, cols)
	for j, h := range header {
		widths[j] = visibleWidth(h)
	}
	for _, r := range rows {
		for j := 0; j < cols && j < len(r); j++ {
			if wd := visibleWidth(r[j]); wd > widths[j] {
				widths[j] = wd
			}
		}
	}

	writeLine := func(cells []string) {
		for j := 0; j < cols; j++ {
			if j > 0 {
				fmt.Fprint(w, "  ")
			}
			if j >= len(cells) {
				continue
			}
			cell := cells[j]
			fmt.Fprint(w, cell)
			if j < cols-1 {
				if pad := widths[j] - visibleWidth(cell); pad > 0 {
					fmt.Fprint(w, strings.Repeat(" ", pad))
				}
			}
		}
		fmt.Fprintln(w)
	}

	writeLine(header)

	total := (cols - 1) * 2
	for _, wd := range widths {
		total += wd
	}
	fmt.Fprintln(w, strings.Repeat("-", total))

	for i, r := range rows {
		writeLine(r)
		if i < len(notes) && notes[i] != "" {
			fmt.Fprintln(w, "  └ "+notes[i])
		}
	}
}

// PrintTable renders the results to w using a fixed-width aligned table.
func PrintTable(w io.Writer, results []Result, color bool) {
	c := func(s string) string { return s }
	if color {
		c = func(s string) string { return ansiCyan + s + ansiReset }
	}
	header := []string{"PROTOCOL", "KIND", "STATUS", "RTT min", "RTT avg", "RTT max", "JITTER", "LOSS", "HANDSHAKE", "OVERHEAD"}
	colored := make([]string, len(header))
	for j, h := range header {
		colored[j] = c(h)
	}

	var rows [][]string
	var notes []string
	for _, r := range results {
		status := string(r.Status)
		if color {
			status = statusColor(r.Status) + status + ansiReset
		}
		rttMin := fmt.Sprintf("%.2fms", r.RTT.MinMs)
		rttAvg := fmt.Sprintf("%.2fms", r.RTT.AvgMs)
		rttMax := fmt.Sprintf("%.2fms", r.RTT.MaxMs)
		jit := fmt.Sprintf("%.2fms", r.RTT.JitterMs)
		loss := fmt.Sprintf("%.2f%%", r.LossPercent)
		hs := fmt.Sprintf("%.1fms", r.HandshakeMs)
		if r.Status != StatusOK {
			rttMin, rttAvg, rttMax, jit, loss, hs = "-", "-", "-", "-", "-", "-"
		}
		rows = append(rows, []string{
			r.Protocol, r.Kind, status,
			rttMin, rttAvg, rttMax, jit, loss, hs,
			fmt.Sprintf("%dB", r.OverheadBytes),
		})

		note := r.Note
		if r.Error != "" {
			note = r.Error
		}
		if len(note) > 60 {
			note = note[:57] + "..."
		}
		if note != "" && r.Status != StatusOK {
			notes = append(notes, note)
		} else {
			notes = append(notes, "")
		}
	}
	renderTable(w, colored, rows, notes)
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
	c := func(s string) string { return s }
	if color {
		c = func(s string) string { return ansiCyan + s + ansiReset }
	}

	bold, reset := "", ""
	if color {
		bold, reset = ansiBold, ansiReset
	}
	fmt.Fprintf(w, "\n%sTHROUGHPUT%s — echo test, %.1fs @ %dB frames\n", bold, reset, sec, frameSize)

	header := []string{"PROTOCOL", "KIND", "STATUS", "UPLOAD", "DOWNLOAD", "LOSS", "DATA"}
	colored := make([]string, len(header))
	for j, h := range header {
		colored[j] = c(h)
	}

	var rows [][]string
	var notes []string
	for _, r := range results {
		status := string(r.Status)
		if color {
			status = statusColor(r.Status) + status + ansiReset
		}
		up := fmt.Sprintf("%.1f Mbps", r.UploadMbps)
		down := fmt.Sprintf("%.1f Mbps", r.DownloadMbps)
		loss := fmt.Sprintf("%.2f%%", r.LossPercent)
		data := humanBytes(r.SentBytes) + " up / " + humanBytes(r.RecvBytes) + " down"
		if r.Status != StatusOK {
			up, down, loss, data = "-", "-", "-", "-"
		}
		rows = append(rows, []string{r.Protocol, r.Kind, status, up, down, loss, data})

		note := ""
		if r.Error != "" || (r.Note != "" && r.Status != StatusOK) {
			note = r.Error
			if note == "" {
				note = r.Note
			}
			if len(note) > 60 {
				note = note[:57] + "..."
			}
		}
		notes = append(notes, note)
	}
	renderTable(w, colored, rows, notes)
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
