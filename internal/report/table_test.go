package report

import (
	"bytes"
	"testing"
)

// TestRenderTableSingleRow verifies that a one-row table aligns its columns
// under the header (the bug the tabwriter separator line used to cause).
func TestRenderTableSingleRow(t *testing.T) {
	var buf bytes.Buffer
	renderTable(&buf,
		[]string{"PROTOCOL", "KIND", "STATUS", "UPLOAD"},
		[][]string{{"tcp", "stream", "ok", "310.2 Mbps"}},
		nil)

	want := "PROTOCOL  KIND    STATUS  UPLOAD\n" +
		"------------------------------------\n" + // 3*2 + 8+6+6+10 = 36 dashes
		"tcp       stream  ok      310.2 Mbps\n"
	if got := buf.String(); got != want {
		t.Fatalf("render mismatch:\n got: %q\nwant: %q", got, want)
	}
}

// TestRenderTableMultiRow verifies rows align with each other and the header
// when one cell is much wider than the header (tabwriter used to split the
// header into its own alignment group).
func TestRenderTableMultiRow(t *testing.T) {
	var buf bytes.Buffer
	renderTable(&buf,
		[]string{"PROTOCOL", "KIND"},
		[][]string{{"tcp", "stream"}, {"shadowsocks", "stream"}},
		nil)

	// Column 0 is 11 wide (shadowsocks); PROTOCOL(8) pads to 11, tcp(3) to 11.
	want := "PROTOCOL     KIND\n" +
		"-------------------\n" + // 1*2 + 11+6 = 19 dashes
		"tcp          stream\n" +
		"shadowsocks  stream\n"
	if got := buf.String(); got != want {
		t.Fatalf("render mismatch:\n got: %q\nwant: %q", got, want)
	}
}

// TestRenderTableColor verifies that ANSI-colored headers still line up with
// plain rows (tabwriter counted escape bytes as width, misaligning them).
func TestRenderTableColor(t *testing.T) {
	var buf bytes.Buffer
	renderTable(&buf,
		[]string{ansiCyan + "PROTOCOL" + ansiReset, ansiCyan + "KIND" + ansiReset},
		[][]string{{"tcp", "stream"}, {"shadowsocks", "stream"}},
		nil)

	// Column 0 is 11 wide (shadowsocks); PROTOCOL(8) pads to 11, tcp(3) to 11.
	want := "PROTOCOL     KIND\n" +
		"-------------------\n" + // 1*2 + 11+6 = 19 dashes
		"tcp          stream\n" +
		"shadowsocks  stream\n"
	if got := stripANSI(buf.String()); got != want {
		t.Fatalf("render mismatch (after ANSI strip):\n got: %q\nwant: %q", got, want)
	}
}

// TestStripANSI checks the escape-sequence stripper used for widths.
func TestStripANSI(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{ansiCyan + "x" + ansiReset, "x"},
		{"a\x1b[1;31mb\x1b[0mc", "abc"},
	}
	for _, c := range cases {
		if got := stripANSI(c.in); got != c.want {
			t.Errorf("stripANSI(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestPrintThroughputTableSingleRow exercises the public API path that
// triggered the reported misalignment (a single-row throughput table).
func TestPrintThroughputTableSingleRow(t *testing.T) {
	var buf bytes.Buffer
	PrintThroughputTable(&buf, []ThroughputResult{{
		Protocol: "tcp", Kind: "stream", Status: StatusOK,
		UploadMbps: 310.2, DownloadMbps: 298.3,
		SentBytes: 193900000, RecvBytes: 186500000,
	}}, 5, 60000, false)

	want := "\nTHROUGHPUT — echo test, 5.0s @ 60000B frames\n" +
		"PROTOCOL  KIND    STATUS  UPLOAD      DOWNLOAD    LOSS   DATA\n" +
		"------------------------------------------------------------------------------------" + // 6*2 + 8+6+6+10+10+5+27 = 84 dashes
		"\ntcp       stream  ok      310.2 Mbps  298.3 Mbps  0.00%  193.9 MB up / 186.5 MB down\n"
	if got := buf.String(); got != want {
		t.Fatalf("render mismatch:\n got: %q\nwant: %q", got, want)
	}
}
