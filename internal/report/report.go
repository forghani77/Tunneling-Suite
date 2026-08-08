// Package report models benchmark results and renders them as a terminal
// table or a JSON document.
package report

import "time"

// Status of a single protocol test.
type Status string

const (
	StatusOK      Status = "ok"
	StatusSkipped Status = "skipped"
	StatusFailed  Status = "failed"
)

// RTTStats summarizes a set of round-trip time samples.
type RTTStats struct {
	MinMs    float64 `json:"min_ms"`
	AvgMs    float64 `json:"avg_ms"`
	MaxMs    float64 `json:"max_ms"`
	JitterMs float64 `json:"jitter_ms"`
	Samples  int     `json:"samples"`
}

// Result is the outcome of testing one protocol.
type Result struct {
	Protocol      string   `json:"protocol"`
	Kind          string   `json:"kind"`
	Status        Status   `json:"status"`
	ConnectMs     float64  `json:"connect_ms"`
	HandshakeMs   float64  `json:"handshake_ms"`
	RTT           RTTStats `json:"rtt"`
	LossPercent   float64  `json:"loss_percent"`
	Sent          int      `json:"sent"`
	Received      int      `json:"received"`
	OverheadBytes int      `json:"overhead_bytes"`
	Note          string   `json:"note,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// Config captures the benchmark parameters for reproducibility.
type Config struct {
	Pings          int     `json:"pings"`
	RTTSize        int     `json:"rtt_size"`
	LossSize       int     `json:"loss_size"`
	GapMs          float64 `json:"gap_ms"`
	TimeoutSec     float64 `json:"timeout_sec"`
	ReadTimeoutMs  float64 `json:"read_timeout_ms"`
	ThroughputSec  float64 `json:"throughput_sec"`
	ThroughputSize int     `json:"throughput_size"`
}

// Summary aggregates statuses across protocols.
type Summary struct {
	Total   int `json:"total"`
	OK      int `json:"ok"`
	Skipped int `json:"skipped"`
	Failed  int `json:"failed"`
}

// ThroughputResult is the outcome of one protocol's throughput speed test.
type ThroughputResult struct {
	Protocol     string  `json:"protocol"`
	Kind         string  `json:"kind"`
	Status       Status  `json:"status"`
	FrameSize    int     `json:"frame_size"`
	DurationSec  float64 `json:"duration_sec"`
	SentBytes    int64   `json:"sent_bytes"`
	RecvBytes    int64   `json:"recv_bytes"`
	SentFrames   int64   `json:"sent_frames"`
	RecvFrames   int64   `json:"recv_frames"`
	UploadMbps   float64 `json:"upload_mbps"`
	DownloadMbps float64 `json:"download_mbps"`
	LossPercent  float64 `json:"loss_percent"`
	Note         string  `json:"note,omitempty"`
	Error        string  `json:"error,omitempty"`
}

// Report is the full machine-readable benchmark output.
type Report struct {
	GeneratedAt       time.Time          `json:"generated_at"`
	Server            string             `json:"server"`
	ProtocolsBasePort int                `json:"protocols_base_port"`
	ControlPort       int                `json:"control_port"`
	ClientIP          string             `json:"client_ip,omitempty"`
	Config            Config             `json:"config"`
	Results           []Result           `json:"results"`
	Summary           Summary            `json:"summary"`
	Throughput        []ThroughputResult `json:"throughput,omitempty"`
	ThroughputSummary Summary            `json:"throughput_summary,omitempty"`
}

// ComputeRTT derives min/avg/max/jitter from RTT samples (milliseconds).
func ComputeRTT(rtts []float64) RTTStats {
	if len(rtts) == 0 {
		return RTTStats{}
	}
	min, max, sum := rtts[0], rtts[0], 0.0
	for _, r := range rtts {
		if r < min {
			min = r
		}
		if r > max {
			max = r
		}
		sum += r
	}
	avg := sum / float64(len(rtts))
	var jitter float64
	for i := 1; i < len(rtts); i++ {
		d := rtts[i] - rtts[i-1]
		if d < 0 {
			d = -d
		}
		jitter += d
	}
	if len(rtts) > 1 {
		jitter /= float64(len(rtts) - 1)
	}
	return RTTStats{MinMs: min, AvgMs: avg, MaxMs: max, JitterMs: jitter, Samples: len(rtts)}
}
