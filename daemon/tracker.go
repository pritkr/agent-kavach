package main

// tracker.go — cost/latency accounting per run.
//
// Cost model (documented estimate, not a cloud bill):
//   cost_usd = duration_sec * sandbox_rate + output_kb * byte_rate + tool_penalty
// Rates are deliberately tiny and linear so dashboards can compare runs.
// Tune via flags in a real deployment; the function stays pure for tests.

const (
	rateDockerPerSec = 0.000050 // $/s — container slice estimate
	rateLocalPerSec  = 0.000020 // $/s — local CPU slice estimate
	ratePerKBOutput  = 0.000001 // $/KiB captured output
)

// EstimateCost returns a deterministic USD estimate for a run.
func EstimateCost(sandbox string, durationSec float64, outputBytes int) float64 {
	if durationSec < 0 {
		durationSec = 0
	}
	if outputBytes < 0 {
		outputBytes = 0
	}
	rate := rateLocalPerSec
	if sandbox == "docker" {
		rate = rateDockerPerSec
	}
	return durationSec*rate + float64(outputBytes)/1024.0*ratePerKBOutput
}
