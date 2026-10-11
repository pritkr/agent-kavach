package main

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// metrics.go — Prometheus text exposition for /metrics (no client lib).
//
// Exposed series:
//   kavach_runs_submitted_total
//   kavach_runs_completed_total{status="done|failed|killed"}
//   kavach_runs_killed_total
//   kavach_kill_switch_activations_total
//   kavach_run_duration_seconds_sum / _count
//   kavach_mcp_tool_calls_total{tool="<name>"}

type Metrics struct {
	submitted     atomic.Int64
	completed     map[string]*atomic.Int64
	completedMu   sync.Mutex
	killed        atomic.Int64
	killSwitch    atomic.Int64
	durationSumMs atomic.Int64
	durationCount atomic.Int64
	toolCalls     map[string]*atomic.Int64
	toolCallsMu   sync.Mutex
}

func NewMetrics() *Metrics {
	return &Metrics{completed: make(map[string]*atomic.Int64), toolCalls: make(map[string]*atomic.Int64)}
}

func (m *Metrics) IncSubmitted()            { m.submitted.Add(1) }
func (m *Metrics) IncKilled()               { m.killed.Add(1) }
func (m *Metrics) IncKillSwitch()           { m.killSwitch.Add(1) }
func (m *Metrics) ObserveDuration(ms int64) { m.durationSumMs.Add(ms); m.durationCount.Add(1) }

func (m *Metrics) IncCompleted(status string) {
	m.completedMu.Lock()
	c, ok := m.completed[status]
	if !ok {
		c = &atomic.Int64{}
		m.completed[status] = c
	}
	m.completedMu.Unlock()
	c.Add(1)
}

func (m *Metrics) IncToolCall(tool string) {
	m.toolCallsMu.Lock()
	c, ok := m.toolCalls[tool]
	if !ok {
		c = &atomic.Int64{}
		m.toolCalls[tool] = c
	}
	m.toolCallsMu.Unlock()
	c.Add(1)
}

// Render exposes the metrics in Prometheus text format (0.0.4).
func (m *Metrics) Render() string {
	var b strings.Builder
	counter := func(name, help string, labels map[string]string, v int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
		if len(labels) == 0 {
			fmt.Fprintf(&b, "%s %d\n", name, v)
			return
		}
		keys := make([]string, 0, len(labels))
		for k := range labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var lp strings.Builder
		for i, k := range keys {
			if i > 0 {
				lp.WriteString(",")
			}
			fmt.Fprintf(&lp, "%s=%q", k, labels[k])
		}
		fmt.Fprintf(&b, "%s{%s} %d\n", name, lp.String(), v)
	}
	counter("kavach_runs_submitted_total", "Runs submitted.", nil, m.submitted.Load())
	m.completedMu.Lock()
	for st, c := range m.completed {
		v := c.Load()
		m.completedMu.Unlock()
		counter("kavach_runs_completed_total", "Runs finished by status.", map[string]string{"status": st}, v)
		m.completedMu.Lock()
	}
	m.completedMu.Unlock()
	counter("kavach_runs_killed_total", "Runs killed.", nil, m.killed.Load())
	counter("kavach_kill_switch_activations_total", "Kill-switch engagements.", nil, m.killSwitch.Load())
	sum := float64(m.durationSumMs.Load()) / 1000.0
	fmt.Fprintf(&b, "# HELP kavach_run_duration_seconds_sum Total run time.\n# TYPE kavach_run_duration_seconds_sum counter\nkavach_run_duration_seconds_sum %.3f\n", sum)
	fmt.Fprintf(&b, "# HELP kavach_run_duration_seconds_count Run count with durations.\n# TYPE kavach_run_duration_seconds_count counter\nkavach_run_duration_seconds_count %d\n", m.durationCount.Load())
	m.toolCallsMu.Lock()
	for tool, c := range m.toolCalls {
		v := c.Load()
		m.toolCallsMu.Unlock()
		counter("kavach_mcp_tool_calls_total", "MCP tool calls.", map[string]string{"tool": tool}, v)
		m.toolCallsMu.Lock()
	}
	m.toolCallsMu.Unlock()
	return b.String()
}
