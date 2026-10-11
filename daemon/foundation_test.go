package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditAppendRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := OpenAuditLog(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Append("run.submitted", map[string]any{"run_id": "r1"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Append("run.finished", map[string]any{"run_id": "r1", "status": "done"}); err != nil {
		t.Fatal(err)
	}
	entries, err := a.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%d want 2", len(entries))
	}
	if entries[0]["event"] != "run.submitted" || entries[1]["event"] != "run.finished" {
		t.Fatalf("bad events: %v", entries)
	}
	if entries[0]["at"] == nil || entries[0]["at"] == "" {
		t.Fatal("missing timestamp")
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("audit perms=%o want 600", fi.Mode().Perm())
	}
}

func TestEstimateCost(t *testing.T) {
	c0 := EstimateCost("local", 0, 0)
	if c0 != 0 {
		t.Fatalf("zero run should cost 0, got %v", c0)
	}
	a := EstimateCost("local", 10, 1024)
	b := EstimateCost("docker", 10, 1024)
	if !(b > a) {
		t.Fatalf("docker (%v) should cost more than local (%v)", b, a)
	}
	if EstimateCost("local", -5, -5) != 0 {
		t.Fatal("negative inputs should clamp to 0")
	}
	// determinism
	if EstimateCost("docker", 3.5, 2048) != EstimateCost("docker", 3.5, 2048) {
		t.Fatal("cost not deterministic")
	}
	// output adds cost
	if !(EstimateCost("local", 1, 10240) > EstimateCost("local", 1, 0)) {
		t.Fatal("output bytes should increase cost")
	}
}

func TestTracerSpans(t *testing.T) {
	tr := NewTracer()
	if tr.TraceID() == "" {
		t.Fatal("empty trace id")
	}
	root := tr.Start("run", "", map[string]any{"run_id": "r1"})
	child := tr.Start("sandbox.exec", root.SpanID, nil)
	tr.End(child, "OK")
	tr.End(root, "OK")
	spans := tr.Export()
	if len(spans) != 2 {
		t.Fatalf("spans=%d want 2", len(spans))
	}
	if spans[1].ParentSpanID != root.SpanID {
		t.Fatal("child missing parent link")
	}
	for _, s := range spans {
		if s.TraceID != tr.TraceID() || s.DurationMs() < 0 {
			t.Fatalf("bad span: %+v", s)
		}
		if s.Status.Code != "OK" {
			t.Fatalf("bad status: %+v", s)
		}
	}
	p := filepath.Join(t.TempDir(), "trace.json")
	if err := DumpTraceFile(p, "r1", spans); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if len(data) == 0 {
		t.Fatal("empty trace dump")
	}
}

func TestMetricsRender(t *testing.T) {
	m := NewMetrics()
	m.IncSubmitted()
	m.IncCompleted("done")
	m.IncCompleted("failed")
	m.IncKilled()
	m.IncKillSwitch()
	m.IncToolCall("shell-sandboxed")
	m.ObserveDuration(1500)
	out := m.Render()
	for _, want := range []string{
		"kavach_runs_submitted_total 1",
		"kavach_runs_completed_total{status=\"done\"} 1",
		"kavach_runs_completed_total{status=\"failed\"} 1",
		"kavach_runs_killed_total 1",
		"kavach_kill_switch_activations_total 1",
		"kavach_mcp_tool_calls_total{tool=\"shell-sandboxed\"} 1",
		"kavach_run_duration_seconds_count 1",
	} {
		if !contains(out, want) {
			t.Fatalf("metrics missing %q\n%s", want, out)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}
