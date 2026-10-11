package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The canary: a fake secret that must never appear in any log, even when a
// command echoes its own environment.
const canaryValue = "canary-kavach-9f8e7d6c5b4a-topsecret"

func canaryPolicy(t *testing.T) *Policy {
	t.Helper()
	t.Setenv("KAVACH_DEMO_TOKEN", canaryValue)
	p, err := LoadPolicy(filepath.Join("..", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVaultInjectsAllowlistedSecret(t *testing.T) {
	v := NewVault(canaryPolicy(t))
	env := v.EnvForTool("shell-sandboxed")
	found := false
	for _, kv := range env {
		if kv == "KAVACH_DEMO_TOKEN="+canaryValue {
			found = true
		}
		if strings.Contains(kv, canaryValue) && !strings.HasPrefix(kv, "KAVACH_DEMO_TOKEN=") {
			t.Fatalf("secret leaked under wrong name: %s", RedactText(kv, []string{canaryValue}))
		}
	}
	if !found {
		t.Fatalf("allowlisted secret not injected: %v", env)
	}
}

func TestVaultUntrustedToolsGetNoSecrets(t *testing.T) {
	v := NewVault(canaryPolicy(t))
	for _, tool := range []string{"web-fetch", "eval-run", "no-such-tool"} {
		for _, kv := range v.EnvForTool(tool) {
			if strings.Contains(kv, canaryValue) {
				t.Fatalf("tool %s received a secret", tool)
			}
		}
		if len(v.EnvForTool(tool)) != 0 {
			t.Fatalf("tool %s env should be empty, got %v", tool, v.EnvForTool(tool))
		}
	}
}

func TestVaultCanaryNeverInLogs(t *testing.T) {
	p := canaryPolicy(t)
	v := NewVault(p)
	dir := t.TempDir()

	// 1. Exec-time: run a command that echoes its own environment, bound to
	//    a tool with the secret allowlisted.
	res := ExecuteWithEnv(context.Background(),
		[]string{"sh", "-c", "echo token-is-$KAVACH_DEMO_TOKEN"},
		"", dir, 15, "canary-test", "shell-sandboxed", v)
	if strings.Contains(res.Output, canaryValue) {
		t.Fatal("canary leaked into exec output")
	}
	if !strings.Contains(res.Output, Redacted) {
		t.Fatalf("expected redaction marker in output, got %q", res.Output)
	}

	// 2. Trajectory ledger: spans carrying the raw command redact on dump.
	tr := NewTracer()
	span := tr.Start("sandbox.exec", "", map[string]any{
		"command": "echo " + canaryValue,
		"output":  res.Output,
	})
	tr.End(span, "OK")
	tracePath := filepath.Join(dir, "trace.json")
	if err := DumpTraceFileRedacted(tracePath, "r-canary", tr.Export(), v.SecretsSnapshot()); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(tracePath)
	if strings.Contains(string(raw), canaryValue) {
		t.Fatal("canary leaked into trace dump")
	}

	// 3. Audit ledger: the log scrubs secrets itself, so raw fields are safe
	//    to hand over. A vault-bound log must still come out clean.
	auditPath := filepath.Join(dir, "audit.jsonl")
	a, err := OpenAuditLogRedacted(auditPath, v.SecretsSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Append("run.submitted", map[string]any{
		"run_id": "r-canary", "command": []string{"echo", canaryValue},
	}); err != nil {
		t.Fatal(err)
	}
	araw, _ := os.ReadFile(auditPath)
	if strings.Contains(string(araw), canaryValue) {
		t.Fatal("canary leaked into audit log")
	}
	if !strings.Contains(string(araw), Redacted) {
		t.Fatalf("expected a redaction marker in the audit log, got %s", araw)
	}
	if err := VerifyLog(auditPath); err != nil {
		t.Fatalf("canary audit log should still verify: %v", err)
	}
}

func TestVaultRestrictedChildSeesOnlyAllowlisted(t *testing.T) {
	t.Setenv("KAVACH_OUTSIDE_SECRET", "outside-"+canaryValue)
	p := canaryPolicy(t)
	v := NewVault(p)
	// web-fetch declares no env: the child must not see the outside secret
	// even though it lives in the daemon's own environment.
	res := ExecuteWithEnv(context.Background(),
		[]string{"sh", "-c", "echo [${KAVACH_OUTSIDE_SECRET-unset}] [${KAVACH_DEMO_TOKEN-unset}]"},
		"", t.TempDir(), 15, "restrict-test", "web-fetch", v)
	if res.ExitCode != 0 {
		t.Fatalf("exec failed: %+v", res)
	}
	if !strings.Contains(res.Output, "[unset] [unset]") {
		t.Fatalf("restricted child saw outside env: %q", res.Output)
	}
}

// TestVaultCanaryNeverInServerLedgers is the end-to-end guarantee: a run that
// is handed the canary secret — and that prints it in its argv — leaves no
// trace of the value in any artifact the daemon writes or serves.
func TestVaultCanaryNeverInServerLedgers(t *testing.T) {
	t.Setenv("KAVACH_DEMO_TOKEN", canaryValue)
	dir := t.TempDir()
	pp := filepath.Join(dir, "policy.yaml")
	manifest := "workspace: " + filepath.Join(dir, "ws") + "\n" +
		"tools:\n  shell-sandboxed:\n    allow: true\n    timeout_sec: 15\n    env:\n      - KAVACH_DEMO_TOKEN\n"
	if err := os.WriteFile(pp, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Config{
		Workspace:  filepath.Join(dir, "ws"),
		AuditPath:  filepath.Join(dir, "audit.jsonl"),
		TracePath:  filepath.Join(dir, "trace.json"),
		Token:      "test-token",
		PolicyPath: pp,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Submit a run bound to the tool that may hold the secret. The command
	// both prints the value from its env and hardcodes it in argv, hitting the
	// output, span-attribute and audit-command redaction paths at once.
	body := `{"tool":"shell-sandboxed","command":["sh","-c","echo $KAVACH_DEMO_TOKEN; echo ` + canaryValue + `"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/runs", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != 202 {
		t.Fatalf("submit code=%d body=%s", rec.Code, rec.Body.String())
	}
	var submitted struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &submitted); err != nil {
		t.Fatal(err)
	}

	// Drain the run synchronously so its artifacts exist before we grep.
	var run *Run
	for i := 0; i < 200; i++ {
		if r, ok := s.store.Get(submitted.ID); ok && r.Status != StatusQueued && r.Status != StatusRunning {
			run = r
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if run == nil {
		t.Fatal("run never finished")
	}
	if !strings.Contains(run.Output, Redacted) {
		t.Fatalf("expected redaction in stored run output, got %q", run.Output)
	}

	// The served JSON for the run must be clean too (spans + output).
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/runs/"+submitted.ID, nil))
	if strings.Contains(rec.Body.String(), canaryValue) {
		t.Fatal("canary leaked into GET /v1/runs/:id")
	}

	// The policy view exposes env *names* only.
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/policy", nil))
	if strings.Contains(rec.Body.String(), canaryValue) {
		t.Fatal("canary leaked into GET /v1/policy")
	}

	// Finally, nothing on disk may hold the value: audit, trace, token.
	for _, name := range []string{"audit.jsonl", "trace.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.Contains(string(raw), canaryValue) {
			t.Fatalf("canary leaked into %s:\n%s", name, RedactText(string(raw), []string{canaryValue}))
		}
	}
	// The audit log is still a valid chain after redaction.
	if err := VerifyLog(filepath.Join(dir, "audit.jsonl")); err != nil {
		t.Fatalf("redacted audit log must still verify: %v", err)
	}
}
