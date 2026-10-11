package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPolicyExample(t *testing.T) {
	p, err := LoadPolicy(filepath.Join("..", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Workspace == "" {
		t.Fatal("empty workspace")
	}
	if len(p.NetworkAllowlist) == 0 {
		t.Fatal("empty network allowlist")
	}
	if p.DefaultTimeout != 120 {
		t.Fatalf("default_timeout=%d want 120", p.DefaultTimeout)
	}
	for _, tool := range KnownTools {
		if !p.Allowed(tool) {
			t.Fatalf("example policy should allow %s", tool)
		}
	}
	// The spec's core invariant: fetch + eval get no secrets.
	for _, tool := range []string{"web-fetch", "eval-run"} {
		if len(p.Tools[tool].Env) != 0 {
			t.Fatalf("%s must declare no env secrets, got %v", tool, p.Tools[tool].Env)
		}
	}
	if p.TimeoutFor("web-fetch") != 10 {
		t.Fatalf("web-fetch timeout=%d want 10", p.TimeoutFor("web-fetch"))
	}
}

func TestLoadPolicyMissingPathFallsBack(t *testing.T) {
	p, err := LoadPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allowed("shell-sandboxed") || p.TimeoutFor("web-fetch") != 10 {
		t.Fatalf("bad defaults: %+v", p)
	}
}

func TestLoadPolicyRejectsUnknownTool(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(p, []byte("tools:\n  rm-rf-everything:\n    allow: true\n"), 0o600)
	if _, err := LoadPolicy(p); err == nil {
		t.Fatal("expected error for unknown tool in manifest")
	}
}

func TestLoadPolicyRejectsTypoKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(p, []byte("toolz:\n  shell-sandboxed:\n    allow: true\n"), 0o600)
	if _, err := LoadPolicy(p); err == nil {
		t.Fatal("expected error for unknown top-level key")
	}
}

func TestPolicyDenyAndTimeoutOverride(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(p, []byte(
		"tools:\n  eval-run:\n    allow: false\n    timeout_sec: 30\n    env: []\n  web-fetch:\n    allow: true\n    timeout_sec: 5\n    env: []\n",
	), 0o600)
	pol, err := LoadPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if pol.Allowed("eval-run") {
		t.Fatal("eval-run should be denied")
	}
	if !pol.Allowed("web-fetch") {
		t.Fatal("web-fetch should be allowed")
	}
	// Timeout override: default binds the cap, larger requests fail closed.
	if got, _ := pol.ResolveTimeout("web-fetch", 0); got != 5 {
		t.Fatalf("default timeout=%d want 5", got)
	}
	if _, err := pol.ResolveTimeout("web-fetch", 10); err == nil {
		t.Fatal("expected error requesting above the policy cap")
	}
	if got, _ := pol.ResolveTimeout("web-fetch", 3); got != 3 {
		t.Fatalf("timeout=%d want 3", got)
	}
}

// TestLoadPolicyFailsClosed mirrors the table in mcp/test_server.py: the daemon
// and the Python gateway must refuse exactly the same manifests, so a policy
// can never be rejected by one enforcement point and accepted by the other.
func TestLoadPolicyFailsClosed(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"unknown top-level key", "toolz:\n  file-read:\n    allow: true\n", "unknown top-level key"},
		{"unknown tool", "tools:\n  rm-rf:\n    allow: true\n", "unknown tool"},
		{"unknown tool key", "tools:\n  file-read:\n    allowd: true\n", "unknown key tools.file-read.allowd"},
		{"tool timeout out of range", "tools:\n  web-fetch:\n    timeout_sec: 900\n", "timeout_sec must be 1..30"},
		{"default timeout out of range", "default_timeout_sec: 0\n", "default_timeout_sec must be 1..1800"},
		{"empty network allowlist", "network_allowlist: []\n", "network_allowlist must not be empty"},
		{"invalid env name", "tools:\n  web-fetch:\n    env:\n      - 'bad name'\n", "invalid env name"},
		{"workspace not a string", "workspace: 42\n", "workspace must be a non-empty string"},
		{"allow not a bool", "tools:\n  web-fetch:\n    allow: maybe\n", "allow must be true/false"},
		{"tools not a mapping", "tools: 5\n", "tools must be a mapping"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "policy.yaml")
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			pol, err := LoadPolicy(p)
			if err == nil {
				t.Fatalf("manifest accepted, want error containing %q (got %+v)", tc.want, pol)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
			// A broken manifest must also stop the server from booting.
			if _, err := NewServer(Config{Workspace: t.TempDir(), AuditPath: filepath.Join(t.TempDir(), "a.jsonl"), Token: "t", PolicyPath: p}); err == nil {
				t.Fatal("NewServer accepted a malformed manifest")
			}
		})
	}
}

// TestLoadPolicyAbsentFileIsAnError: naming a manifest that does not exist is a
// configuration error, not a silent fall back to permissive defaults.
func TestLoadPolicyAbsentFileIsAnError(t *testing.T) {
	if _, err := LoadPolicy(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected an error for a missing manifest")
	}
}

// testServer builds a daemon wired to a temp policy without binding sockets.
func testServer(t *testing.T, policyText string) *Server {
	t.Helper()
	dir := t.TempDir()
	pp := filepath.Join(dir, "policy.yaml")
	if policyText == "" {
		pp = ""
	} else {
		if err := os.WriteFile(pp, []byte(policyText), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := NewServer(Config{
		Workspace:  dir + "/ws",
		AuditPath:  dir + "/audit.jsonl",
		TracePath:  dir + "/trace.json",
		Token:      "test-token",
		Policy:     nil,
		PolicyPath: pp,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func callTool(t *testing.T, s *Server, tool string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/tool-calls",
		strings.NewReader(`{"tool":`+quote(tool)+`}`))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func quote(s string) string {
	return `"` + s + `"`
}

func TestDaemonRejectsUnknownTool(t *testing.T) {
	s := testServer(t, "")
	code, body := callTool(t, s, "rm-rf-everything")
	if code != 400 {
		t.Fatalf("code=%d body=%s want 400", code, body)
	}
	if !strings.Contains(body, "unknown_tool") {
		t.Fatalf("expected structured unknown_tool error: %s", body)
	}
}

func TestDaemonRejectsDeniedTool(t *testing.T) {
	s := testServer(t, "tools:\n  eval-run:\n    allow: false\n")
	code, body := callTool(t, s, "eval-run")
	if code != 403 {
		t.Fatalf("code=%d body=%s want 403", code, body)
	}
	if !strings.Contains(body, "tool_denied") {
		t.Fatalf("expected structured tool_denied error: %s", body)
	}
	// …while an allowed tool still passes.
	code, _ = callTool(t, s, "file-read")
	if code != 200 {
		t.Fatalf("allowed tool got code=%d", code)
	}
}

// submitRun posts a run and returns the HTTP code plus the decoded body.
func submitRun(t *testing.T, s *Server, payload string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/runs", strings.NewReader(payload)))
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestDaemonRunBindsPolicyTimeout(t *testing.T) {
	// Per-tool cap of 7s, tighter than the 30s built-in default.
	s := testServer(t, "tools:\n  shell-sandboxed:\n    allow: true\n    timeout_sec: 7\n")

	// Omitted timeout binds the policy cap.
	code, body := submitRun(t, s, `{"tool":"shell-sandboxed","command":["true"]}`)
	if code != 202 {
		t.Fatalf("code=%d body=%v want 202", code, body)
	}
	id, _ := body["id"].(string)
	run, ok := s.store.Get(id)
	if !ok {
		t.Fatalf("run %q not found", id)
	}
	if run.TimeoutSec != 7 {
		t.Fatalf("effective timeout=%d want policy cap 7", run.TimeoutSec)
	}

	// A smaller request is honoured.
	code, body = submitRun(t, s, `{"tool":"shell-sandboxed","command":["true"],"timeout_sec":3}`)
	if code != 202 {
		t.Fatalf("code=%d body=%v want 202", code, body)
	}
	if got, _ := s.store.Get(body["id"].(string)); got.TimeoutSec != 3 {
		t.Fatalf("effective timeout=%d want 3", got.TimeoutSec)
	}

	// A larger request is refused: policy cannot be widened from the client.
	code, body = submitRun(t, s, `{"tool":"shell-sandboxed","command":["true"],"timeout_sec":60}`)
	if code != 400 {
		t.Fatalf("code=%d body=%v want 400", code, body)
	}
	if !strings.Contains(fmt.Sprint(body["error"]), "invalid_args") {
		t.Fatalf("expected structured invalid_args error, got %v", body)
	}
}

func TestDaemonRunRejectsUnknownAndDeniedToolBinding(t *testing.T) {
	s := testServer(t, "tools:\n  web-fetch:\n    allow: false\n")
	code, body := submitRun(t, s, `{"tool":"web-fetch","command":["true"]}`)
	if code != 403 {
		t.Fatalf("code=%d body=%v want 403", code, body)
	}
	if !strings.Contains(fmt.Sprint(body), "tool_denied") {
		t.Fatalf("expected tool_denied, got %v", body)
	}
	code, body = submitRun(t, s, `{"tool":"rm-rf","command":["true"]}`)
	if code != 400 {
		t.Fatalf("code=%d body=%v want 400", code, body)
	}
	if !strings.Contains(fmt.Sprint(body), "unknown_tool") {
		t.Fatalf("expected unknown_tool, got %v", body)
	}
}

func TestPolicyWorkspaceBecomesRunRoot(t *testing.T) {
	dir := t.TempDir()
	pp := filepath.Join(dir, "policy.yaml")
	os.WriteFile(pp, []byte("workspace: "+filepath.Join(dir, "from-policy")+"\n"), 0o600)
	s, err := NewServer(Config{
		// Workspace deliberately empty: the manifest must supply it.
		AuditPath:  filepath.Join(dir, "audit.jsonl"),
		TracePath:  filepath.Join(dir, "trace.json"),
		Token:      "test-token",
		PolicyPath: pp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.Workspace != filepath.Join(dir, "from-policy") {
		t.Fatalf("workspace=%q want the policy root", s.cfg.Workspace)
	}
	if _, err := os.Stat(s.cfg.Workspace); err != nil {
		t.Fatalf("policy workspace not created: %v", err)
	}
}
