package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditChainValid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := OpenAuditLog(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{"run.submitted", "run.started", "run.finished"} {
		if err := a.Append(ev, map[string]any{"run_id": "r1"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyLog(p); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	entries, err := a.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries=%d want 3", len(entries))
	}
	prev := genesisHash
	for i, e := range entries {
		if e["prev_hash"] != prev {
			t.Fatalf("entry %d prev_hash not chained", i)
		}
		h, _ := e["hash"].(string)
		if h == "" {
			t.Fatalf("entry %d missing hash", i)
		}
		prev = h
		if seq, _ := e["seq"].(float64); int(seq) != i {
			t.Fatalf("entry %d seq=%v want %d", i, e["seq"], i)
		}
	}
	// Reopen: the tip must resume, not restart (no fork after restart).
	a2, err := OpenAuditLog(p)
	if err != nil {
		t.Fatal(err)
	}
	tip, seq := a2.ChainTip()
	if tip != prev || seq != 3 {
		t.Fatalf("tip not resumed: hash=%.12s seq=%d", tip, seq)
	}
	if err := a2.Append("run.killed", map[string]any{"run_id": "r2"}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLog(p); err != nil {
		t.Fatalf("chain broken across reopen: %v", err)
	}
}

func TestAuditChainDetectsEdit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	a, _ := OpenAuditLog(p)
	_ = a.Append("run.submitted", map[string]any{"run_id": "r1"})
	_ = a.Append("run.finished", map[string]any{"run_id": "r1", "status": "done"})
	raw, _ := os.ReadFile(p)
	// Attacker flips the outcome of the last entry; hashes stay as-is.
	doctored := strings.Replace(string(raw), `"done"`, `"failed"`, 1)
	if doctored == string(raw) {
		t.Fatal("test setup failed: status string not found")
	}
	if err := os.WriteFile(p, []byte(doctored), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLog(p); err == nil {
		t.Fatal("edited line NOT detected")
	} else if !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("wrong error for edit: %v", err)
	}
}

func TestAuditChainDetectsRelink(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	a, _ := OpenAuditLog(p)
	_ = a.Append("run.submitted", map[string]any{"run_id": "r1"})
	_ = a.Append("run.finished", map[string]any{"run_id": "r1"})
	lines := strings.Split(strings.TrimRight(string(mustRead(t, p)), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d", len(lines))
	}
	// Attacker drops the first line, trying to hide the submission.
	if err := os.WriteFile(p, []byte(lines[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLog(p); err == nil {
		t.Fatal("dropped prefix line NOT detected")
	}
}

func TestAuditChainDetectsTornTail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	a, _ := OpenAuditLog(p)
	_ = a.Append("run.submitted", map[string]any{"run_id": "r1"})
	_ = a.Append("run.finished", map[string]any{"run_id": "r1", "status": "done"})
	raw := mustRead(t, p)
	// Crash mid-fsync: last 24 bytes never hit disk (mid-line cut).
	if err := os.WriteFile(p, raw[:len(raw)-24], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLog(p); err == nil {
		t.Fatal("truncated tail NOT detected")
	}
}

func TestAuditChainEmptyIsValid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := OpenAuditLog(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = a
	if err := VerifyLog(p); err != nil {
		t.Fatalf("empty log should verify: %v", err)
	}
}

func TestAuditChainLegacyPrefix(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	// Pre-v2 line without chain fields (trusted prefix after upgrade).
	if err := os.WriteFile(p, []byte("{\"at\":\"2026-01-01T00:00:00Z\",\"event\":\"run.submitted\",\"run_id\":\"old\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := OpenAuditLog(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Append("run.finished", map[string]any{"run_id": "old"}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLog(p); err != nil {
		t.Fatalf("legacy prefix should verify: %v", err)
	}
}

// TestVerifyExitCodes covers the -verify entry point: the exit status a CI job
// or an operator would act on.
func TestVerifyExitCodes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := OpenAuditLog(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Append("run.submitted", map[string]any{"run_id": "r1"})
	_ = a.Append("run.finished", map[string]any{"run_id": "r1", "status": "done"})

	var out, errOut bytes.Buffer
	if code := runVerify(p, "", &out, &errOut); code != 0 {
		t.Fatalf("valid chain exit=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "audit chain OK") {
		t.Fatalf("unexpected stdout: %q", out.String())
	}

	// Edit one byte of the middle entry and re-verify.
	raw := mustRead(t, p)
	doctored := strings.Replace(string(raw), `"run_id":"r1"`, `"run_id":"rX"`, 1)
	if doctored == string(raw) {
		t.Fatal("test setup failed: run_id not found")
	}
	if err := os.WriteFile(p, []byte(doctored), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := runVerify(p, "", &out, &errOut); code != 1 {
		t.Fatalf("edited line exit=%d want 1", code)
	}
	if !strings.Contains(errOut.String(), "TAMPER DETECTED") {
		t.Fatalf("missing tamper banner: %q", errOut.String())
	}

	// Truncate the tail (crash mid-fsync) and re-verify.
	if err := os.WriteFile(p, raw[:len(raw)-20], 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runVerify(p, "", &out, &errOut); code != 1 {
		t.Fatalf("truncated tail exit=%d want 1", code)
	}
}

// TestVerifyUnavailableLogFailsClosed: a log we cannot read must not be
// reported as verified — it is a failure with a distinct message.
func TestVerifyUnavailableLogFailsClosed(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runVerify(filepath.Join(t.TempDir(), "absent.jsonl"), "", &out, &errOut); code != 1 {
		t.Fatalf("missing log exit=%d want 1", code)
	}
	if !strings.Contains(errOut.String(), "AUDIT LOG UNAVAILABLE") {
		t.Fatalf("unexpected stderr: %q", errOut.String())
	}
	if strings.Contains(errOut.String(), "audit chain OK") {
		t.Fatal("a missing log must never be reported as OK")
	}
}

// TestAuditRefusesToForkAfterCorruption: a corrupt log must stop the daemon at
// boot rather than append past the damage and hide it.
func TestAuditRefusesToForkAfterCorruption(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := OpenAuditLog(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Append("run.submitted", map[string]any{"run_id": "r1"})
	if err := os.WriteFile(p, []byte("{\"at\":\"2026-01-01T00:00:00Z\",\"event\":\"r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAuditLog(p); err == nil {
		t.Fatal("expected OpenAuditLog to reject a corrupt log")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
