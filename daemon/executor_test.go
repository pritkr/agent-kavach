package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestExecuteLocalEcho(t *testing.T) {
	if DockerAvailable() {
		t.Skip("docker present; local fallback covered by executeLocal tests below")
	}
	res := Execute(context.Background(), []string{"echo", "hello-kavach"}, "", t.TempDir(), 10, "x")
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d err=%s out=%s", res.ExitCode, res.ErrMsg, res.Output)
	}
	if !strings.Contains(res.Output, "hello-kavach") {
		t.Fatalf("missing output: %q", res.Output)
	}
	if res.Sandbox != "local" {
		t.Fatalf("sandbox=%q want local", res.Sandbox)
	}
}

func TestExecuteLocalDirect(t *testing.T) {
	res := executeLocal(context.Background(), []string{"echo", "direct"}, t.TempDir(), 10)
	if res.ExitCode != 0 || !strings.Contains(res.Output, "direct") {
		t.Fatalf("unexpected: %+v", res)
	}
}

func TestExecuteEmptyCommand(t *testing.T) {
	res := Execute(context.Background(), nil, "", t.TempDir(), 10, "x")
	if res.ExitCode == 0 || res.ErrMsg == "" {
		t.Fatalf("expected failure: %+v", res)
	}
}

func TestExecuteLocalFailureCode(t *testing.T) {
	res := executeLocal(context.Background(), []string{"sh", "-c", "exit 3"}, t.TempDir(), 10)
	if res.ExitCode != 3 {
		t.Fatalf("exit=%d want 3 (%+v)", res.ExitCode, res)
	}
	if res.Killed {
		t.Fatal("should not be marked killed")
	}
}

func TestExecuteLocalTimeoutKills(t *testing.T) {
	start := time.Now()
	res := executeLocal(context.Background(), []string{"sleep", "30"}, t.TempDir(), 1)
	if !res.Killed {
		t.Fatalf("expected killed: %+v", res)
	}
	if res.ExitCode != 124 {
		t.Fatalf("exit=%d want 124", res.ExitCode)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("timeout took too long: %v", time.Since(start))
	}
}

func TestExecuteLocalOutputTruncated(t *testing.T) {
	res := executeLocal(context.Background(), []string{"sh", "-c", "yes x | head -c 600000"}, t.TempDir(), 15)
	if len(res.Output) > maxOutputBytes+256 {
		t.Fatalf("output not truncated: %d bytes", len(res.Output))
	}
	if !strings.Contains(res.Output, "truncated") {
		t.Fatal("expected truncation marker")
	}
}
