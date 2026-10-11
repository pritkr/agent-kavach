package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// ExecResult is the outcome of one sandboxed command execution.
type ExecResult struct {
	Output   string
	ExitCode int
	Sandbox  string // "docker" | "local" | "runsc"
	ErrMsg   string
	Killed   bool
	// Hardening names the kernel-level controls actually applied to the child
	// (v3), e.g. "no_new_privs+seccomp+setsid". It is evidence, not a promise:
	// it reflects the plan this run really used, after every probe.
	Hardening string
}

const maxOutputBytes = 256 * 1024 // 256 KiB cap per run

// DockerAvailable reports whether the docker CLI exists on PATH.
func DockerAvailable() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

// Execute runs cmd sandboxed through the strongest available backend (see
// sandbox.go): gVisor/runsc, else Docker, else a local subprocess wrapped with
// rlimits + timeout + process-group kill + the v3 kernel hardening.
func Execute(ctx context.Context, cmd []string, image, workspace string, timeoutSec int, containerName string) ExecResult {
	return ExecuteWithEnv(ctx, cmd, image, workspace, timeoutSec, containerName, "", nil)
}

// ExecuteWithEnv is Execute with vault-backed credential injection: the tool
// binding selects which process-env secrets the child receives (nil vault =
// legacy inherit-everything mode). Every byte of child output is scrubbed of
// known secret values before it is returned, so redaction holds even when a
// command echoes its own environment.
// It resolves a backend the same way the server does (strongest available), so
// there is exactly one place that knows what a run's confinement is — and one
// place that can refuse.
func ExecuteWithEnv(ctx context.Context, cmd []string, image, workspace string, timeoutSec int, containerName, tool string, v *Vault) ExecResult {
	b, err := NewBackendRegistry(BackendAuto).Select()
	if err != nil {
		return ExecResult{Sandbox: BackendLocal, ExitCode: 125, ErrMsg: err.Error(), Hardening: "none"}
	}
	out := b.Run(ctx, RunRequest{
		Command:   cmd,
		Image:     image,
		Workspace: workspace,
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Name:      containerName,
		Env:       buildEnv(tool, v),
	})
	return redactOutcome(ExecResult{
		Output:    out.Output,
		ExitCode:  out.ExitCode,
		Killed:    out.Killed,
		ErrMsg:    out.ErrMsg,
		Sandbox:   out.Backend,
		Hardening: out.Hardening,
	}, v)
}

// redactOutcome scrubs every known secret value out of a finished run's output
// and error. It lives here — not at the call site — because the backend registry
// (v3) reaches the executor by a different route than ExecuteWithEnv, and
// redaction that depends on the route taken is redaction that eventually gets
// skipped. The snapshot is read live, so a secret exported after boot is still
// masked.
func redactOutcome(res ExecResult, v *Vault) ExecResult {
	if v == nil {
		return res
	}
	if secrets := v.SecretsSnapshot(); len(secrets) > 0 {
		res.Output = RedactText(res.Output, secrets)
		res.ErrMsg = RedactText(res.ErrMsg, secrets)
	}
	return res
}

func truncate(b []byte) string {
	if len(b) > maxOutputBytes {
		return string(b[:maxOutputBytes]) + fmt.Sprintf("\n…[truncated %d bytes]", len(b)-maxOutputBytes)
	}
	return string(b)
}

// executeLocal is the fallback when Docker is absent: the command is wrapped
// in `sh` with hard rlimits (ulimit -t CPU seconds, -v address space,
// -f max file size), a wall-clock timeout, and process-group kill so no
// orphaned grandchildren survive. It inherits the parent environment
// (legacy mode); use executeLocalEnv for vault-restricted env.
func executeLocal(ctx context.Context, cmd []string, workspace string, timeoutSec int) ExecResult {
	return executeLocalEnv(ctx, cmd, workspace, timeoutSec, nil)
}

// executeLocalEnv is executeLocal with an explicit child environment. A
// non-nil env replaces the inherited environment (vault-restricted mode);
// nil inherits it (legacy mode).
func executeLocalEnv(ctx context.Context, cmd []string, workspace string, timeoutSec int, env []string) ExecResult {
	if len(cmd) == 0 {
		return ExecResult{ErrMsg: "empty command", ExitCode: 2}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	// ulimit -t <cpu> -v <addrspace KB> -f <filesize KB>; timeout slightly
	// above the wall clock so SIGKILL-by-timeout wins deterministically.
	cpuLimit := timeoutSec + 5
	if cpuLimit < 10 {
		cpuLimit = 10
	}
	wrapper := fmt.Sprintf("ulimit -t %d; ulimit -v 524288; ulimit -f 102400; exec \"$@\"", cpuLimit)
	argv := append([]string{"sh", "-c", wrapper, "kavach-fallback"}, cmd...)

	// v3 hardening. localPlan decides what is actually possible here (kernel
	// probes, the re-exec helper, operator switches) and returns both the argv to
	// run and the process policy to ask for. Whatever it drops comes back in
	// skipped[] and is logged — the fallback path is a degraded *report*, never
	// a silent one.
	plan := localPlan(localPlanRequest{
		cfg:             localHardeningConfig(),
		argv:            argv,
		execSelf:        selfExecutable(),
		helperAvailable: true,
	})
	for _, s := range plan.skipped {
		logHardeningWarn("plan:"+s, s+" — run without it")
	}
	c := exec.CommandContext(ctx, plan.argv[0], plan.argv[1:]...)
	c.Dir = workspace
	if env != nil {
		c.Env = env
	}
	// Setsid (a new session *and* process group) so SIGKILL reaches the whole
	// tree on timeout; Pdeathsig on Linux so a daemon crash cannot orphan the
	// payload. The seccomp filter and no_new_privs are installed by the re-exec
	// helper this plan may have prepended, before it execs `sh`.
	applyProcPolicy(c, plan.policy)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	// Start explicitly so the pid is published before the killer goroutine can
	// read it: exec.Cmd.Process is written by Start, so touching it from
	// another goroutine beforehand is a data race (and would silently miss the
	// kill, leaving orphaned grandchildren).
	if err := c.Start(); err != nil {
		return ExecResult{Sandbox: "local", ExitCode: 1, ErrMsg: err.Error(), Hardening: strings.Join(plan.summarize(), "+")}
	}
	pgid := c.Process.Pid
	// Defensive: kill the whole group if the context fires before Go's own
	// killer does. select on `finished` so the goroutine always exits.
	finished := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		case <-finished:
		}
	}()
	err := c.Wait()
	close(finished)
	res := ExecResult{
		Output:    truncate(out.Bytes()),
		Sandbox:   "local",
		Hardening: strings.Join(plan.summarize(), "+"),
	}
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			res.Killed = true
			res.ErrMsg = fmt.Sprintf("timeout after %ds", timeoutSec)
			res.ExitCode = 124
			return res
		}
		res.ErrMsg = err.Error()
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		} else {
			res.ExitCode = 1
		}
		return res
	}
	res.ExitCode = 0
	return res
}
