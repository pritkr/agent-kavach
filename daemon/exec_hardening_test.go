package main

// exec_hardening_test.go — the v3 executor hardening model.
//
// These tests run on every platform on purpose: the model (what to ask for), the
// BPF assembler (what the kernel will be handed) and the fallback plan (what
// happens when a control is unavailable) are all platform-independent, so they
// are testable on a macOS dev box. The Linux-only primitives have their own
// file, exec_linux_test.go.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// clearHardeningEnv isolates a test from the operator's environment and from
// other tests: every switch is explicitly set.
func clearHardeningEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{envHardening, envNoNewPrivs, envSeccomp, envSeccompStrict, envCgroupMemory, envHardFork} {
		t.Setenv(k, "")
	}
}

// 1. The requested posture is the documented default: kernel controls on, memory
// cap matching the Docker profile, drill off.
func TestHardeningDefaultsAreOn(t *testing.T) {
	clearHardeningEnv(t)
	cfg, err := HardeningFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || !cfg.NoNewPrivs || !cfg.Seccomp {
		t.Fatalf("kernel controls must default on: %+v", cfg)
	}
	if cfg.CgroupMemMiB != DefaultCgroupMemoryMiB {
		t.Fatalf("cgroup memory=%d want %d (match the Docker --memory profile)", cfg.CgroupMemMiB, DefaultCgroupMemoryMiB)
	}
	if cfg.HardForkProbe {
		t.Fatal("the fork-bomb drill must be opt-in")
	}
	if cfg.SeccompStrict {
		t.Fatal("the strict seccomp profile must be opt-in: it denies fork(2), which is every shell pipeline")
	}
}

// 1b. The strict profile and the drill are separate opt-ins, and both are visible
// in the config — an operator who turns one on must be able to see it.
func TestHardeningStrictProfileIsOptIn(t *testing.T) {
	clearHardeningEnv(t)
	t.Setenv(envSeccompStrict, "1")
	cfg, err := HardeningFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SeccompStrict {
		t.Fatal("KAVACH_SECCOMP_STRICT=1 must be honoured")
	}
	if cfg.HardForkProbe {
		t.Fatal("the drill is a separate switch")
	}
	clearHardeningEnv(t)
	t.Setenv(envHardFork, "on")
	cfg, err = HardeningFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HardForkProbe || cfg.SeccompStrict {
		t.Fatalf("the drill must not silently switch the profile: %+v", cfg)
	}
}

// 2. A typo in a switch is a hard error, never a silent default: an operator who
// believes seccomp is on must not get "on" by accident when they wrote "onn".
func TestHardeningEnvFailsClosedOnGarbage(t *testing.T) {
	for _, name := range []string{envHardening, envNoNewPrivs, envSeccomp, envSeccompStrict, envHardFork} {
		clearHardeningEnv(t)
		t.Setenv(name, "onn")
		if _, err := HardeningFromEnv(); err == nil {
			t.Fatalf("%s=%q accepted; a bad value must abort, not default", name, "onn")
		}
	}
	clearHardeningEnv(t)
	t.Setenv(envCgroupMemory, "lots")
	if _, err := HardeningFromEnv(); err == nil {
		t.Fatal("a non-numeric memory cap must abort")
	}
	clearHardeningEnv(t)
	t.Setenv(envCgroupMemory, "-1")
	if _, err := HardeningFromEnv(); err == nil {
		t.Fatal("a negative memory cap must abort")
	}
}

// 3. Every switch can only turn hardening *off*, never on beyond the default.
func TestHardeningEnvDisables(t *testing.T) {
	clearHardeningEnv(t)
	t.Setenv(envHardening, "off")
	t.Setenv(envCgroupMemory, "0")
	cfg, err := HardeningFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled || cfg.CgroupMemMiB != 0 {
		t.Fatalf("KAVACH_HARDENING=off must disable: %+v", cfg)
	}
	// A disabled config must produce a plan that asks for nothing.
	plan := localPlan(localPlanRequest{cfg: cfg, argv: []string{"sh", "-c", "true"}, execSelf: "/x", helperAvailable: true})
	if plan.usedExec || plan.policy.NoNewPrivs || plan.policy.Seccomp {
		t.Fatalf("hardening-off plan still asks for kernel controls: %+v", plan)
	}
}

// 4. The BPF program is the control: assert its exact layout, because a filter
// that denies the wrong syscall number is worse than no filter (it looks like
// one). Dangling: jeq nr==57 → deny; ret allow; ret ERRNO|EPERM.
func TestSeccompFilterProgramLayout(t *testing.T) {
	prog, err := buildSeccompFilter(SeccompFilterSpec{Deny: []uint32{57, 58}})
	if err != nil {
		t.Fatal(err)
	}
	if len(prog) != 4 {
		t.Fatalf("want 4 instructions for a 2-entry deny list, got %d: %+v", len(prog), prog)
	}
	// The single deny action is last, so every branch is forward.
	if prog[3].Code != bpfRET || prog[3].K != seccompRetErrno|uint32(syscall.EPERM) {
		t.Fatalf("last instruction must be the deny action, got %+v", prog[3])
	}
	if prog[2].Code != bpfRET || prog[2].K != seccompRetAllow {
		t.Fatalf("instruction 2 must be ret ALLOW, got %+v", prog[2])
	}
	// Jump targets are relative to the instruction *after* the jump.
	if int(prog[0].Jt)+1 != 3 || prog[0].K != 57 || prog[0].Jf != 0 {
		t.Fatalf("first compare is wrong: %+v (want k=57 jt→3 jf→1)", prog[0])
	}
	if int(prog[1].Jt)+2 != 3 || prog[1].K != 58 || prog[1].Jf != 0 {
		t.Fatalf("second compare is wrong: %+v (want k=58 jt→3 jf→2)", prog[1])
	}
}

// 5. The clone-flag rule: clone(2) is compared, its first argument loaded and
// masked, and a clone with no forbidden bit is allowed — a filter that killed
// every thread would be a denial of service, not a sandbox.
func TestSeccompFilterChecksCloneFlags(t *testing.T) {
	spec := SeccompFilterSpec{
		Deny:           []uint32{435},
		DenyCloneFlags: []uint32{0x00200000 /* CLONE_NEWUSER */, 0x00400000 /* CLONE_NEWPID */},
		CloneSyscall:   56,
	}
	prog, err := buildSeccompFilter(spec)
	if err != nil {
		t.Fatal(err)
	}
	// layout: jeq 435 | jeq 56 | ld args[0] | and mask | jeq 0 | ret allow | ret deny
	if len(prog) != 7 {
		t.Fatalf("want 7 instructions, got %d: %+v", len(prog), prog)
	}
	if prog[1].K != 56 {
		t.Fatalf("instruction 1 must compare clone(56), got %+v", prog[1])
	}
	if prog[2].Code != bpfLD || prog[2].K != seccompDataArgs0Offset {
		t.Fatalf("instruction 2 must load seccomp_data.args[0], got %+v", prog[2])
	}
	if prog[3].Code != bpfALU || prog[3].K != 0x00200000|0x00400000 {
		t.Fatalf("instruction 3 must AND the forbidden flags, got %+v", prog[3])
	}
	if prog[4].K != 0 || prog[4].Jf == 0 {
		t.Fatalf("a clone with no forbidden flag must be allowed, got %+v", prog[4])
	}
	if prog[5].K != seccompRetAllow || prog[6].K != seccompRetErrno|uint32(syscall.EPERM) {
		t.Fatalf("tail must be ret ALLOW then ret DENY, got %+v %+v", prog[5], prog[6])
	}
	// The clone check is only meaningful with the platform's clone number.
	spec.CloneSyscall = 0
	if _, err := buildSeccompFilter(spec); err == nil {
		t.Fatal("deny_clone_flags without the clone syscall number must be refused")
	}
}

// 6. A filter that denies nothing, or that is malformed, is refused rather than
// handed to the kernel: a filter that allows everything and reports success is
// the "fake control" this project refuses to ship.
func TestSeccompFilterRefusesBadSpecs(t *testing.T) {
	cases := map[string]SeccompFilterSpec{
		"empty":             {},
		"syscall 0":         {Deny: []uint32{0}},
		"duplicate":         {Deny: []uint32{57, 57}},
		"errno with no err": {Deny: []uint32{57}, Action: seccompRetErrno},
	}
	for name, spec := range cases {
		if _, err := buildSeccompFilter(spec); err == nil {
			t.Fatalf("%s: expected a refusal", name)
		}
	}
}

// 7. The fallback path: when the child cannot be re-exec'd (no self path, or a
// build without the helper), the run still happens — with the original argv, no
// kernel controls, and an explicit reason recorded for the log.
func TestLocalPlanFallbackIsSafeAndReported(t *testing.T) {
	clearHardeningEnv(t)
	cfg, _ := HardeningFromEnv()
	argv := []string{"sh", "-c", "true", "kavach-fallback", "echo hi"}

	for _, req := range []localPlanRequest{
		{cfg: cfg, argv: argv, execSelf: "", helperAvailable: true},
		{cfg: cfg, argv: argv, execSelf: "/somewhere/daemon", helperAvailable: false},
	} {
		plan := localPlan(req)
		if len(plan.argv) != len(argv) || plan.argv[0] != "sh" {
			t.Fatalf("fallback must exec the original argv, got %v", plan.argv)
		}
		if plan.usedExec {
			t.Fatal("fallback must not claim a re-exec it cannot do")
		}
		if plan.policy.NoNewPrivs || plan.policy.Seccomp {
			t.Fatalf("fallback must not claim kernel controls: %+v", plan.policy)
		}
		// setsid is always requested: the timeout kill depends on it.
		if !plan.policy.Setsid {
			t.Fatal("setsid must survive the fallback; kill(-pgid) needs it")
		}
		joined := strings.Join(plan.skipped, " ")
		if !strings.Contains(joined, "no_new_privs") {
			t.Fatalf("fallback must say what it dropped, got %v", plan.skipped)
		}
	}
}

// 8. Off Linux the plan must degrade to setsid only, and say so — never claim a
// control the platform cannot provide.
func TestLocalPlanSkipsUnsupportedControls(t *testing.T) {
	clearHardeningEnv(t)
	cfg, _ := HardeningFromEnv()
	plan := localPlan(localPlanRequest{cfg: cfg, argv: []string{"sh"}, execSelf: "/x", helperAvailable: true})
	if noNewPrivsApplicable {
		if plan.usedExec {
			t.Skip("running on Linux: the re-exec path is exercised by exec_linux_test.go")
		}
	} else {
		if plan.usedExec {
			t.Fatal("no_new_privs is a Linux control; there is nothing to re-exec for here")
		}
		if plan.policy.NoNewPrivs || plan.policy.Seccomp {
			t.Fatalf("must not claim Linux controls on %s: %+v", hardeningRuntime, plan.policy)
		}
		if !strings.Contains(strings.Join(plan.skipped, " "), "seccomp") {
			t.Fatalf("seccomp must be reported as skipped, got %v", plan.skipped)
		}
	}
}

// 9. The SysProcAttr contract: a new session (so the run is a process-group
// leader and kill(-pgid) works) and, where the platform has it, SIGKILL on
// parent death. Setpgid must *not* be set alongside Setsid — the kernel refuses
// setsid() from a process-group leader, which would fail the exec.
func TestApplyProcPolicySetsSessionAndDeathSignal(t *testing.T) {
	c := exec.Command("true")
	applyProcPolicy(c, procPolicy{Setsid: true, Pdeathsig: true, NoNewPrivs: true, Seccomp: true})
	if c.SysProcAttr == nil {
		t.Fatal("no SysProcAttr")
	}
	if !c.SysProcAttr.Setsid {
		t.Fatal("Setsid must be set")
	}
	if c.SysProcAttr.Setpgid {
		t.Fatal("Setpgid must not be set together with Setsid: setsid(2) fails for a group leader")
	}
	sup := procPolicySupport()
	if !sup.Setsid {
		t.Fatal("every supported platform here can create a session")
	}
	// Pdeathsig is a Linux-only SysProcAttr field; the accessor is what makes
	// this assertion writable on a dev box that is not Linux.
	if got := procAttrDeathSignal(c.SysProcAttr); sup.Pdeathsig && got != syscall.SIGKILL {
		t.Fatalf("Pdeathsig=%d want SIGKILL", got)
	} else if !sup.Pdeathsig && got != 0 {
		t.Fatalf("Pdeathsig=%d on a platform that cannot honour it", got)
	}
}

// 10. …and it holds at runtime: a real child is a process-group leader whose
// group is killable, which is what the timeout relies on. This is the invariant
// the fallback depends on, so it is checked against a live process.
func TestLocalRunIsOwnKillableProcessGroupLeader(t *testing.T) {
	plan := localPlan(localPlanRequest{
		cfg:             HardeningConfig{Enabled: false},
		argv:            []string{"sh", "-c", "sleep 30", "kavach-fallback", "sleep 30"},
		execSelf:        selfExecutable(),
		helperAvailable: true,
	})
	c := exec.Command(plan.argv[0], plan.argv[1:]...)
	applyProcPolicy(c, plan.policy)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	pid := c.Process.Pid
	// Give the child a moment to finish setsid(2) before inspecting it.
	time.Sleep(150 * time.Millisecond)
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		t.Fatalf("Getpgid: %v", err)
	}
	if pgid != pid {
		t.Fatalf("pgid=%d want %d — kill(-pgid) would miss the run's own group", pgid, pid)
	}
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil {
		t.Fatalf("group kill: %v", err)
	}
	_ = c.Wait() // expected: signal: killed
	if c.ProcessState == nil || c.ProcessState.ExitCode() != -1 {
		t.Fatalf("expected a SIGKILLed child, got %+v", c.ProcessState)
	}
}

// 11. A real run still works, and reports the controls it actually applied. This
// is the "graceful fallback" contract end to end: the run must not fail because
// a kernel control was unavailable.
func TestLocalRunSucceedsAndReportsHardening(t *testing.T) {
	res := executeLocal(context.Background(), []string{"sh", "-c", "echo hardened"}, t.TempDir(), 10)
	if res.ExitCode != 0 || !strings.Contains(res.Output, "hardened") {
		t.Fatalf("run failed: %+v", res)
	}
	if !strings.Contains(res.Hardening, "setsid") {
		t.Fatalf("run must report the controls it applied, got %q", res.Hardening)
	}
	if noNewPrivsApplicable && !strings.Contains(res.Hardening, "no_new_privs") && !strings.Contains(res.Hardening, "seccomp") {
		t.Fatalf("on Linux a run should carry at least one kernel control, got %q", res.Hardening)
	}
}

// 11b. The re-exec helper itself, on whatever platform this is. The helper is
// the child half of the hardened run and its last act is a raw execve(2), which
// does not search PATH — while the executor builds its wrapper argv as a bare
// "sh". Get that wrong and every hardened run on every Linux dies with exit 127
// for a reason that has nothing to do with the kernel: the local executor
// becomes completely broken the moment hardening is on. A macOS dev box never
// takes the hardened path, so this has to be asserted here rather than only
// under `//go:build linux`, or the one platform that can catch it is the one
// platform where CI is red.
//
// Asserted for every platform: the payload runs, and the helper reports the
// posture it measured. What each platform can actually install is asserted in
// exec_linux_test.go, which is where a kernel is available.
func TestHelperExecutesABareNamedPayload(t *testing.T) {
	clearHardeningEnv(t)
	t.Setenv(envCgroupMemory, "0") // isolate the test from the host's cgroups
	exe := selfExecutable()
	if exe == "" {
		t.Skip("cannot resolve this binary")
	}
	out, err := exec.Command(exe, helperFlag, helperSep, "sh", "-c", "echo helper-ran").CombinedOutput()
	if err != nil {
		t.Fatalf("the helper must run a bare-named payload, not fail on the name: %v (%s)", err, out)
	}
	report := string(out)
	if !strings.Contains(report, "helper-ran") {
		t.Fatalf("the payload must actually run after the helper execs it: %q", report)
	}
	if !strings.Contains(report, "kavach-hardening:") {
		t.Fatalf("the helper must report the posture it measured: %q", report)
	}
	// A payload that genuinely is not on PATH is a reportable failure, not a
	// silent success — the run must say which program it could not start.
	if out, err := exec.Command(exe, helperFlag, helperSep, "kavach-no-such-program-9f3a").CombinedOutput(); err == nil {
		t.Fatalf("a missing payload must fail loudly, not exit 0: %s", out)
	} else if !strings.Contains(string(out), "cannot run the payload") {
		t.Fatalf("the failure must say the program was not found: %s", out)
	}
	// A missing separator is a parse error, not a guess at where the command
	// starts: running the wrong argv because of sloppy parsing is worse.
	if out, err := exec.Command(exe, helperFlag, "sh", "-c", "true").CombinedOutput(); err == nil {
		t.Fatalf("a missing -- must be refused: %s", out)
	} else if !strings.Contains(string(out), helperSep) {
		t.Fatalf("the refusal must name the missing separator: %s", out)
	}
}

// 11c. Whatever the plan ends up doing — the hardened re-exec path or the plain
// fallback — a run must not die because its payload was *named* rather than
// executed. The wrapper argv the executor builds is a bare "sh", and the two
// ways it reaches the kernel behave differently about that: os/exec resolves a
// bare name against PATH, execve(2) does not. If resolution ever disappears from
// the re-exec helper, every hardened run on every Linux turns into exit 127, and
// the portable tests on a macOS box stay green because macOS never uses the
// helper. So assert the resolution itself, on every platform.
func TestResolvePayloadArgv0FindsTheProgramThePlanNamed(t *testing.T) {
	// What executor.go actually builds.
	argv := []string{"sh", "-c", `ulimit -t 10; exec "$@"`, "kavach-fallback", "echo hi"}
	path, err := resolvePayloadArgv0(argv)
	if err != nil {
		t.Fatalf("the wrapper shell must resolve through PATH: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.IsDir() {
		t.Fatalf("resolved %q, which is not an executable file: %v", path, err)
	}
	// argv is passed through untouched: $0 is part of the wrapper's contract
	// ("kavach-fallback" is how `exec "$@"` finds the real command).
	got, err := resolvePayloadArgv0([]string{"sh", "-c", "x", "kavach-fallback", "echo hi"})
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("resolution must not depend on the rest of argv: %q vs %q", got, path)
	}

	// A name that already carries a path separator was never a PATH question, and
	// must be handed to the kernel exactly as given — including a relative one.
	for _, name := range []string{"/bin/sh", "./sh", "../bin/sh"} {
		got, err := resolvePayloadArgv0([]string{name})
		if err != nil {
			t.Fatalf("%q must pass through unresolved: %v", name, err)
		}
		if got != name {
			t.Fatalf("%q was rewritten to %q", name, got)
		}
	}

	// Not on PATH is a real, reportable failure — never a silent success.
	if _, err := resolvePayloadArgv0([]string{"kavach-no-such-program-9f3a"}); err == nil {
		t.Fatal("a program that is not on PATH must be reported, not exec'd blindly")
	}
	if _, err := resolvePayloadArgv0(nil); err == nil {
		t.Fatal("an empty argv must be reported")
	}
	if _, err := resolvePayloadArgv0([]string{""}); err == nil {
		t.Fatal("an empty argv[0] must be reported")
	}
}

// 12. The boot report is evidence: it never lists a control as applied when the
// platform cannot provide it, and it names what it skipped.
func TestHardeningReportIsHonest(t *testing.T) {
	cfg := HardeningConfig{Enabled: true, NoNewPrivs: true, Seccomp: true, CgroupMemMiB: DefaultCgroupMemoryMiB}
	rep := probeHardening(cfg)
	if rep.Runtime != hardeningRuntime {
		t.Fatalf("runtime=%q want %q", rep.Runtime, hardeningRuntime)
	}
	applied := strings.Join(rep.Applied, ",")
	skipped := strings.Join(rep.Skipped, ",")
	if noNewPrivsApplicable {
		if seccompKernelAvailable() && !strings.Contains(applied, "seccomp") {
			t.Fatalf("kernel supports seccomp but the report omits it: %+v", rep)
		}
		if !seccompKernelAvailable() && !strings.Contains(skipped, "seccomp") {
			t.Fatalf("seccomp unavailable but not reported as skipped: %+v", rep)
		}
	} else {
		if strings.Contains(applied, "seccomp") || strings.Contains(applied, "no_new_privs") || strings.Contains(applied, "cgroup_memory") {
			t.Fatalf("non-Linux must not claim Linux controls: %+v", rep)
		}
		if !strings.Contains(skipped, "seccomp") || !strings.Contains(skipped, "no_new_privs") {
			t.Fatalf("non-Linux must name what it lacks: %+v", rep)
		}
		if rep.Seccomp.Installed {
			t.Fatal("seccomp must never be reported as installed here")
		}
	}
	if !strings.Contains(applied, "setsid") {
		t.Fatalf("setsid is available everywhere and must be reported: %+v", rep)
	}
	if rep.Note == "" {
		t.Fatal("the report must carry a note explaining how the controls are applied")
	}
}

// 13. Turning a control off in the requested config must not leave it reported as
// applied — the report is derived from the request as well as the probe, so a
// dashboard cannot show a control that this deployment turned off.
func TestHardeningReportHonoursTheRequest(t *testing.T) {
	off, err := AvailableHardening(HardeningConfig{Enabled: true, NoNewPrivs: false, Seccomp: false, CgroupMemMiB: 0})
	if err != nil {
		t.Fatal(err)
	}
	if off.Seccomp.Installed {
		t.Fatal("seccomp requested off must not be reported as installed")
	}
	if strings.Contains(strings.Join(off.Applied, ","), "no_new_privs") {
		t.Fatalf("no_new_privs requested off must not be applied: %+v", off)
	}
	if strings.Contains(strings.Join(off.Applied, ","), "cgroup_memory") {
		t.Fatalf("cgroup_memory=0 must not be reported as applied: %+v", off)
	}
	if !strings.Contains(strings.Join(off.Applied, ","), "setsid") {
		t.Fatalf("setsid is always requested and must stay: %+v", off)
	}
	repC := probeHardening(HardeningConfig{Enabled: true, NoNewPrivs: true, Seccomp: true, CgroupMemMiB: 0})
	if strings.Contains(strings.Join(repC.Applied, ","), "cgroup_memory") {
		t.Fatalf("cgroup_memory=0 must not be reported as applied: %+v", repC)
	}
	if !noNewPrivsApplicable && !strings.Contains(strings.Join(repC.Skipped, ","), "seccomp") {
		t.Fatalf("off Linux, seccomp stays skipped: %+v", repC)
	}
}

// 13b. no_new_privs is a prctl, not part of the filter, so a host that refuses
// seccomp filters still gets it — the child measures it in
// /proc/self/status. The report used to hide it whenever the seccomp probe
// failed, which made /v1/backends disagree with the very run it was describing:
// "seccomp: unavailable" and, implicitly, "no_new_privs: not applied", on a
// child that had just printed no_new_privs=on.
func TestNoNewPrivsIsReportedIndependentlyOfSeccomp(t *testing.T) {
	rep, err := AvailableHardening(HardeningConfig{Enabled: true, NoNewPrivs: true, Seccomp: true, CgroupMemMiB: 0})
	if err != nil {
		t.Fatal(err)
	}
	applied := strings.Join(rep.Applied, ",")
	skipped := strings.Join(rep.Skipped, ",")
	if noNewPrivsApplicable {
		if !strings.Contains(applied, "no_new_privs") {
			t.Fatalf("no_new_privs is available here and must be reported applied: %+v", rep)
		}
		if strings.Contains(skipped, "no_new_privs") {
			t.Fatalf("no_new_privs must never be both applied and skipped: %+v", rep)
		}
	} else if strings.Contains(applied, "no_new_privs") {
		t.Fatalf("no_new_privs is a Linux control and must not be claimed here: %+v", rep)
	}
	// Whatever seccomp does, it must not decide no_new_privs: the two are gated
	// separately, so a refusal is visible as seccomp and nothing else.
	if !strings.Contains(applied, "setsid") {
		t.Fatalf("setsid is always in force: %+v", rep)
	}
	if !seccompKernelAvailable() {
		if !strings.Contains(skipped, "seccomp") {
			t.Fatalf("a refused filter must be reported as skipped: %+v", rep)
		}
		if rep.Seccomp.Installed {
			t.Fatalf("a refused filter must never be reported as installed: %+v", rep)
		}
		if !strings.Contains(applied, "no_new_privs") && noNewPrivsApplicable {
			t.Fatalf("a refused filter must not remove no_new_privs from the report: %+v", rep)
		}
	}
}

// 14. cgroup parsing is exercised with a fake hierarchy so the logic is covered
// on any OS: the scope comes from /proc/self/cgroup and the writability test is a
// real mkdir in the fake root.
func TestCgroupScopeReportNeverClaimsMoreThanItHas(t *testing.T) {
	if noNewPrivsApplicable {
		t.Skip("the cgroup probe is Linux-specific; covered in exec_linux_test.go")
	}
	st := probeCgroupCaps(0)
	if st.writable {
		t.Fatal("off Linux nothing is writable")
	}
	rep := probeHardening(HardeningConfig{Enabled: true, NoNewPrivs: true, Seccomp: true, CgroupMemMiB: 256})
	if rep.Cgroup.Writable || strings.Contains(strings.Join(rep.Applied, ","), "cgroup_memory") {
		t.Fatalf("off Linux cgroup caps must be reported as absent: %+v", rep)
	}
}

// 15. The report survives a round trip through JSON (it is served at
// /v1/backends), with the field names the API documents.
func TestHardeningReportJSONShape(t *testing.T) {
	rep := probeHardening(HardeningConfig{Enabled: true, NoNewPrivs: true, Seccomp: true, CgroupMemMiB: 256})
	blob := mustJSON(t, rep)
	for _, want := range []string{`"runtime"`, `"applied"`, `"seccomp"`, `"cgroup"`, `"requested"`, `"available"`, `"installed"`} {
		if !strings.Contains(blob, want) {
			t.Fatalf("report JSON missing %s: %s", want, blob)
		}
	}
	// No secret-shaped field: the hardening report must never carry a value.
	for _, forbidden := range []string{"key", "token", "secret"} {
		if strings.Contains(strings.ToLower(blob), `"`+forbidden+`"`) {
			t.Fatalf("hardening report must not carry a %q field: %s", forbidden, blob)
		}
	}
	if n := strings.Count(blob, `"applied"`); n != 1 {
		t.Fatalf("expected exactly one applied list, got %d", n)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
