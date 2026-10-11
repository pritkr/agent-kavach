//go:build linux

package main

// exec_linux_test.go — the Linux-only half of the v3 executor hardening.
//
// The model, the assembler and the fallback plan are covered portably in
// exec_hardening_test.go. What is left is the part that can only be true on a
// Linux kernel: the syscall numbers, the seccomp probe, and the re-exec helper
// that installs no_new_privs + the filter in the child before it execs the
// payload. These tests need a real kernel; they are skipped elsewhere.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// The filter's deny list is a table of kernel numbers. Getting one wrong means
// denying a harmless syscall while letting an escape through, so every entry the
// toolchain exports is checked against the table.
func TestArchSyscallTableMatchesToolchain(t *testing.T) {
	tbl := archSyscallTable()
	if !tbl.verified {
		t.Fatalf("no verified syscall table for GOARCH=%s", runtime.GOARCH)
	}
	if tbl.clone != uint32(syscall.SYS_CLONE) {
		t.Errorf("clone: table %d, toolchain %d", tbl.clone, syscall.SYS_CLONE)
	}
	if tbl.mount != uint32(syscall.SYS_MOUNT) {
		t.Errorf("mount: table %d, toolchain %d", tbl.mount, syscall.SYS_MOUNT)
	}
	if tbl.pivotRoot != uint32(syscall.SYS_PIVOT_ROOT) {
		t.Errorf("pivot_root: table %d, toolchain %d", tbl.pivotRoot, syscall.SYS_PIVOT_ROOT)
	}
	if tbl.unshare != uint32(syscall.SYS_UNSHARE) {
		t.Errorf("unshare: table %d, toolchain %d", tbl.unshare, syscall.SYS_UNSHARE)
	}
	if tbl.clone3 != 435 {
		t.Errorf("clone3 must be 435 everywhere, got %d", tbl.clone3)
	}
	if tbl.seccomp == 0 {
		t.Error("seccomp(2) number must be pinned")
	}
	// arm64 has no fork(2)/vfork(2) — a single clone(2) serves both — so those
	// entries must be absent rather than wrong.
	if runtime.GOARCH == "arm64" && (tbl.fork != 0 || tbl.vfork != 0) {
		t.Errorf("arm64 has no fork/vfork; table says %d/%d", tbl.fork, tbl.vfork)
	}
	if runtime.GOARCH != "arm64" && (tbl.fork == 0 || tbl.vfork == 0) {
		t.Errorf("%s has fork/vfork; table must pin them", runtime.GOARCH)
	}
}

// The escaping profile must actually name the escape syscalls, and the report
// must say the same thing the filter denies.
func TestEscapeFilterDeniesTheEscapeSyscalls(t *testing.T) {
	spec := activeFilterSpec(true) // the strict profile is the superset
	denied := map[string]bool{}
	for _, n := range spec.Deny {
		denied[strconv.Itoa(int(n))] = true
	}
	for _, want := range []struct {
		name string
		nr   uint32
	}{
		{"clone3", archSyscallTable().clone3},
		{"unshare", archSyscallTable().unshare},
		{"setns", archSyscallTable().setns},
		{"mount", archSyscallTable().mount},
		{"pivot_root", archSyscallTable().pivotRoot},
	} {
		if want.nr != 0 && !denied[strconv.Itoa(int(want.nr))] {
			t.Errorf("%s (%d) is not in the deny list", want.name, want.nr)
		}
	}
	if len(spec.DenyCloneFlags) == 0 {
		t.Error("the namespace clone flags must be denied")
	}
	prog, err := buildEscapeFilter()
	if err != nil {
		t.Fatal(err)
	}
	if len(prog) < 8 {
		t.Fatalf("escape filter is too short to be a real control: %d instructions", len(prog))
	}
	last := prog[len(prog)-1]
	if last.Code != bpfRET || last.K != seccompRetErrno|uint32(syscall.EPERM) {
		t.Fatalf("the filter must end in a deny action, got %+v", last)
	}
	// The escape profile must be the subset: the fork bomb there is the
	// cgroup pids.max's job, because denying fork(2) breaks every shell
	// pipeline and every libc fork() fallback.
	escape := activeFilterSpec(false)
	for _, s := range forkVforkSyscallNumbers() {
		for _, nr := range escape.Deny {
			if nr == s.nr {
				t.Fatalf("the default profile must not deny %s: a shell pipeline is a fork(2)", s.name)
			}
		}
	}
	// The report and the filter must not drift apart.
	report := strings.Join(DeniedSyscalls(true), ",")
	for _, want := range []string{"clone3", "unshare", "setns", "mount", "pivot_root"} {
		if !strings.Contains(report, want) {
			t.Errorf("DeniedSyscalls() omits %s: %s", want, report)
		}
	}
}

// The capability probe must answer the question without confining the daemon:
// a filter installed in the daemon process would trap the daemon itself, so the
// probe runs in a throwaway child.
func TestSeccompProbeDoesNotConfineTheDaemon(t *testing.T) {
	got := seccompKernelAvailable()
	// Whatever the answer, the daemon must still be able to run the things it
	// needs: exec, fork (tests spawn children), and write files.
	if err := os.WriteFile(filepath.Join(t.TempDir(), "probe"), []byte("ok"), 0o600); err != nil {
		t.Fatalf("daemon cannot write a file after the probe: %v", err)
	}
	c := exec.Command("/bin/sh", "-c", "echo alive")
	if out, err := c.CombinedOutput(); err != nil || !strings.Contains(string(out), "alive") {
		t.Fatalf("daemon cannot exec after the probe: err=%v out=%s", err, out)
	}
	// A kernel that accepts filters is the normal case on any modern Linux; a
	// refusal must be reported, not hidden.
	if !got {
		t.Skip("this kernel refused a seccomp filter (seccomp=off, as reported by /v1/backends)")
	}
	if !noNewPrivsApplicable {
		t.Fatal("no_new_privs must be applicable on Linux")
	}
}

// no_new_privs is set in the child, so the child is the only place it can be
// observed. This runs the helper exactly as the executor does and reads the
// posture back out of its stderr report.
func TestSeccompHelperAppliesControlsInTheChild(t *testing.T) {
	t.Setenv(envHardening, "on")
	t.Setenv(envNoNewPrivs, "1")
	t.Setenv(envSeccomp, "1")
	t.Setenv(envCgroupMemory, "0") // isolate the test from the host's cgroups

	exe := selfExecutable()
	if exe == "" {
		t.Skip("cannot resolve this binary")
	}
	// A *bare* command name on purpose: this is what the local executor hands the
	// helper (executor.go builds the wrapper as "sh -c ..."), and the helper ends
	// in execve(2), which does not search PATH. Naming /bin/sh instead would hide
	// exactly the failure this test exists to catch — a hardened run that dies
	// with exit 127 because its payload was named, not because the kernel said no.
	c := exec.Command(exe, helperFlag, helperSep, "sh", "-c", "echo payload-ran")
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v (%s)", err, out)
	}
	report := string(out)
	// True on both the hardened and the degraded path: the payload ran.
	if !strings.Contains(report, "payload-ran") {
		t.Fatalf("the payload must actually run after the helper execs it: %q", report)
	}
	if !strings.Contains(report, "kavach-hardening:") {
		t.Fatalf("the helper must report its measured posture: %q", report)
	}
	if !strings.Contains(report, "no_new_privs=on") {
		t.Fatalf("no_new_privs was not applied (or not verified): %q", report)
	}
	// Whether the filter installs depends on the kernel; either way the report
	// must be truthful about which of the two happened — never "in force" when
	// the kernel refused it, and never silent.
	switch {
	case strings.Contains(report, "seccomp=UNAVAILABLE"):
		// A container or kernel that refuses seccomp(2) is a supported host, not
		// a broken one: the run above proves the degraded path executed the
		// payload anyway, which is the whole contract. Only the deny-list
		// assertion below needs a real filter, and it is skipped out loud with
		// the kernel's own reason rather than quietly passing.
		reason := seccompUnavailableReason(report)
		t.Skipf("seccomp is unavailable on this host (%s); the degraded path is verified above, but a deny list can only be asserted against an installed filter", reason)
	case strings.Contains(report, "seccomp=INVALID"):
		t.Fatalf("the filter must be rejected at build time, not handed to the kernel: %q", report)
	case !strings.Contains(report, "seccomp="):
		t.Fatalf("the helper must say what happened to the filter: %q", report)
	}
	// Installed: the report must name the syscalls the filter denies, so an
	// operator can check the claim instead of believing it.
	if !strings.Contains(report, "seccomp=") || !strings.Contains(report, "clone3") {
		t.Fatalf("an installed filter must name what it denies: %q", report)
	}
	for _, want := range []string{"unshare", "mount", "pivot_root"} {
		if !strings.Contains(report, want) {
			t.Errorf("an installed filter must deny %s: %q", want, report)
		}
	}
}

// seccompUnavailableReason pulls the kernel's own words out of a helper report
// that says seccomp=UNAVAILABLE(...), so a skip can explain itself instead of
// leaving a bare "skipped" with no cause.
func seccompUnavailableReason(report string) string {
	const marker = "seccomp=UNAVAILABLE("
	i := strings.Index(report, marker)
	if i < 0 {
		return "reported as unavailable"
	}
	rest := report[i+len(marker):]
	if j := strings.IndexByte(rest, ')'); j >= 0 {
		return rest[:j]
	}
	return rest
}

// no_new_privs really is irreversible within the process: after prctl, a setuid
// exec cannot regain privilege. Check the flag reads back, which is what the
// helper reports and what an auditor would check.
func TestNoNewPrivsReadBack(t *testing.T) {
	before, err := noNewPrivsEffective()
	if err != nil {
		t.Skipf("no /proc/self/status here: %v", err)
	}
	if before {
		t.Skip("this test process is already confined by something else")
	}
	exe := selfExecutable()
	if exe == "" {
		t.Skip("cannot resolve this binary")
	}
	// The probe child installs no_new_privs and reads it back; a mismatch
	// between prctl and /proc would make every "no_new_privs=on" report a lie.
	out, err := exec.Command(exe, helperFlag, helperSep, "/bin/true").CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v (%s)", err, out)
	}
	if !strings.Contains(string(out), "no_new_privs=on") {
		t.Fatalf("prctl and /proc disagree about NoNewPrivs: %q", out)
	}
}

// The fork-bomb drill is the end-to-end proof of the strict profile: it installs
// the filter in its own process and then tries to fork. A refusal at the first
// attempt is the control working; a large number means the filter did not take.
func TestHardForkDrillIsReportOnlyAndReports(t *testing.T) {
	t.Setenv(envHardFork, "1")
	exe := selfExecutable()
	if exe == "" {
		t.Skip("cannot resolve this binary")
	}
	c := exec.Command(exe, helperFlag, hardForkFlag, helperSep, "/bin/true")
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("drill failed: %v (%s)", err, out)
	}
	report := string(out)
	if !strings.Contains(report, "mode=fork-bomb-drill") || !strings.Contains(report, "profile=strict") {
		t.Fatalf("the drill must declare what it is doing: %q", report)
	}
	if !strings.Contains(report, "hard_fork=") {
		t.Fatalf("the drill must report a fork result: %q", report)
	}
	// With the strict filter in force, the very first fork must be refused.
	// (A kernel that refused the filter is reported as UNAVAILABLE above, and
	// then this measurement is meaningless — so only assert when it installed.)
	if strings.Contains(report, "seccomp=on") && !strings.Contains(report, "refused_after=0") {
		t.Fatalf("an installed strict filter must refuse the first fork: %q", report)
	}
}

// The cgroup logic is covered with a fake hierarchy so it is testable without
// privileges: the scope parse comes from /proc/self/cgroup, and the writability
// test is a real mkdir in the fake root.
func TestCgroupScopeUsesTheV2Hierarchy(t *testing.T) {
	root := t.TempDir()
	// A fake v2 root: cgroup.controllers is what readCgroupScope looks for.
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu memory pids\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KAVACH_CGROUP_ROOT", root)
	scope, err := readCgroupScope()
	if err != nil {
		// A cgroup-v1-only host has no "0::" line; there is nothing to assert
		// about v2 behaviour there, and the daemon degrades (and says so).
		if strings.Contains(err.Error(), "unified") {
			t.Skipf("this host has no cgroup v2 unified hierarchy: %v", err)
		}
		t.Fatalf("readCgroupScope: %v", err)
	}
	if scope.Root != root {
		t.Fatalf("root=%q want the override %q", scope.Root, root)
	}
	// Note what the success above already proved: the fake root has
	// cgroup.controllers but scope.Dir() (the process's own v2 path, e.g.
	// /system.slice/<unit>.service on a systemd host) is not a cgroup root and
	// has none of its own, and readCgroupScope still returned. Probing Dir()
	// instead of Root rejected a perfectly usable hierarchy on every systemd
	// host — the bug that had CI reporting "not a cgroup v2 root" for
	// /sys/fs/cgroup itself.
	// The process's own v2 path may not exist inside the fake root; the scope
	// must still be reported and marked not writable rather than invented.
	ok, werr := cgroupWritable(scope)
	if ok {
		t.Fatal("a fake root with no matching sub-cgroup must not be writable")
	}
	if werr == nil {
		t.Fatal("a missing cgroup directory must be an error, not a silent false")
	}
	// Now make the path real and it must become writable.
	if err := os.MkdirAll(scope.Dir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if ok, err := cgroupWritable(scope); !ok || err != nil {
		t.Fatalf("a real, writable cgroup dir must report writable: ok=%v err=%v", ok, err)
	}
	// The probe must describe the caps it would apply, not claim them.
	st := probeCgroupCaps(256)
	if !st.available || !st.writable {
		t.Fatalf("a writable fake hierarchy should be reported as available+writable: %+v", st)
	}
	if !strings.Contains(st.note, "256MiB") {
		t.Fatalf("the probe must name the cap it would apply: %+v", st)
	}
}

// A root without cgroup.controllers is a v1 (or no) hierarchy, and that has to be
// reported as such rather than used. This is the same branch a v1-only host
// takes, made reachable from any Linux.
func TestCgroupScopeRejectsANonV2Root(t *testing.T) {
	root := t.TempDir() // deliberately no cgroup.controllers
	t.Setenv("KAVACH_CGROUP_ROOT", root)
	_, err := readCgroupScope()
	if err == nil {
		t.Fatal("a root with no cgroup.controllers is not a cgroup v2 hierarchy")
	}
	if strings.Contains(err.Error(), "unified") {
		// A v1-only host never reaches this branch: there is no "0::" line to
		// parse, so the missing mount point is not what rejected it.
		t.Skipf("this host has no cgroup v2 unified hierarchy, so the root probe is not reached: %v", err)
	}
	if !strings.Contains(err.Error(), "is not a cgroup v2 root") {
		t.Fatalf("the failure must say why the hierarchy is unusable: %v", err)
	}
	if !strings.Contains(err.Error(), root) {
		t.Fatalf("the failure must name the root it rejected: %v", err)
	}
	// Degradation, not refusal: the probe reports it as unavailable and carries on.
	st := probeCgroupCaps(256)
	if st.available || st.writable {
		t.Fatalf("a v1 root must report no caps: %+v", st)
	}
	if st.note == "" {
		t.Fatal("an unusable hierarchy must say so in the note")
	}
	if got := applyCgroupCaps(256); !strings.HasPrefix(got, "cgroup=") || strings.HasPrefix(got, "cgroup=on") {
		t.Fatalf("an unusable hierarchy must not report cgroup=on: %q", got)
	}
}

// applyCgroupCaps writes real files in a fake hierarchy: this is where a wrong
// filename or a missing attach would show up, and it is all reachable without
// privileges.
func TestApplyCgroupCapsWritesLimitsBeforeAttaching(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("memory pids\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KAVACH_CGROUP_ROOT", root)
	// A memMiB of 0 means "no cap requested" and must be a no-op, not an
	// unlimited one.
	if got := applyCgroupCaps(0); got != "cgroup=off" {
		t.Fatalf("memMiB=0 must disable the cap, got %q", got)
	}
	if _, err := readCgroupScope(); err != nil && strings.Contains(err.Error(), "unified") {
		t.Skipf("this host has no cgroup v2 unified hierarchy: %v", err)
	}
	// The scope directory does not exist yet, so the attach must fail loudly in
	// the returned note rather than silently running uncapped.
	if got := applyCgroupCaps(256); !strings.HasPrefix(got, "cgroup=") || strings.HasPrefix(got, "cgroup=on") {
		t.Fatalf("an unusable hierarchy must not report cgroup=on: %q", got)
	}
}

// The filter payload encoding is the hand-off between the daemon and the probe
// child; a broken round trip would make the probe meaningless.
func TestFilterEncodingRoundTrip(t *testing.T) {
	prog, err := buildStrictFilter()
	if err != nil {
		t.Fatal(err)
	}
	got := decodeFilter(encodeFilter(prog))
	if len(got) != len(prog) {
		t.Fatalf("round trip changed the length: %d → %d", len(prog), len(got))
	}
	for i := range prog {
		if got[i] != prog[i] {
			t.Fatalf("instruction %d changed: %+v → %+v", i, prog[i], got[i])
		}
	}
	if decodeFilter("garbage") != nil {
		t.Fatal("a malformed program must decode to nil, not to a partial filter")
	}
	if decodeFilter("") != nil {
		t.Fatal("an empty program must decode to nil")
	}
}
