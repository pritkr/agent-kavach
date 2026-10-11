//go:build linux

package main

// exec_linux.go — Linux executor hardening (v3).
//
// Everything that needs a Linux kernel primitive lives here; the model, the BPF
// assembler and the plan that decides what to run live in exec_hardening.go so
// they can be tested on any OS, and exec_fallback.go supplies the same
// primitives as honest no-ops elsewhere.
//
// Process-level controls:
//
//	SysProcAttr{Setsid: true}      a new session (and therefore a new process
//	                                group with pgid == pid, which is what keeps
//	                                the existing kill(-pgid) timeout kill
//	                                correct)
//	SysProcAttr{Pdeathsig: SIGKILL} the kernel kills the run when the daemon
//	                                thread that forked it dies — a daemon crash
//	                                cannot leave a payload running
//	no_new_privs                   prctl(PR_SET_NO_NEW_PRIVS, 1). Go's
//	                                syscall.SysProcAttr has no NoNewPrivs field
//	                                (verified against the toolchain), so it
//	                                cannot be part of the struct literal; it is
//	                                set in the child by the re-exec helper
//
// seccomp: the child (the re-exec helper) calls
// prctl(PR_SET_NO_NEW_PRIVS, 1) and then seccomp(SECCOMP_SET_MODE_FILTER, prog)
// with a BPF program that denies
//
//	fork, vfork, clone3         process creation by the pre-clone3 libc path and
//	                            by the modern one — a fork bomb's two doors
//	clone & (CLONE_NEW*|UNTRACED|…)   the escape primitives: new mount/pid/
//	                            user/net/cgroup/uts/ipc namespaces, or escape a
//	                            ptrace-based confinement
//	unshare, setns, mount,
//	pivot_root                   the syscall spellings of the same intent
//
// and allows everything else, including a plain clone(2). That exclusion is
// deliberate: clone is how a threaded runtime (Go, Java, node, Python
// threadpools) starts a thread, and a filter that denies it turns the sandbox
// into a denial of service. The honest consequence — a payload can still
// create threads, and glibc ≥ 2.34 can fall back from a denied clone3 to
// clone(2) inside fork() — is documented as a residual limit; the *fork-bomb*
// control is the cgroup pids.max, which counts processes in the kernel and
// survives a seccomp bypass entirely.
//
// Denied calls return EPERM rather than SIGKILL on purpose: EPERM is visible to
// the payload, fails the run with a status the audit log records, and cannot be
// confused with a timeout or an OOM kill.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// hardeningRuntime is reported by /v1/backends.
const hardeningRuntime = "linux"

// Linux kernel ABI constants the Go syscall package does not export.
const (
	prSetNoNewPrivs        = 0x26 // 38
	seccompSetModeFilter   = 1
	seccompFilterFlagTSync = 1
)

// cgroupV2DefaultRoot is the conventional unified mount point; overridable so a
// host that mounts the hierarchy elsewhere (and every test) can be handled.
const cgroupV2DefaultRoot = "/sys/fs/cgroup"

// cgroupPidsMax is the per-run process cap. Same order as the Docker profile's
// --pids-limit 64, so the two executors behave alike.
const cgroupPidsMax = 64

// blockedCloneFlags are clone(2)/clone3(2) flag bits that turn a thread into an
// escape primitive. Any one of them set means "give me a new view of the world".
var blockedCloneFlags = []uint32{
	0x00020000, // CLONE_NEWNS      mount namespace
	0x00040000, // CLONE_NEWCGROUP  cgroup namespace
	0x00080000, // CLONE_NEWUTS     uts namespace
	0x00100000, // CLONE_NEWIPC     ipc namespace
	0x00200000, // CLONE_NEWUSER    user namespace
	0x00400000, // CLONE_NEWPID     pid namespace
	0x04000000, // CLONE_NEWNET     network namespace
	0x00002000, // CLONE_UNTRACED   escape a ptrace-based confinement
	0x00800000, // CLONE_PTRACE     ditto
}

// noNewPrivsApplicable: prctl(PR_SET_NO_NEW_PRIVS) is a Linux interface.
const noNewPrivsApplicable = true

// seccompKernelAvailable memoises the one-time child probe: does this kernel
// actually accept a filter? Never inferred from the kernel version string.
var seccompKernelAvailable = sync.OnceValue(probeSeccompSupported)

// procPolicySupport reports the process-level controls Linux offers.
func procPolicySupport() procPolicy {
	return procPolicy{Setsid: true, Pdeathsig: true}
}

// applyProcPolicy sets the SysProcAttr fields this platform supports.
func applyProcPolicy(cmd *exec.Cmd, p procPolicy) {
	attr := &syscall.SysProcAttr{}
	if p.Setsid {
		// New session *and* new process group (pgid == pid): the timeout kill
		// sends SIGKILL to -pgid and still reaches every descendant.
		attr.Setsid = true
	}
	if p.Pdeathsig {
		attr.Pdeathsig = syscall.SIGKILL
	}
	cmd.SysProcAttr = attr
}

// procAttrDeathSignal reports the death signal an applied SysProcAttr carries.
// It exists because Pdeathsig is a Linux-only field: without an accessor, the
// test for "SIGKILL when the daemon dies" could not even be written on a
// non-Linux dev box.
func procAttrDeathSignal(a *syscall.SysProcAttr) syscall.Signal {
	if a == nil {
		return 0
	}
	return a.Pdeathsig
}

// installNoNewPrivs sets PR_SET_NO_NEW_PRIVS on the calling thread. Called by
// the re-exec helper in the child, immediately before the seccomp filter (which
// the kernel requires) and before the payload execve.
func installNoNewPrivs() error {
	if err := prctlNoNewPrivs(); err != nil {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}
	return nil
}

func prctlNoNewPrivs() error {
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); errno != 0 {
		return errno
	}
	return nil
}

// noNewPrivsEffective reads the flag back from /proc/self/status. It is a
// report-only read (the field is unprivileged), which is what lets the helper
// log *measured* evidence instead of an intention.
func noNewPrivsEffective() (bool, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "NoNewPrivs:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "NoNewPrivs:")) == "1", nil
		}
	}
	return false, errors.New("NoNewPrivs absent from /proc/self/status")
}

// installSeccompFilter applies prog to every thread of the current process.
// no_new_privs must already be set (or the caller needs CAP_SYS_ADMIN, which
// kavach deliberately never has).
func installSeccompFilter(prog []sockFilter) error {
	if len(prog) == 0 {
		return errors.New("seccomp: empty program")
	}
	if err := prctlNoNewPrivs(); err != nil {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}
	nr := seccompSyscallNumber()
	if nr == 0 {
		return fmt.Errorf("%w: seccomp(2) number unknown for GOARCH=%s", ErrHardeningUnsupported, runtime.GOARCH)
	}
	// SECCOMP_FILTER_FLAG_TSYNC applies the filter to *all* threads, not just the
	// one calling seccomp(). It is the correct default; a kernel that refuses
	// it (it can fail when a thread cannot be synchronised) gets a retry
	// without the flag, which is still correct for a freshly forked child that
	// has exactly one thread.
	fprog := sockFprog{Length: uint16(len(prog)), Filter: &prog[0]}
	_, _, errno := syscall.Syscall(nr, seccompSetModeFilter, uintptr(unsafe.Pointer(&fprog)), seccompFilterFlagTSync)
	if errno == 0 {
		return nil
	}
	_, _, errno = syscall.Syscall(nr, seccompSetModeFilter, uintptr(unsafe.Pointer(&fprog)), 0)
	if errno != 0 {
		return fmt.Errorf("seccomp(SET_MODE_FILTER): %w", errno)
	}
	return nil
}

// seccompSyscallNumber returns seccomp(2)'s number for this architecture, or 0
// when unknown (→ a clean skip, never a guess at the wrong syscall).
func seccompSyscallNumber() uintptr { return archSyscallTable().seccomp }

// probeSeccompSupported answers "would a filter be accepted here?" without
// confining the daemon. The daemon is long-lived: installing the real filter in
// it would trap the daemon itself. So the probe forks a throwaway child of this
// same binary, which tries a real filter on a harmless syscall and exits. The
// probe filter denies clone3 only — a syscall the probe child never calls — so it
// can still report and exit.
func probeSeccompSupported() bool {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return false
	}
	prog, err := buildEscapeFilter()
	if err != nil {
		return false
	}
	cmd := exec.Command(exe, seccompProbeFlag)
	cmd.Env = append(os.Environ(), seccompProbeProgEnv+"="+encodeFilter(prog))
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return false
	}
	go func() { done <- cmd.Wait() }()
	// 5s is generous for a fork+exit; a wedged probe must not block boot.
	select {
	case err := <-done:
		return err == nil
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return false
	}
}

// encodeFilter / decodeFilter hand the assembled BPF program to the probe child
// through the environment. It is inert data (four integers per instruction), and
// the child hands it straight to seccomp(2) — there is nothing to interpret.
func encodeFilter(prog []sockFilter) string {
	var b strings.Builder
	for i, f := range prog {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d:%d:%d:%d", f.Code, f.Jt, f.Jf, f.K)
	}
	return b.String()
}

func decodeFilter(s string) []sockFilter {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]sockFilter, 0, len(parts))
	for _, p := range parts {
		f := strings.Split(p, ":")
		if len(f) != 4 {
			return nil
		}
		var ins sockFilter
		ins.Code = uint16(mustAtoi(f[0]))
		ins.Jt = uint8(mustAtoi(f[1]))
		ins.Jf = uint8(mustAtoi(f[2]))
		ins.K = uint32(mustAtoi(f[3]))
		out = append(out, ins)
	}
	return out
}

func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// runSeccompProbe is the child half of probeSeccompSupported: install the
// program it was handed, report, exit 0. Exit 0 means "the kernel accepted the
// filter".
func runSeccompProbe() int {
	prog := decodeFilter(os.Getenv(seccompProbeProgEnv))
	if len(prog) == 0 {
		return 2
	}
	if err := installSeccompFilter(prog); err != nil {
		return 1
	}
	return 0
}

// archSyscalls is the per-architecture numbering the filter needs. The Go
// syscall package cannot be used for it: it omits seccomp and setns on
// linux/amd64, and fork/vfork on arm64 (arm64 has neither — one clone(2) serves
// both), so a table with two branches is the only portable way to name them.
// The linux-only test cross-checks every entry the toolchain does export.
type archSyscalls struct {
	arch      string
	clone     uint32
	fork      uint32 // 0 = this architecture has no fork(2)
	vfork     uint32 // 0 = this architecture has no vfork(2)
	clone3    uint32
	mount     uint32
	pivotRoot uint32
	unshare   uint32
	setns     uint32
	seccomp   uintptr // 0 = unknown → the filter is skipped, not guessed
	verified  bool    // cross-checked against the toolchain
}

func archSyscallTable() archSyscalls {
	switch runtime.GOARCH {
	case "amd64":
		// asm/unistd_64.h.
		return archSyscalls{"amd64", 56, 57, 58, 435, 165, 155, 272, 308, 317, true}
	case "arm64":
		// asm-generic/unistd.h. No fork(2)/vfork(2), clone3 is 435 like
		// everywhere, and setns is the generic 268 (not amd64's 308).
		return archSyscalls{"arm64", 220, 0, 0, 435, 40, 41, 97, 268, 277, true}
	default:
		// Unverified: keep clone (the thread/escape-relevant one) from the
		// toolchain and mark the rest unknown, so the report can say the
		// table is unverified rather than implying parity.
		return archSyscalls{arch: runtime.GOARCH, clone: uint32(syscall.SYS_CLONE), clone3: 435}
	}
}

// syscallNumber is one entry of the architecture-dependent deny list.
type syscallNumber struct {
	name string
	nr   uint32
}

// forkVforkSyscallNumbers returns fork(2)/vfork(2) where they exist.
func forkVforkSyscallNumbers() []syscallNumber {
	tbl := archSyscallTable()
	var out []syscallNumber
	if tbl.fork != 0 {
		out = append(out, syscallNumber{"fork", tbl.fork})
	}
	if tbl.vfork != 0 {
		out = append(out, syscallNumber{"vfork", tbl.vfork})
	}
	return out
}

// escapeSyscallNumbers are the namespace / mount escape primitives. Unknown
// (0) entries are omitted rather than denying syscall 0.
func escapeSyscallNumbers() []syscallNumber {
	tbl := archSyscallTable()
	var out []syscallNumber
	for _, e := range []struct {
		name string
		nr   uint32
	}{
		{"unshare", tbl.unshare},
		{"setns", tbl.setns},
		{"mount", tbl.mount},
		{"pivot_root", tbl.pivotRoot},
	} {
		if e.nr != 0 {
			out = append(out, syscallNumber{e.name, e.nr})
		}
	}
	return out
}

// DeniedSyscalls is the human-readable deny list of the requested profile, for
// /v1/backends, the audit trail and the child's own report. Order is stable so
// two reports can be compared.
func DeniedSyscalls(strict bool) []string {
	out := make([]string, 0, 8)
	if strict {
		for _, s := range forkVforkSyscallNumbers() {
			out = append(out, s.name)
		}
	}
	out = append(out, "clone3")
	if len(blockedCloneFlags) > 0 {
		out = append(out, "clone(CLONE_NEW*|CLONE_UNTRACED)")
	}
	for _, s := range escapeSyscallNumbers() {
		out = append(out, s.name)
	}
	sort.Strings(out)
	return out
}

// activeFilterSpec returns the filter for the requested profile.
//
// escape (default) — an *escape barrier*: no namespace creation, no mount or
// root changes, no clone3. A plain fork(2)/clone(2) is still allowed, because it
// is how a shell runs `a | b` and how libc implements fork(); denying it turns
// ordinary work into EPERM, and a sandbox that breaks ordinary work is a denial
// of service, not a boundary.
//
// strict (opt-in, KAVACH_SECCOMP_STRICT=1) — escape plus fork(2)/vfork(2)
// denied, closing the fork bomb at the syscall level too, at the cost of
// breaking pipelines and anything else that forks. The drill
// (KAVACH_HARD_FORK=1) runs this profile and reports what actually happened.
//
// Either way the *fork-bomb* control of record is the cgroup's pids.max, which
// the kernel enforces and a seccomp bypass cannot evade.
func activeFilterSpec(strict bool) SeccompFilterSpec {
	tbl := archSyscallTable()
	var deny []uint32
	if strict {
		for _, s := range forkVforkSyscallNumbers() {
			deny = append(deny, s.nr)
		}
	}
	deny = append(deny, tbl.clone3)
	for _, s := range escapeSyscallNumbers() {
		deny = append(deny, s.nr)
	}
	reason := "kavach: no namespaces, no mount changes, no clone3"
	if strict {
		reason = "kavach: no process creation, no namespaces, no mount changes"
	}
	return SeccompFilterSpec{
		Deny:           deny,
		DenyCloneFlags: blockedCloneFlags,
		CloneSyscall:   tbl.clone,
		Action:         seccompRetErrno | syscallErrnoEPERM,
		Reason:         reason,
	}
}

// buildEscapeFilter assembles the escape profile (the default) into the
// loadable program.
func buildEscapeFilter() ([]sockFilter, error) { return buildSeccompFilter(activeFilterSpec(false)) }

// buildStrictFilter assembles the strict profile.
func buildStrictFilter() ([]sockFilter, error) { return buildSeccompFilter(activeFilterSpec(true)) }

// cgroupScope is the caller's position in the unified (v2) cgroup hierarchy,
// read from /proc/self/cgroup. Every cap the executor applies is relative to it.
type cgroupScope struct {
	Root string // unified mount point, e.g. "/sys/fs/cgroup"
	Rel  string // this process's path inside the hierarchy, always rooted
}

// readCgroupScope parses /proc/self/cgroup for the unified (v2) entry and
// confirms the mount point really is a cgroup v2 root.
//
// The cgroup.controllers probe belongs on the *root*, not on this process's
// sub-directory. Those are different questions: a v1-only host has a
// /sys/fs/cgroup that is not a unified hierarchy, and that must be reported as
// such; whereas a real sub-directory simply may not exist yet under an
// overridden root (and whether it exists, and whether it is writable, is exactly
// what cgroupWritable answers). Probing Dir() conflated the two and made a
// perfectly usable hierarchy look like a broken one — on a systemd host the
// scope is something like /system.slice/<unit>.service, which is not a cgroup
// root at all.
func readCgroupScope() (cgroupScope, error) {
	root := cgroupRoot()
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return cgroupScope{}, err
	}
	scope := cgroupScope{Root: root}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] != "0" {
			continue
		}
		rel := parts[2]
		if !strings.HasPrefix(rel, "/") {
			rel = "/" + rel
		}
		scope.Rel = rel
		break
	}
	if scope.Rel == "" {
		return scope, errors.New("no unified (v2) entry in /proc/self/cgroup")
	}
	if _, err := os.Stat(filepath.Join(scope.Root, "cgroup.controllers")); err != nil {
		return scope, fmt.Errorf("%s is not a cgroup v2 root: %w", scope.Root, err)
	}
	return scope, nil
}

// Dir is the cgroup v2 directory for this scope.
func (s cgroupScope) Dir() string {
	if s.Root == "" {
		return ""
	}
	if s.Rel == "" || s.Rel == "/" {
		return filepath.Clean(s.Root)
	}
	return filepath.Clean(s.Root + s.Rel)
}

// String renders the scope for reports.
func (s cgroupScope) String() string { return s.Dir() }

// cgroupRoot is the unified mount point, overridable for tests and for hosts
// that mount the hierarchy elsewhere.
func cgroupRoot() string {
	if v := strings.TrimSpace(os.Getenv("KAVACH_CGROUP_ROOT")); v != "" {
		return v
	}
	return cgroupV2DefaultRoot
}

// cgroupWritable reports whether the daemon may create children of scope and
// write limits into them. The honest test: an unprivileged container normally
// mounts /sys/fs/cgroup read-only, and this is where that shows up.
func cgroupWritable(scope cgroupScope) (bool, error) {
	fi, err := os.Stat(scope.Dir())
	if err != nil {
		return false, err
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("%s is not a directory", scope.Dir())
	}
	probe, err := os.MkdirTemp(scope.Dir(), ".kavach-probe-")
	if err != nil {
		return false, err
	}
	_ = os.Remove(probe)
	return true, nil
}

// cgroupState is what the cgroup probe found.
type cgroupState struct {
	available bool
	writable  bool
	scope     string
	note      string
}

// probeCgroupCaps reports what the cgroup v2 executor can enforce, without
// changing anything: read the scope, test writability, report the planned caps.
func probeCgroupCaps(memMiB int64) cgroupState {
	scope, err := readCgroupScope()
	if err != nil {
		return cgroupState{note: err.Error()}
	}
	st := cgroupState{available: true, scope: scope.Dir(), note: "caps applied per run in the child"}
	ok, err := cgroupWritable(scope)
	if err != nil {
		st.note = "not writable: " + err.Error()
		return st
	}
	if !ok {
		st.note = "not writable"
		return st
	}
	st.writable = true
	st.note = fmt.Sprintf("memory.max=%dMiB pids.max=%d per run", memMiB, cgroupPidsMax)
	return st
}

// applyCgroupCaps moves the calling process into a fresh cgroup v2 scope and
// writes the limits. It runs in the child, so the cgroup contains exactly one
// process and the caps exist before the payload does. Every failure is a
// reported string, never a failed run: a cgroup is a bound, not the sandbox.
func applyCgroupCaps(memMiB int64) string {
	if memMiB <= 0 {
		return "cgroup=off"
	}
	scope, err := readCgroupScope()
	if err != nil {
		return "cgroup=unavailable(" + err.Error() + ")"
	}
	ok, err := cgroupWritable(scope)
	if err != nil || !ok {
		return "cgroup=readonly"
	}
	dir, err := os.MkdirTemp(scope.Dir(), "kavach-run-")
	if err != nil {
		return "cgroup=unavailable(" + err.Error() + ")"
	}
	// Limits go on the new cgroup before it has any process, so they are in
	// force the instant the payload appears.
	if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte(strconv.FormatInt(memMiB*1024*1024, 10)), 0o600); err != nil {
		return "cgroup=memory_unavailable(" + err.Error() + ")"
	}
	if err := os.WriteFile(filepath.Join(dir, "pids.max"), []byte(strconv.Itoa(cgroupPidsMax)), 0o600); err != nil {
		return "cgroup=pids_unavailable(" + err.Error() + ")"
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		return "cgroup=attach_failed(" + err.Error() + ")"
	}
	return fmt.Sprintf("cgroup=on(dir=%s memory_max=%dMiB pids_max=%d)", dir, memMiB, cgroupPidsMax)
}

// probeHardening assembles the boot report for Linux.
func probeHardening(cfg HardeningConfig) HardeningReport {
	rep := HardeningReport{Runtime: hardeningRuntime, Requested: cfg}
	rep.Note = "no_new_privs + seccomp are installed by the child, before it execs the payload (re-exec helper)"
	sup := procPolicySupport()
	if sup.Setsid {
		rep.Applied = append(rep.Applied, "setsid")
	} else {
		rep.Skipped = append(rep.Skipped, "setsid="+unsupportedReason())
	}
	if sup.Pdeathsig {
		rep.Applied = append(rep.Applied, "pdeathsig")
	} else {
		rep.Skipped = append(rep.Skipped, "pdeathsig="+unsupportedReason())
	}
	switch {
	case !cfg.Seccomp:
		// Off by policy: report it as deliberately absent, not as a failure.
	case seccompKernelAvailable():
		note := "escape profile (fork allowed; the fork-bomb control is cgroup pids.max), installed in the child before exec, SECCOMP_FILTER_FLAG_TSYNC"
		if cfg.SeccompStrict {
			note = "strict profile (fork and vfork denied), installed in the child before exec, SECCOMP_FILTER_FLAG_TSYNC"
		}
		rep.Seccomp = SeccompReport{
			Available: true,
			Installed: true,
			Action:    "SECCOMP_RET_ERRNO(EPERM)",
			Blocked:   DeniedSyscalls(cfg.SeccompStrict || cfg.HardForkProbe),
			Note:      note,
		}
		rep.Applied = append(rep.Applied, "seccomp")
	default:
		rep.Seccomp = SeccompReport{Available: false, Note: "kernel refused a probe filter"}
		rep.Skipped = append(rep.Skipped, "seccomp=kernel refused a probe filter")
	}
	if cfg.CgroupMemMiB > 0 {
		st := probeCgroupCaps(cfg.CgroupMemMiB)
		rep.Cgroup = CgroupReport{
			Available: st.available,
			Writable:  st.writable,
			Scope:     st.scope,
			Note:      st.note,
		}
		if st.writable {
			rep.Cgroup.MemoryMax = fmt.Sprintf("%d MiB", cfg.CgroupMemMiB)
			rep.Cgroup.PidsMax = strconv.Itoa(cgroupPidsMax)
			rep.Applied = append(rep.Applied, "cgroup_memory")
		} else {
			rep.Skipped = append(rep.Skipped, "cgroup_memory="+st.note)
		}
	}
	sort.Strings(rep.Applied)
	sort.Strings(rep.Skipped)
	return rep
}

// runSeccompExec is the re-exec helper: apply no_new_privs, the seccomp filter
// and the cgroup caps, then exec argv. It is what makes the kernel controls
// possible at all without cgo, and the only place in the daemon that calls
// execve directly.
//
// Before execve it reports the posture it *measured* on fd 2 (never stdout,
// which is the run's captured output) so the audit trail carries evidence
// rather than an intention.
func runSeccompExec(argv []string, hardFork bool) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "kavach: -seccomp-exec needs a command to run")
		return 2
	}
	// The config is re-resolved from this process's own (inherited) environment,
	// so a hand-invoked child behaves exactly like an executor-started one.
	cfg, cerr := HardeningFromEnv()
	if cerr != nil {
		fmt.Fprintf(os.Stderr, "kavach-hardening: invalid config: %v — no kernel controls applied\n", cerr)
		cfg = HardeningConfig{Enabled: false}
	}
	if hardFork {
		// The drill is the one run that *does* install the strict profile and
		// then tries to fork in the same process: refused at the first attempt
		// is the proof that the control works. It is opt-in because the strict
		// profile breaks ordinary forking work.
		note := []string{"mode=fork-bomb-drill", "profile=strict"}
		if prog, berr := buildStrictFilter(); berr != nil {
			note = append(note, "seccomp=INVALID("+berr.Error()+")")
		} else if ierr := installSeccompFilter(prog); ierr != nil {
			note = append(note, "seccomp=UNAVAILABLE("+ierr.Error()+")")
		} else {
			note = append(note, "seccomp=on(deny "+strings.Join(DeniedSyscalls(true), ",")+")")
		}
		note = append(note, forkDrill())
		fmt.Fprintln(os.Stderr, "kavach-hardening: "+strings.Join(note, " "))
		return 0
	}
	var note []string
	if cfg.Enabled && cfg.NoNewPrivs {
		switch err := installNoNewPrivs(); {
		case err != nil:
			note = append(note, "no_new_privs=UNAVAILABLE("+err.Error()+")")
		default:
			ok, verr := noNewPrivsEffective()
			switch {
			case verr != nil:
				note = append(note, "no_new_privs=UNKNOWN")
			case ok:
				note = append(note, "no_new_privs=on")
			default:
				note = append(note, "no_new_privs=off(prctl-reported)")
			}
		}
	} else {
		note = append(note, "no_new_privs=off(by-config)")
	}
	if cfg.Enabled && cfg.Seccomp {
		strict := cfg.SeccompStrict
		prog, berr := buildSeccompFilter(activeFilterSpec(strict))
		if berr != nil {
			note = append(note, "seccomp=INVALID("+berr.Error()+")")
		} else if ierr := installSeccompFilter(prog); ierr != nil {
			note = append(note, "seccomp=UNAVAILABLE("+ierr.Error()+")")
		} else {
			profile := "escape"
			if strict {
				profile = "strict"
			}
			note = append(note, "seccomp="+profile+"(deny "+strings.Join(DeniedSyscalls(strict), ",")+")")
		}
	} else {
		note = append(note, "seccomp=off(by-config)")
	}
	if cfg.CgroupMemMiB > 0 {
		note = append(note, applyCgroupCaps(cfg.CgroupMemMiB))
	}
	fmt.Fprintln(os.Stderr, "kavach-hardening: "+strings.Join(note, " "))
	// execve(2) does not search PATH, so a bare name has to be resolved first.
	// A run must never die here because the payload was named "sh".
	path, rerr := resolvePayloadArgv0(argv)
	if rerr != nil {
		fmt.Fprintf(os.Stderr, "kavach: cannot run the payload: %v\n", rerr)
		return 127
	}
	if err := syscall.Exec(path, argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "kavach: exec %s: %v\n", path, err)
		return 127
	}
	return 0 // unreachable
}

// forkDrill is the report-only fork-bomb measurement: fork until the kernel
// refuses (or a ceiling is reached) and report the count. It is what the
// KAVACH_HARD_FORK=1 path runs instead of the payload.
func forkDrill() string {
	const ceiling = 512
	refused := -1
	for i := 0; i < ceiling; i++ {
		pid, err := syscall.ForkExec("/bin/true", []string{"true"}, &syscall.ProcAttr{})
		if err != nil {
			refused = i
			break
		}
		// Reap immediately: the point is the ceiling, not the leak.
		for {
			if _, werr := syscall.Wait4(pid, nil, 0, nil); werr != syscall.EINTR {
				break
			}
		}
	}
	if refused < 0 {
		return fmt.Sprintf("hard_fork=unbounded(>%d forks, capped by pids.max or nothing)", ceiling)
	}
	return fmt.Sprintf("hard_fork=refused_after=%d", refused)
}
