package main

// exec_hardening.go — executor hardening model (v3), platform-independent.
//
// The local executor is a *containment* boundary, not a confinement one: a
// child that runs on the host kernel can be constrained, not jailed. v3
// narrows it as far as the kernel allows with no cgo, no C library and no
// external runtime:
//
//	no_new_privs   the child can never regain privilege through a setuid/setgid
//	               binary, a file capability or a setuid exec of the wrapper
//	setsid         a new session: no controlling terminal, and kill(-pgid) still
//	               reaches the whole run tree
//	pdeathsig      SIGKILL the instant the daemon thread that forked it exits, so
//	               a crashed daemon never leaves a payload running
//	seccomp        prctl(PR_SET_NO_NEW_PRIVS) + SECCOMP_MODE_FILTER, denying the
//	               process-creating syscalls (clone, clone3, fork, vfork) that a
//	               fork bomb needs. Every other syscall still works — including
//	               the execve the filter is installed immediately before
//	cgroup v2      memory.max + pids.max on the child when /sys/fs/cgroup is
//	               writable by the daemon's uid
//
// Two deliberate limits, both load-bearing for honesty:
//
//   - Go's syscall.SysProcAttr has no NoNewPrivs field (checked against the
//     toolchain, not assumed), so no_new_privs cannot ride along in
//     SysProcAttr{...} here. It is applied by the same re-exec that installs
//     the seccomp filter: the child prctl()s itself before exec'ing the
//     payload, which is precisely where a filter must be installed anyway.
//   - Blocking clone/fork is a *bound* on process creation, not a jail. The
//     fork wrapper is an ordinary binary and cannot grant itself a capability
//     it does not have, so the filter is report-only for the hard-fork drill
//     (KAVACH_HARD_FORK=1) and enforcing for the ordinary case, where a runtime
//     that needs a thread after the filter is installed gets a loud, bounded
//     ENOSYS instead of a hang. See exec_linux.go.
//
// Every control is probed, not assumed. On a kernel, in a container or on an OS
// without the primitive, kavach degrades with a single logged warning and keeps
// executing rather than refusing all work; what is actually in force is served
// by HardeningReport (see /v1/backends) so the claim can be checked instead of
// believed.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// The operator switches for the kernel controls (all documented in the README's
// v3 table). Every one of them is *off-able*; none of them can widen anything
// beyond "less hardening".
const (
	envHardening     = "KAVACH_HARDENING"        // on|off — master switch for the kernel controls
	envNoNewPrivs    = "KAVACH_NO_NEW_PRIVS"     // 0|1 (default 1)
	envSeccomp       = "KAVACH_SECCOMP"          // 0|1 (default 1)
	envSeccompStrict = "KAVACH_SECCOMP_STRICT"   // 0|1 (default 0) — also deny fork/vfork
	envCgroupMemory  = "KAVACH_CGROUP_MEMORY_MB" // MiB memory.max per run (0 = off, default 256)
	envHardFork      = "KAVACH_HARD_FORK"        // 0|1 (default 0) — fork-bomb drill
)

// DefaultCgroupMemoryMiB mirrors the Docker profile's --memory 256m so the two
// executors bound memory identically whenever the local one can use cgroups.
const DefaultCgroupMemoryMiB = 256

// ErrHardeningUnsupported marks a control this kernel/OS cannot provide. It is
// a graceful-degradation signal, never a run failure.
var ErrHardeningUnsupported = errors.New("hardening unsupported on this platform")

// HardeningConfig is the requested hardening, read from the environment.
type HardeningConfig struct {
	Enabled    bool `json:"enabled"`      // master switch
	NoNewPrivs bool `json:"no_new_privs"` // prctl(PR_SET_NO_NEW_PRIVS)
	Seccomp    bool `json:"seccomp"`      // SECCOMP_MODE_FILTER
	// SeccompStrict selects the strict profile, which additionally denies
	// fork(2)/vfork(2). Off by default: a plain fork is how a shell runs a
	// pipeline and how libc implements fork(), so denying it turns ordinary
	// work (`cmd | grep`, `$(...)`) into EPERM. The strict profile is for
	// operators whose payloads are single-threaded and who want the fork bomb
	// closed at the syscall level as well as by cgroup pids.max.
	SeccompStrict bool  `json:"seccomp_strict"`
	CgroupMemMiB  int64 `json:"cgroup_memory_mb"` // 0 = no cgroup memory cap
	HardForkProbe bool  `json:"hard_fork"`        // fork-bomb drill
}

// HardeningFromEnv parses the operator switches. A malformed value is a hard
// error (never a silent default): a typo must not quietly drop a control the
// operator believed was on.
func HardeningFromEnv() (HardeningConfig, error) {
	cfg := HardeningConfig{
		Enabled:      true,
		NoNewPrivs:   true,
		Seccomp:      true,
		CgroupMemMiB: DefaultCgroupMemoryMiB,
	}
	get := func(name string, def bool) (bool, error) {
		raw := strings.TrimSpace(os.Getenv(name))
		if raw == "" {
			return def, nil
		}
		switch strings.ToLower(raw) {
		case "1", "on", "true", "yes", "enabled":
			return true, nil
		case "0", "off", "false", "no", "disabled":
			return false, nil
		}
		return false, fmt.Errorf("%s: want 0|1 (got %q)", name, raw)
	}
	var err error
	if cfg.Enabled, err = get(envHardening, true); err != nil {
		return cfg, err
	}
	if cfg.NoNewPrivs, err = get(envNoNewPrivs, true); err != nil {
		return cfg, err
	}
	if cfg.Seccomp, err = get(envSeccomp, true); err != nil {
		return cfg, err
	}
	if cfg.SeccompStrict, err = get(envSeccompStrict, false); err != nil {
		return cfg, err
	}
	if cfg.HardForkProbe, err = get(envHardFork, false); err != nil {
		return cfg, err
	}
	if raw := strings.TrimSpace(os.Getenv(envCgroupMemory)); raw != "" {
		n, convErr := strconv.ParseInt(raw, 10, 64)
		if convErr != nil || n < 0 || n > 1<<20 {
			return cfg, fmt.Errorf("%s: want an integer 0..%d MiB (got %q)", envCgroupMemory, 1<<20, raw)
		}
		cfg.CgroupMemMiB = n
	}
	return cfg, nil
}

// String renders the config for logs. It carries no secret: the only value in
// play is a size.
func (c HardeningConfig) String() string {
	b, _ := json.Marshal(c)
	return string(b)
}

// The re-exec protocol. The parent runs
//
//	<daemon> -seccomp-exec [--] <argv...>
//
// and the child applies the kernel controls and then execs argv, so the process
// that runs the payload is already confined. Every platform file understands
// the same markers, so the plan is identical on every OS.
const (
	helperFlag          = "-seccomp-exec"
	helperSep           = "--"
	hardForkFlag        = "-hard-fork"
	seccompProbeFlag    = "-seccomp-probe"
	seccompProbeProgEnv = "KAVACH_SECCOMP_PROBE_PROGRAM" // probe child only
)

// procPolicy is the set of process-level controls requested for a child: the
// portable part (Setsid) plus the Linux-only additions. The platform files
// apply what they can and ignore the rest, so a request is never a promise.
type procPolicy struct {
	Setsid     bool
	Pdeathsig  bool
	NoNewPrivs bool
	Seccomp    bool
	CgroupMem  bool
}

// SeccompFilterSpec is a portable description of a seccomp-BPF program: deny the
// listed syscalls outright, deny clone(2) when it is asked for any of the listed
// flag bits, allow everything else. The kernel ABI constants and the seccomp(2)
// call live in exec_linux.go; the program is assembled here so it is reviewable
// and testable on any OS, without a kernel header or cgo.
type SeccompFilterSpec struct {
	// Deny are syscall numbers refused unconditionally.
	Deny []uint32 `json:"deny,omitempty"`
	// DenyCloneFlags are clone(2) flag bits whose presence is refused. A plain
	// clone (thread creation) is deliberately still allowed: a filter that
	// kills every thread turns a sandbox into a denial of service.
	DenyCloneFlags []uint32 `json:"deny_clone_flags,omitempty"`
	// CloneSyscall is this platform's clone(2) number. It is required when
	// DenyCloneFlags is set, and spelled out rather than looked up so the
	// assembler stays platform-independent and testable.
	CloneSyscall uint32 `json:"clone_syscall,omitempty"`
	// Action is the seccomp return value for a refused call. Default: EPERM.
	Action uint32 `json:"action"`
	// Reason is for the audit trail; it is not a filter feature.
	Reason string `json:"reason"`
}

// seccomp BPF opcodes and the SECCOMP_RET_* values. The Go syscall package omits
// seccomp from its linux/amd64 syscall table, so the stable uapi values are
// spelled out here (uapi/linux/seccomp.h, uapi/linux/filter.h).
const (
	bpfLD  = 0x00 // BPF_LD | BPF_W | BPF_ABS
	bpfALU = 0x04 // BPF_ALU | BPF_AND | BPF_K
	bpfJMP = 0x05 // BPF_JMP | BPF_JEQ | BPF_K
	bpfJA  = 0x05 // BPF_JMP | BPF_JA
	bpfRET = 0x06 // BPF_RET | BPF_K

	seccompRetErrno = 0x00050000 // SECCOMP_RET_ERRNO
	seccompRetAllow = 0x7fff0000 // SECCOMP_RET_ALLOW

	seccompDataNROffset    = 0  // offsetof(struct seccomp_data, nr)
	seccompDataArgs0Offset = 16 // offsetof(struct seccomp_data, args[0])
)

var syscallErrnoEPERM = uint32(syscall.EPERM)

// sockFilter mirrors struct sock_filter so the program can be built without cgo.
// Field layout matches the kernel ABI exactly (uapi/linux/filter.h).
type sockFilter struct {
	Code uint16 `json:"code"`
	Jt   uint8  `json:"jt"`
	Jf   uint8  `json:"jf"`
	K    uint32 `json:"k"`
}

// sockFprog mirrors struct sock_fprog, the argument of SECCOMP_SET_MODE_FILTER.
type sockFprog struct {
	Length uint16      `json:"length"`
	Filter *sockFilter `json:"-"`
}

// bpfAsm is a minimal BPF assembler: every branch is *forward* (a filter never
// needs to loop), so jumps are patched by label once the layout is known. This
// keeps the deny/allow layout readable and checkable in a test instead of being
// hand-counted jump offsets.
type bpfAsm struct {
	ins  []sockFilter
	refs []asmRef
}

type asmRef struct {
	idx   int
	field string // "jt" | "jf" | "k" (ja)
	label string
}

func (a *bpfAsm) emit(code uint16, jt, jf uint8, k uint32) int {
	a.ins = append(a.ins, sockFilter{Code: code, Jt: jt, Jf: jf, K: k})
	return len(a.ins) - 1
}

func (a *bpfAsm) ld(off uint32) { a.emit(bpfLD, 0, 0, off) }
func (a *bpfAsm) aluAnd(k uint32) {
	a.emit(bpfALU, 0, 0, k)
}
func (a *bpfAsm) ret(k uint32) { a.emit(bpfRET, 0, 0, k) }

// jeq branches to jtLabel when A == k and to jfLabel otherwise.
func (a *bpfAsm) jeq(k uint32, jtLabel, jfLabel string) {
	idx := a.emit(bpfJMP, 0, 0, k)
	a.refs = append(a.refs,
		asmRef{idx: idx, field: "jt", label: jtLabel},
		asmRef{idx: idx, field: "jf", label: jfLabel},
	)
}

// ja jumps unconditionally (BPF_JA carries its offset in k).
func (a *bpfAsm) ja(label string) {
	idx := a.emit(bpfJA, 0, 0, 0)
	a.refs = append(a.refs, asmRef{idx: idx, field: "k", label: label})
}

func (a *bpfAsm) mark(label string) int { return len(a.ins) }

// resolve patches every recorded branch. BPF jump offsets are relative to the
// instruction *after* the jump, and are unsigned bytes.
func (a *bpfAsm) resolve(labels map[string]int) error {
	for _, r := range a.refs {
		// asmNext is the fall-through target: the instruction after this jump.
		// Using it for the deny chain keeps every branch forward and lets the
		// chain read top-to-bottom.
		target, ok := labels[r.label]
		if r.label == asmNext {
			target, ok = r.idx+1, true
		}
		if !ok {
			return fmt.Errorf("seccomp: unresolved branch label %q", r.label)
		}
		ins := &a.ins[r.idx]
		rel := target - (r.idx + 1)
		if rel < 0 {
			return fmt.Errorf("seccomp: backward branch to %q (%d) is not expressible", r.label, rel)
		}
		switch r.field {
		case "jt":
			if rel > 255 {
				return fmt.Errorf("seccomp: branch to %q is %d instructions away (max 255)", r.label, rel)
			}
			ins.Jt = uint8(rel)
		case "jf":
			if rel > 255 {
				return fmt.Errorf("seccomp: branch to %q is %d instructions away (max 255)", r.label, rel)
			}
			ins.Jf = uint8(rel)
		case "k":
			ins.K = uint32(rel)
		}
	}
	return nil
}

// asmNext is the reserved label for "the next instruction" (fall through).
const asmNext = "\x00next"

// buildSeccompFilter assembles spec into a kernel-loadable BPF program:
//
//	jeq nr == denied → deny          (one per denied syscall; each fall-through
//	                                 lands on the next comparison)
//	jeq nr == clone → check flags    (only when DenyCloneFlags is set)
//	ret allow
//	check: ld args[0]; and mask; jeq 0 → allow
//	deny:  ret ACTION
//
// Every branch is forward, so the assembler patches it by label and the layout
// stays checkable in a test instead of being hand-counted jump offsets.
func buildSeccompFilter(spec SeccompFilterSpec) ([]sockFilter, error) {
	if len(spec.Deny) == 0 && len(spec.DenyCloneFlags) == 0 {
		return nil, fmt.Errorf("seccomp: refusing to build a filter that denies nothing")
	}
	action := spec.Action
	if action == 0 {
		action = seccompRetErrno | syscallErrnoEPERM
	}
	if action&0x0000ffff == 0 {
		return nil, fmt.Errorf("seccomp: refusing an ERRNO action with no errno")
	}
	seen := make(map[uint32]bool, len(spec.Deny))
	for _, nr := range spec.Deny {
		if nr == 0 {
			return nil, fmt.Errorf("seccomp: syscall 0 is read, not a filterable call")
		}
		if seen[nr] {
			return nil, fmt.Errorf("seccomp: duplicate syscall number %d in deny list", nr)
		}
		seen[nr] = true
	}
	// A mask of the denied clone flags; an empty mask means "no clone check".
	var mask uint32
	for _, f := range spec.DenyCloneFlags {
		mask |= f
	}
	if len(spec.DenyCloneFlags) > 0 && spec.CloneSyscall == 0 {
		return nil, fmt.Errorf("seccomp: deny_clone_flags needs the platform's clone syscall number")
	}

	a := &bpfAsm{}
	for _, nr := range spec.Deny {
		a.jeq(nr, "deny", asmNext)
	}
	labels := map[string]int{}
	if mask != 0 {
		a.jeq(spec.CloneSyscall, "clonecheck", "allow")
		labels["clonecheck"] = a.mark("clonecheck")
		a.ld(seccompDataArgs0Offset)
		a.aluAnd(mask)
		a.jeq(0, "allow", "deny")
	}
	labels["allow"] = a.mark("allow")
	a.ret(seccompRetAllow)
	labels["deny"] = a.mark("deny")
	a.ret(action)
	if err := a.resolve(labels); err != nil {
		return nil, err
	}
	return a.ins, nil
}

// HardeningReport is what the daemon can *prove* about the executor it is
// running, as opposed to what it hopes for. Served by /v1/backends so an
// operator — or a test — never has to take the sandbox claim on trust.
type HardeningReport struct {
	Runtime   string          `json:"runtime"`
	Applied   []string        `json:"applied"`           // controls actually in force
	Skipped   []string        `json:"skipped,omitempty"` // requested but unavailable
	Seccomp   SeccompReport   `json:"seccomp"`
	Cgroup    CgroupReport    `json:"cgroup"`
	Requested HardeningConfig `json:"requested"`      // resolved operator config
	Note      string          `json:"note,omitempty"` // how no_new_privs is applied
}

// SeccompReport describes the seccomp filter in force.
type SeccompReport struct {
	Available bool     `json:"available"`
	Installed bool     `json:"installed"`
	Action    string   `json:"action,omitempty"`
	Blocked   []string `json:"blocked,omitempty"`
	Note      string   `json:"note,omitempty"`
}

// CgroupReport describes the cgroup v2 caps in force.
type CgroupReport struct {
	Available bool   `json:"available"`
	Writable  bool   `json:"writable"`
	MemoryMax string `json:"memory_max,omitempty"`
	PidsMax   string `json:"pids_max,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Note      string `json:"note,omitempty"`
}

var (
	hardeningProbeOnce sync.Once
	hardeningProbed    HardeningReport
	hardeningProbeErr  error

	hardeningLogMu sync.Mutex
	hardeningLogs  = map[string]bool{}
)

// AvailableHardening probes the host once and reports what the local executor
// can actually enforce. The probe is a no-op for the daemon process itself:
// no_new_privs and seccomp are verified in the *child* (the re-exec helper, see
// exec_linux.go), because installing them in a long-lived daemon would confine
// the daemon.
//
// The memoised probe is authoritative for the kernel; cfg only filters what the
// caller asked for, so a test that switches seccomp off never sees "installed".
func AvailableHardening(cfg HardeningConfig) (HardeningReport, error) {
	hardeningProbeOnce.Do(func() {
		probed, err := HardeningFromEnv()
		if err != nil {
			hardeningProbed = HardeningReport{Runtime: hardeningRuntime}
			hardeningProbeErr = err
			return
		}
		hardeningProbed = probeHardening(probed)
	})
	if hardeningProbeErr != nil {
		return hardeningProbed, hardeningProbeErr
	}
	rep := hardeningProbed
	rep.Requested = cfg
	rep.Applied = append([]string(nil), hardeningProbed.Applied...)
	rep.Skipped = append([]string(nil), hardeningProbed.Skipped...)
	rep.Seccomp.Blocked = append([]string(nil), hardeningProbed.Seccomp.Blocked...)
	enabled := cfg.Enabled
	if enabled && cfg.NoNewPrivs {
		// no_new_privs is a plain prctl(PR_SET_NO_NEW_PRIVS), confirmed in the
		// child by reading /proc/self/status back. It does not depend on the
		// seccomp filter, so its availability is a platform fact (and the
		// seccomp filter needs no_new_privs, never the other way round). Gating
		// this on Seccomp.Available would report a control the child measurably
		// applied as absent on any host that refuses filters — the report
		// disagreeing with the child's own evidence.
		if noNewPrivsApplicable {
			rep.Applied = appendSorted(rep.Applied, "no_new_privs")
		} else {
			rep.Applied = dropItem(rep.Applied, "no_new_privs")
		}
	} else {
		rep.Applied = dropItem(rep.Applied, "no_new_privs")
	}
	if enabled && cfg.Seccomp {
		rep.Seccomp.Installed = hardeningProbed.Seccomp.Installed
	} else {
		rep.Seccomp.Installed = false
	}
	if cfg.CgroupMemMiB == 0 {
		rep.Applied = dropItem(rep.Applied, "cgroup_memory")
		rep.Cgroup = CgroupReport{Available: hardeningProbed.Cgroup.Available, Note: "disabled by policy"}
	}
	return rep, nil
}

// SandboxHardening is the boot-time report, resolved from the daemon's own
// environment so the log states the configuration actually in force. A bad
// environment value is reported as "nothing enforced" rather than aborting the
// daemon: the operator can fix it without an outage, and the log says exactly
// what was ignored.
func SandboxHardening() HardeningReport {
	cfg, err := HardeningFromEnv()
	if err != nil {
		return HardeningReport{Runtime: hardeningRuntime, Note: "invalid environment: " + err.Error()}
	}
	rep, err := AvailableHardening(cfg)
	if err != nil {
		return HardeningReport{Runtime: hardeningRuntime, Note: "invalid environment: " + err.Error()}
	}
	return rep
}

// logHardeningOnce writes the boot-time hardening report exactly once.
func logHardeningOnce(rep HardeningReport) {
	hardeningLogMu.Lock()
	if hardeningLogs["boot"] {
		hardeningLogMu.Unlock()
		return
	}
	hardeningLogs["boot"] = true
	hardeningLogMu.Unlock()
	log.Printf("hardening: runtime=%s applied=[%s] skipped=[%s] seccomp{installed=%v blocked=[%s]} cgroup{memory_max=%s pids_max=%s} %s",
		rep.Runtime, strings.Join(rep.Applied, " "), strings.Join(rep.Skipped, " "),
		rep.Seccomp.Installed, strings.Join(rep.Seccomp.Blocked, " "),
		rep.Cgroup.MemoryMax, rep.Cgroup.PidsMax, rep.Note)
}

// logHardeningWarn logs a degradation exactly once per key.
func logHardeningWarn(key, msg string) {
	hardeningLogMu.Lock()
	defer hardeningLogMu.Unlock()
	if hardeningLogs[key] {
		return
	}
	hardeningLogs[key] = true
	log.Printf("hardening: %s", msg)
}

func dropItem(list []string, want string) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		if s != want {
			out = append(out, s)
		}
	}
	return out
}

func appendSorted(list []string, item string) []string {
	for _, s := range list {
		if s == item {
			return list
		}
	}
	out := append(list, item)
	sort.Strings(out)
	return out
}

// localHardeningConfig resolves the operator switches for one run. It is read
// per call (four getenvs) so a test can change the environment without fighting
// a cache, and so an operator who edits the daemon's environment does not need
// a restart to be believed. A malformed value degrades to "no kernel controls"
// and is logged once, loudly — refusing to run anything would turn a typo into
// an outage, and silently running with defaults would hide it.
func localHardeningConfig() HardeningConfig {
	cfg, err := HardeningFromEnv()
	if err != nil {
		logHardeningWarn("config", err.Error()+" — continuing with no kernel controls")
		return HardeningConfig{Enabled: false}
	}
	return cfg
}

// selfExecutable resolves this binary for the re-exec helper. It returns ""
// when the path cannot be resolved, which makes localPlan fall back to the
// un-hardened argv and say so.
func selfExecutable() string {
	exe, err := os.Executable()
	if err != nil {
		logHardeningWarn("exe", "os.Executable(): "+err.Error()+" — the child cannot be re-exec'd for no_new_privs/seccomp")
		return ""
	}
	return exe
}

// localPlanRequest is the input of localPlan.
type localPlanRequest struct {
	cfg             HardeningConfig
	argv            []string
	execSelf        string // os.Executable(); "" when it cannot be resolved
	helperAvailable bool   // this binary implements the -seccomp-exec helper
}

// resolvePayloadArgv0 turns argv[0] into a path the kernel can exec directly.
//
// The re-exec helper ends in syscall.Exec, which is a raw execve(2): unlike
// os/exec it performs *no* PATH lookup. The local executor builds its wrapper
// argv as a bare "sh" (executor.go), which is fine when the payload is handed
// to os/exec — exec.Cmd resolves it — but the moment hardening puts the re-exec
// helper in the path, the same bare name reaches execve verbatim and fails with
// ENOENT. That turned every hardened local run into exit 127: the run aborted
// because of a *name*, not because of anything the kernel refused.
//
// So the resolution happens here, once, in the one place that calls execve. argv
// is passed through untouched, so $0 (and the "kavach-fallback" $0 the wrapper
// sets) stays exactly what the caller asked for; only the file the kernel is
// pointed at changes. A name that already contains a path separator is returned
// unchanged, because it was never a PATH question.
func resolvePayloadArgv0(argv []string) (string, error) {
	if len(argv) == 0 {
		return "", errors.New("no command to resolve")
	}
	name := argv[0]
	if name == "" {
		return "", errors.New("argv[0] is empty")
	}
	if strings.ContainsRune(name, filepath.Separator) {
		return name, nil
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%q is not on PATH: %w", name, err)
	}
	return path, nil
}

// localPlanResult is the plan: what to exec, what to ask the kernel for, and
// what could not be honoured (reported, never silently dropped).
type localPlanResult struct {
	argv     []string
	policy   procPolicy
	skipped  []string
	usedExec bool
}

// localPlan turns a hardened request into the actual argv to exec plus the
// policy to apply to it. It is pure: given the same request and the same
// execSelf/helperAvailable inputs it always returns the same plan, which is
// what makes the fallback path testable without a kernel.
//
// Order matters: the helper installs the controls *before* it execs the
// payload, so the process that runs the payload is already confined.
func localPlan(req localPlanRequest) localPlanResult {
	sup := procPolicySupport()
	res := localPlanResult{argv: req.argv, policy: procPolicy{Setsid: sup.Setsid, Pdeathsig: sup.Pdeathsig}}
	wantNNP := req.cfg.Enabled && req.cfg.NoNewPrivs
	wantSeccomp := req.cfg.Enabled && req.cfg.Seccomp
	if wantNNP && !noNewPrivsApplicable {
		res.skipped = append(res.skipped, "no_new_privs="+unsupportedReason())
		wantNNP = false
	}
	if wantSeccomp && !seccompKernelAvailable() {
		res.skipped = append(res.skipped, "seccomp="+unsupportedReason())
		wantSeccomp = false
	}
	if !wantNNP && !wantSeccomp {
		return res
	}
	if req.execSelf == "" || !req.helperAvailable {
		if wantNNP {
			res.skipped = append(res.skipped, "no_new_privs=re-exec helper unavailable")
		}
		if wantSeccomp {
			res.skipped = append(res.skipped, "seccomp=re-exec helper unavailable")
		}
		return res
	}
	prefix := []string{req.execSelf, helperFlag}
	if wantSeccomp && req.cfg.HardForkProbe {
		// The drill reports what the filter would do instead of applying it:
		// the drill itself is an ordinary process that calls fork(2), and
		// denying fork in the process that performs the drill would stop it
		// from reporting anything. A real payload always gets the filter.
		prefix = append(prefix, hardForkFlag)
	}
	prefix = append(prefix, helperSep)
	prefix = append(prefix, req.argv...)
	res.argv = prefix
	res.usedExec = true
	res.policy.NoNewPrivs = wantNNP
	res.policy.Seccomp = wantSeccomp
	return res
}

// summarize renders the applied controls of a plan, for the audit trail.
func (p localPlanResult) summarize() []string {
	var out []string
	if p.policy.Setsid {
		out = append(out, "setsid")
	}
	if p.policy.Pdeathsig {
		out = append(out, "pdeathsig")
	}
	if p.policy.NoNewPrivs {
		out = append(out, "no_new_privs")
	}
	if p.policy.Seccomp {
		out = append(out, "seccomp")
	}
	sort.Strings(out)
	return out
}

// unsupportedReason explains why a control is not available, in the operator's
// terms: the platform's own words, not a guess.
func unsupportedReason() string {
	if hardeningProbeErr != nil {
		return "invalid environment: " + hardeningProbeErr.Error()
	}
	return ErrHardeningUnsupported.Error()
}
