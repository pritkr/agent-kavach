//go:build !linux

package main

// exec_fallback.go — executor hardening on platforms without the Linux kernel
// primitives.
//
// The daemon still ships and still runs here (a macOS laptop is the normal dev
// box), so this file does two things, both of them honest:
//
//   - It applies what the platform *does* have. Setsid is a POSIX primitive and
//     exists on darwin and the BSDs, so a local run is still its own session
//     leader with no controlling terminal — and, importantly, still its own
//     process group, which is what the timeout's kill(-pgid) depends on.
//   - It reports everything else as unavailable, through the same
//     HardeningReport the Linux path fills in, so /v1/backends says
//     "no_new_privs: not available here" instead of claiming a control that was
//     never applied. Graceful degradation, never a silent claim.
//
// The rejected calls return ErrHardeningUnsupported rather than a fabricated
// success: a caller that asked for confinement and did not get it must be able
// to tell.

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"syscall"
)

// hardeningRuntime is reported by /v1/backends.
const hardeningRuntime = "non-linux"

// noNewPrivsApplicable: prctl(PR_SET_NO_NEW_PRIVS) is a Linux interface.
const noNewPrivsApplicable = false

// seccompKernelAvailable is false everywhere but Linux. seccomp-BPF is a Linux
// kernel feature; there is no honest substitute to fall back to.
func seccompKernelAvailable() bool { return false }

// procPolicySupport reports what this platform offers. Setsid is the only one
// that exists outside Linux, so Pdeathsig (a Linux prctl/PR_SET_PDEATHSIG
// feature) is false.
func procPolicySupport() procPolicy { return procPolicy{Setsid: true} }

// applyProcPolicy sets the SysProcAttr fields this platform supports.
func applyProcPolicy(cmd *exec.Cmd, p procPolicy) {
	attr := &syscall.SysProcAttr{}
	if p.Setsid {
		// New session (and therefore a new process group with pgid == pid):
		// the timeout kill(-pgid) still reaches every descendant, and the run
		// cannot acquire the controlling terminal of the daemon's.
		attr.Setsid = true
	}
	cmd.SysProcAttr = attr
}

// procAttrDeathSignal is always 0 off Linux: PR_SET_PDEATHSIG has no equivalent
// here, so the field does not even exist in the struct. The accessor keeps the
// test for that invariant writable on a non-Linux dev box.
func procAttrDeathSignal(*syscall.SysProcAttr) syscall.Signal { return 0 }

// installNoNewPrivs fails loudly rather than pretending.
func installNoNewPrivs() error {
	return fmt.Errorf("%w: prctl(PR_SET_NO_NEW_PRIVS) is a Linux interface (GOOS=%s)", ErrHardeningUnsupported, runtime.GOOS)
}

// installSeccompFilter fails loudly rather than pretending.
func installSeccompFilter([]sockFilter) error {
	return fmt.Errorf("%w: seccomp-BPF is a Linux kernel feature (GOOS=%s)", ErrHardeningUnsupported, runtime.GOOS)
}

// readCgroupScope fails: cgroup v2 does not exist here.
func readCgroupScope() (cgroupScope, error) {
	return cgroupScope{}, fmt.Errorf("%w: cgroup v2 is a Linux kernel feature (GOOS=%s)", ErrHardeningUnsupported, runtime.GOOS)
}

// cgroupScope is a placeholder so the report can name the capability. There is
// no hierarchy to point at off Linux, hence the empty fields.
type cgroupScope struct {
	Root string
	Rel  string
}

// Dir is the cgroup v2 directory for this scope (empty off Linux).
func (s cgroupScope) Dir() string {
	if s.Root == "" {
		return ""
	}
	if s.Rel == "" || s.Rel == "/" {
		return s.Root
	}
	return s.Root + s.Rel
}

// cgroupState mirrors the Linux probe's result so the report code is one path.
type cgroupState struct {
	available bool
	writable  bool
	scope     string
	note      string
}

// probeCgroupCaps: there is no cgroup hierarchy off Linux, so nothing is
// available and nothing is writable. Returning that explicitly (instead of
// omitting the field) is what makes /v1/backends say "not here" rather than
// leaving an operator to guess.
func probeCgroupCaps(int64) cgroupState {
	return cgroupState{note: ErrHardeningUnsupported.Error()}
}

// applyCgroupCaps is a no-op that says so.
func applyCgroupCaps(int64) string { return "cgroup=unavailable(not-linux)" }

// runSeccompProbe cannot run a seccomp filter here, so it reports the same
// thing the parent expects: a non-zero exit, i.e. "not available".
func runSeccompProbe() int { return 1 }

// runSeccompExec is the re-exec helper off Linux. The child cannot confine
// itself, so it says so on stderr — which the run's captured output carries
// into the audit trail — and then execs the payload anyway. Executing is not
// faking success: the caller already recorded that the controls were skipped,
// and the report says why.
func runSeccompExec(argv []string, hardFork bool) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "kavach: -seccomp-exec needs a command to run")
		return 2
	}
	// Re-resolved from this process's own (inherited) environment, exactly like
	// the Linux child does, so a hand-invoked child behaves the same.
	cfg, cerr := HardeningFromEnv()
	if cerr != nil {
		fmt.Fprintf(os.Stderr, "kavach-hardening: invalid config: %v — no kernel controls applied\n", cerr)
		cfg = HardeningConfig{Enabled: false}
	}
	note := []string{"runtime=" + runtime.GOOS, "no_new_privs=unavailable(prctl)", "seccomp=unavailable(seccomp-bpf)"}
	if cfg.CgroupMemMiB > 0 {
		note = append(note, applyCgroupCaps(cfg.CgroupMemMiB))
	}
	if hardFork {
		note = append(note, "hard_fork=not-run(no filter to report)")
	}
	fmt.Fprintln(os.Stderr, "kavach-hardening: "+strings.Join(note, " "))
	// execve(2) does not search PATH, so a bare name has to be resolved first.
	// The same resolution the Linux helper needs, so the non-Linux helper does
	// not carry a second copy of the exit-127 bug.
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

// DeniedSyscalls is empty off Linux: there is no filter, so listing denied
// syscalls would be a lie. The strict argument is accepted and ignored.
func DeniedSyscalls(bool) []string { return nil }

// probeHardening assembles the boot report off Linux.
func probeHardening(cfg HardeningConfig) HardeningReport {
	rep := HardeningReport{Runtime: hardeningRuntime, Requested: cfg}
	rep.Note = "no_new_privs, seccomp and cgroup v2 are Linux controls; the local executor on this platform is confined by rlimits + timeout + process-group kill only"
	sup := procPolicySupport()
	if sup.Setsid {
		rep.Applied = append(rep.Applied, "setsid")
	}
	if sup.Pdeathsig {
		rep.Applied = append(rep.Applied, "pdeathsig")
	} else {
		rep.Skipped = append(rep.Skipped, "pdeathsig="+ErrHardeningUnsupported.Error())
	}
	if cfg.Seccomp {
		rep.Seccomp = SeccompReport{Available: false, Note: ErrHardeningUnsupported.Error()}
		rep.Skipped = append(rep.Skipped, "seccomp="+ErrHardeningUnsupported.Error())
	}
	if cfg.NoNewPrivs {
		rep.Skipped = append(rep.Skipped, "no_new_privs="+ErrHardeningUnsupported.Error())
	}
	if cfg.CgroupMemMiB > 0 {
		rep.Cgroup = CgroupReport{Available: false, Note: ErrHardeningUnsupported.Error()}
		rep.Skipped = append(rep.Skipped, "cgroup_memory="+ErrHardeningUnsupported.Error())
	}
	sort.Strings(rep.Applied)
	sort.Strings(rep.Skipped)
	return rep
}
