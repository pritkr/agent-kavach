package main

// sandbox.go — pluggable sandbox backends (v3).
//
// Until v2 the executor was an if/else on `docker`: Docker when present, a
// local subprocess otherwise. That made two things impossible to say out loud:
// which one a given run used, and whether the stronger one was even *possible*
// on this host. v3 makes the choice explicit and inspectable:
//
//	Backend is the interface every executor implements (Run/Stop/Inspect).
//	dockerBackend  the supported deployment: --network none, memory/cpu/pids
//	               caps, read-only rootfs, workspace bind-mounted
//	localBackend   rlimits + timeout + process-group kill + the v3 kernel
//	               hardening (no_new_privs / seccomp / cgroup v2) from
//	               exec_linux.go
//	runscBackend   gVisor: docker with `--runtime=runsc`, i.e. a userspace
//	               syscall interception layer between the agent and the host
//	               kernel. Auto-detected by looking for the `runsc` binary.
//
// The one rule that matters most here: a backend that cannot run returns the
// structured ErrBackendUnavailable. It never degrades into "ran it locally and
// reported success", because the whole point of asking for gVisor is that the
// run must *not* happen without it. policy.yaml can pin a backend; a pinned
// backend that is unavailable is a hard failure at run time, and the boot log
// plus /v1/backends say so.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrBackendUnavailable is the one error every backend uses to say "I cannot run
// here", with a machine-readable reason so a caller can tell a missing binary
// from a failed probe.
var ErrBackendUnavailable = errors.New("backend unavailable")

// The backend names. policy.yaml may only name one of these, and anything else
// is a manifest error (fail closed).
const (
	BackendDocker = "docker"
	BackendLocal  = "local"
	BackendRunsc  = "runsc"
	BackendAuto   = "auto"
)

// KnownBackends is the closed universe, in auto-preference order. "auto" is a
// policy-only value: it means "pick the strongest available".
var KnownBackends = []string{BackendRunsc, BackendDocker, BackendLocal, BackendAuto}

// IsKnownBackend reports whether name is a legal backend selector.
func IsKnownBackend(name string) bool {
	for _, b := range KnownBackends {
		if b == name {
			return true
		}
	}
	return false
}

// BackendUnavailableError carries the reason a backend cannot run, so
// /v1/runs and the audit trail can say *why* instead of a bare "error".
type BackendUnavailableError struct {
	Backend string `json:"backend"`
	Reason  string `json:"reason"`
	Hint    string `json:"hint,omitempty"`
}

func (e *BackendUnavailableError) Error() string {
	return fmt.Sprintf("backend %q unavailable: %s", e.Backend, e.Reason)
}

// Unwrap makes errors.Is(err, ErrBackendUnavailable) true for callers that do
// not want to know the concrete type.
func (e *BackendUnavailableError) Unwrap() error { return ErrBackendUnavailable }

// BackendInfo is what a backend says about itself, for /v1/backends.
type BackendInfo struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	// Kind is the isolation mechanism in one word: "container", "gvisor" or
	// "host-process". It is the thing an operator is actually choosing between.
	Kind string `json:"kind"`
	// Isolation is a plain-language statement of what this backend does and does
	// not provide. It is served, not just documented, so a dashboard can show it.
	Isolation string `json:"isolation"`
	// Reason explains an unavailability (empty when available).
	Reason string `json:"reason,omitempty"`
	// Hint says what to do about it.
	Hint string `json:"hint,omitempty"`
	// Runtime names the binary that was found (docker, runsc, sh).
	Runtime string `json:"runtime,omitempty"`
	// Version is the runtime's own version string, when it answers quickly.
	Version string `json:"version,omitempty"`
	// Confined is the headline: does a syscalls-reaching agent hit the host
	// kernel directly? "yes" for local, "no" for docker/runsc.
	Confined bool `json:"confined"`
}

// RunRequest is one execution handed to a backend.
type RunRequest struct {
	Command []string
	Image   string
	// Workspace is the host directory mounted/bound as the run's working dir.
	Workspace string
	Timeout   time.Duration
	// Name identifies the run to the backend (container name / log tag).
	Name string
	// Env are "K=V" pairs for the child. Nil means "inherit" (legacy local mode).
	Env []string
}

// RunOutcome is the backend's result. It is deliberately the same shape the
// executor already returns, so the HTTP surface does not change.
type RunOutcome struct {
	Output   string
	ExitCode int
	Killed   bool
	ErrMsg   string
	// Backend is the name that actually ran it ("docker", "local", "runsc").
	Backend string
	// Hardening names the kernel controls in force (local only; "" elsewhere).
	Hardening string
}

// Backend is the executor interface. Three implementations ship; the point of
// the interface is that a fourth (bubblewrap, a remote pool, a VM) can be added
// without touching the server.
type Backend interface {
	// Name is one of KnownBackends.
	Name() string
	// Available reports whether this backend can run *here*, with the reason
	// when it cannot. It must be cheap and side-effect free.
	Available() (bool, string)
	// Run executes req under the backend's confinement.
	Run(ctx context.Context, req RunRequest) RunOutcome
	// Stop kills the run named by the handle returned in RunOutcome… except it
	// does not, which is why it takes a RunRequest name: kills are by name, so
	// the API stays "stop this run" without a handle type.
	Stop(ctx context.Context, name string) error
	// Inspect describes the backend (served at /v1/backends).
	Inspect() BackendInfo
}

// --- docker ---

// dockerBackend is the supported deployment. The flags are the v2 profile,
// unchanged: no network, memory/swap/cpu/pids caps, read-only rootfs, noexec
// tmpfs, workspace mounted at /w.
type dockerBackend struct {
	// runtime is the docker --runtime value: "" (runc) or "runsc" (gVisor).
	runtime string
	// name is the backend name: BackendDocker or BackendRunsc.
	name string
	kind string
}

func newDockerBackend() *dockerBackend {
	return &dockerBackend{name: BackendDocker, kind: "container", runtime: ""}
}

func (b *dockerBackend) Name() string { return b.name }

func (b *dockerBackend) Available() (bool, string) {
	if _, err := exec.LookPath("docker"); err != nil {
		return false, "docker CLI not on PATH"
	}
	if b.runtime != "" {
		// A runsc-pinned docker that cannot actually start a runsc container is
		// not "available" — that is exactly the fake-success case to avoid.
		if err := b.probeRuntime(); err != nil {
			return false, err.Error()
		}
	}
	return true, ""
}

// probeRuntime asks docker for the runtimes it has, once per process.
func (b *dockerBackend) probeRuntime() error {
	out, err := exec.Command("docker", "info", "--format", "{{json .Runtimes}}").Output()
	if err != nil {
		return fmt.Errorf("cannot query docker runtimes: %w", err)
	}
	if !strings.Contains(string(out), b.runtime) {
		return fmt.Errorf("docker has no %q runtime registered (daemon.json needs {{\"runtimes\": {{\"%s\": ...}}}})", b.runtime, b.runtime)
	}
	return nil
}

func (b *dockerBackend) Run(ctx context.Context, req RunRequest) RunOutcome {
	if len(req.Command) == 0 {
		return RunOutcome{Backend: b.name, ExitCode: 2, ErrMsg: "empty command"}
	}
	if ok, why := b.Available(); !ok {
		return RunOutcome{Backend: b.name, ExitCode: 125, ErrMsg: (&BackendUnavailableError{Backend: b.name, Reason: why}).Error()}
	}
	image := req.Image
	if image == "" {
		image = "alpine:3.20"
	}
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	args := []string{"run", "--rm", "--name", req.Name, "--network", "none",
		"--memory", "256m", "--memory-swap", "256m", "--cpus", "0.5",
		"--pids-limit", "64", "--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"}
	if b.runtime != "" {
		args = append(args, "--runtime", b.runtime)
	}
	for _, kv := range req.Env {
		// Only vault-built env reaches here; still, never forward a bare "K="
		// entry, and never let the list smuggle extra docker flags.
		if kv == "" || kv[0] == '-' || !hasEnvValue(kv) {
			continue
		}
		args = append(args, "-e", kv)
	}
	quoted := make([]string, len(req.Command))
	for i, a := range req.Command {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", `'"'"'`) + "'"
	}
	args = append(args, "-v", req.Workspace+":/w:rw", "-w", "/w", image, "sh", "-c", strings.Join(quoted, " "))

	out, code, killed, err := runCaptured(ctx, "docker", args...)
	res := RunOutcome{Output: truncate([]byte(out)), ExitCode: code, Killed: killed, Backend: b.name}
	if killed {
		b.Stop(context.Background(), req.Name)
		res.ErrMsg = fmt.Sprintf("timeout after %d s", int(req.Timeout.Seconds()))
		res.ExitCode = 124
		return res
	}
	if err != nil {
		res.ErrMsg = err.Error()
		if res.ExitCode == 0 {
			res.ExitCode = 1
		}
	}
	return res
}

func (b *dockerBackend) Stop(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "docker", "kill", name).Run()
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", name).Run()
	return nil
}

func (b *dockerBackend) Inspect() BackendInfo {
	info := BackendInfo{Name: b.name, Kind: b.kind, Confined: true, Runtime: "docker"}
	// The isolation text describes what the backend *is*, so it is populated even
	// when the backend is absent: an operator deciding whether to install
	// something needs to know what it would buy them.
	if b.runtime != "" {
		info.Isolation = "gVisor (runsc): the agent's syscalls are interpreted in userspace by the gVisor sandbox and answered by a much smaller host-kernel surface (Sentry)"
	} else {
		info.Isolation = "container (runc): namespaces + seccomp + cgroups, but the host kernel is still the one the agent's syscalls reach"
	}
	ok, why := b.Available()
	info.Available = ok
	info.Reason = why
	if !ok {
		info.Hint = dockerHint
		return info
	}
	if v, err := exec.Command("docker", "--version").Output(); err == nil {
		info.Version = strings.TrimSpace(firstLine(string(v)))
	}
	if b.runtime != "" {
		info.Runtime = "docker --runtime=runsc"
	}
	return info
}

const dockerHint = "install Docker, or pin `backend: local` in policy.yaml if the local-subprocess posture is acceptable for your workload"

// --- local ---

// localBackend runs the command as a direct child on the host kernel, wrapped in
// `sh` with rlimits and the v3 hardening. It is the fallback, and it is honest
// about being the weakest option: Inspect reports Confined: false.
type localBackend struct{}

func newLocalBackend() *localBackend { return &localBackend{} }

func (b *localBackend) Name() string { return BackendLocal }

func (b *localBackend) Available() (bool, string) {
	if _, err := exec.LookPath("sh"); err != nil {
		return false, "no POSIX shell on PATH to wrap the command in"
	}
	return true, ""
}

func (b *localBackend) Run(ctx context.Context, req RunRequest) RunOutcome {
	timeoutSec := int(req.Timeout / time.Second)
	if timeoutSec <= 0 {
		timeoutSec = 1
	}
	res := executeLocalEnv(ctx, req.Command, req.Workspace, timeoutSec, req.Env)
	return RunOutcome{
		Output: res.Output, ExitCode: res.ExitCode, Killed: res.Killed,
		ErrMsg: res.ErrMsg, Backend: BackendLocal, Hardening: res.Hardening,
	}
}

func (b *localBackend) Stop(ctx context.Context, name string) error {
	// The local executor kills by process group on timeout and by context
	// cancel on the kill-switch; there is no per-name container to remove.
	// Name is accepted so the interface is uniform, and refusing beats
	// pretending: a caller that asked to stop something specific must learn
	// that the local backend cannot address it.
	return fmt.Errorf("the local backend has no addressable run %q: it kills by process group on timeout/cancel", name)
}

func (b *localBackend) Inspect() BackendInfo {
	info := BackendInfo{
		Name: BackendLocal, Kind: "host-process", Runtime: "sh",
		Isolation: "host process: rlimits + wall-clock timeout + process-group SIGKILL",
		Confined:  false,
	}
	ok, why := b.Available()
	info.Available, info.Reason = ok, why
	if !ok {
		info.Hint = "install any POSIX shell (sh)"
		return info
	}
	// Name only the kernel controls this host really has, so the sentence cannot
	// advertise a control the report says was skipped.
	if rep := SandboxHardening(); len(rep.Applied) > 0 {
		info.Isolation += "; kernel controls in force here: " + strings.Join(rep.Applied, " ")
	}
	info.Isolation += " — no namespace and no mount isolation, so the agent's syscalls reach the host kernel"
	return info
}

// --- runsc / gVisor ---

// runscBackend is gVisor: docker with `--runtime=runsc`. It is the only backend
// that puts a userspace syscall interception layer between the agent and the host
// kernel, which is the difference between "relies on the container runtime" and
// "runtime-isolated".
//
// Auto-detection is deliberately two-stage, because a `runsc` binary on PATH is
// not a working gVisor runtime:
//
//  1. `runsc` is on PATH (or KAVACH_RUNSC points at it), and
//  2. the docker daemon has a runtime registered under that name.
//
// If either fails, Available reports it and Run returns ErrBackendUnavailable.
// There is no local-subprocess fallback here: a run that asked for gVisor and
// did not get it must fail, loudly, rather than execute unconfined and report
// success.
type runscBackend struct {
	// binary is the resolved runsc path ("" = not found).
	binary string
	// dockerRuntime is the name docker knows the runtime by.
	dockerRuntime string
	inner         *dockerBackend
}

func newRunscBackend() *runscBackend {
	return &runscBackend{dockerRuntime: "runsc", inner: &dockerBackend{name: BackendRunsc, kind: "gvisor", runtime: "runsc"}}
}

func (b *runscBackend) Name() string { return BackendRunsc }

func (b *runscBackend) Available() (bool, string) {
	if b.binary == "" {
		if p := runscPath(); p == "" {
			return false, "runsc binary not found (install gVisor, or point KAVACH_RUNSC at it)"
		}
	}
	if ok, why := b.inner.Available(); !ok {
		return false, "docker unavailable: " + why
	}
	return true, ""
}

func (b *runscBackend) Run(ctx context.Context, req RunRequest) RunOutcome {
	if ok, why := b.Available(); !ok {
		return RunOutcome{
			Backend: BackendRunsc, ExitCode: 125,
			ErrMsg: (&BackendUnavailableError{
				Backend: BackendRunsc, Reason: why,
				Hint: "register the runtime in /etc/docker/daemon.json: {\"runtimes\": {\"runsc\": {\"path\": \"<runsc path>\"}}} then restart dockerd",
			}).Error(),
		}
	}
	return b.inner.Run(ctx, req)
}

func (b *runscBackend) Stop(ctx context.Context, name string) error { return b.inner.Stop(ctx, name) }

func (b *runscBackend) Inspect() BackendInfo {
	info := BackendInfo{
		Name: BackendRunsc, Kind: "gvisor", Confined: true, Runtime: "runsc",
		Isolation: "gVisor (runsc): the agent's syscalls are interpreted in userspace by the gVisor sandbox; the host kernel only sees gVisor's own, much smaller, syscall surface",
	}
	ok, why := b.Available()
	info.Available, info.Reason = ok, why
	if !ok {
		info.Hint = "install gVisor (https://gvisor.dev/docs/user_guide/install/) and register runsc in dockerd, or point KAVACH_RUNSC at an existing runsc"
		return info
	}
	if v, err := exec.Command(b.binary, "--version").Output(); err == nil {
		info.Version = strings.TrimSpace(firstLine(string(v)))
	}
	if inner := b.inner.Inspect(); inner.Version != "" {
		info.Version = strings.TrimSpace(info.Version + " / docker " + inner.Version)
	}
	return info
}

// runscPath resolves the runsc binary: $KAVACH_RUNSC first (an explicit path or
// name), then PATH. A missing binary is not an error here — it is the
// availability answer. It is resolved once per registry (NewBackendRegistry) so
// /v1/backends does not scan PATH on every scrape, and left unmemoised so a
// test — or an operator who installs gVisor without restarting — sees the truth.
func runscPath() string {
	if p := strings.TrimSpace(envOrEmpty("KAVACH_RUNSC")); p != "" {
		if strings.ContainsRune(p, os.PathSeparator) {
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
			return ""
		}
		if resolved, err := exec.LookPath(p); err == nil {
			return resolved
		}
		return ""
	}
	if resolved, err := exec.LookPath("runsc"); err == nil {
		return resolved
	}
	return ""
}

// --- registry / selection ---

// BackendRegistry holds the three backends plus the resolved policy pin.
type BackendRegistry struct {
	mu       sync.Mutex
	backends []Backend
	pinned   string // "" = auto
	active   string
}

// NewBackendRegistry builds the registry, resolving the runsc path once so
// /v1/backends does not stat a binary on every scrape.
func NewBackendRegistry(pinned string) *BackendRegistry {
	runsc := newRunscBackend()
	runsc.binary = runscPath()
	if pinned == "" {
		pinned = BackendAuto
	}
	return &BackendRegistry{
		backends: []Backend{runsc, newDockerBackend(), newLocalBackend()},
		pinned:   pinned,
	}
}

// Backends returns the backends in preference order.
func (r *BackendRegistry) Backends() []Backend {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Backend(nil), r.backends...)
}

// Pinned is the policy selector ("auto" or a concrete backend).
func (r *BackendRegistry) Pinned() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pinned
}

// InspectAll returns one BackendInfo per backend, in preference order.
func (r *BackendRegistry) InspectAll() []BackendInfo {
	var out []BackendInfo
	for _, b := range r.Backends() {
		out = append(out, b.Inspect())
	}
	sort.SliceStable(out, func(i, j int) bool { return backendRank(out[i].Name) < backendRank(out[j].Name) })
	return out
}

func backendRank(name string) int {
	for i, b := range KnownBackends {
		if b == name {
			return i
		}
	}
	return len(KnownBackends)
}

// Select returns the backend a run should use, and a structured error when the
// pinned one cannot run. Selection is deliberately *not* "pick whatever is
// available": a pinned backend that is unavailable is an error, because silently
// running under a weaker backend is precisely the failure mode this file exists
// to prevent.
func (r *BackendRegistry) Select() (Backend, error) {
	r.mu.Lock()
	pinned := r.pinned
	backends := append([]Backend(nil), r.backends...)
	r.mu.Unlock()

	if pinned != BackendAuto {
		for _, b := range backends {
			if b.Name() != pinned {
				continue
			}
			ok, why := b.Available()
			r.setActive(pinned)
			if !ok {
				return nil, &BackendUnavailableError{
					Backend: pinned, Reason: why,
					Hint: "policy.yaml pins `backend: " + pinned + "`, so kavach refuses to fall back to a weaker backend",
				}
			}
			return b, nil
		}
		return nil, &BackendUnavailableError{
			Backend: pinned, Reason: "not a known backend",
			Hint: "known backends: " + strings.Join(KnownBackends, ", "),
		}
	}
	// auto: strongest first.
	for _, b := range backends {
		if ok, _ := b.Available(); ok {
			r.setActive(b.Name())
			return b, nil
		}
	}
	return nil, &BackendUnavailableError{
		Backend: BackendAuto, Reason: "no backend is available on this host",
		Hint: "install docker (or gVisor for the runsc backend); the local backend needs a POSIX shell",
	}
}

func (r *BackendRegistry) setActive(name string) {
	r.mu.Lock()
	r.active = name
	r.mu.Unlock()
}

// Active is the backend the last Select chose ("" before the first run).
func (r *BackendRegistry) Active() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active
}

// runCaptured runs a command, returning combined output, exit code, whether it
// was killed by the context, and the error. Shared by the docker and runsc
// backends so the two differ only in their flags.
func runCaptured(ctx context.Context, name string, args ...string) (string, int, bool, error) {
	c := exec.CommandContext(ctx, name, args...)
	var sb strings.Builder
	c.Stdout = &sb
	c.Stderr = &sb
	err := c.Run()
	killed := ctx.Err() == context.DeadlineExceeded
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	return sb.String(), code, killed, err
}

// hasEnvValue reports whether a "K=V" pair actually carries a value. An empty
// one leaks the *name* of a secret the caller expected to be absent, so it is
// dropped rather than forwarded.
func hasEnvValue(kv string) bool {
	i := strings.IndexByte(kv, '=')
	return i > 0 && i < len(kv)-1
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func envOrEmpty(name string) string { return os.Getenv(name) }
