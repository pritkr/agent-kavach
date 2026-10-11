package main

// sandbox_test.go — the pluggable backend interface (v3).
//
// The interface's whole reason to exist is that a run must never be executed
// somewhere weaker than what was asked for. So the tests here are mostly about
// refusals: the gVisor backend with no runsc, a pinned backend that is not
// installed, the docker profile's flags, and what /v1/backends reports.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeRuntimeDir writes an executable named `name` into a temp dir and returns
// that dir, so a test can put a stub `docker`/`runsc` first on PATH and observe
// exactly what the backend would have executed — without a container runtime.
func fakeRuntimeDir(t *testing.T, name, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// 1. Interface conformance: all three backends implement the same interface, and
// the method set is exactly Run/Stop/Inspect plus Name/Available. A test that
// only checked the happy path would let a backend grow a private shortcut and
// drift back into "runs it locally instead".
func TestBackendInterfaceConformance(t *testing.T) {
	runsc := newRunscBackend()
	backends := []Backend{newDockerBackend(), newLocalBackend(), runsc}
	want := map[string]bool{"Name": true, "Available": true, "Run": true, "Stop": true, "Inspect": true}
	for _, b := range backends {
		// Compile-time conformance (a backend missing a method does not build).
		var _ Backend = b
		got := map[string]bool{}
		rt := reflect.TypeOf(b)
		for i := 0; i < rt.NumMethod(); i++ {
			got[rt.Method(i).Name] = true
		}
		for m := range want {
			if !got[m] {
				t.Errorf("%T is missing %s", b, m)
			}
		}
		for m := range got {
			if !want[m] {
				t.Errorf("%T exposes %s, which no caller should depend on", b, m)
			}
		}
		if !IsKnownBackend(b.Name()) {
			t.Errorf("%T.Name()=%q is not in the closed set", b, b.Name())
		}
	}
}

// 2. Every backend can describe itself, and the description says the one thing an
// operator needs: can a syscall from the agent reach the host kernel?
func TestBackendInspectIsHonest(t *testing.T) {
	local := newLocalBackend().Inspect()
	if local.Available {
		if local.Confined {
			t.Fatal("the local backend runs on the host kernel; it must not claim confinement")
		}
		if local.Kind != "host-process" {
			t.Fatalf("kind=%q want host-process", local.Kind)
		}
		if !strings.Contains(local.Isolation, "setsid") {
			t.Fatalf("the local description must name what it does apply: %q", local.Isolation)
		}
	}
	docker := newDockerBackend().Inspect()
	if docker.Confined != true {
		t.Fatal("the docker backend is confined (namespaces + seccomp + cgroups)")
	}
	runsc := newRunscBackend().Inspect()
	if runsc.Confined != true || runsc.Kind != "gvisor" {
		t.Fatalf("runsc must describe itself as gvisor+confined: %+v", runsc)
	}
	if !strings.Contains(runsc.Isolation, "gVisor") {
		t.Fatalf("the gVisor description must say what it is: %q", runsc.Isolation)
	}
}

// 3. gVisor auto-detection: no runsc anywhere means "unavailable", never a
// silent success. The error must be the structured one so a caller can tell
// "not installed" from "installed but broken".
func TestRunscAbsentIsUnavailableNotSuccess(t *testing.T) {
	t.Setenv("KAVACH_RUNSC", "")
	t.Setenv("PATH", t.TempDir()) // an empty PATH: no docker, no runsc
	b := newRunscBackend()
	ok, why := b.Available()
	if ok {
		t.Fatal("runsc must not be available with an empty PATH")
	}
	if !strings.Contains(why, "runsc") {
		t.Fatalf("the reason must name what is missing, got %q", why)
	}
	out := b.Run(context.Background(), RunRequest{Command: []string{"echo", "hi"}, Timeout: 5 * time.Second})
	if out.ExitCode == 0 || out.ErrMsg == "" {
		t.Fatalf("a run must not report success without runsc: %+v", out)
	}
	if out.Backend != BackendRunsc {
		t.Fatalf("the outcome must be attributed to runsc, got %q", out.Backend)
	}
	if !strings.Contains(out.ErrMsg, "unavailable") {
		t.Fatalf("the error must be the structured unavailable error: %q", out.ErrMsg)
	}
}

// 4. The strongest guarantee: a run that asks for gVisor and cannot get it must
// not execute anything at all. The command would create a file; the file must
// not exist afterwards.
func TestRunscRefusalExecutesNothing(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "pwned")
	t.Setenv("KAVACH_RUNSC", "")
	t.Setenv("PATH", t.TempDir())
	b := newRunscBackend()
	out := b.Run(context.Background(), RunRequest{
		Command:   []string{"touch", marker},
		Workspace: dir,
		Timeout:   5 * time.Second,
	})
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the payload ran even though runsc was unavailable — that is the fake-success failure mode")
	}
	if out.ExitCode != 125 {
		t.Fatalf("exit=%d want 125 (the same code docker uses for 'cannot run')", out.ExitCode)
	}
}

// 5. A pinned backend that is unavailable is a hard error naming the pin. The
// whole point of `backend: runsc` is that kavach must not quietly fall back to a
// host process.
func TestPinnedBackendUnavailableIsAHardError(t *testing.T) {
	t.Setenv("KAVACH_RUNSC", "")
	t.Setenv("PATH", t.TempDir())
	r := NewBackendRegistry(BackendRunsc)
	if r.Pinned() != BackendRunsc {
		t.Fatalf("pinned=%q", r.Pinned())
	}
	b, err := r.Select()
	if err == nil {
		t.Fatalf("selecting an unavailable pinned backend must fail, got %T", b)
	}
	if b != nil {
		t.Fatal("no backend may be returned alongside an error")
	}
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("error must wrap ErrBackendUnavailable: %v", err)
	}
	var be *BackendUnavailableError
	if !errors.As(err, &be) {
		t.Fatalf("error must be structured: %T", err)
	}
	if be.Backend != BackendRunsc {
		t.Fatalf("backend=%q want runsc", be.Backend)
	}
	if !strings.Contains(be.Hint, "policy.yaml") {
		t.Fatalf("the hint must explain that the pin caused it: %q", be.Hint)
	}
	if strings.Contains(err.Error(), "local") {
		t.Fatalf("the error must not suggest a weaker backend: %v", err)
	}
}

// 6. auto prefers the strongest backend that actually works, and with nothing
// installed it is an error rather than a guess.
func TestRegistryAutoPicksTheStrongestAvailable(t *testing.T) {
	t.Setenv("KAVACH_RUNSC", "")
	// A stub docker that answers `info` with a runsc runtime and succeeds at run.
	dir := fakeRuntimeDir(t, "docker", `#!/bin/sh
case "$1" in
  info) echo '{"runc":["runc"],"runsc":["/usr/bin/runsc"]}' ;;
  --version) echo "Docker version 99.0.0, build test" ;;
  run) echo "stub-container-ran"; exit 0 ;;
  kill|rm) exit 0 ;;
esac
exit 0
`)
	t.Setenv("PATH", dir)
	r := NewBackendRegistry("")
	if r.Pinned() != BackendAuto {
		t.Fatalf("empty pin must mean auto, got %q", r.Pinned())
	}
	b, err := r.Select()
	if err != nil {
		t.Fatal(err)
	}
	// No runsc binary on PATH, so docker wins; local is the last resort.
	if b.Name() != BackendDocker {
		t.Fatalf("auto selected %q, want docker (runsc is absent, local is weaker)", b.Name())
	}
	if r.Active() != BackendDocker {
		t.Fatalf("the registry must remember what it selected, got %q", r.Active())
	}

	// With runsc on PATH and registered, auto must pick gVisor.
	both := filepath.Join(dir, "runsc")
	if err := os.WriteFile(both, []byte("#!/bin/sh\necho runsc version 20260101\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	r2 := NewBackendRegistry("")
	b2, err := r2.Select()
	if err != nil {
		t.Fatal(err)
	}
	if b2.Name() != BackendRunsc {
		t.Fatalf("auto selected %q, want runsc when gVisor is present", b2.Name())
	}
}

// 7. A runsc binary on PATH is not enough: docker must have the runtime
// registered, or "available" would be a lie.
func TestRunscRequiresDockerRuntimeRegistration(t *testing.T) {
	dir := fakeRuntimeDir(t, "runsc", "#!/bin/sh\necho runsc version 20260101\n")
	t.Setenv("KAVACH_RUNSC", "")
	t.Setenv("PATH", dir)
	b := newRunscBackend()
	b.binary = runscPath()
	if ok, _ := b.Available(); ok {
		t.Fatal("runsc on PATH without docker must not be 'available'")
	}
	// Now add a docker that reports no runsc runtime.
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "docker"), []byte("#!/bin/sh\necho '{\"runc\":[\"runc\"]}'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "runsc"), []byte("#!/bin/sh\ntrue\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir2)
	b2 := newRunscBackend()
	b2.binary = runscPath()
	ok, why := b2.Available()
	if ok {
		t.Fatal("docker without a runsc runtime must not make the backend available")
	}
	if !strings.Contains(why, "daemon.json") {
		t.Fatalf("the reason must say how to fix it, got %q", why)
	}
}

// 8. KAVACH_RUNSC is honoured (an operator who installed gVisor somewhere
// non-standard must not have to put it on PATH).
func TestRunscPathOverride(t *testing.T) {
	dir := fakeRuntimeDir(t, "my-runsc", "#!/bin/sh\ntrue\n")
	t.Setenv("KAVACH_RUNSC", filepath.Join(dir, "my-runsc"))
	if got := runscPath(); got != filepath.Join(dir, "my-runsc") {
		t.Fatalf("KAVACH_RUNSC ignored: %q", got)
	}
	// A named lookup through PATH also works.
	t.Setenv("KAVACH_RUNSC", "my-runsc")
	t.Setenv("PATH", dir)
	if got := runscPath(); got == "" {
		t.Fatal("KAVACH_RUNSC as a bare name must resolve through PATH")
	}
	// A path that does not exist resolves to nothing rather than failing loudly
	// at exec time.
	t.Setenv("KAVACH_RUNSC", filepath.Join(dir, "nope"))
	if got := runscPath(); got != "" {
		t.Fatalf("a missing explicit path must resolve to empty, got %q", got)
	}
}

// 9. The docker profile is the security-relevant part: assert the exact flags, so
// a future "convenience" edit cannot quietly drop --network none or the pids
// limit. The stub echoes its argv, so the assertions are on the real command
// line the backend would have run.
func TestDockerBackendProfileFlags(t *testing.T) {
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	stub := `#!/bin/sh
if [ "$1" = "run" ]; then
  : > ` + argvFile + `
  for a in "$@"; do printf '%s\n' "$a" >> ` + argvFile + `; done
  echo container-output
  exit 0
fi
case "$1" in
  info) echo '{"runc":["runc"]}' ;;
  --version) echo "Docker version 99.0.0" ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("KAVACH_RUNSC", "")
	ws := t.TempDir()
	b := newDockerBackend()
	out := b.Run(context.Background(), RunRequest{
		Command:   []string{"echo", "hi there"},
		Workspace: ws,
		Timeout:   30 * time.Second,
		Name:      "kavach-test",
		Env:       []string{"KAVACH_DEMO_TOKEN=secret", "-not-a-flag", "EMPTY="},
	})
	if out.ExitCode != 0 || !strings.Contains(out.Output, "container-output") {
		t.Fatalf("stub docker not invoked: %+v", out)
	}
	raw, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--network none", "--memory 256m", "--memory-swap 256m", "--cpus 0.5",
		"--pids-limit 64", "--read-only", "noexec,nosuid", ws + ":/w:rw",
		"--name kavach-test",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("docker argv missing %q\ngot: %s", want, joined)
		}
	}
	// The vault-built env is forwarded, but nothing can smuggle a flag.
	if !strings.Contains(joined, "-e KAVACH_DEMO_TOKEN=secret") {
		t.Errorf("the allowlisted secret was not forwarded: %s", joined)
	}
	if strings.Contains(joined, "-not-a-flag") {
		t.Error("a value that looks like a flag reached the docker command line")
	}
	if strings.Contains(joined, "EMPTY=") {
		t.Error("an empty value was forwarded")
	}
	// argv is quoted so a command cannot break out of sh -c.
	if !strings.Contains(joined, `'echo' 'hi there'`) {
		t.Errorf("argv was not quoted per argument: %s", joined)
	}
}

// 10. The runsc backend is docker with --runtime runsc and nothing else changed.
func TestRunscBackendAddsOnlyTheRuntimeFlag(t *testing.T) {
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	stub := `#!/bin/sh
if [ "$1" = "run" ]; then
  : > ` + argvFile + `
  for a in "$@"; do printf '%s\n' "$a" >> ` + argvFile + `; done
  echo gvisor-ran
  exit 0
fi
case "$1" in
  info) echo '{"runsc":["/usr/bin/runsc"]}' ;;
  --version) echo "Docker version 99.0.0" ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "runsc"), []byte("#!/bin/sh\necho runsc version 20260101\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("KAVACH_RUNSC", "")
	b := newRunscBackend()
	b.binary = runscPath()
	out := b.Run(context.Background(), RunRequest{
		Command: []string{"true"}, Workspace: t.TempDir(),
		Timeout: 30 * time.Second, Name: "kavach-runsc",
	})
	if out.ExitCode != 0 || out.Backend != BackendRunsc {
		t.Fatalf("runsc run failed: %+v", out)
	}
	raw, _ := os.ReadFile(argvFile)
	joined := strings.Join(strings.Split(strings.TrimRight(string(raw), "\n"), "\n"), " ")
	if !strings.Contains(joined, "--runtime runsc") {
		t.Fatalf("runsc backend must pass --runtime runsc: %s", joined)
	}
	// The confinement flags must survive unchanged.
	for _, want := range []string{"--network none", "--pids-limit 64", "--read-only"} {
		if !strings.Contains(joined, want) {
			t.Errorf("runsc profile dropped %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, "gvisor-ran") {
		t.Error("unexpected: the stub output leaked into the argv file")
	}
	info := b.Inspect()
	if !info.Available || !info.Confined || info.Version == "" {
		t.Fatalf("inspect must report a working, versioned gVisor: %+v", info)
	}
	if !strings.Contains(info.Version, "runsc version") {
		t.Fatalf("version must come from runsc itself: %q", info.Version)
	}
}

// 11. The local backend runs for real, and reports that it is the host-process
// backend. Its Stop is honest about not being able to address a run by name —
// refusing beats pretending.
func TestLocalBackendRunsAndRefusesNamedStops(t *testing.T) {
	b := newLocalBackend()
	out := b.Run(context.Background(), RunRequest{
		Command:   []string{"echo", "local-ran"},
		Workspace: t.TempDir(),
		Timeout:   20 * time.Second,
		Name:      "kavach-local",
	})
	if out.ExitCode != 0 || !strings.Contains(out.Output, "local-ran") {
		t.Fatalf("local run failed: %+v", out)
	}
	if out.Backend != BackendLocal || out.Hardening == "" {
		t.Fatalf("the local outcome must name its backend and controls: %+v", out)
	}
	if err := b.Stop(context.Background(), "kavach-local"); err == nil {
		t.Fatal("the local backend must refuse a named stop rather than pretend")
	}

	// An empty command is refused, not run.
	if got := b.Run(context.Background(), RunRequest{Timeout: time.Second}); got.ExitCode == 0 {
		t.Fatal("an empty command must not succeed")
	}
}

// 12. /v1/backends lists every backend with its availability and the reason,
// names the pin and the resolution, and carries the local executor's controls.
// This is the endpoint an operator (or a dashboard) reads instead of the docs.
func TestBackendsEndpointListsAvailability(t *testing.T) {
	t.Setenv("KAVACH_RUNSC", "")
	s := testServer(t, "")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/backends", nil))
	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Pinned     string `json:"pinned"`
		Active     string `json:"active"`
		ResolvedTo string `json:"resolved_to"`
		Backends   []struct {
			Name      string `json:"name"`
			Available bool   `json:"available"`
			Kind      string `json:"kind"`
			Reason    string `json:"reason"`
			Confined  bool   `json:"confined"`
		} `json:"backends"`
		Hardening map[string]any `json:"hardening"`
		Anchor    map[string]any `json:"anchor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if body.Pinned != BackendAuto {
		t.Fatalf("pinned=%q want auto", body.Pinned)
	}
	// All three backends, in strength order.
	want := []string{BackendRunsc, BackendDocker, BackendLocal}
	if len(body.Backends) != len(want) {
		t.Fatalf("backends=%d want %d: %+v", len(body.Backends), len(want), body.Backends)
	}
	for i, w := range want {
		if body.Backends[i].Name != w {
			t.Errorf("backends[%d]=%q want %q", i, body.Backends[i].Name, w)
		}
	}
	// Availability must come with a reason when false, and the local backend
	// must be present and marked unconfined.
	for _, b := range body.Backends {
		if b.Name == BackendLocal {
			if !b.Available {
				t.Errorf("the local backend needs only a shell: %q", b.Reason)
			}
			if b.Confined {
				t.Error("local must be reported as unconfined")
			}
		}
		if !b.Available && b.Reason == "" {
			t.Errorf("%s is unavailable with no reason", b.Name)
		}
	}
	if body.ResolvedTo == "" {
		t.Fatalf("the endpoint must say what a run would resolve to: %s", rec.Body.String())
	}
	if _, ok := body.Hardening["runtime"]; !ok {
		t.Errorf("the hardening report must be served: %v", body.Hardening)
	}
	if _, ok := body.Anchor["enabled"]; !ok {
		t.Errorf("the anchor status must be served: %v", body.Anchor)
	}
	// Method discipline.
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/backends", nil))
	if rec.Code != 405 {
		t.Fatalf("POST /v1/backends code=%d want 405", rec.Code)
	}
}

// 13. With a pinned-but-absent backend the endpoint must say so in the payload
// rather than pretending a run would work.
func TestBackendsEndpointReportsAnUnresolvablePin(t *testing.T) {
	t.Setenv("KAVACH_RUNSC", "")
	t.Setenv("PATH", t.TempDir()) // no docker, no runsc, no sh → nothing available
	s := testServer(t, "backend: runsc\n")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/backends", nil))
	if rec.Code != 200 {
		t.Fatalf("code=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"unavailable"`) {
		t.Fatalf("an unresolvable pin must be reported: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "policy.yaml") {
		t.Fatalf("the reason must name the pin: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"resolved_to"`) {
		t.Fatalf("nothing may be resolved to: %s", rec.Body.String())
	}
}

// 14. A run whose pinned backend is unavailable fails with a structured reason
// and is audited, instead of executing unconfined.
func TestRunWithUnavailablePinnedBackendFailsClosed(t *testing.T) {
	t.Setenv("KAVACH_RUNSC", "")
	s := testServer(t, "backend: runsc\n")
	// A run through the server must not execute: the marker file proves it.
	marker := filepath.Join(t.TempDir(), "executed")
	run := &Run{ID: newID(), Command: []string{"touch", marker}, TimeoutSec: 5}
	res := s.execute(context.Background(), run)
	if res.ExitCode == 0 {
		t.Fatalf("a run with no backend must fail: %+v", res)
	}
	if !strings.Contains(res.ErrMsg, "unavailable") {
		t.Fatalf("the reason must be the structured unavailable error: %q", res.ErrMsg)
	}
	// The run must name the backend it *asked for*, never one that did the work.
	if res.Sandbox != BackendRunsc {
		t.Fatalf("sandbox=%q want the requested backend runsc, not one that ran nothing", res.Sandbox)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the command executed even though no backend was available")
	}
	// It must be in the audit trail: a run that did not happen is a fact worth
	// recording, not a silent no-op.
	entries, err := s.audit.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e["event"] == "run.backend_unavailable" && e["run_id"] == run.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("the refused run was not audited")
	}
}

// 15. policy.yaml can pin the backend, both parsers agree, and a typo is a hard
// error (fail closed) — mirrored in mcp/test_server.py.
func TestPolicyBackendPin(t *testing.T) {
	dir := t.TempDir()
	pp := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pp, []byte("backend: runsc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := LoadPolicy(pp)
	if err != nil {
		t.Fatal(err)
	}
	if pol.Backend != BackendRunsc {
		t.Fatalf("backend=%q want runsc", pol.Backend)
	}
	// The committed manifest and the built-in default both mean "auto".
	def := DefaultPolicy()
	if def.Backend != BackendAuto {
		t.Fatalf("default backend=%q want auto", def.Backend)
	}
	example, err := LoadPolicy(filepath.Join("..", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if example.Backend != BackendAuto {
		t.Fatalf("the shipped policy.yaml must pin a known backend, got %q", example.Backend)
	}
	// A typo is refused, not ignored.
	for _, bad := range []string{"backend: runsc\n", "backend: RUNSC\n", "backend: vm\n", "backend: 3\n"} {
		bad := bad
		if bad == "backend: runsc\n" {
			continue
		}
		p := filepath.Join(dir, "bad.yaml")
		if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(p); err == nil {
			t.Errorf("manifest %q was accepted; a bad backend must abort the boot", bad)
		} else if !strings.Contains(err.Error(), "backend must be one of") {
			t.Errorf("unexpected error for %q: %v", bad, err)
		}
	}
	// /v1/policy exposes the pin so the operator can see it.
	s := testServer(t, "backend: local\n")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/policy", nil))
	if !strings.Contains(rec.Body.String(), `"backend":"local"`) {
		t.Fatalf("/v1/policy must expose the backend pin: %s", rec.Body.String())
	}
}

// 16. runCaptured is shared by both container backends: a timeout must be
// reported as killed with the container torn down, not as a mystery exit code.
func TestRunCapturedReportsTimeoutAsKilled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	out, code, killed, err := runCaptured(ctx, "/bin/sh", "-c", "sleep 30")
	if !killed {
		t.Fatalf("a context deadline must be reported as killed: code=%d err=%v out=%q", code, err, out)
	}
}

// 17. The closed backend set is a closed set: anything else is unknown, and
// KnownBackends is ordered strongest-first so "auto" is meaningful.
func TestKnownBackendsIsClosedAndOrdered(t *testing.T) {
	if len(KnownBackends) != 4 {
		t.Fatalf("KnownBackends=%v", KnownBackends)
	}
	for _, name := range []string{BackendRunsc, BackendDocker, BackendLocal, BackendAuto} {
		if !IsKnownBackend(name) {
			t.Errorf("%s should be known", name)
		}
	}
	for _, name := range []string{"", "vm", "bwrap", "DOCKER", "runsc ", "firecracker"} {
		if IsKnownBackend(name) {
			t.Errorf("%q must not be a known backend", name)
		}
	}
	if KnownBackends[0] != BackendRunsc {
		t.Errorf("auto must try gVisor first, got %q", KnownBackends[0])
	}
	if rank := backendRank(BackendLocal); rank <= backendRank(BackendRunsc) {
		t.Error("local must rank below runsc")
	}
	// The registry's inspection list must follow the same order.
	if runtime.GOOS == "" { // keeps the runtime import meaningful on every build
		t.Fatal("unreachable")
	}
	r := NewBackendRegistry("")
	names := []string{}
	for _, i := range r.InspectAll() {
		names = append(names, i.Name)
	}
	if strings.Join(names, ",") != strings.Join([]string{BackendRunsc, BackendDocker, BackendLocal}, ",") {
		t.Fatalf("InspectAll order=%v", names)
	}
}

// httptestRecorderGet is a small helper shared with the anchor tests: it serves
// one GET against the server's mux and returns the body.
func httptestRecorderGet(t *testing.T, s *Server, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != 200 {
		t.Fatalf("GET %s code=%d body=%s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}
