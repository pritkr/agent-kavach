// Package main implements agent-kavach: a zero-cloud, self-hosted agent
// sandbox runner daemon.
//
// Security model:
//   - Listens ONLY on a Unix-domain socket (zero open TCP ports).
//   - Socket file is chmod 0600; parent dir 0700.
//   - Every request must present a bearer token stored in a 0600 file.
//   - policy.yaml is loaded at boot: the single source of truth for the tool
//     allow/deny list, per-tool timeouts, the network allowlist, the workspace
//     root and the sandbox backend. Unknown tools are refused with a structured
//     error, and a pinned backend that is unavailable fails every run rather
//     than degrading to a weaker one.
//   - Credentials named in a tool's `env` allowlist are injected from the
//     process environment at exec time and redacted ([REDACTED]) from every
//     log path: spans, trace dumps, audit entries, stored run output.
//   - Commands run through the backend registry — gVisor (runsc) if installed,
//     else Docker (no network, memory/cpu/pids limits, read-only rootfs), else a
//     local subprocess wrapped with rlimits, a wall-clock timeout, process-group
//     kill and the v3 kernel hardening (no_new_privs, seccomp, cgroup v2,
//     setsid, pdeathsig). What is in force is served at /v1/backends.
//   - A global kill-switch plus per-run kill stops runaway agents.
//   - Every state transition is appended to a hash-chained, append-only audit
//     log (JSONL) whose head is periodically HMAC-anchored outside it;
//     `-verify` replays the chain and authenticates the anchors offline, and
//     exits 1 on tamper or anchor mismatch.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// Internal hardening modes first, before flag parsing: they are the child
	// side of the v3 executor (see exec_linux.go) and must never appear in the
	// daemon's option surface. The child re-resolves the hardening config from
	// its own (inherited) environment, so a directly invoked child behaves the
	// same as one the executor started.
	if code, handled := internalMode(os.Args[1:]); handled {
		os.Exit(code)
	}

	var (
		sockPath      = flag.String("socket", "/tmp/agent-kavach/kavach.sock", "unix socket path")
		tokenPath     = flag.String("token", "/tmp/agent-kavach/kavach.token", "bearer token file (0600)")
		workspace     = flag.String("workspace", "", "sandbox workspace root (default: from policy.yaml)")
		auditPath     = flag.String("audit", "/tmp/agent-kavach/audit.jsonl", "audit log path")
		tracePath     = flag.String("trace", "/tmp/agent-kavach/trace.json", "trace dump path")
		anchorPath    = flag.String("anchors", "", "external HMAC anchor file (default: <audit dir>/anchors.jsonl; empty = auto)")
		anchorEvery   = flag.Duration("anchor-every", 0, "how often to anchor the audit chain head (0 = env KAVACH_ANCHOR_INTERVAL, default 60s)")
		workers       = flag.Int("workers", 2, "job queue worker count")
		timeout       = flag.Int("timeout", 120, "default per-run timeout in seconds")
		policy        = flag.String("policy", "", "policy.yaml manifest path (empty = built-in defaults)")
		verify        = flag.String("verify", "", "verify an audit log's hash chain and its external anchors, then exit (0 intact, 1 tamper or anchor mismatch)")
		verifyAnchors = flag.String("verify-anchors", "", "anchor file to check against <audit> (default: <audit dir>/anchors.jsonl)")
		noAnchor      = flag.Bool("no-anchor", false, "disable the periodic external anchor (verify still reports the unanchored window)")
	)
	flag.Parse()

	// Offline audit verification: replay the hash chain, then check it against
	// the external anchors. Handled before any boot side effect so it also runs
	// on a cold box.
	if *verify != "" {
		anchors := *verifyAnchors
		if anchors == "" {
			anchors = defaultAnchorPath(*verify)
		}
		os.Exit(runVerify(*verify, anchors, os.Stdout, os.Stderr))
	}

	token, err := LoadOrCreateToken(*tokenPath)
	if err != nil {
		log.Fatalf("token: %v", err)
	}

	cfg := Config{
		SocketPath:     *sockPath,
		TokenPath:      *tokenPath,
		Workspace:      *workspace,
		AuditPath:      *auditPath,
		TracePath:      *tracePath,
		Workers:        *workers,
		DefaultTimeout: *timeout,
		Token:          token,
		PolicyPath:     *policy,
		AnchorPath:     firstNonEmpty(*anchorPath, defaultAnchorPath(*auditPath)),
		// Precedence: -anchor-every, then $KAVACH_ANCHOR_INTERVAL, then the
		// built-in default (inside the Anchor).
		AnchorInterval: firstPositiveDuration(*anchorEvery, AnchorIntervalFromEnv()),
		DisableAnchor:  *noAnchor,
		Backend:        "",
	}

	// NewServer loads the policy (refusing a broken manifest) and creates the
	// workspace root, so -workspace may be left empty.
	srv, err := NewServer(cfg)
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	// v3: what the executor can actually enforce, and what it cannot. Logged
	// before the first run so the boot log is the record of the posture.
	logHardeningOnce(SandboxHardening())

	// v3: external HMAC anchor of the audit chain head. Opt-in by construction —
	// without a key the daemon warns and verify reports the unanchored window —
	// and never fatal.
	srv.StartAnchoring()

	// Graceful shutdown: new runs rejected, running runs get SIGKILL via context cancel.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Println("shutting down (kill-switch engaged)")
		srv.EngageKillSwitch("shutdown")
		srv.Close()
	}()

	log.Printf("agent-kavach listening on unix://%s (backend=%s policy=%s)",
		*sockPath, srv.ActiveBackendName(), policySource(srv))
	if err := srv.Serve(); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

// firstNonEmpty returns the first non-empty string (a tiny helper so the flag
// defaults stay readable).
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// firstPositiveDuration returns the first positive duration, or 0.
func firstPositiveDuration(vals ...time.Duration) time.Duration {
	for _, v := range vals {
		if v > 0 {
			return v
		}
	}
	return 0
}

// internalMode dispatches the hidden hardening-helper modes before flag parsing.
// These are the child side of the v3 executor (exec_linux.go): the parent
// re-execs this binary to install no_new_privs/seccomp/cgroup before the payload
// runs, and the capability probe forks it the same way. Keeping them out of the
// flag set means they cannot be used to change daemon behaviour by accident.
//
// The child re-resolves the hardening config from its own (inherited)
// environment, so invoking it by hand behaves exactly like an executor-started
// child.
func internalMode(args []string) (int, bool) {
	if len(args) == 0 {
		return 0, false
	}
	switch args[0] {
	case seccompProbeFlag:
		return runSeccompProbe(), true
	case helperFlag:
		argv, hardFork := parseHelperArgs(args[1:])
		return runSeccompExec(argv, hardFork), true
	}
	return 0, false
}

// parseHelperArgs splits the helper's arguments: optional -hard-fork, then "--",
// then the command to run. A missing separator is an error rather than a
// guess — running the wrong argv because of sloppy parsing would be worse than
// refusing.
func parseHelperArgs(args []string) (argv []string, hardFork bool) {
	sep := -1
	for i, a := range args {
		if a == hardForkFlag {
			hardFork = true
			continue
		}
		if a == helperSep {
			sep = i
			break
		}
	}
	if sep < 0 {
		fmt.Fprintf(os.Stderr, "kavach: %s needs %s before the command\n", helperFlag, helperSep)
		return nil, hardFork
	}
	return args[sep+1:], hardFork
}

// policySource names the manifest in force, for the boot log line.
func policySource(s *Server) string {
	if p := s.policy.Path(); p != "" {
		return p
	}
	return "built-in defaults"
}

// runVerify is the offline audit check behind -verify. It returns the process
// exit code:
//
//	0  the hash chain is intact AND every anchor agrees with it. A missing
//	   anchor file or a missing key is a *warning* on stderr, not a silent pass:
//	   the chain really is verified, but nothing outside the log binds it, and
//	   the operator is told so.
//	1  any edited, relinked, resequenced, unchained or truncated line; any
//	   anchor whose MAC or chain does not verify; any anchor whose hash is not in
//	   the log (the wholesale-rewrite case); or a log that cannot be read at all —
//	   because "cannot verify" must never read as "verified".
func runVerify(path, anchors string, stdout, stderr io.Writer) int {
	if err := VerifyLog(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			fmt.Fprintf(stderr, "AUDIT LOG UNAVAILABLE: %s: %v (cannot verify — treat as failure)\n", path, err)
			return 1
		}
		fmt.Fprintf(stderr, "TAMPER DETECTED: %s: %v\n", path, err)
		return 1
	}
	fmt.Fprintf(stdout, "audit chain OK: %s\n", path)

	chk := VerifyAnchoredLog(path, anchors, AnchorKeyFromEnv())
	switch chk.Status {
	case "fail":
		// chk.Note already carries the banner; do not print it twice.
		fmt.Fprintf(stderr, "%s\n", chk.Note)
		for _, p := range chk.Problems {
			fmt.Fprintf(stderr, "  - %s\n", p)
		}
		return 1
	case "warn":
		// Warnings go to stderr so a scheduler watching stderr sees them, and
		// they never contain the word "pass".
		fmt.Fprintf(stderr, "WARNING: %s: %s\n", anchors, chk.Note)
		for _, w := range chk.Warnings {
			fmt.Fprintf(stderr, "  - %s\n", w)
		}
	default:
		fmt.Fprintf(stdout, "anchors OK: %d verified, %s\n", chk.Verified, chk.Note)
	}
	return 0
}
