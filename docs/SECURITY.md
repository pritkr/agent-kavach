# agent-kavach — threat model

Scope: the runner daemon (`daemon/`), the tool gateway (`mcp/`) and the
`policy.yaml` manifest they share. This document states what those controls
actually stop and — more importantly — what they do not. It is written to be
useful to someone deciding whether to run agent-kavach against workloads they
care about, so the "does not stop" section is the load-bearing part.

Last reviewed: 2026-09-26 (v3 — executor hardening, pluggable backends,
external audit anchor). v2's controls (vault, hash chain, policy manifest) are
unchanged and are still described below.

## 1. What we are defending

| Asset | Why it matters |
|---|---|
| Host filesystem outside the workspace | A sandbox escape here is host compromise |
| Credentials reachable by an agent run | API keys, tokens, deploy credentials |
| Audit trail | The record of what the agent actually did |
| Host network position | Agent runs must not become a network pivot |
| Availability | A runaway agent must be stoppable |

The adversary is **an autonomous agent whose input an attacker controls** —
i.e. prompt injection delivered through a fetched web page, a repository file,
a task description, or tool output. The agent is assumed to be *actively
hostile but sandboxed*: it will try to read files it was not given, exfiltrate
what it can reach, disable its own limits, and lie in its own logs.

## 2. Trusted computing base

Everything below is **trusted**; a compromise here defeats the controls.

- The Go daemon binary and the Python gateway binary.
- The host kernel and the container runtime — including the `runsc` binary and
  its dockerd registration, if the gVisor backend is in use.
- `policy.yaml` itself. It is the source of truth for what may run; anyone who
  can write it can widen the sandbox *and* choose the backend that runs it. Mount
  it read-only in production.
- The bearer token file (`0600`) and the operator's shell.
- `$KAVACH_ANCHOR_KEY`, for as long as the anchoring claim is meant to hold: an
  attacker who has it can write anchors consistent with a forged log (§5.3).

Everything **else** — including the agent, its prompts, the content it fetches,
and the scripts it executes — is untrusted input.

## 3. Attack surface

```
  browser ──(optional TCP bridge, dev only)──┐
  agent loop (TS) ──HTTP loopback──▶ mcp/server.py ──tools──▶ workspace / network
                                              │
                                        unix socket 0600 + bearer
                                              │
                                          daemon (Go)
                                       │            │
                             Backend registry      audit.jsonl (hash-chained)
                             runsc│docker│local        + anchors.jsonl (HMAC)
                                        │
                             hardened child: no_new_privs, seccomp,
                             setsid, pdeathsig, cgroup v2 pids/memory
```

The MCP gateway speaks plain HTTP because it lives on a loopback address
*inside* the deployment. It is the one component with a network listener.

## 4. What kavach stops

### 4.1 No open ports on the control plane

The daemon binds a **Unix-domain socket only** — there is no `net.Listen("tcp")`
anywhere in it, and the container has no `EXPOSE`. The socket file is created
under a restrictive umask and then explicitly `chmod 0600`; its parent directory
is `0700`. Every route except `/healthz` (open on purpose, for liveness probes
that must not need the secret) requires a bearer token compared with
`subtle.ConstantTimeCompare`. The token is 256 bits from `crypto/rand`, stored
`0600`, and the daemon **refuses to start** if the token file is group- or
other-readable.

Consequence: an attacker on the host network has nothing to connect to. An
attacker with a foothold on the host still needs the token *and* the socket's
`0600`, i.e. the same Unix UID.

### 4.2 Prompt injection is contained to the workspace

Injection is not prevented — a fetched page can still tell the agent to do
nasty things. What is prevented is the *blast radius*:

- **Gateway argument validation.** Every tool validates its arguments before
  dispatch: argv shape and length (≤64 args, ≤8192 bytes each, no NUL bytes),
  unknown-field rejection, URL scheme (`http`/`https` only) and path shape.
  Rejections are structured `{"code","message"}` errors, never stack traces.
- **Workspace scoping.** `file-read` and `eval-run` resolve
  `workspace / <arg>` and then call `.relative_to(workspace)`. `..` traversal,
  absolute paths and symlink escapes all fail with `path_outside_workspace`,
  because `resolve()` follows symlinks *before* the containment check.
- **Network allowlist.** `web-fetch` only reaches hosts in the policy
  `network_allowlist` (exact host or `*.suffix` wildcard). This is the control
  that stops an injected instruction from exfiltrating data to an attacker's
  server: the egress destination is decided by policy, not by the model.
- **No secrets to leak to the untrusted paths.** See §4.4.

### 4.3 Resource and lifetime limits

- **Per-tool wall-clock timeout**, from `policy.yaml`. Omitting `timeout_sec`
  binds the policy cap; asking for *more* than the cap is a structured
  `invalid_args` rejection, so policy cannot be widened from the client side.
- **Per-run timeout** (default 120 s, hard max 1800 s) with process-group
  `SIGKILL`, so orphaned grandchildren die with the run.
- **Container profile** (identical for `docker` and `runsc`, which only differs
  by `--runtime runsc`): `--network none`, `--memory 256m --memory-swap 256m`,
  `--cpus 0.5`, `--pids-limit 64`, `--read-only`, `--tmpfs /tmp:rw,noexec,nosuid`,
  workspace bind-mounted at `/w`. A fork bomb hits the pids limit; a disk fill
  hits a read-only rootfs.
- **Local profile**: rlimits + timeout + process-group kill, plus the v3 kernel
  controls of §4.7 (`no_new_privs`, seccomp, session, death signal, and a cgroup
  memory/pids cap where the hierarchy is writable).
- **Output caps**: 256 KiB per daemon run, 64 KiB per gateway call. A
  zip-bomb-style `file-read` is truncated, not amplified.
- **Kill-switch**: a global latch cancels in-flight runs and refuses new ones
  until explicitly released, plus a per-run `kill`. The trajectory records
  `killed` rather than pretending the run succeeded.

### 4.4 Credential vault — least privilege per tool

`policy.yaml` declares, per tool, the **names** of environment variables it may
receive. Values are read from the daemon's process environment at exec time and
injected into that one child process. Two properties matter:

- **The untrusted tools get nothing.** `web-fetch` and `eval-run` declare
  `env: []`. Fetched content and executed scripts are the least trustworthy
  inputs in the system, so they receive no credentials at all. Only
  `shell-sandboxed` (an operator-chosen, workspace-scoped command) can hold a
  secret, and then only the names listed.
- **Secrets never reach a log.** Redaction is applied on the way *out*, not on
  the way in, so it holds even when a command prints its own environment:

  | Log path | Redaction |
  |---|---|
  | `audit.jsonl` | inside `AuditLog.Append` — no call site can forget |
  | `trace.json` | `DumpTraceFileRedacted` masks span attributes and names |
  | run record + `GET /v1/runs/:id` | `Run.Redacted` masks argv, output, error, spans |
  | SSE events | `run.queued` / `run.started` payloads |
  | child stdout/stderr | scrubbed in `ExecuteWithEnv` before storage |

  The test suite proves this with a canary value
  (`canary-kavach-9f8e7d6c5b4a-topsecret`): a real run is submitted with the
  secret in its environment *and* hardcoded in its argv, and the canary must not
  appear in `audit.jsonl`, `trace.json`, or any served JSON.

A vault-restricted child receives a **minimal base environment** (`PATH`,
`HOME`, `TMPDIR`, locale, `TZ`, `USER`…) plus its allowlisted secrets — not the
daemon's inherited environment. A secret in the daemon's env that no tool
declares is simply not there.

### 4.5 Declarative policy, enforced at both hops

`policy.yaml` (allow/deny, per-tool timeout, network allowlist, workspace
root) is loaded at boot by the daemon and by the gateway. The rules:

- **Closed tool universe.** Anything outside the five known tools is refused
  with a structured `unknown_tool` error at the daemon edge *and* at the gateway.
- **Fail-closed parsing.** Unknown top-level keys, unknown tool names, unknown
  per-tool keys, and out-of-range values are **hard errors** that abort startup
  (gateway exit code 2, daemon refuses to boot). A typo can never silently
  widen access.
- **Deny before validate.** A denied tool answers `tool_denied` regardless of
  what the caller sent, so a denied tool cannot be probed through its
  validation errors.
- The manifest is a single artifact, so the two enforcement points cannot drift
  out of sync. `GET /v1/policy` and `GET /policy` expose what is actually in
  force (env **names** only).

### 4.6 Tamper-evident audit

Every state transition (`run.submitted`, `run.started`, `run.finished`,
`run.killed`, `killswitch.engaged`, `killswitch.released`) is appended to
`audit.jsonl` (`0600`, fsynced per line) with a hash chain:

```
hash = sha256(prev_hash + "\n" + canonical_json_of_entry_without_hash)
```

`daemon -verify <audit.jsonl>` replays the chain offline and **exits 1** on:

| Tamper | Detected as |
|---|---|
| A field edited in place | `hash mismatch — entry was edited` |
| A line deleted from the middle or start | `prev_hash mismatch` |
| Lines reordered / resequenced | `seq` + `prev_hash` mismatch |
| The tail cut by a crash | `torn tail: last line is not newline-terminated` |
| An unchained line injected after chaining began | `unchained entry after chaining started` |
| An append after corruption | the daemon refuses to open the log at all |

The chain means a log cannot be quietly edited: to change history you must
recompute every hash from the edit point onward, and the re-computation is
itself visible as a discontinuity unless the attacker holds an anchor outside
the file (see §5.3 and §4.9).

### 4.7 Kernel-level executor hardening (v3)

The local backend is a host process, so v3 constrains it with the primitives the
kernel offers, and — this is the load-bearing part — *reports* which ones are
actually in force. `daemon/exec_hardening.go` holds the model and the BPF
assembler; `daemon/exec_linux.go` holds the Linux primitives.

| Control | What it stops | Cost / limit |
|---|---|---|
| `prctl(PR_SET_NO_NEW_PRIVS)` | The child regaining privilege through a setuid/setgid binary, a file capability, or a setuid exec of the wrapper. Once set it is **irreversible** for that process | Applied by the child, not by `SysProcAttr`: Go's `syscall.SysProcAttr` has no `NoNewPrivs` field |
| seccomp-BPF (`SECCOMP_MODE_FILTER`, `SECCOMP_FILTER_FLAG_TSYNC`) | Namespace escape: `clone` with `CLONE_NEW*`/`CLONE_UNTRACED`, `clone3`, `unshare`, `setns`, `mount`, `pivot_root` | `EPERM`, not `SIGKILL`, so a refusal is visible in the run's exit status |
| `SysProcAttr{Setsid: true}` | The run acquiring a controlling terminal; also gives a fresh process group, which the timeout's `kill(-pgid)` needs | — |
| `SysProcAttr{Pdeathsig: SIGKILL}` | A payload outliving a **crashed** daemon (the kill-switch only covers a graceful exit) | Delivered on *thread* exit, so a runtime that retires threads could in principle kill a live run early; the run is recorded as `killed`, not lost |
| cgroup v2 `memory.max` + `pids.max` | Memory exhaustion and process-count abuse (the fork bomb), enforced in the kernel where a seccomp bypass cannot reach | Requires a writable `/sys/fs/cgroup`; the common unprivileged container mounts it read-only, and then the report says `cgroup_memory: skipped` |
| rlimits + timeout + group kill (v2) | CPU, address space, file size, wall clock, orphans | unchanged |

Ordering is the subtle part. A seccomp filter has to be installed by a process
that already has `no_new_privs`, and it has to be in place *before* the payload
runs. Go's `os/exec` offers no hook between fork and exec, so the executor
re-execs its own binary with an internal `-seccomp-exec` helper which prctl()s
itself, installs the filter, reports the posture it measured (on fd 2, so the
run's captured output is untouched), and only then `execve`s the payload. The
filter, `no_new_privs`, the session and the death signal are all inherited
across that `execve`.

Two profiles, because denying plain `fork(2)` breaks ordinary work:

- **escape (default)** — the escape barrier above. `fork(2)`/`clone(2)` are
  allowed, because a shell pipeline (`cmd | grep`) and libc's own `fork()` are
  built on them, and a filter that breaks those is a denial of service, not a
  boundary. glibc ≥ 2.34 also falls back from a denied `clone3` to `clone(2)`,
  so this profile alone does **not** stop a fork bomb.
- **strict (`KAVACH_SECCOMP_STRICT=1`)** — escape plus `fork(2)`/`vfork(2)`
  denied. For single-threaded payloads. The drill
  (`KAVACH_HARD_FORK=1 … -hard-fork`) installs this profile and then tries to
  fork, so "is fork actually refused?" is a measurement, not a claim.

The fork-bomb control of record is therefore the cgroup's `pids.max=64`, which
the kernel enforces and a seccomp bypass cannot evade. When cgroups are not
writable, **neither** control is in force and `GET /v1/backends` says so.

Degradation is deliberate and one-way: every control is probed, and a kernel
without it produces a single logged warning plus a `skipped` entry, never a
failed run and never a false `applied`. `GET /v1/backends` serves the report, so
"is this host actually confined?" is answerable without reading the source.

### 4.8 Pluggable sandbox backends, and the gVisor path (v3)

`Backend` (`Run`/`Stop`/`Inspect`) is now the executor interface, with three
implementations: `local`, `docker` and **`runsc` (gVisor)**. Selection is
`runsc → docker → local` under `backend: auto`, or a pin.

The rule that makes the interface worth having: **a backend that cannot run
returns the structured `ErrBackendUnavailable` and the run fails.** It never
falls back to a weaker backend and never reports success for work it did not do
under the requested confinement. A pin in `policy.yaml`
(`backend: runsc|docker|local`) makes that explicit: once pinned, an absent
runtime fails every run loudly, which is exactly the behaviour you want when the
whole point of the pin was "do not run unconfined code".

Enabling gVisor, concretely:

```bash
# 1. install the runsc binary (Debian/Ubuntu; see gvisor.dev for other platforms)
curl -fsSL https://gvisor.dev/public.key \
  | sudo tee /usr/share/keyrings/gvisor-archive-keyring.gpg >/dev/null
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor-apt-generic bullseye main" \
  | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update && sudo apt-get install -y runsc

# 2. register it with dockerd — a runsc binary on PATH without this is NOT
#    available, and kavach reports exactly that
sudo tee /etc/docker/daemon.json >/dev/null <<'JSON'
{ "runtimes": { "runsc": { "path": "/usr/bin/runsc" } } }
JSON
sudo systemctl restart docker

# 3. confirm, then pin
curl --unix-socket /tmp/agent-kavach/kavach.sock \
     -H "Authorization: Bearer $(cat /tmp/agent-kavach/kavach.token)" \
     http://localhost/v1/backends        # backends[0].available == true, kind "gvisor"
# policy.yaml: backend: runsc
```

`KAVACH_RUNSC` points at a `runsc` installed somewhere non-standard. Inside a
container, gVisor additionally needs `--privileged` on *the* container or a
dedicated cgroup namespace — a normal container cannot nest it.

### 4.9 External audit anchoring (v3)

The chain in §4.6 is inside the file it protects. v3 adds an anchor *outside* it:
every 60 s (`-anchor-every`, or `KAVACH_ANCHOR_INTERVAL`) the daemon appends one
record to `anchors.jsonl` (`0600`, fsynced) beside the audit log:

```
{ "version":1, "at":"…", "seq":137, "hash":"<chain head>", "lines":137,
  "mac":"<hex HMAC-SHA256>", "prev_mac":"<the previous record's mac>" }

mac = HMAC-SHA256($KAVACH_ANCHOR_KEY, "v1|at|seq|hash|prev_mac")
```

Properties that matter:

- **The key never leaves the process.** It is read from `$KAVACH_ANCHOR_KEY`
  (hex-decoded when 64 characters), never logged, never written, never served.
  Only its bit length appears, in `GET /v1/backends`. A test asserts the key
  never reaches the anchor file, the audit log, the API or the verify output.
- **A short key is refused**, not used: HMAC-SHA256 with a 4-byte key is still
  HMAC-SHA256, and accepting it would manufacture exactly the false confidence
  this control exists to remove. Below 32 bytes the daemon warns and anchors
  nothing.
- **Anchors are chained to each other** (`prev_mac`), so removing one from the
  middle is detectable, not just editing one in place.
- **The MAC covers an explicit payload**, not a marshalled struct, so a new field
  can never fall silently outside the signature.
- **The child reports what it measured**: the helper re-reads `NoNewPrivs` from
  `/proc/self/status` after the prctl, so "no_new_privs=on" in the audit trail is
  an observation, not an intention.

`daemon -verify` (and `make verify`) authenticates the anchors when they are
present, and distinguishes three states on stderr:

| State | Exit | Meaning |
|---|---|---|
| chain + anchors agree | 0 | `anchors OK: N verified, anchored through seq …` |
| no key / no anchor file / unanchored tail | 0, **WARNING** on stderr | the chain is verified, but nothing outside the log binds it; the exact unanchored line count is printed |
| MAC mismatch, `prev_mac` break, anchored hash not in the log, truncated below an anchor | 1 | `ANCHOR MISMATCH` with the specific problem |

## 5. What kavach does **not** stop

Read this section before deploying. The controls above are containment, not
confinement.

### 5.1 The local-subprocess backend is a bound, not a jail (v3)

When no container backend is available, `daemon/executor.go` runs the command as
a **direct child of the daemon on the host kernel**. v3 constrains it hard (§4.7):
`no_new_privs`, a seccomp filter over the escape syscalls, a new session, a death
signal, rlimits, a cgroup memory/pids cap where the hierarchy is writable, a wall
-clock and a process-group kill.

What that still does **not** give you:

- **No namespace, no mount isolation, no separate filesystem view.** The child
  sees the host filesystem, with the daemon's own credentials. A read-only
  rootfs, as the docker/runsc backends provide, simply is not there.
- **The syscall filter is an escape barrier, not a jail.** It blocks the
  namespace/mount primitives; it does not stop arbitrary code execution in the
  child's own address space, and a 0-day in the *allowed* syscalls is
  unrestricted. The `local` backend reports `"confined": false` at
  `/v1/backends` for exactly this reason.
- **The fork bomb needs cgroups.** Under the default escape profile, `fork(2)`
  works (it must — see §4.7), and glibc ≥ 2.34 can satisfy a fork from
  `clone(2)` when `clone3` is denied. `pids.max` is the control, and it is
  absent when `/sys/fs/cgroup` is read-only. When both are missing, the run is
  bounded only by rlimits, the timeout and the group kill.

**Mitigation today:** install Docker (or gVisor) and let `auto` select it; pin
`backend: docker` (or `runsc`) so a missing runtime cannot silently drop you
here. Treat the local backend as *unsafe for untrusted code* — it is the laptop
dev path, and the v3 controls raise the cost of an escape without removing it.

### 5.2 Container escape in general — gVisor reduces the surface, it does not eliminate it

Even with Docker, a kernel-level container escape (a vulnerable
`runc`/`containerd`, a malicious image, a `--privileged` misconfiguration) lands
on the host. v3 ships the **`runsc` (gVisor) backend** (§4.8): the agent's
syscalls are interpreted in userspace by gVisor's Sentry, so the host kernel
only sees gVisor's own, much smaller, syscall surface. That is a real reduction
in exposure and it is now a config change rather than a roadmap item.

It is not a proof:

- gVisor's own sandbox has been, and can be, escaped; its seccomp allowlist for
  the guest is generous by design.
- gVisor does not remove the need for the v2 controls (no network, resource
  caps, read-only rootfs) — it adds a layer under them.
- **Nesting costs.** gVisor needs `--privileged` or a cgroup namespace in a
  container, which weakens *that* container's posture. Deploy the daemon on a
  VM or a dedicated host, not inside an over-permissioned neighbour.
- If gVisor is not installed, `auto` silently does the next best thing. That is
  why `backend: runsc` (a pin) is the recommended production setting: it turns a
  missing runtime into a visible, per-run failure.

### 5.3 The unanchored window, and why the anchor is not evidence on its own

v2's chain does **not** detect an attacker who rewrites the *entire* file and
recomputes every hash, because nothing outside the log anchored the chain: a
forged `"status":"failed"` → `"status":"done"` with a fully re-signed chain
passed `-verify` with exit 0.

v3's anchor (§4.9) makes that case detectable — a rewritten-from-zero log no
longer contains the anchored hash, so `-verify` exits 1 with `ANCHOR MISMATCH`.
What remains open, precisely:

- **An anchor pins a prefix.** A forger who keeps everything up to the newest
  anchor byte-identical (which they must, or the chain breaks) can still rewrite
  the suffix. The verifier therefore reports the **unanchored window** — the
  number of lines after the newest verified anchor — instead of collapsing "the
  chain is intact" into "the log is untampered". The window is
  `anchor_interval × run rate`; shorten the interval if that is too much.
- **A forger with the key can re-anchor.** HMAC gives integrity and
  authenticity against an attacker who does *not* hold `$KAVACH_ANCHOR_KEY`.
  An attacker who has read the daemon's environment (see §5.4) can write
  consistent anchors. The anchor key must live in a secret store or be injected
  per-run, not baked into an image.
- **There is no timestamping authority.** `at` is the daemon's own clock, so an
  attacker who controls the daemon controls the timestamps. Nothing here proves
  *when* anything happened, only *that these two files agree*. Detecting
  backdating and proving time needs RFC 3161 / a transparency log.
- **The anchor file is not evidence while it sits next to the log.** Anyone with
  write access to `/data` can delete it, and "no anchors" then degrades to a
  warning (§4.9), not a failure — by design, so a fresh install is not an
  outage. Ship `anchors.jsonl` off-box to append-only/WORM storage and alert on
  it stopping; a chain plus its anchor history in two places is what makes a
  rewrite *detectable after the fact*.
- Without a key configured at all, `-verify` says `UNANCHORED` on stderr and
  still exits 0 for an intact chain. That is a warning you must alert on, not a
  pass.

### 5.4 No real secret store

The "vault" is the policy env allowlist plus process-env injection
(non-goal for v2). Consequences:

- Secret **values** live in the daemon's environment. Anything that can read
  `/proc/<pid>/environ` of the daemon (root, or the same UID on some systems)
  can read every allowlisted secret.
- There is no rotation, no per-run scoping, no short-lived/ephemeral
  credentials, no KMS/Vault integration, and no audit of *which* secret a run
  actually received.
- Redaction is **value-based**. A secret that is transformed before it is
  printed (base64, split across writes, hashed) will not match and will be
  logged. Redaction is a strong safety net, not a guarantee against a
  determined exfiltration attempt via an untrusted tool.

### 5.5 No multi-user isolation, no RBAC

There is one identity: whoever holds the bearer token is fully privileged. No
per-user quotas, no per-tenant workspaces, no authorisation on which tool *may*
be used *by whom* — only whether policy permits it at all. Do not expose
kavach to mutually-distrusting tenants.

### 5.6 Denial of service from the host side

Per-run timeouts, pids/memory/cpu limits and the kill-switch bound a *run*, but
an authenticated client can still submit runs continuously and saturate the
worker pool and the host. There is no global rate limit, no per-caller quota
and no queue-depth rejection beyond the in-memory channel.

### 5.7 The gateway has a loopback TCP listener

`mcp/server.py` listens on `127.0.0.1` **without authentication** — it has no
bearer token, on the assumption that only the local agent loop can reach it.
That assumption breaks under any of: a container sharing the network
namespace, an SSH local-forward, a `socat`/`--net=host` mistake, or a
multi-tenant host. The gateway is *not* a hardened public endpoint.

### 5.8 Prompt-injection resistance is out of scope

kavach does not attempt to detect or reason about injected instructions. It
bounds what a successful injection can reach. Do not deploy it as a
prompt-injection *defence*; deploy it as a blast-radius limiter.

## 6. Roadmap

| Item | Why | Status |
|---|---|---|
| **gVisor (`runsc`) backend** | The missing confinement layer: syscalls interpreted in userspace, so an escape attempt hits gVisor's seccomp table rather than the host kernel. Moves §5.2 from "relies on the container runtime" toward "runtime-isolated" | **Shipped in v3** — §4.8; auto-detected, pinnable, refuses to fake success |
| **Kernel-level executor hardening** | Narrow the local backend from "rlimits" to `no_new_privs` + seccomp + cgroups + session/death signal | **Shipped in v3** — §4.7; probed, reported and degradable |
| **External audit anchor** | Make §5.3's wholesale rewrite detectable | **Shipped in v3** — §4.9; HMAC anchor chain, unanchored window reported. Still missing: a timestamping authority and a transport to WORM storage |
| `bwrap`/namespace backend | A confinement layer that does not need Docker at all, so the "no Docker" path stops being the weak one | Planned — the `Backend` interface is the seam |
| Rootless / user-namespace isolation for the daemon itself | The daemon runs as a uid with access to the workspace; a daemon compromise is a workspace compromise | Planned |
| Real secret store | Vault/KMS or per-run ephemeral credentials, with a record of which secret each run received (§5.4), and an anchor key that is not in the daemon's environment (§5.3) | Planned |
| Multi-user RBAC + per-caller quotas | §5.5, §5.6. | Planned |
| Timestamping authority | Prove *when*, not just *that* (§5.3) | Planned |

v3 delivered the confinement layer the v2 roadmap called for — a real
executor-hardening posture, a gVisor backend behind a stable interface, and an
external anchor for the audit chain — and, deliberately, made all three
*inspectable* at `/v1/backends` instead of asking to be believed. The next
frontier is key management (a real secret store, including the anchor key) and a
fourth backend that needs neither Docker nor root.

## 7. Operator checklist

- [ ] `policy.yaml` is mounted **read-only**; whoever can write it owns the sandbox —
      including `backend:`, which chooses the confinement.
- [ ] `GET /v1/backends` says the backend you expect is `available: true`, and you
      have **pinned** it (`backend: runsc` or `backend: docker`) so a missing
      runtime fails loudly instead of degrading.
- [ ] The local backend's `hardening` block lists the controls you expect. If
      `cgroup_memory` is `skipped`, the fork-bomb and memory controls are *not* in
      force on that host.
- [ ] Socket and token paths are on a `0700` directory, not a shared `/tmp`.
- [ ] `make verify` (i.e. `daemon -verify audit.jsonl`) runs on a schedule and
      something alerts on a non-zero exit **and on its stderr** — an
      `UNANCHORED` or "not externally anchored" warning is the signal that
      detection has degraded, not a pass.
- [ ] `$KAVACH_ANCHOR_KEY` is injected at run time (≥32 bytes, not in the image,
      not in git) and `anchors.jsonl` is shipped off-box to append-only storage.
- [ ] Secrets named in a tool's `env` are scoped to that tool and rotated.
- [ ] The gateway stays on loopback; nothing else shares its network namespace.
- [ ] `go test -race ./...` stays green — the daemon shares run state between
      handler and worker goroutines.

## 8. Verifying the controls yourself

```bash
# hardening: the BPF program, the fallback plan, the SysProcAttr contract
cd daemon && go test -run 'Hardening|Seccomp|LocalPlan|ApplyProcPolicy' -v ./...
GOOS=linux go vet ./...            # the Linux-only file at least has to compile

# backends: conformance for all three, the exact docker argv, and the refusal
# path (a runsc request that cannot be honoured must execute nothing)
cd daemon && go test -run 'Backend|Runsc|Docker' -v ./...

# what this host can actually enforce
curl --unix-socket /tmp/agent-kavach/kavach.sock \
     -H "Authorization: Bearer $(cat /tmp/agent-kavach/kavach.token)" \
     http://localhost/v1/backends | python3 -m json.tool

# anchor: the wholesale rewrite v2 could not see
cd daemon && go test -run Anchor -v ./...
export KAVACH_ANCHOR_KEY=$(openssl rand -hex 32)
./daemon -verify /tmp/agent-kavach/audit.jsonl; echo "exit=$?"     # 0 + WARNING (UNANCHORED)

# audit: edited / truncated / relinked chains all fail verification
cd daemon && go test -run 'AuditChain|Verify' -v ./...
go build -o daemon . && ./daemon -verify /tmp/agent-kavach/audit.jsonl   # exit 0
sed 's/"status":"done"/"status":"failed"/' audit.jsonl > forged.jsonl
./daemon -verify forged.jsonl                                            # exit 1

# policy: denied tools and out-of-policy timeouts are refused, on both hops
cd daemon && go test -run 'Policy|Daemon' -v ./...
python3 -m pytest -q mcp -k policy
```
