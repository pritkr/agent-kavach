# agent-kavach

Zero-cloud, self-hosted agent sandbox runner. A plan→tool→observe agent loop
executes only through a validated MCP tool gateway, and every command runs
inside a sandbox owned by a Go daemon that exposes **zero open ports**.

```
web (React SSE dashboard: stream, cost/lat chart, KILL) ──▶ runner/ (TS loop:
  plan→tool→observe, retry×3 backoff, structured errors, trajectory JSONL)
        │ tools via mcp/ (Python http): shell-sandboxed, file-read scoped,
        │ web-fetch allowlist, scheme-lookup, eval-run; arg validation
        ▼
daemon/ (Go: 0 open ports — Unix socket 0600 + token, job queue, backends:
  runsc/gVisor → docker → local subprocess (no_new_privs, seccomp, cgroup v2,
  setsid, pdeathsig), kill-switch, /metrics, cost/latency ledger,
  hash-chained audit.jsonl + external HMAC anchors)
        ▲                                          ▲
        └───────────── policy.yaml ────────────────┘
          one manifest, both enforcement points: tool allow/deny,
          per-tool timeout, network allowlist, workspace root, sandbox backend
          and the per-tool credential (env) allowlist
```

## What's new in v3

v2 made the *policies* enforceable. v3 makes the *sandbox* enforceable — and,
just as importantly, checkable. The three controls:

1. **Hardened local executor** — every local run now gets
   `no_new_privs` + `seccomp` + `setsid` + `pdeathsig` from the kernel, and a
   `memory.max`/`pids.max` cgroup v2 cap when `/sys/fs/cgroup` is writable.
   `prctl(PR_SET_NO_NEW_PRIVS)` + `SECCOMP_MODE_FILTER` are installed by the
   child *before* it execs the payload (a re-exec through the daemon's own
   `-seccomp-exec` helper), so the process that runs the agent is already
   confined. Denied calls are the escape primitives — `clone` with
   `CLONE_NEW*`/`CLONE_UNTRACED`, `clone3`, `unshare`, `setns`, `mount`,
   `pivot_root` — with `EPERM`, not `SIGKILL`, so a refusal is visible in the
   run's exit status instead of looking like a timeout. Every control is
   *probed*: on a kernel or platform without one, kavach logs a single warning
   and carries on, and `GET /v1/backends` reports what is actually in force.
2. **Pluggable sandbox backends** — `Backend` (Run/Stop/Inspect) with three
   implementations behind one interface: `docker`, `local`, and **`runsc`
   (gVisor)**, which auto-detects the `runsc` binary and the docker runtime
   registration. A backend that cannot run returns a structured
   `ErrBackendUnavailable` and the run **fails** — it never degrades into
   "ran it locally and reported success". `policy.yaml` can pin
   `backend: runsc|docker|local|auto`, and a pinned-but-absent backend is a hard
   failure. `GET /v1/backends` lists every backend with its availability, the
   reason when it is missing, and whether the agent's syscalls can reach the host
   kernel.
3. **External audit anchor** — the audit chain head is periodically HMAC-SHA256
   anchored into `anchors.jsonl` under `$KAVACH_ANCHOR_KEY` (never logged, never
   served, never written anywhere else). `-verify` now checks the anchors when
   they are present: a wholesale rewrite of the log with recomputed hashes —
   the attack v2 could not see — is an `ANCHOR MISMATCH` and exit 1. What
   anchoring does **not** cover is reported as a number (the "unanchored
   window"), and a missing key is a loud `UNANCHORED` warning, never a silent
   pass.

Plus [`docs/SECURITY.md`](docs/SECURITY.md): what these controls stop, and what
they do not.

### v3 environment switches

Every v3 control is a switch, and every switch can only *remove* hardening. A
malformed value is a hard error (it degrades with a logged warning) rather than a
silent default.

| Variable | Default | Effect |
|---|---|---|
| `KAVACH_HARDENING` | `on` | master switch for the kernel controls |
| `KAVACH_NO_NEW_PRIVS` | `1` | `prctl(PR_SET_NO_NEW_PRIVS)` in the child |
| `KAVACH_SECCOMP` | `1` | the seccomp-BPF filter |
| `KAVACH_SECCOMP_STRICT` | `0` | also deny `fork(2)`/`vfork(2)`. Breaks shell pipelines — for single-threaded payloads only |
| `KAVACH_HARD_FORK` | `0` | run the fork-bomb drill instead of a payload: it installs the strict filter and reports whether `fork(2)` is really refused |
| `KAVACH_CGROUP_MEMORY_MB` | `256` | cgroup v2 `memory.max` per run (`0` = off) |
| `KAVACH_ANCHOR_KEY` | unset | ≥32 bytes; enables the external audit anchor. Absent ⇒ `-verify` reports `UNANCHORED` |
| `KAVACH_ANCHOR_INTERVAL` | `60s` | anchor period (also `-anchor-every`) |
| `KAVACH_RUNSC` | unset | path to a `runsc` binary not on `PATH` |
| `KAVACH_CGROUP_ROOT` | `/sys/fs/cgroup` | cgroup v2 mount point, if not the default |

## What's new in v2

The three controls that separate a demo runner from a deployable one:

1. **Credential vault** — `policy.yaml` declares, per tool, the env names it may
   receive; values are injected from the process env at exec time. The untrusted
   tools (`web-fetch`, `eval-run`) get **none**, and every log path redacts
   values as `[REDACTED]` — including a command's own captured stdout.
2. **Tamper-evident audit** — every `audit.jsonl` line embeds `prev_hash` +
   `sha256(prev_hash ‖ line)`. `make verify` replays the chain offline and
   exits 1 on an edited, relinked, resequenced, unchained or truncated line.
3. **Declarative policy manifest** — one `policy.yaml` for tool allow/deny,
   per-tool timeout, network allowlist and workspace root, loaded at boot by the
   daemon *and* read by the Python gateway. Unknown tools and malformed
   manifests are refused (fail closed).

## Security model

Full threat model, including what kavach explicitly does **not** stop:
**[docs/SECURITY.md](docs/SECURITY.md)**.

| Control | Implementation |
|---|---|
| Zero open ports | Daemon binds a Unix-domain socket only (no `net.Listen("tcp")` anywhere); container has no `EXPOSE` |
| Socket identity | Socket file `0600`, parent dir `0700`, bearer token in a `0600` file (refused if group/other-readable); `/healthz` is the only unauthenticated route |
| Policy manifest | `policy.yaml` (repo root) is the single source of truth for tool allow/deny, per-tool timeout, network allowlist, workspace root and the sandbox `backend` pin. Both the daemon and the MCP gateway read it; unknown tools → structured `unknown_tool`, denied tools → `tool_denied`, unknown keys/values abort boot (fail closed) |
| Sandbox backends | One `Backend` interface (`Run`/`Stop`/`Inspect`) with `runsc` (gVisor) → `docker` → `local` selection. Auto-detected, never faked: an unavailable backend returns a structured `ErrBackendUnavailable` and the run fails; a `policy.yaml` pin makes that a hard error. `GET /v1/backends` shows each backend's availability, the reason and whether the agent's syscalls reach the host kernel |
| Executor hardening | Local runs get `prctl(PR_SET_NO_NEW_PRIVS)` + a seccomp-BPF filter (denying `clone3`, namespace `clone`, `unshare`/`setns`/`mount`/`pivot_root`) installed in the child before it execs the payload, plus `SysProcAttr{Setsid, Pdeathsig: SIGKILL}` and a cgroup v2 `memory.max`/`pids.max` cap when `/sys/fs/cgroup` is writable. Opt-in switches exist for every control; unsupported ones degrade with a logged warning and appear in `GET /v1/backends` as skipped, not applied |
| Credential vault | Each tool declares the env names it may receive. Values are injected from the daemon's process env at exec time; `web-fetch` and `eval-run` get **none**. Restricted children also lose the inherited environment |
| Secret redaction | Secret *values* are masked as `[REDACTED]` inside `AuditLog.Append`, the trace dump, run records, SSE payloads and captured stdout — so a command that echoes its own env still leaks nothing. Proven with a canary secret in `go test -run Vault` |
| Tamper-evident audit | `audit.jsonl` is `0600` and hash-chained: each line embeds `prev_hash` + `sha256(prev_hash ‖ line)`. `daemon -verify audit.jsonl` (or `make verify`) replays the chain offline and **exits 1** on an edited, relinked, resequenced, unchained or truncated line |
| External anchor | Every 60 s (configurable) the chain head is appended to `anchors.jsonl` as `HMAC-SHA256($KAVACH_ANCHOR_KEY, v‖at‖seq‖hash‖prev_mac)`, chained anchor-to-anchor. `-verify` authenticates them: a wholesale rewrite, an edited anchor, a removed anchor or truncation below an anchor is exit 1. The key is never logged, served or written; a missing key is reported as `UNANCHORED`, not as a pass |
| Filesystem scope | `file-read` / `eval-run` resolve inside the policy workspace; `..`, absolute-path and symlink escapes rejected (`path_outside_workspace`) |
| Network scope | `web-fetch` reaches only hosts in the policy `network_allowlist`, http(s) only — so an injected instruction cannot pick its own exfil destination |
| Timeouts | Every tool is capped by its per-tool policy timeout; a larger request is rejected. Per-run timeout default 120 s, hard max 1800 s, with process-group `SIGKILL` |
| Resource limits | runsc/docker: `--network none`, 256 MiB, 0.5 CPU, `--pids-limit 64`, read-only rootfs, `noexec` tmpfs. Local subprocess: `ulimit` CPU/address-space/file-size + timeout + pgroup kill + the kernel controls above |
| Output caps | 256 KiB per daemon run, 64 KiB per MCP tool call |
| Kill-switch | Global latch: cancels in-flight runs, refuses new ones until released; per-run `kill` API; trajectory marked `killed` |

### Known limits (the honest list)

- **gVisor is available, not automatic.** The `runsc` backend needs gVisor
  installed *and* registered with dockerd (steps below). Without it, the best
  available confinement is the docker one, and a kernel-level container escape
  still lands on the host kernel. What is actually installed is visible at
  `GET /v1/backends`; pin `backend: runsc` in policy so a missing runtime fails
  loudly instead of silently downgrading.
- **The local executor is a bound, not a jail.** Even with `no_new_privs`,
  seccomp and cgroups, the child shares the host filesystem and network
  namespaces. The seccomp filter blocks the escape syscalls, not arbitrary code
  execution; glibc ≥ 2.34 falls back from a denied `clone3` to `clone(2)` inside
  `fork(2)`, so the fork-bomb control of record is the cgroup's `pids.max`, and
  that control is absent when `/sys/fs/cgroup` is read-only. `Pdeathsig` is
  delivered on *thread* exit, so a runtime that retires threads can in principle
  kill a live run early — the run is recorded as killed, not silently lost.
- **An anchor pins a prefix.** HMAC anchoring makes a *whole-log* rewrite with
  recomputed hashes detectable, but the lines appended after the newest anchor
  are still forgeable — so `-verify` reports the unanchored window as a number
  instead of claiming the log is untampered. There is **no timestamping
  authority**: `at` is the daemon's own clock, so the anchor gives integrity and
  authenticity, not provable time. Ship `anchors.jsonl` to append-only/WORM
  storage off-box to make it evidence.
- **The "vault" is not a secret store.** No KMS/Vault, no rotation, no
  per-run scoping; redaction is value-based, so a *transformed* secret can
  still be logged.
- **No multi-user RBAC** and no per-caller rate limits — one token, full
  privileges.
- **The MCP gateway listens on loopback with no auth.** Do not share its
  network namespace.

## Quickstart

```bash
make deps          # test-only Python deps (the runtime itself is stdlib-only)
make build         # go build + npm install/build (runner, web)
make test          # go test + pytest + npm test (all green, see below)

# run locally: daemon on a Unix socket + MCP gateway on loopback
make run            # both read ./policy.yaml; MCP : 127.0.0.1:8077

# offline tamper check on the hash-chained audit log + the external anchors
# (exit 1 = tampered or anchor mismatch; a WARNING on stderr = UNANCHORED)
make verify

# what can this host actually enforce? backends, kernel controls, anchor health
make backends

# evals (spins up hermetic fixtures, generates trajectories, scores them)
make eval

# dashboard dev: bridge the socket to TCP, then point the web app at it
make proxy          # socat 127.0.0.1:8080 -> unix socket
cd web && VITE_KAVACH_API=http://127.0.0.1:8080 npm run dev

# ship it
make docker-build
docker compose up            # daemon + MCP (no published ports)
docker compose --profile web up  # + dashboard on 127.0.0.1:4173
```

## Enabling gVisor (runsc)

The `runsc` backend is the one that puts a **userspace syscall interception
layer** between the agent and the host kernel: with gVisor, an escape attempt
hits gVisor's seccomp table (Sentry) instead of the host's syscalls. It is a real
option now, not a roadmap item — it needs two things on the host.

```bash
# 1. install gVisor (Debian/Ubuntu):
curl -fsSL https://gvisor.dev/public.key \
  | sudo tee /usr/share/keyrings/gvisor-archive-keyring.gpg >/dev/null
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor-apt-generic bullseye main" \
  | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update && sudo apt-get install -y runsc

# 2. register it with dockerd (this is the step that is easy to miss: a `runsc`
#    on PATH without this registration is NOT available, and kavach says so):
sudo tee /etc/docker/daemon.json >/dev/null <<'JSON'
{ "runtimes": { "runsc": { "path": "/usr/bin/runsc" } } }
JSON
sudo systemctl restart docker

# 3. check what kavach now sees (the endpoint needs the bearer token):
curl --unix-socket /tmp/agent-kavach/kavach.sock \
     -H "Authorization: Bearer $(cat /tmp/agent-kavach/kavach.token)" \
     http://localhost/v1/backends | python3 -m json.tool
#   → backends[0] = {"name":"runsc","available":true,"kind":"gvisor", …}
#   (make backends is the same thing, with the right paths already filled in)

# 4. pin it, so a missing runtime fails every run loudly instead of silently
#    downgrading to docker or the local subprocess:
#    policy.yaml:  backend: runsc
```

Under Docker-in-Docker (CI, or kavach itself in a container) add
`--privileged` to *your* build container, or gVisor will not start inside it.
`KAVACH_RUNSC` overrides the binary path when gVisor is installed somewhere
unusual; with the pin in place, a wrong path is a loud per-run failure, not a
quiet downgrade.

## Audit anchoring in practice

```bash
# 32+ bytes of key material; keep it out of the repo and out of the image.
export KAVACH_ANCHOR_KEY="$(openssl rand -hex 32)"

# -verify checks the anchors beside the log as well as the chain.
# stdout = the result, stderr = anything you must not miss.
make verify; echo "exit=$?"
#   audit chain OK: /tmp/agent-kavach/audit.jsonl
#   WARNING: .../anchors.jsonl: anchored through seq 412 of 449; the last 37
#     line(s) are not externally anchored                     <- stderr, exit 0

# an edited line is caught by the chain alone (exit 1):
sed 's/"status":"done"/"status":"failed"/' /tmp/agent-kavach/audit.jsonl > /tmp/forged.jsonl
./daemon/daemon -verify /tmp/forged.jsonl; echo "exit=$?"
#   TAMPER DETECTED: /tmp/forged.jsonl: line 3: hash mismatch — entry was edited

# ...and the case v2 could not see -- a *whole-log* rewrite with every hash
# recomputed -- passes the chain and is caught by the anchor (exit 1):
#   audit chain OK: /tmp/forged.jsonl
#   ANCHOR MISMATCH: 1 problem(s); the log does not match what was anchored
#     - anchor 2: anchored hash 99aa27ce67d234eb... at seq 3 is not in the log
#       (it was rewritten away, or the log was replaced)
# `go test -run TestAnchorDetectsWholesaleRewrite` builds exactly that forgery.
```

Anchor interval: `-anchor-every 30s` or `KAVACH_ANCHOR_INTERVAL=30s` (0/unset =
the 60 s default). The anchor file lives beside the audit log (`-anchors <path>`)
and is `0600`. Ship it off-box — see [docs/SECURITY.md §5.3](docs/SECURITY.md)
for why the anchor file alone is not evidence.

## Repo tree

```
policy.yaml The declarative manifest: tool allow/deny, per-tool timeout,
          network allowlist, workspace root, sandbox backend pin, per-tool
          credential allowlist. Read at boot by the daemon (-policy) and the
          gateway (--policy).
daemon/   Go unix-socket daemon: server, queue, sandbox (backend interface:
          runsc/docker/local + /v1/backends), executor hardening (exec_hardening,
          exec_linux seccomp+cgroup), anchor (external HMAC anchors), auth
          (0600 token), killswitch, metrics, trace, tracker, audit
          (hash-chained), policy (manifest loader), vault (redaction)
mcp/      Python stdlib-only MCP server: server.py, policy.py (manifest
          reader), tools.json (5 tools), test_server.py (44 tests)
runner/   TypeScript loop.ts (retry×3 backoff, trajectory JSONL), tools.ts
          (MCP client), replay.ts, scripts/replay.js CLI (20 tests)
web/      Vite React: SSE stream view, cost/latency SVG chart, KILL button,
          replay view
eval/     tasks.json (8 tasks), passk.py scorer, gen_trajs.mjs, trajs/
          (24 golden trajectories, 3 samples × 8 tasks), test_passk.py
docs/     SECURITY.md — threat model: what kavach stops vs. what it does not
tools/    stub_fetch.py (hermetic eval fixture)
```

## Measured results (real runs, 2026-09-26)

Suites — all green, no mocks in the eval path:

| Suite | Result |
|---|---|
| `go test ./...` (daemon) | **99 passed** on darwin/arm64 (also clean under `-race`); the Linux-only tests (`exec_linux_test.go`) run in CI on `ubuntu-latest`, where the seccomp/cgroup paths actually execute — and a host that refuses seccomp filters skips the filter-specific assertions *with the kernel's reason* rather than passing quietly |
| `pytest -q mcp eval` | **49 passed** (44 gateway + 5 scorer) |
| `npm test` (runner: `tsc` + `node --test "dist/tests/*.test.js"`) | **20 passed** |
| `vite build` (web) | ok, 148.9 kB bundle |

Two of these commands need a host that is set up, which is exactly why CI kept
disagreeing with a developer machine and then with itself:

- `pytest` comes from `requirements-dev.txt` (`make deps`). The runtime is
  stdlib-only, so this is the only install a suite needs — and the file exists
  because CI once ran the suites on a bare interpreter and failed with
  `No module named pytest` while every laptop had it.
- `npm test` builds first and then hands `--test` a **glob**, not a directory. On
  Node 22 a positional `--test` argument is a file-or-glob pattern, so
  `node --test dist/tests` goes to the module loader and dies with
  `Cannot find module .../dist/tests`; Node 24+ recurses into the directory, so a
  newer local node never noticed. The glob is the only form that means the same
  thing on both.

v3 additions:

- `go test -run 'Hardening|Seccomp|LocalPlan'` — the BPF program's exact layout,
  the fallback plan when a control is unavailable, the `SysProcAttr` contract, and
  a live check that a run is still a killable process-group leader.
- `go test -run 'Helper|ResolvePayload|NoNewPrivs'` — the re-exec helper
  end to end on *any* platform, handed a **bare** payload name like the one the
  executor builds. The helper's last act is a raw `execve(2)`, which does not
  search `PATH`, while `os/exec` does: get that wrong and every hardened run on
  every Linux becomes `exit 127` for a reason that has nothing to do with the
  kernel. It is asserted portably because a macOS box never takes the hardened
  path, and the one platform that can catch it was the one platform CI was red on.
- `go test -run 'Backend|Runsc|Docker'` — interface conformance for all three
  backends, the exact docker argv (a stub `docker` on PATH records it), and the
  refusal path: a `runsc` request that cannot be honoured returns
  `ErrBackendUnavailable` **and executes nothing** (the test asserts the marker
  file was never created).
- `go test -run Anchor` — the wholesale rewrite v2 could not detect is now an
  `ANCHOR MISMATCH`; an edited anchor, a removed anchor, a wrong key and
  truncation below an anchor all fail; a missing key warns; the key never appears
  in the anchor file, the audit log, `/v1/backends` or the verify output.

v2 additions: `go test -run Vault` proves the canary secret never reaches
`audit.jsonl`, `trace.json` or any served JSON; `go test -run 'AuditChain|Verify'`
proves an edited, relinked or truncated chain fails verification;
`pytest -k policy` proves the shared manifest denies tools and caps timeouts on
the gateway side too.

Eval (`python3 eval/passk.py --tasks eval/tasks.json --trajectories-dir eval/trajs`,
trajectories generated live against the real MCP server + stub fetch host):

| Task | pass@1 | pass@3 |
|---|---|---|
| file-edit | ✅ | ✅ |
| fetch-parse | ✅ | ✅ |
| scheme-lookup | ✅ | ✅ |
| script-run | ✅ | ✅ |
| multi-tool-chain | ✅ | ✅ |
| retry-recovery | ✅ | ✅ |
| forbidden-path (fail-closed) | ✅ | ✅ |
| kill-drill (killed) | ✅ | ✅ |
| **Total** | **pass@1 = 1.00** | **pass^3 = 1.00** |

## API sketch

Daemon (Unix socket, `Authorization: Bearer <token>`, except `/healthz`):

- `POST /v1/runs {"command":[...],"image?":"","tool?":"","timeout_sec?":N}` → `202 {id, trace_id, status}`
  — with `"tool"`, the tool must be known and allowed by `policy.yaml`, and
  `timeout_sec` is capped by that tool's policy timeout.
- `GET /v1/runs`, `GET /v1/runs/:id`, `POST /v1/runs/:id/kill`
- `POST /v1/killswitch {"engaged":bool,"reason?":""}` / `GET /v1/killswitch`
- `GET /v1/events` (SSE), `POST /v1/tool-calls`, `GET /v1/audit`, `GET /metrics`
- `GET /v1/policy` — the manifest in force (env **names** only, never values),
  including the `backend` pin
- `GET /v1/backends` — every backend with `available` + the reason when missing,
  the pin, what a run resolves to, the local executor's kernel controls, and the
  anchor's health
- offline: `daemon -verify <audit.jsonl>` → exit 0 chain + anchors agree (or a
  `UNANCHORED` warning on stderr), exit 1 tampered or anchor mismatch
- offline drill: `KAVACH_HARD_FORK=1 daemon -seccomp-exec -hard-fork -- …`
  installs the strict filter and reports whether fork(2) is actually refused

MCP (`http://127.0.0.1:8077`): `GET /tools/list`, `GET /policy`,
`POST /tools/call {"tool":"shell-sandboxed|file-read|web-fetch|scheme-lookup|eval-run","args":{…}}`
→ `{"ok":true,"result":{…}}` or `{"ok":false,"error":{"code","message"}}`.
The gateway refuses `unknown_tool` / `tool_denied` / `invalid_args` from the
same `policy.yaml` the daemon uses, before any argument is looked at.

## License

MIT — see [LICENSE](LICENSE).
