"""agent-kavach MCP server: plain-HTTP tool gateway (stdlib only).

Exposes the 5 tools declared in tools.json over two endpoints:

    GET  /healthz      -> {"ok": true, ...}
    GET  /tools/list   -> the tools.json document
    POST /tools/call   -> {"tool": "<name>", "args": {...}} -> result envelope

Result envelope (always HTTP 200 for a well-formed request)::

    {"ok": true, "tool": "...", "result": {...}, "latency_ms": N}
    {"ok": false, "tool": "...", "error": {"code": "...", "message": "..."}}

Security model (mirrors the Go daemon):
  - every manifest in policy.yaml is the single source of truth: tool
    allow/deny, per-tool timeout, network allowlist and workspace root are
    read by this gateway *and* by the daemon (see mcp/policy.py).
  - file-read / eval-run are scoped to the policy workspace root; absolute
    paths, ".." escapes and symlink escapes are rejected.
  - web-fetch only allows hosts in the policy network allowlist.
  - every tool has a hard wall-clock timeout, never above its policy cap (30s).
  - secrets named in a tool's `env` allowlist are injected by the daemon at exec
    time and are never logged here.

Run:  python3 server.py [--port 8077 --policy ../policy.yaml --workspace /tmp/kavach-ws]
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:  # imported as a package under some runners, as a script under others
    from .policy import KNOWN_TOOLS, MAX_TIMEOUT_SEC, Policy, PolicyError, discover_policy
except ImportError:  # pragma: no cover - `python3 mcp/server.py` path
    from policy import KNOWN_TOOLS, MAX_TIMEOUT_SEC, Policy, PolicyError, discover_policy

HERE = Path(__file__).resolve().parent
TOOLS_JSON = HERE / "tools.json"

MAX_OUTPUT_BYTES = 64 * 1024
MAX_ARG_COUNT = 64
MAX_ARG_LEN = 8192

# Built-in execution-scheme registry. A JSON file at
# $KAVACH_SCHEMES_FILE (or ./schemes.json) may add/override entries.
BUILTIN_SCHEMES = {
    "fast": {
        "timeout_sec": 10,
        "max_retries": 1,
        "backoff_ms": 200,
        "cost_budget_usd": 0.01,
        "description": "Single quick attempt, tiny budget. For lookups and pings.",
    },
    "balanced": {
        "timeout_sec": 30,
        "max_retries": 3,
        "backoff_ms": 500,
        "cost_budget_usd": 0.10,
        "description": "Default: retry x3 with backoff. For ordinary agent steps.",
    },
    "thorough": {
        "timeout_sec": 30,
        "max_retries": 5,
        "backoff_ms": 1000,
        "cost_budget_usd": 0.50,
        "description": "Persistent multi-attempt runs. For evals and long builds.",
    },
}


class Config:
    """Effective gateway config: policy.yaml first, explicit args as overrides.

    Precedence for workspace / fetch allowlist is
    explicit argument > KAVACH_* env var > policy.yaml > built-in default, so
    an operator can redirect a deployment without editing the shared manifest.
    Per-tool allow/deny and timeouts come from the manifest only: there is no
    override that widens them.
    """

    def __init__(
        self,
        workspace: str | None = None,
        allowlist: list[str] | None = None,
        schemes_file: str | None = None,
        policy: Policy | str | None = None,
    ) -> None:
        if isinstance(policy, str) or policy is None:
            self.policy = discover_policy(policy)  # type: ignore[arg-type]
        else:
            self.policy = policy
        ws = (
            workspace
            or os.environ.get("KAVACH_WORKSPACE")
            or self.policy.workspace
            or "/tmp/agent-kavach/workspace"
        )
        self.workspace = Path(ws).resolve()
        raw = os.environ.get("KAVACH_FETCH_ALLOWLIST", "")
        env_hosts = [h.strip().lower() for h in raw.split(",") if h.strip()]
        chosen = allowlist if allowlist is not None else (env_hosts or list(self.policy.network_allowlist))
        self.allowlist = [h.lower() for h in chosen]
        self.schemes_file = schemes_file or os.environ.get("KAVACH_SCHEMES_FILE", "")

    # -- policy passthroughs --------------------------------------------

    def allowed(self, tool: str) -> bool:
        return self.policy.allowed(tool)

    def timeout_for(self, tool: str) -> int:
        return min(self.policy.timeout_for(tool), MAX_TIMEOUT_SEC)

    def env_names(self, tool: str) -> tuple[str, ...]:
        return self.policy.env_names(tool)


def error(code: str, message: str) -> dict:
    return {"code": code, "message": message}


# ---------------------------------------------------------------- validation

def _ensure_timeout(args: dict, default: int = MAX_TIMEOUT_SEC, cap: int = MAX_TIMEOUT_SEC) -> tuple[int | None, dict | None]:
    """Validate timeout_sec against the *policy* cap for a tool.

    `default` is the fallback when the caller omits the field; `cap` is the
    manifest's per-tool ceiling. A request above the cap is rejected outright
    so policy cannot be bypassed from the client side.
    """
    t = args.get("timeout_sec", default)
    if isinstance(t, bool) or not isinstance(t, int):
        return None, error("invalid_args", "timeout_sec must be an integer")
    if t < 1 or t > cap:
        return None, error("invalid_args", f"timeout_sec must be 1..{cap} (policy cap for this tool)")
    return t, None


def _resolve_workspace_path(workspace: Path, rel: str) -> tuple[Path | None, dict | None]:
    if not isinstance(rel, str) or not rel or len(rel) > 1024:
        return None, error("invalid_args", "path must be a non-empty string (max 1024 chars)")
    if "\x00" in rel:
        return None, error("invalid_args", "path contains NUL byte")
    candidate = (workspace / rel).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError:
        return None, error("path_outside_workspace", f"path escapes workspace: {rel!r}")
    return candidate, None


def _tool_timeout(cfg: "Config | None", tool: str, default: int) -> tuple[int, int]:
    """Return (default, cap) for a tool: the policy cap when a cfg is bound."""
    if cfg is None:
        return default, MAX_TIMEOUT_SEC
    cap = cfg.timeout_for(tool)
    return cap, cap


def validate_args(tool: str, args: dict, cfg: "Config | None" = None) -> dict | None:
    """Return an error dict when args are invalid, else None.

    With a `cfg` bound, per-tool timeout defaults and ceilings come from
    policy.yaml; without one the historical built-in bounds apply.
    """
    if not isinstance(args, dict):
        return error("invalid_args", "args must be a JSON object")
    if tool == "shell-sandboxed":
        cmd = args.get("command")
        if not isinstance(cmd, list) or not cmd:
            return error("invalid_args", "command must be a non-empty array of strings")
        if len(cmd) > MAX_ARG_COUNT:
            return error("invalid_args", f"command has too many args (max {MAX_ARG_COUNT})")
        for a in cmd:
            if not isinstance(a, str) or not a:
                return error("invalid_args", "every command arg must be a non-empty string")
            if len(a) > MAX_ARG_LEN:
                return error("invalid_args", "command arg too long (max 8192 bytes)")
            if "\x00" in a:
                return error("invalid_args", "command arg contains NUL byte")
        extra = set(args) - {"command", "timeout_sec"}
        if extra:
            return error("invalid_args", f"unknown fields: {sorted(extra)}")
        d, cap = _tool_timeout(cfg, tool, MAX_TIMEOUT_SEC)
        _, err = _ensure_timeout(args, d, cap)
        return err
    if tool == "file-read":
        if "path" not in args:
            return error("invalid_args", "missing required field: path")
        extra = set(args) - {"path", "max_bytes"}
        if extra:
            return error("invalid_args", f"unknown fields: {sorted(extra)}")
        mb = args.get("max_bytes", 65536)
        if isinstance(mb, bool) or not isinstance(mb, int) or mb < 1 or mb > 1024 * 1024:
            return error("invalid_args", "max_bytes must be 1..1048576")
        return None
    if tool == "web-fetch":
        url = args.get("url")
        if not isinstance(url, str) or not url:
            return error("invalid_args", "url must be a non-empty string")
        if len(url) > 2048:
            return error("invalid_args", "url too long (max 2048 chars)")
        extra = set(args) - {"url", "timeout_sec"}
        if extra:
            return error("invalid_args", f"unknown fields: {sorted(extra)}")
        d, cap = _tool_timeout(cfg, tool, 10)
        _, err = _ensure_timeout(args, d, cap)
        return err
    if tool == "scheme-lookup":
        name = args.get("name")
        if not isinstance(name, str) or not name or len(name) > 64:
            return error("invalid_args", "name must be a non-empty string (max 64 chars)")
        extra = set(args) - {"name"}
        if extra:
            return error("invalid_args", f"unknown fields: {sorted(extra)}")
        return None
    if tool == "eval-run":
        script = args.get("script")
        if not isinstance(script, str) or not script:
            return error("invalid_args", "script must be a non-empty workspace-relative path")
        extra = set(args) - {"script", "timeout_sec"}
        if extra:
            return error("invalid_args", f"unknown fields: {sorted(extra)}")
        d, cap = _tool_timeout(cfg, tool, MAX_TIMEOUT_SEC)
        _, err = _ensure_timeout(args, d, cap)
        return err
    return error("unknown_tool", f"unknown tool: {tool!r}")


def check_policy(tool: str, cfg: Config) -> dict | None:
    """Manifest gate: unknown tool first, then allow/deny. Fail-closed.

    Runs before argument validation so a denied tool answers tool_denied
    regardless of what the caller sent.
    """
    if tool not in KNOWN_TOOLS:
        return error("unknown_tool", f"unknown tool: {tool!r}")
    if not cfg.allowed(tool):
        return error("tool_denied", f"tool {tool!r} is denied by policy.yaml")
    return None


# ---------------------------------------------------------------- execution

def load_schemes(cfg: Config) -> dict:
    schemes = dict(BUILTIN_SCHEMES)
    path = cfg.schemes_file or str(HERE / "schemes.json")
    try:
        with open(path, encoding="utf-8") as f:
            custom = json.load(f)
        if isinstance(custom, dict):
            for k, v in custom.items():
                if isinstance(v, dict):
                    schemes[str(k)] = v
    except (OSError, ValueError):
        pass
    return schemes


def _truncate(data: bytes) -> tuple[str, bool]:
    if len(data) > MAX_OUTPUT_BYTES:
        return (
            data[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")
            + f"\n…[truncated {len(data) - MAX_OUTPUT_BYTES} bytes]",
            True,
        )
    return (data.decode("utf-8", "replace"), False)


def tool_shell_sandboxed(args: dict, cfg: Config) -> tuple[dict | None, dict | None]:
    timeout, err = _ensure_timeout(args, *_tool_timeout(cfg, "shell-sandboxed", MAX_TIMEOUT_SEC))
    if err:
        return None, err
    assert timeout is not None
    cfg.workspace.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            list(args["command"]),
            cwd=str(cfg.workspace),
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, error("timeout", f"command timed out after {timeout}s")
    text, truncated = _truncate((proc.stdout or b"") + (proc.stderr or b""))
    return (
        {
            "exit_code": proc.returncode,
            "output": text,
            "truncated": truncated,
            "timeout_sec": timeout,
        },
        None,
    )


def tool_file_read(args: dict, cfg: Config) -> tuple[dict | None, dict | None]:
    target, err = _resolve_workspace_path(cfg.workspace, args.get("path", ""))
    if err:
        return None, err
    assert target is not None
    max_bytes = args.get("max_bytes", 65536)
    try:
        if not target.is_file():
            return None, error("not_found", f"no such file: {args.get('path')!r}")
        data = target.read_bytes()[: int(max_bytes)]
    except OSError as e:
        return None, error("read_error", str(e))
    return (
        {
            "path": args.get("path"),
            "size_bytes": target.stat().st_size,
            "content": data.decode("utf-8", "replace"),
            "truncated": target.stat().st_size > int(max_bytes),
        },
        None,
    )


def _host_allowed(host: str, allowlist: list[str]) -> bool:
    host = (host or "").lower().split(":")[0].strip(".")
    for entry in allowlist:
        e = entry.lower().strip(".")
        if not e:
            continue
        if e.startswith("*."):
            if fnmatch.fnmatch(host, e[1:]) or host == e[2:]:
                return True
        elif host == e:
            return True
    return False


def tool_web_fetch(args: dict, cfg: Config) -> tuple[dict | None, dict | None]:
    url = args["url"]
    try:
        parts = urllib.parse.urlparse(url)
    except ValueError as e:
        return None, error("invalid_args", f"malformed url: {e}")
    if parts.scheme not in ("http", "https"):
        return None, error("invalid_args", "url scheme must be http or https")
    if not parts.hostname or not _host_allowed(parts.hostname, cfg.allowlist):
        return None, error("host_not_allowlisted", f"host not on allowlist: {parts.hostname!r}")
    timeout, err = _ensure_timeout(args, *_tool_timeout(cfg, "web-fetch", 10))
    if err:
        return None, err
    assert timeout is not None
    req = urllib.request.Request(url, headers={"User-Agent": "agent-kavach/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(MAX_OUTPUT_BYTES + 1)
            truncated = len(body) > MAX_OUTPUT_BYTES
            body = body[:MAX_OUTPUT_BYTES]
            return (
                {
                    "url": url,
                    "status": resp.status,
                    "content_type": resp.headers.get("Content-Type", ""),
                    "body": body.decode("utf-8", "replace"),
                    "truncated": truncated,
                },
                None,
            )
    except Exception as e:  # network errors -> structured error, never a traceback
        return None, error("fetch_error", f"{type(e).__name__}: {e}")


def tool_scheme_lookup(args: dict, cfg: Config) -> tuple[dict | None, dict | None]:
    schemes = load_schemes(cfg)
    name = args["name"]
    if name not in schemes:
        return None, error("not_found", f"unknown scheme {name!r}; known: {sorted(schemes)}")
    return {"name": name, "scheme": schemes[name]}, None


def tool_eval_run(args: dict, cfg: Config) -> tuple[dict | None, dict | None]:
    target, err = _resolve_workspace_path(cfg.workspace, args.get("script", ""))
    if err:
        return None, err
    assert target is not None
    if target.suffix != ".py":
        return None, error("invalid_args", "eval-run only executes .py files")
    if not target.is_file():
        return None, error("not_found", f"no such script: {args.get('script')!r}")
    timeout, err = _ensure_timeout(args, *_tool_timeout(cfg, "eval-run", MAX_TIMEOUT_SEC))
    if err:
        return None, err
    assert timeout is not None
    try:
        proc = subprocess.run(
            [sys.executable, str(target)],
            cwd=str(cfg.workspace),
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, error("timeout", f"script timed out after {timeout}s")
    text, truncated = _truncate((proc.stdout or b"") + (proc.stderr or b""))
    return (
        {
            "script": args.get("script"),
            "exit_code": proc.returncode,
            "output": text,
            "truncated": truncated,
        },
        None,
    )


EXECUTORS = {
    "shell-sandboxed": tool_shell_sandboxed,
    "file-read": tool_file_read,
    "web-fetch": tool_web_fetch,
    "scheme-lookup": tool_scheme_lookup,
    "eval-run": tool_eval_run,
}


def execute_tool(tool: str, args: dict, cfg: Config) -> dict:
    """Policy gate + validate + dispatch. Always returns a JSON-serialisable envelope."""
    start = time.monotonic()
    args = args if isinstance(args, dict) else {}

    def rejected(err: dict) -> dict:
        return {
            "ok": False,
            "tool": tool,
            "error": err,
            "latency_ms": int((time.monotonic() - start) * 1000),
        }

    # 1. Manifest gate: unknown tool, then allow/deny. Never widened by args.
    perr = check_policy(tool, cfg)
    if perr is not None:
        return rejected(perr)
    # 2. Arg validation with the tool's policy timeout bound.
    verr = validate_args(tool, args, cfg)
    if verr is not None:
        return rejected(verr)
    try:
        result, err = EXECUTORS[tool](args, cfg)
    except Exception as e:  # defensive: tools never raise to the socket
        err, result = error("internal", f"{type(e).__name__}: {e}"), None
    latency_ms = int((time.monotonic() - start) * 1000)
    if err is not None:
        return {"ok": False, "tool": tool, "error": err, "latency_ms": latency_ms}
    return {"ok": True, "tool": tool, "result": result, "latency_ms": latency_ms}


def load_tools_spec(cfg: Config | None = None) -> dict:
    """The tools.json document, with timeout bounds reconciled against policy.

    tools.json ships the built-in 30 s ceiling. If policy.yaml caps a tool
    lower, the advertised schema is rewritten to the *effective* bound, so a
    client never sees a `maximum` wider than what we actually enforce.
    """
    with open(TOOLS_JSON, encoding="utf-8") as f:
        spec = json.load(f)
    if cfg is None:
        return spec
    for tool in spec.get("tools", []):
        name = tool.get("name")
        if name not in KNOWN_TOOLS:
            continue
        props = tool.get("input_schema", {}).get("properties", {})
        schema = props.get("timeout_sec")
        if not isinstance(schema, dict):
            continue
        cap = cfg.timeout_for(name)
        schema["default"] = cap
        schema["maximum"] = cap
        schema["description"] = f"Wall-clock timeout, max {cap}s (policy cap)"
    return spec


# ---------------------------------------------------------------- HTTP layer

class Handler(BaseHTTPRequestHandler):
    cfg: Config = Config()
    server_version = "agent-kavach-mcp/1.0"

    def log_message(self, fmt: str, *argv) -> None:  # quieter logs
        sys.stderr.write("mcp: " + fmt % argv + "\n")

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/healthz":
            self._send(200, {"ok": True, "service": "agent-kavach-mcp"})
        elif parsed.path == "/tools/list":
            try:
                self._send(200, load_tools_spec(self.cfg))
            except OSError as e:
                self._send(500, {"ok": False, "error": error("internal", str(e))})
        elif parsed.path == "/policy":
            # The manifest this gateway enforces (env names only, never values).
            self._send(200, {"ok": True, "policy": self.cfg.policy.as_public_dict()})
        else:
            self._send(404, {"ok": False, "error": error("not_found", "unknown path")})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/tools/call":
            self._send(404, {"ok": False, "error": error("not_found", "unknown path")})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 1 << 20:
            self._send(400, {"ok": False, "error": error("invalid_args", "body must be 1..1MiB JSON")})
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except ValueError:
            self._send(400, {"ok": False, "error": error("invalid_args", "body is not valid JSON")})
            return
        tool = payload.get("tool") if isinstance(payload, dict) else None
        args = payload.get("args", {}) if isinstance(payload, dict) else {}
        if not isinstance(tool, str) or not tool:
            self._send(400, {"ok": False, "error": error("invalid_args", "need {\"tool\": \"<name>\", \"args\": {...}}")})
            return
        self._send(200, execute_tool(tool, args if isinstance(args, dict) else {}, self.cfg))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="agent-kavach MCP tool server")
    ap.add_argument("--port", type=int, default=int(os.environ.get("KAVACH_MCP_PORT", "8077")))
    ap.add_argument("--host", default=os.environ.get("KAVACH_MCP_HOST", "127.0.0.1"))
    ap.add_argument("--workspace", default=None, help="override the policy workspace root")
    ap.add_argument("--allowlist", default=None, help="comma-separated fetch hosts (overrides the policy allowlist)")
    ap.add_argument(
        "--policy",
        default=None,
        help="policy.yaml manifest (default: $KAVACH_POLICY, else <repo>/policy.yaml)",
    )
    args = ap.parse_args(argv)
    allow = [h.strip() for h in args.allowlist.split(",") if h.strip()] if args.allowlist else None
    try:
        cfg = Config(workspace=args.workspace, allowlist=allow, policy=args.policy)
    except PolicyError as e:
        # Fail closed: a configured-but-broken manifest must not start a
        # gateway that silently runs with wider defaults.
        print(f"policy error: {e}", file=sys.stderr)
        return 2
    Handler.cfg = cfg
    Handler.cfg.workspace.mkdir(parents=True, exist_ok=True)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    src = Handler.cfg.policy.path or "built-in defaults"
    print(
        f"agent-kavach-mcp on http://{args.host}:{args.port} "
        f"workspace={Handler.cfg.workspace} policy={src}",
        flush=True,
    )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
