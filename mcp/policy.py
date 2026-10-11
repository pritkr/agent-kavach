"""agent-kavach policy manifest reader (stdlib only).

The Go daemon (`daemon/policy.go`) and this module are the two enforcement
points for one declarative file, `policy.yaml`:

    workspace:        root every path is resolved inside
    network_allowlist: hosts web-fetch may reach
    default_timeout_sec
    backend:          sandbox executor pin (daemon-side): auto|docker|local|runsc
    tools:
      <tool>:
        allow:        false removes the tool everywhere (fail-closed deny)
        timeout_sec:  per-tool wall-clock cap
        env:          process-env names the tool may receive (daemon-side)

Both implementations parse the same deliberately small YAML subset (nested
maps, scalar lists, scalars, comments) and reject unknown tools, unknown keys
and out-of-range values as hard errors: a typo'd manifest must never silently
widen access. Keep the two parsers in sync.

Discovery order: explicit argument -> $KAVACH_POLICY -> <repo>/policy.yaml ->
built-in defaults. A file that exists but is invalid is a hard failure, not a
silent fallback.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# The closed tool universe. Anything else is rejected as unknown_tool.
KNOWN_TOOLS = (
    "shell-sandboxed",
    "file-read",
    "web-fetch",
    "scheme-lookup",
    "eval-run",
)

# Absolute per-tool ceiling; a manifest may only lower it (1..MAX_TIMEOUT_SEC).
MAX_TIMEOUT_SEC = 30

DEFAULT_WORKSPACE = "/tmp/agent-kavach/workspace"
DEFAULT_NETWORK_ALLOWLIST = ("example.com",)
DEFAULT_TIMEOUT_SEC = 120

# The closed backend universe (daemon-side). Mirrors KnownBackends in
# daemon/sandbox.go. "auto" means "strongest available".
KNOWN_BACKENDS = ("docker", "local", "runsc", "auto")
DEFAULT_BACKEND = "auto"

# Built-in per-tool defaults, mirroring daemon/policy.go.
DEFAULT_TOOL_TIMEOUTS = {
    "shell-sandboxed": 30,
    "file-read": 30,
    "web-fetch": 10,
    "scheme-lookup": 10,
    "eval-run": 30,
}

TOP_LEVEL_KEYS = ("workspace", "network_allowlist", "default_timeout_sec", "backend", "tools")
TOOL_KEYS = ("allow", "timeout_sec", "env")

# <repo>/policy.yaml — mcp/ is <repo>/mcp.
REPO_POLICY_PATH = Path(__file__).resolve().parent.parent / "policy.yaml"


class PolicyError(ValueError):
    """Raised for any malformed or self-contradictory manifest."""


class ToolPolicy:
    """One tool stanza."""

    __slots__ = ("allow", "timeout_sec", "env")

    def __init__(self, allow: bool = True, timeout_sec: int = 30, env: tuple[str, ...] = ()) -> None:
        self.allow = allow
        self.timeout_sec = timeout_sec
        self.env = tuple(env)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ToolPolicy(allow={self.allow!r}, timeout_sec={self.timeout_sec!r}, env={self.env!r})"


class Policy:
    """The decoded manifest."""

    __slots__ = ("workspace", "network_allowlist", "default_timeout_sec", "backend", "tools", "path")

    def __init__(
        self,
        workspace: str = DEFAULT_WORKSPACE,
        network_allowlist: tuple[str, ...] = DEFAULT_NETWORK_ALLOWLIST,
        default_timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        backend: str = DEFAULT_BACKEND,
        tools: dict[str, ToolPolicy] | None = None,
        path: str = "",
    ) -> None:
        self.workspace = workspace
        self.network_allowlist = tuple(network_allowlist)
        self.default_timeout_sec = default_timeout_sec
        self.backend = backend
        self.tools = tools if tools is not None else {}
        self.path = path

    # -- queries ---------------------------------------------------------

    def allowed(self, tool: str) -> bool:
        """Report whether tool may execute. Unknown tools are never allowed."""
        if tool not in KNOWN_TOOLS:
            return False
        tp = self.tools.get(tool)
        if tp is None:
            return tool in DEFAULT_TOOL_TIMEOUTS
        return tp.allow

    def timeout_for(self, tool: str) -> int:
        """Per-tool wall-clock cap in seconds."""
        tp = self.tools.get(tool)
        if tp is not None and tp.timeout_sec > 0:
            return tp.timeout_sec
        return DEFAULT_TOOL_TIMEOUTS.get(tool, MAX_TIMEOUT_SEC)

    def resolve_timeout(self, tool: str, requested: int) -> int:
        """Map a requested timeout to an effective one.

        requested <= 0 means "policy default". Anything above the per-tool cap
        raises, so a caller cannot smuggle a longer execution past policy.
        """
        cap = self.timeout_for(tool)
        if requested is None or requested <= 0:
            return cap
        if requested > cap:
            raise PolicyError(f"timeout_sec {requested} exceeds policy max {cap} for tool {tool!r}")
        return requested

    def env_names(self, tool: str) -> tuple[str, ...]:
        """Env names the manifest grants this tool (the daemon injects values)."""
        if tool not in KNOWN_TOOLS:
            return ()
        tp = self.tools.get(tool)
        return tp.env if tp else ()

    def as_public_dict(self) -> dict:
        """Manifest view safe to log or serve: names only, never values."""
        return {
            "workspace": self.workspace,
            "network_allowlist": list(self.network_allowlist),
            "default_timeout_sec": self.default_timeout_sec,
            "backend": self.backend,
            "tools": {
                name: {
                    "allow": self.allowed(name),
                    "timeout_sec": self.timeout_for(name),
                    "env": list(self.env_names(name)),
                }
                for name in KNOWN_TOOLS
            },
        }


def default_policy() -> Policy:
    """The built-in manifest used when no policy.yaml is present."""
    return Policy(
        workspace=DEFAULT_WORKSPACE,
        network_allowlist=DEFAULT_NETWORK_ALLOWLIST,
        default_timeout_sec=DEFAULT_TIMEOUT_SEC,
        backend=DEFAULT_BACKEND,
        tools={name: ToolPolicy(True, secs) for name, secs in DEFAULT_TOOL_TIMEOUTS.items()},
        path="",
    )


def load_policy(path: str | os.PathLike[str] | None) -> Policy:
    """Read + validate a manifest file. An empty path yields the defaults."""
    if not path:
        return default_policy()
    text = Path(path).read_text(encoding="utf-8")
    raw = parse_mini_yaml(text)
    pol = default_policy()
    pol.path = str(path)

    for key in raw:
        if key not in TOP_LEVEL_KEYS:
            raise PolicyError(f"policy: unknown top-level key {key!r}")

    if "workspace" in raw:
        ws = raw["workspace"]
        if not isinstance(ws, str) or not ws:
            raise PolicyError("policy: workspace must be a non-empty string")
        pol.workspace = ws

    if "network_allowlist" in raw:
        hosts = _string_list(raw["network_allowlist"], "policy: network_allowlist")
        if not hosts:
            raise PolicyError("policy: network_allowlist must not be empty")
        pol.network_allowlist = tuple(h.lower() for h in hosts)

    if "default_timeout_sec" in raw:
        n = _int(raw["default_timeout_sec"], "policy: default_timeout_sec")
        if not 1 <= n <= 1800:
            raise PolicyError("policy: default_timeout_sec must be 1..1800")
        pol.default_timeout_sec = n

    if "backend" in raw and raw["backend"] is not None:
        backend = raw["backend"]
        if not isinstance(backend, str) or backend not in KNOWN_BACKENDS:
            raise PolicyError("policy: backend must be one of " + ", ".join(KNOWN_BACKENDS))
        pol.backend = backend

    if "tools" in raw and raw["tools"] is not None:
        tools = raw["tools"]
        if not isinstance(tools, dict):
            raise PolicyError("policy: tools must be a mapping")
        for name, entry in tools.items():
            if name not in KNOWN_TOOLS:
                raise PolicyError(f"policy: unknown tool {name!r}")
            pol.tools[name] = _tool_policy(name, entry)

    return pol


def _tool_policy(name: str, entry) -> ToolPolicy:
    if entry is None:
        return ToolPolicy(True, DEFAULT_TOOL_TIMEOUTS[name])
    if not isinstance(entry, dict):
        raise PolicyError(f"policy: tools.{name} must be a mapping")
    for field in entry:
        if field not in TOOL_KEYS:
            raise PolicyError(f"policy: unknown key tools.{name}.{field}")
    tp = ToolPolicy(True, DEFAULT_TOOL_TIMEOUTS[name])
    if "allow" in entry:
        if not isinstance(entry["allow"], bool):
            raise PolicyError(f"policy: tools.{name}.allow must be true/false")
        tp.allow = entry["allow"]
    if "timeout_sec" in entry:
        n = _int(entry["timeout_sec"], f"policy: tools.{name}.timeout_sec")
        if not 1 <= n <= MAX_TIMEOUT_SEC:
            raise PolicyError(f"policy: tools.{name}.timeout_sec must be 1..{MAX_TIMEOUT_SEC}")
        tp.timeout_sec = n
    if "env" in entry:
        names = _string_list(entry["env"], f"policy: tools.{name}.env")
        for env_name in names:
            if not _valid_env_name(env_name):
                raise PolicyError(f"policy: tools.{name}.env: invalid env name {env_name!r}")
        tp.env = tuple(names)
    return tp


def _int(value, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyError(f"{where} must be an integer")
    return value


def _string_list(value, where: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PolicyError(f"{where}: must be a list")
    out = []
    for item in value:
        if not isinstance(item, str):
            raise PolicyError(f"{where}: list items must be strings")
        out.append(item)
    return out


def _valid_env_name(name: str) -> bool:
    if not name:
        return False
    if not (name[0].isalpha() or name[0] == "_"):
        return False
    return all(c.isalnum() or c == "_" for c in name)


def discover_policy(explicit: str | os.PathLike[str] | None = None) -> Policy:
    """Resolve the effective manifest: explicit -> $KAVACH_POLICY -> repo -> built-in.

    An explicitly named file that is missing or invalid raises: a configured
    but broken manifest must fail closed rather than degrade to defaults.
    """
    if explicit:
        return load_policy(explicit)
    env_path = os.environ.get("KAVACH_POLICY", "").strip()
    if env_path:
        return load_policy(env_path)
    if REPO_POLICY_PATH.is_file():
        return load_policy(REPO_POLICY_PATH)
    return default_policy()


# --------------------------------------------------------------------- YAML

class _Line:
    __slots__ = ("indent", "content")

    def __init__(self, indent: int, content: str) -> None:
        self.indent = indent
        self.content = content


class _Cursor:
    __slots__ = ("lines", "pos")

    def __init__(self, lines: list[_Line]) -> None:
        self.lines = lines
        self.pos = 0

    def peek(self) -> _Line | None:
        return self.lines[self.pos] if self.pos < len(self.lines) else None


def _strip_comment(s: str) -> str:
    """Cut a trailing # comment (only outside quotes, preceded by whitespace)."""
    quote = ""
    for i, c in enumerate(s):
        if quote:
            if c == quote:
                quote = ""
            continue
        if c in "\"'":
            quote = c
            continue
        if c == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i].rstrip(" \t")
    return s


def _split_key(s: str) -> tuple[str, str] | None:
    """Split "key: value" on the first colon that ends the key.

    Colons inside plain values (URLs, times) are left alone.
    """
    quote = ""
    for i, c in enumerate(s):
        if quote:
            if c == quote:
                quote = ""
            continue
        if c in "\"'":
            quote = c
            continue
        if c == ":" and (i + 1 == len(s) or s[i + 1] in " \t"):
            key = s[:i].strip()
            if not key:
                return None
            return key, s[i + 1 :].strip()
    return None


def _parse_scalar(s: str):
    s = s.strip()
    if s == "[]":
        return []
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part) for part in _split_flow(inner)]
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        if s[0] == '"':
            try:
                value = json.loads(s)
            except ValueError as exc:
                raise PolicyError(f"bad double-quoted string {s!r}") from exc
            if not isinstance(value, str):
                raise PolicyError(f"bad double-quoted string {s!r}")
            return value
        return s[1:-1]
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~"):
        return None
    try:
        return int(s)
    except ValueError:
        return s


def _split_flow(s: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    quote = ""
    for c in s:
        if quote:
            cur.append(c)
            if c == quote:
                quote = ""
            continue
        if c in "\"'":
            quote = c
            cur.append(c)
            continue
        if c == ",":
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(c)
    parts.append("".join(cur))
    return parts


def _is_list_item(content: str) -> bool:
    return content == "-" or content.startswith("- ")


def _parse_map(cur: _Cursor, parent_indent: int) -> dict:
    out: dict = {}
    while True:
        ln = cur.peek()
        if ln is None or ln.indent <= parent_indent:
            return out
        if _is_list_item(ln.content):
            raise PolicyError(f"unexpected list item {ln.content!r} (want key: value)")
        parts = _split_key(ln.content)
        if parts is None:
            raise PolicyError(f"bad mapping line {ln.content!r} (want key: value)")
        key, val = parts
        cur.pos += 1
        if val != "":
            out[key] = _parse_scalar(val)
            continue
        nxt = cur.peek()
        if nxt is not None and nxt.indent > ln.indent:
            if _is_list_item(nxt.content):
                out[key] = _parse_list(cur, ln.indent)
            else:
                out[key] = _parse_map(cur, ln.indent)
        else:
            out[key] = None


def _parse_list(cur: _Cursor, parent_indent: int) -> list:
    out: list = []
    while True:
        ln = cur.peek()
        if ln is None or ln.indent <= parent_indent or not _is_list_item(ln.content):
            return out
        item = ln.content[1:].strip() if len(ln.content) > 1 else ""
        cur.pos += 1
        if not item:
            out.append("")
            continue
        if ": " in item or item.endswith(":"):
            raise PolicyError(f"nested mappings in lists are not supported: {ln.content!r}")
        out.append(_parse_scalar(item))


def parse_mini_yaml(src: str) -> dict:
    """Parse the manifest subset into dict/list/str/int/bool/None leaves."""
    lines: list[_Line] = []
    for raw in src.split("\n"):
        line = raw.rstrip(" \t\r")
        if not line:
            continue
        stripped = line.lstrip(" ")
        if stripped.startswith("#"):
            continue
        if line.startswith("\t"):
            raise PolicyError("tabs are not allowed for indentation")
        indent = len(line) - len(stripped)
        content = _strip_comment(stripped)
        if not content:
            continue
        lines.append(_Line(indent, content))

    cur = _Cursor(lines)
    out = _parse_map(cur, -1)
    leftover = cur.peek()
    if leftover is not None:
        raise PolicyError(f"unexpected content at {leftover.content!r}")
    return out
