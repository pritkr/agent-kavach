"""pytest suite for the agent-kavach MCP server (stdlib-only, no fixtures needed)."""

import json
import re
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

import server
from server import Config, Handler, execute_tool, validate_args

try:  # `pytest mcp` puts mcp/ on sys.path; keep the import robust either way
    import policy
except ImportError:  # pragma: no cover
    from mcp import policy

# The canary: a fake secret that must never appear in any log or policy view.
canary = "canary-kavach-9f8e7d6c5b4a-topsecret"


@pytest.fixture()
def cfg(tmp_path: Path) -> Config:
    ws = tmp_path / "ws"
    ws.mkdir()
    return Config(workspace=str(ws), allowlist=["example.com", "*.trusted.test"])


# ---- schema / registry -----------------------------------------------------

def test_tools_json_lists_five_tools():
    spec = json.loads((Path(server.__file__).parent / "tools.json").read_text())
    names = [t["name"] for t in spec["tools"]]
    assert names == ["shell-sandboxed", "file-read", "web-fetch", "scheme-lookup", "eval-run"]
    for t in spec["tools"]:
        assert t["input_schema"]["type"] == "object"


def test_unknown_tool_rejected(cfg: Config):
    env = execute_tool("nope", {}, cfg)
    assert env["ok"] is False
    assert env["error"]["code"] == "unknown_tool"


# ---- shell-sandboxed --------------------------------------------------------

def test_shell_sandboxed_echo(cfg: Config):
    env = execute_tool("shell-sandboxed", {"command": ["echo", "hi"]}, cfg)
    assert env["ok"] is True
    assert env["result"]["exit_code"] == 0
    assert "hi" in env["result"]["output"]
    assert env["latency_ms"] >= 0


def test_shell_sandboxed_rejects_empty_command(cfg: Config):
    env = execute_tool("shell-sandboxed", {"command": []}, cfg)
    assert env["ok"] is False
    assert env["error"]["code"] == "invalid_args"


def test_shell_sandboxed_rejects_overlong_timeout(cfg: Config):
    env = execute_tool("shell-sandboxed", {"command": ["true"], "timeout_sec": 999}, cfg)
    assert env["ok"] is False
    assert "timeout_sec" in env["error"]["message"]


def test_shell_sandboxed_timeout_kills(cfg: Config):
    env = execute_tool(
        "shell-sandboxed",
        {"command": ["python3", "-c", "import time; time.sleep(5)"], "timeout_sec": 1},
        cfg,
    )
    assert env["ok"] is False
    assert env["error"]["code"] == "timeout"


# ---- file-read ---------------------------------------------------------------

def test_file_read_roundtrip(cfg: Config):
    (cfg.workspace / "hello.txt").write_text("kavach\n")
    env = execute_tool("file-read", {"path": "hello.txt"}, cfg)
    assert env["ok"] is True
    assert env["result"]["content"] == "kavach\n"


def test_file_read_rejects_escape(cfg: Config):
    env = execute_tool("file-read", {"path": "../outside.txt"}, cfg)
    assert env["ok"] is False
    assert env["error"]["code"] == "path_outside_workspace"


def test_file_read_missing_is_not_found(cfg: Config):
    env = execute_tool("file-read", {"path": "ghost.txt"}, cfg)
    assert env["ok"] is False
    assert env["error"]["code"] == "not_found"


def test_file_read_rejects_symlink_escape(cfg: Config, tmp_path: Path):
    secret = tmp_path / "secret.txt"
    secret.write_text("s3cret")
    (cfg.workspace / "link.txt").symlink_to(secret)
    env = execute_tool("file-read", {"path": "link.txt"}, cfg)
    assert env["ok"] is False
    assert env["error"]["code"] == "path_outside_workspace"


# ---- web-fetch -----------------------------------------------------------------

def test_web_fetch_rejects_non_allowlisted_host(cfg: Config):
    env = execute_tool("web-fetch", {"url": "https://evil.example/x"}, cfg)
    assert env["ok"] is False
    assert env["error"]["code"] == "host_not_allowlisted"


def test_web_fetch_rejects_non_http_scheme(cfg: Config):
    env = execute_tool("web-fetch", {"url": "file:///etc/passwd"}, cfg)
    assert env["ok"] is False
    assert env["error"]["code"] == "invalid_args"


def test_web_fetch_allows_wildcard_subdomain():
    cfg = Config(workspace="/tmp", allowlist=["*.trusted.test"])
    assert validate_args("web-fetch", {"url": "https://a.trusted.test/x"}) is None
    env = execute_tool("web-fetch", {"url": "https://other.test/x"}, cfg)
    assert env["ok"] is False
    assert env["error"]["code"] == "host_not_allowlisted"


# ---- scheme-lookup ---------------------------------------------------------------

def test_scheme_lookup_builtin(cfg: Config):
    env = execute_tool("scheme-lookup", {"name": "balanced"}, cfg)
    assert env["ok"] is True
    assert env["result"]["scheme"]["max_retries"] == 3


def test_scheme_lookup_unknown(cfg: Config):
    env = execute_tool("scheme-lookup", {"name": "warp9"}, cfg)
    assert env["ok"] is False
    assert env["error"]["code"] == "not_found"


# ---- eval-run --------------------------------------------------------------------

def test_eval_run_executes_workspace_script(cfg: Config):
    (cfg.workspace / "add.py").write_text("print(2 + 3)\n")
    env = execute_tool("eval-run", {"script": "add.py"}, cfg)
    assert env["ok"] is True
    assert env["result"]["exit_code"] == 0
    assert "5" in env["result"]["output"]


def test_eval_run_rejects_non_python(cfg: Config):
    (cfg.workspace / "run.sh").write_text("echo hi\n")
    env = execute_tool("eval-run", {"script": "run.sh"}, cfg)
    assert env["ok"] is False
    assert env["error"]["code"] == "invalid_args"


def test_eval_run_rejects_escape(cfg: Config):
    env = execute_tool("eval-run", {"script": "../evil.py"}, cfg)
    assert env["ok"] is False
    assert env["error"]["code"] == "path_outside_workspace"


# ---- HTTP integration ------------------------------------------------------------

@pytest.fixture()
def live_server(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "note.txt").write_text("via-http\n")
    old = Handler.cfg
    Handler.cfg = Config(workspace=str(ws), allowlist=["example.com"])
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    Handler.cfg = old


def _post(base: str, path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        base + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.load(resp)


def test_http_healthz_and_list(live_server: str):
    with urllib.request.urlopen(live_server + "/healthz", timeout=10) as resp:
        assert json.load(resp)["ok"] is True
    with urllib.request.urlopen(live_server + "/tools/list", timeout=10) as resp:
        spec = json.load(resp)
    assert len(spec["tools"]) == 5


def test_http_tool_call_roundtrip(live_server: str):
    env = _post(live_server, "/tools/call", {"tool": "file-read", "args": {"path": "note.txt"}})
    assert env["ok"] is True
    assert env["result"]["content"] == "via-http\n"
    bad = _post(live_server, "/tools/call", {"tool": "file-read", "args": {"path": "../x"}})
    assert bad["ok"] is False


# ---- policy manifest (policy.yaml is the single source of truth) ------------

REPO_ROOT = Path(server.__file__).resolve().parent.parent


def write_policy(tmp_path: Path, body: str) -> str:
    p = tmp_path / "policy.yaml"
    p.write_text(body)
    return str(p)


def test_policy_example_manifest_loads():
    """The committed policy.yaml parses here exactly as it does in the daemon."""
    pol = policy.load_policy(REPO_ROOT / "policy.yaml")
    assert pol.workspace == "/tmp/agent-kavach/workspace"
    assert pol.network_allowlist == ("example.com",)
    assert pol.default_timeout_sec == 120
    assert pol.timeout_for("web-fetch") == 10
    # The spec's core invariant, enforced from the manifest itself.
    assert pol.env_names("web-fetch") == ()
    assert pol.env_names("eval-run") == ()
    assert pol.env_names("shell-sandboxed") == ("KAVACH_DEMO_TOKEN",)
    assert pol.backend == "auto"


def test_policy_backend_pin_is_validated(tmp_path: Path):
    """`backend` is a closed set: a typo must fail the boot, not be ignored.

    The gateway executes nothing itself — the daemon does — but it reads the same
    manifest, so it must refuse the same values. Otherwise a manifest pinning a
    nonexistent backend would be rejected by one enforcement point and accepted
    by the other.
    """
    assert policy.load_policy(REPO_ROOT / "policy.yaml").backend == "auto"
    assert policy.load_policy("").backend == policy.DEFAULT_BACKEND
    for good in policy.KNOWN_BACKENDS:
        p = write_policy(tmp_path, f"backend: {good}\n")
        assert policy.load_policy(p).backend == good
    for bad in ("vm", "RUNSC", "gvisor", "3"):
        p = write_policy(tmp_path, f"backend: {bad}\n")
        with pytest.raises(policy.PolicyError, match="backend must be one of"):
            policy.load_policy(p)
        assert server.main(["--policy", p, "--port", "0"]) == 2


def test_policy_public_dict_includes_backend(tmp_path: Path):
    """The served manifest view shows the pin, so an operator can see it."""
    p = write_policy(tmp_path, "backend: runsc\n")
    assert policy.load_policy(p).as_public_dict()["backend"] == "runsc"


def test_policy_default_when_no_file():
    pol = policy.load_policy("")
    assert pol.path == ""
    assert pol.allowed("file-read") is True
    assert pol.timeout_for("web-fetch") == 10


def test_policy_discovery_prefers_kavach_policy_env(tmp_path: Path, monkeypatch):
    p = write_policy(tmp_path, "workspace: /tmp/from-env\n")
    monkeypatch.setenv("KAVACH_POLICY", p)
    assert policy.discover_policy().workspace == "/tmp/from-env"
    # An explicit argument still wins over the env var.
    explicit = tmp_path / "explicit.yaml"
    explicit.write_text("workspace: /tmp/explicit\n")
    assert policy.discover_policy(str(explicit)).workspace == "/tmp/explicit"


def test_policy_rejects_unknown_tool(tmp_path: Path):
    p = write_policy(tmp_path, "tools:\n  rm-rf-everything:\n    allow: true\n")
    with pytest.raises(policy.PolicyError, match="unknown tool"):
        policy.load_policy(p)


def test_policy_rejects_typo_key(tmp_path: Path):
    p = write_policy(tmp_path, "toolz:\n  file-read:\n    allow: true\n")
    with pytest.raises(policy.PolicyError, match="unknown top-level key"):
        policy.load_policy(p)


def test_policy_rejects_out_of_range_timeout(tmp_path: Path):
    p = write_policy(tmp_path, "tools:\n  web-fetch:\n    timeout_sec: 900\n")
    with pytest.raises(policy.PolicyError, match="timeout_sec must be"):
        policy.load_policy(p)


def test_policy_deny_blocks_tool_end_to_end(tmp_path: Path):
    """A denied tool is refused even when the request is otherwise valid."""
    p = write_policy(tmp_path, "tools:\n  eval-run:\n    allow: false\n")
    cfg = Config(workspace=str(tmp_path / "ws"), policy=p)
    (cfg.workspace).mkdir(parents=True, exist_ok=True)
    (cfg.workspace / "s.py").write_text("print(1)\n")
    env = execute_tool("eval-run", {"script": "s.py"}, cfg)
    assert env["ok"] is False
    assert env["error"]["code"] == "tool_denied"
    # Deny wins over argument validation: garbage args still say tool_denied.
    assert execute_tool("eval-run", {"script": "../escape.py"}, cfg)["error"]["code"] == "tool_denied"
    # ...while an allowed tool on the same manifest still runs.
    assert execute_tool("file-read", {"path": "s.py"}, cfg)["ok"] is True


def test_policy_timeout_override(tmp_path: Path):
    """policy.yaml sets the per-tool cap; requests above it fail closed."""
    p = write_policy(tmp_path, "tools:\n  web-fetch:\n    timeout_sec: 5\n  shell-sandboxed:\n    timeout_sec: 12\n")
    cfg = Config(workspace=str(tmp_path / "ws"), allowlist=["example.com"], policy=p)
    assert cfg.timeout_for("web-fetch") == 5
    # Below the cap: accepted.
    assert validate_args("web-fetch", {"url": "https://example.com/x", "timeout_sec": 3}, cfg) is None
    assert validate_args("shell-sandboxed", {"command": ["true"], "timeout_sec": 12}, cfg) is None
    # Above the cap: rejected, both through validation and end-to-end.
    err = validate_args("web-fetch", {"url": "https://example.com/x", "timeout_sec": 30}, cfg)
    assert err is not None and "1..5" in err["message"]
    env = execute_tool("web-fetch", {"url": "https://example.com/x", "timeout_sec": 30}, cfg)
    assert env["ok"] is False
    assert "1..5" in env["error"]["message"]
    # Omitting the field binds the policy default.
    assert cfg.policy.resolve_timeout("web-fetch", 0) == 5
    with pytest.raises(policy.PolicyError, match="exceeds policy max"):
        cfg.policy.resolve_timeout("shell-sandboxed", 13)


def test_policy_workspace_and_allowlist_come_from_manifest(tmp_path: Path):
    ws = tmp_path / "policyws"
    p = write_policy(
        tmp_path,
        f"workspace: {ws}\nnetwork_allowlist:\n  - good.test\n  - '*.ok.test'\n",
    )
    cfg = Config(policy=p)
    assert cfg.workspace == ws.resolve()
    assert cfg.allowlist == ["good.test", "*.ok.test"]
    cfg.workspace.mkdir(parents=True, exist_ok=True)
    (ws / "inside.txt").write_text("scoped\n")
    assert execute_tool("file-read", {"path": "inside.txt"}, cfg)["ok"] is True
    assert execute_tool("web-fetch", {"url": "https://other.test/"}, cfg)["error"]["code"] == "host_not_allowlisted"


def test_policy_never_exposes_secret_values(tmp_path: Path):
    """The manifest carries env *names* only; the gateway logs no values."""
    p = write_policy(tmp_path, "tools:\n  shell-sandboxed:\n    env:\n      - KAVACH_DEMO_TOKEN\n")
    cfg = Config(workspace=str(tmp_path / "ws"), policy=p)
    blob = json.dumps(cfg.policy.as_public_dict())
    assert "KAVACH_DEMO_TOKEN" in blob
    assert canary not in blob


@pytest.mark.parametrize(
    "body, message",
    [
        ("toolz:\n  file-read:\n    allow: true\n", "unknown top-level key"),
        ("tools:\n  rm-rf:\n    allow: true\n", "unknown tool"),
        ("tools:\n  file-read:\n    allowd: true\n", "unknown key"),
        ("tools:\n  web-fetch:\n    timeout_sec: 900\n", "timeout_sec must be"),
        ("default_timeout_sec: 0\n", "default_timeout_sec must be"),
        ("network_allowlist: []\n", "network_allowlist must not be empty"),
        ("tools:\n  web-fetch:\n    env:\n      - 'bad name'\n", "invalid env name"),
        ("workspace: 42\n", "workspace must be a non-empty string"),
        ("tools:\n  web-fetch:\n    allow: maybe\n", "allow must be true/false"),
    ],
)
def test_policy_fails_closed_on_bad_manifests(tmp_path: Path, body: str, message: str):
    """Every manifest mistake is a hard error, never a silent widening.

    The parametrised cases mirror daemon/policy_test.go so the Go daemon and
    this gateway cannot drift apart in what they refuse.
    """
    p = write_policy(tmp_path, body)
    with pytest.raises(policy.PolicyError, match=re.escape(message)):
        policy.load_policy(p)
    # …and the gateway refuses to boot on it rather than using defaults.
    assert server.main(["--policy", p, "--port", "0"]) == 2


def test_policy_never_starts_with_broken_manifest(tmp_path: Path, capsys):
    p = write_policy(tmp_path, "tools:\n  nope:\n    allow: true\n")
    assert server.main(["--policy", p, "--port", "0"]) == 2
    assert "policy error" in capsys.readouterr().err


def test_tools_list_advertises_the_policy_timeout(tmp_path: Path):
    """/tools/list must never promise a wider bound than we enforce."""
    p = write_policy(tmp_path, "tools:\n  web-fetch:\n    timeout_sec: 4\n  shell-sandboxed:\n    timeout_sec: 20\n")
    cfg = Config(workspace=str(tmp_path / "ws"), policy=p)
    props = {t["name"]: t["input_schema"].get("properties", {}).get("timeout_sec", {}) for t in server.load_tools_spec(cfg)["tools"]}
    assert props["web-fetch"]["maximum"] == 4
    assert props["web-fetch"]["default"] == 4
    assert props["shell-sandboxed"]["maximum"] == 20
    # No timeout_sec property at all (file-read, scheme-lookup): nothing to say.
    assert props["file-read"] == {}
    # And what is advertised is what is enforced.
    assert validate_args("web-fetch", {"url": "https://x.test/", "timeout_sec": 5}, cfg) is not None
    assert validate_args("web-fetch", {"url": "https://x.test/", "timeout_sec": 4}, cfg) is None


def test_policy_env_endpoint_shows_names_only(live_server: str):
    with urllib.request.urlopen(live_server + "/policy", timeout=10) as resp:
        doc = json.load(resp)
    assert doc["ok"] is True
    assert set(doc["policy"]["tools"]) == set(policy.KNOWN_TOOLS)
    assert doc["policy"]["tools"]["eval-run"]["allow"] is True
