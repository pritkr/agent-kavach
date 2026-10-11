"""Tests for the pass^k scorer (synthetic + committed golden trajectories)."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import passk

EVAL = Path(__file__).parent
TASKS = {t["id"]: t for t in json.loads((EVAL / "tasks.json").read_text())["tasks"]}


def ev(seq, phase, **kw):
    return {"seq": seq, "ts": "2026-01-01T00:00:00Z", "runId": "r", "phase": phase, **kw}


def obs(step, tool, ok=True):
    return ev(
        10 + step, "observe", step=step, tool=tool,
        observation={"step": step, "tool": tool, "ok": ok, "latencyMs": 5, "attempt": 1},
    )


def test_tools_in_order_check():
    events = [
        ev(1, "plan", step=1, tool="file-read"),
        ev(2, "tool", step=1, tool="file-read"),
        obs(1, "file-read"),
        ev(4, "tool", step=2, tool="shell-sandboxed"),
        obs(2, "shell-sandboxed"),
        ev(6, "done", status="done"),
    ]
    ok, failures = passk.check_pass(TASKS["file-edit"], events)
    assert ok, failures


def test_tools_in_order_fails_when_missing():
    events = [ev(1, "tool", step=1, tool="file-read"), obs(1, "file-read"), ev(3, "done", status="done")]
    ok, failures = passk.check_pass(TASKS["file-edit"], events)
    assert not ok
    assert any("shell-sandboxed" in f for f in failures)


def test_max_errors_and_status_checks():
    events = [ev(1, "tool", step=1, tool="x"), obs(1, "x", ok=False), ev(3, "done", status="failed")]
    ok, _ = passk.check_pass({"checks": [{"type": "max_errors", "n": 1}]}, events)
    assert ok
    ok, _ = passk.check_pass({"checks": [{"type": "max_errors", "n": 0}]}, events)
    assert not ok
    ok, _ = passk.check_pass({"checks": [{"type": "status", "want": "failed"}]}, events)
    assert ok


def test_unknown_check_type_fails():
    ok, failures = passk.check_pass({"checks": [{"type": "telepathy"}]}, [])
    assert not ok and failures


def test_golden_trajectories_all_pass():
    trajs = EVAL / "trajs"
    assert trajs.is_dir(), "run eval/gen_trajs.mjs to generate golden trajectories"
    for task_id in TASKS:
        sample = trajs / f"{task_id}.0.jsonl"
        assert sample.exists(), f"missing {sample}"
        ok, failures = passk.check_pass(TASKS[task_id], passk.load_events(sample))
        assert ok, f"{task_id}: {failures}"
