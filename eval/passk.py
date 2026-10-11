#!/usr/bin/env python3
"""pass^k scorer for agent-kavach trajectories.

Scores one sample or a whole suite of trajectory JSONL files against
eval/tasks.json.

Single sample:
    python3 passk.py --tasks tasks.json --trajectory traj.jsonl --task file-edit

Suite (files named <task-id>.<sample>.jsonl, k samples per task):
    python3 passk.py --tasks tasks.json --trajectories-dir ./trajs/

Metrics:
    pass@1 = fraction of tasks passing on the first sample
    pass^k = fraction of tasks passing on ANY of k samples (k from tasks.json)

Exit code: 0 if pass@1 == 1.0, else 1 (CI-friendly).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_events(path: Path) -> list[dict]:
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def summarize(events: list[dict]) -> dict:
    tool_calls = [e.get("tool", "") for e in events if e.get("phase") == "tool"]
    succeeded: set[str] = set()
    errors = 0
    status = "unknown"
    for e in events:
        if e.get("phase") == "observe":
            obs = e.get("observation", {}) or {}
            if obs.get("ok"):
                succeeded.add(obs.get("tool", ""))
            else:
                errors += 1
        if e.get("phase") == "done":
            status = e.get("status", "unknown")
    return {"tool_calls": tool_calls, "succeeded": succeeded, "errors": errors, "status": status}


def check_pass(task: dict, events: list[dict]) -> tuple[bool, list[str]]:
    s = summarize(events)
    failures: list[str] = []
    for c in task.get("checks", []):
        t = c.get("type")
        if t == "tool_called":
            if c["tool"] not in s["tool_calls"]:
                failures.append(f"tool {c['tool']} never called (saw {s['tool_calls']})")
        elif t == "tool_succeeded":
            if c["tool"] not in s["succeeded"]:
                failures.append(f"tool {c['tool']} never succeeded")
        elif t == "tools_in_order":
            calls = s["tool_calls"]
            cursor = 0
            for want in c["tools"]:
                try:
                    idx = calls.index(want, cursor)
                except ValueError:
                    failures.append(f"missing tool {want} in order (saw {calls})")
                    break
                cursor = idx + 1
        elif t == "max_errors":
            if s["errors"] > c["n"]:
                failures.append(f"errors={s['errors']} > max {c['n']}")
        elif t == "status":
            if s["status"] != c["want"]:
                failures.append(f"status={s['status']}, want {c['want']}")
        else:
            failures.append(f"unknown check type {t!r}")
    return (not failures, failures)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="pass^k trajectory scorer")
    ap.add_argument("--tasks", required=True, help="path to tasks.json")
    ap.add_argument("--trajectory", help="single trajectory JSONL file")
    ap.add_argument("--task", help="task id for single-trajectory mode")
    ap.add_argument("--trajectories-dir", help="dir of <task>.<sample>.jsonl files")
    ap.add_argument("--k", type=int, default=None, help="override k from tasks.json")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args(argv)

    suite = json.loads(Path(args.tasks).read_text(encoding="utf-8"))
    tasks = {t["id"]: t for t in suite["tasks"]}
    k = args.k or suite.get("k", 3)

    results: dict[str, dict] = {}
    if args.trajectories_dir:
        d = Path(args.trajectories_dir)
        for task_id in tasks:
            samples = sorted(d.glob(f"{task_id}.*.jsonl"))
            sample_ok = []
            sample_failures = []
            for s in samples[:k]:
                ok, failures = check_pass(tasks[task_id], load_events(s))
                sample_ok.append(ok)
                sample_failures.append(failures)
            while len(sample_ok) < 1:
                sample_ok.append(False)
                sample_failures.append(["no trajectory sample found"])
            results[task_id] = {
                "pass@1": sample_ok[0],
                f"pass@{k}": any(sample_ok),
                "samples": len(sample_ok),
                "failures_first": sample_failures[0],
            }
    elif args.trajectory and args.task:
        if args.task not in tasks:
            print(f"unknown task {args.task!r}; known: {sorted(tasks)}", file=sys.stderr)
            return 2
        ok, failures = check_pass(tasks[args.task], load_events(Path(args.trajectory)))
        results[args.task] = {"pass@1": ok, f"pass@{k}": ok, "samples": 1, "failures_first": failures}
    else:
        ap.error("need --trajectory + --task OR --trajectories-dir")
        return 2

    pass1 = sum(1 for r in results.values() if r["pass@1"]) / len(results)
    passk = sum(1 for r in results.values() if r[f"pass@{k}"]) / len(results)
    report = {"k": k, "pass@1": round(pass1, 4), f"pass@{k}": round(passk, 4), "tasks": results}

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for tid, r in results.items():
            mark = "PASS" if r["pass@1"] else "FAIL"
            print(f"[{mark}] {tid} (pass@{k}={r[f'pass@{k}']}, samples={r['samples']})")
            for f in r["failures_first"]:
                print(f"       - {f}")
        print(f"\npass@1 = {report['pass@1']:.2f}   pass^{k} = {report[f'pass@{k}']:.2f}")

    return 0 if pass1 == 1.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
