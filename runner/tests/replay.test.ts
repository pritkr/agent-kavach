/** Replay tests: load / summarise / verify / format. */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TrajectoryEvent } from "../src/loop";
import { formatReplay, loadTrajectory, summarizeTrajectory, verifyTrajectory } from "../src/replay";

function sampleEvents(): TrajectoryEvent[] {
  const base = { ts: new Date().toISOString(), runId: "r1" } as const;
  return [
    { seq: 1, ...base, phase: "plan", step: 1, tool: "file-read", args: { path: "a.txt" } },
    { seq: 2, ...base, phase: "tool", step: 1, tool: "file-read", args: { path: "a.txt" } },
    {
      seq: 3,
      ...base,
      phase: "observe",
      step: 1,
      tool: "file-read",
      observation: { step: 1, tool: "file-read", ok: true, output: "hi", latencyMs: 12, attempt: 1 },
    },
    { seq: 4, ...base, phase: "plan", step: 2, tool: "shell-sandboxed", args: { command: ["echo", "x"] } },
    { seq: 5, ...base, phase: "tool", step: 2, tool: "shell-sandboxed", args: { command: ["echo", "x"] } },
    {
      seq: 6,
      ...base,
      phase: "observe",
      step: 2,
      tool: "shell-sandboxed",
      observation: { step: 2, tool: "shell-sandboxed", ok: true, latencyMs: 30, attempt: 1 },
    },
    { seq: 7, ...base, phase: "done", status: "done" },
  ];
}

function writeSample(): string {
  const p = join(mkdtempSync(join(tmpdir(), "kavach-")), "traj.jsonl");
  writeFileSync(p, sampleEvents().map((e) => JSON.stringify(e)).join("\n") + "\n");
  return p;
}

describe("replay", () => {
  it("loads JSONL trajectories, skipping blank lines", () => {
    const p = writeSample();
    const events = loadTrajectory(p);
    assert.equal(events.length, 7);
    assert.equal(events[0].phase, "plan");
  });

  it("summarises steps, tools, latency and status", () => {
    const s = summarizeTrajectory(sampleEvents());
    assert.equal(s.steps, 2);
    assert.equal(s.toolCalls, 2);
    assert.equal(s.errors, 0);
    assert.equal(s.killed, false);
    assert.equal(s.status, "done");
    assert.deepEqual(s.toolsUsed, ["file-read", "shell-sandboxed"]);
    assert.equal(s.totalLatencyMs, 42);
  });

  it("detects killed trajectories", () => {
    const evs = sampleEvents();
    evs.push({ seq: 8, ts: new Date().toISOString(), runId: "r1", phase: "killed", reason: "test" });
    assert.equal(summarizeTrajectory(evs).killed, true);
  });

  it("verifies tool order and success", () => {
    const { ok, failures } = verifyTrajectory(sampleEvents(), {
      toolsInOrder: ["file-read", "shell-sandboxed"],
      mustSucceed: true,
      maxErrors: 0,
    });
    assert.equal(ok, true);
    assert.deepEqual(failures, []);
  });

  it("reports missing tools and bad status", () => {
    const { ok, failures } = verifyTrajectory(sampleEvents(), {
      toolsInOrder: ["shell-sandboxed", "web-fetch"],
      mustSucceed: true,
    });
    assert.equal(ok, false);
    assert.ok(failures.some((f) => f.includes("web-fetch")));
  });

  it("formats a human-readable replay", () => {
    const lines = formatReplay(sampleEvents());
    assert.equal(lines.length, 7);
    assert.ok(lines[0].includes("[plan]"));
    assert.ok(lines[lines.length - 1].includes("[done]"));
  });
});
