/** AgentLoop tests: retry/backoff, kill-switch, trajectory output. */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AgentLoop } from "../src/loop";
import { AgentError } from "../src/errors";
import { ToolCaller } from "../src/tools";

/** Programmable fake: fails `failTimes` with a retryable error, then succeeds. */
function fakeMcp(opts: { failTimes?: number; output?: unknown; fatal?: boolean } = {}): ToolCaller & {
  calls: number;
} {
  const state = { calls: 0 };
  return {
    calls: 0,
    async call(tool: string, _args: Record<string, unknown>): Promise<unknown> {
      state.calls++;
      (this as { calls: number }).calls = state.calls;
      if (opts.fatal) {
        throw new AgentError("INVALID_ARGS", "bad args", { retryable: false, tool });
      }
      if (state.calls <= (opts.failTimes ?? 0)) {
        throw new AgentError("TIMEOUT", "boom", { retryable: true, tool });
      }
      return opts.output ?? { echo: "ok" };
    },
  };
}

describe("AgentLoop.callToolWithRetry", () => {
  it("returns success on first attempt", async () => {
    const loop = new AgentLoop({ mcp: fakeMcp(), backoffMs: 1 });
    const obs = await loop.callToolWithRetry("shell-sandboxed", { command: ["echo", "hi"] }, 1);
    assert.equal(obs.ok, true);
    assert.equal(obs.attempt, 1);
  });

  it("retries transient failures and succeeds (retry x3 budget)", async () => {
    const mcp = fakeMcp({ failTimes: 2 });
    const loop = new AgentLoop({ mcp, backoffMs: 1 });
    const obs = await loop.callToolWithRetry("shell-sandboxed", { command: ["x"] }, 1);
    assert.equal(obs.ok, true);
    assert.equal(obs.attempt, 3);
    assert.equal(mcp.calls, 3);
  });

  it("gives up after maxRetries+1 attempts with structured error", async () => {
    const mcp = fakeMcp({ failTimes: 99 });
    const loop = new AgentLoop({ mcp, backoffMs: 1, maxRetries: 3 });
    const obs = await loop.callToolWithRetry("shell-sandboxed", { command: ["x"] }, 2);
    assert.equal(obs.ok, false);
    assert.equal(obs.attempt, 4);
    assert.equal(mcp.calls, 4);
    assert.equal(obs.error?.code, "TIMEOUT");
    assert.equal(obs.error?.retryable, true);
  });

  it("does not retry non-retryable errors", async () => {
    const mcp = fakeMcp({ fatal: true });
    const loop = new AgentLoop({ mcp, backoffMs: 1 });
    const obs = await loop.callToolWithRetry("file-read", { path: "../x" }, 1);
    assert.equal(obs.ok, false);
    assert.equal(mcp.calls, 1);
    assert.equal(obs.error?.retryable, false);
  });

  it("exponential backoff doubles per attempt", () => {
    const loop = new AgentLoop({ mcp: fakeMcp(), backoffMs: 100 });
    assert.equal(loop.backoffFor(1), 100);
    assert.equal(loop.backoffFor(2), 200);
    assert.equal(loop.backoffFor(3), 400);
  });
});

describe("AgentLoop.run", () => {
  it("runs plan->tool->observe until planner returns null", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kavach-"));
    const traj = join(dir, "traj.jsonl");
    const loop = new AgentLoop({ mcp: fakeMcp(), trajectoryPath: traj, backoffMs: 1 });
    const summary = await loop.run("do things", async (_task, hist) => {
      if (hist.length >= 2) return null;
      return { tool: "shell-sandboxed", args: { command: ["echo", "x"] } };
    });
    assert.equal(summary.status, "done");
    assert.equal(summary.steps, 2);
    const lines = readFileSync(traj, "utf-8").trim().split("\n");
    const phases = lines.map((l) => JSON.parse(l).phase);
    assert.ok(phases.includes("plan") && phases.includes("tool") && phases.includes("observe"));
    assert.equal(phases[phases.length - 1], "done");
  });

  it("stops as failed on non-retryable tool error", async () => {
    const loop = new AgentLoop({ mcp: fakeMcp({ fatal: true }), backoffMs: 1 });
    const summary = await loop.run("t", async () => ({ tool: "file-read", args: {} }));
    assert.equal(summary.status, "failed");
    assert.equal(summary.steps, 1);
  });

  it("kill() marks the trajectory killed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kavach-"));
    const traj = join(dir, "traj.jsonl");
    const loop = new AgentLoop({ mcp: fakeMcp(), trajectoryPath: traj, backoffMs: 1 });
    loop.kill("operator stop");
    const summary = await loop.run("t", async () => ({ tool: "shell-sandboxed", args: {} }));
    assert.equal(summary.status, "killed");
    const raw = readFileSync(traj, "utf-8");
    assert.ok(raw.includes('"phase":"killed"'));
  });
});
