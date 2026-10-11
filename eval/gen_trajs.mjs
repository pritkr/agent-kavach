#!/usr/bin/env node
/** Generate real eval trajectories by driving AgentLoop against a live MCP server.
 *
 *  Usage (from eval/):
 *    KAVACH_MCP_URL=http://127.0.0.1:8077 node gen_trajs.mjs --out ./trajs --samples 3
 *
 *  Exits 0 even if individual runs fail — scoring happens in passk.py.
 *  Hermetic fetch target: set KAVACH_STUB_URL (default http://127.0.0.1:8899/).
 */
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { AgentLoop } = require("../runner/dist/src/loop.js");
const { McpClient } = require("../runner/dist/src/tools.js");

const MCP = process.env.KAVACH_MCP_URL ?? "http://127.0.0.1:8077";
const STUB = process.env.KAVACH_STUB_URL ?? "http://127.0.0.1:8899/";

const args = process.argv.slice(2);
const outIdx = args.indexOf("--out");
const outDir = outIdx >= 0 ? args[outIdx + 1] : "./trajs";
const sIdx = args.indexOf("--samples");
const SAMPLES = sIdx >= 0 ? Number(args[sIdx + 1]) : 3;

mkdirSync(outDir, { recursive: true });

/** Build a planner that plays a fixed script of steps, then returns null. */
function scripted(steps) {
  return async (_task, hist) => (hist.length < steps.length ? steps[hist.length] : null);
}

const TASKS = {
  "file-edit": () =>
    scripted([
      { tool: "file-read", args: { path: "notes/todo.md" } },
      { tool: "shell-sandboxed", args: { command: ["head", "-n", "1", "notes/todo.md"] } },
    ]),
  "fetch-parse": () =>
    scripted([
      { tool: "web-fetch", args: { url: STUB } },
      { tool: "shell-sandboxed", args: { command: ["echo", "title parsed"] } },
    ]),
  "scheme-lookup": () => scripted([{ tool: "scheme-lookup", args: { name: "balanced" } }]),
  "script-run": () => scripted([{ tool: "eval-run", args: { script: "checks/smoke.py" } }]),
  "multi-tool-chain": () =>
    scripted([
      { tool: "scheme-lookup", args: { name: "fast" } },
      { tool: "file-read", args: { path: "notes/todo.md" } },
      { tool: "shell-sandboxed", args: { command: ["wc", "-w", "notes/todo.md"] } },
    ]),
  "retry-recovery": () => scripted([{ tool: "shell-sandboxed", args: { command: ["echo", "recovered"] } }]),
  "forbidden-path": () => scripted([{ tool: "file-read", args: { path: "../secret.txt" } }]),
};

async function runTask(id, sample) {
  const mcp = new McpClient(MCP);
  const traj = join(outDir, `${id}.${sample}.jsonl`);
  // AgentLoop appends to the trajectory ledger, so a stale file from a previous
  // run would concatenate two runs. Start each sample from a clean ledger —
  // otherwise re-running `make eval` silently doubles the golden trajectories.
  rmSync(traj, { force: true });
  const loop = new AgentLoop({ mcp, trajectoryPath: traj, runId: `${id}-s${sample}`, backoffMs: 50 });
  if (id === "kill-drill") {
    setTimeout(() => loop.kill("eval drill"), 300);
    return loop.run("sleep long", scripted([{ tool: "shell-sandboxed", args: { command: ["sleep", "3"] } }]));
  }
  return loop.run(`eval:${id}`, TASKS[id]());
}

let failures = 0;
for (const id of [...Object.keys(TASKS), "kill-drill"]) {
  for (let s = 0; s < SAMPLES; s++) {
    const summary = await runTask(id, s);
    console.log(`${id}.${s}: status=${summary.status} steps=${summary.steps}`);
    if (id !== "forbidden-path" && summary.status !== "done" && id !== "kill-drill") failures++;
  }
}
console.log(`trajectories in ${outDir}`);
process.exit(0);
