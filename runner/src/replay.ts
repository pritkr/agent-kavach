/** Offline trajectory replay: load JSONL, summarise, verify expectations. */

import { readFileSync } from "node:fs";
import { TrajectoryEvent } from "./loop";

export interface TrajectorySummary {
  runId: string;
  events: number;
  steps: number;
  toolCalls: number;
  errors: number;
  killed: boolean;
  status: string;
  toolsUsed: string[];
  totalLatencyMs: number;
}

export interface VerifyExpectation {
  toolsInOrder?: string[];
  mustSucceed?: boolean;
  maxErrors?: number;
}

export function loadTrajectory(path: string): TrajectoryEvent[] {
  const raw = readFileSync(path, "utf-8");
  const events: TrajectoryEvent[] = [];
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    events.push(JSON.parse(t) as TrajectoryEvent);
  }
  return events;
}

export function summarizeTrajectory(events: TrajectoryEvent[]): TrajectorySummary {
  const toolsUsed: string[] = [];
  let steps = 0;
  let errors = 0;
  let killed = false;
  let status = "unknown";
  let totalLatencyMs = 0;
  let runId = "";
  for (const ev of events) {
    runId = ev.runId;
    if (ev.phase === "plan") steps = Math.max(steps, ev.step ?? steps);
    if (ev.phase === "tool" && ev.tool && !toolsUsed.includes(ev.tool)) toolsUsed.push(ev.tool);
    if (ev.phase === "observe" && ev.observation) {
      totalLatencyMs += ev.observation.latencyMs;
      if (!ev.observation.ok) errors++;
    }
    if (ev.phase === "killed") killed = true;
    if (ev.phase === "done" && ev.status) status = ev.status;
  }
  return {
    runId,
    events: events.length,
    steps,
    toolCalls: events.filter((e) => e.phase === "tool").length,
    errors,
    killed,
    status,
    toolsUsed,
    totalLatencyMs,
  };
}

export function verifyTrajectory(
  events: TrajectoryEvent[],
  expected: VerifyExpectation,
): { ok: boolean; failures: string[] } {
  const failures: string[] = [];
  const summary = summarizeTrajectory(events);
  if (expected.mustSucceed && summary.status !== "done") {
    failures.push(`status=${summary.status}, want done`);
  }
  if (expected.maxErrors !== undefined && summary.errors > expected.maxErrors) {
    failures.push(`errors=${summary.errors} > maxErrors=${expected.maxErrors}`);
  }
  if (expected.toolsInOrder) {
    const calls = events.filter((e) => e.phase === "tool").map((e) => e.tool ?? "");
    let cursor = 0;
    for (const want of expected.toolsInOrder) {
      const idx = calls.indexOf(want, cursor);
      if (idx === -1) {
        failures.push(`missing tool ${want} after position ${cursor} in [${calls.join(", ")}]`);
        break;
      }
      cursor = idx + 1;
    }
  }
  return { ok: failures.length === 0, failures };
}

/** Human-readable one-line-per-event replay (used by the CLI + web replay view). */
export function formatReplay(events: TrajectoryEvent[]): string[] {
  return events.map((ev) => {
    switch (ev.phase) {
      case "plan":
        return `#${ev.seq} [plan] step=${ev.step} tool=${ev.tool} args=${JSON.stringify(ev.args)}`;
      case "tool":
        return `#${ev.seq} [tool] step=${ev.step} ${ev.tool}`;
      case "observe": {
        const o = ev.observation;
        const body = o?.ok ? `ok latency=${o.latencyMs}ms` : `ERROR ${o?.error?.code}: ${o?.error?.message}`;
        return `#${ev.seq} [observe] step=${ev.step} ${o?.tool} ${body}`;
      }
      case "killed":
        return `#${ev.seq} [killed] reason=${ev.reason}`;
      case "done":
        return `#${ev.seq} [done] status=${ev.status}${ev.reason ? ` reason=${ev.reason}` : ""}`;
      default:
        return `#${ev.seq} [${ev.phase}]`;
    }
  });
}
