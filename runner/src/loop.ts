/**
 * AgentLoop: plan -> tool -> observe, with retry x3 + exponential backoff.
 *
 * Every phase transition is appended to a trajectory JSONL file so a run can
 * be replayed offline (see replay.ts) and scored (see eval/passk.py).
 */

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { AgentError, AgentErrorJson } from "./errors";
import { ToolCaller } from "./tools";

export interface PlanStep {
  tool: string;
  args: Record<string, unknown>;
  rationale?: string;
}

/** Return the next step, or null when the task is complete. */
export type Planner = (task: string, history: Observation[]) => Promise<PlanStep | null>;

export interface Observation {
  step: number;
  tool: string;
  ok: boolean;
  output?: unknown;
  error?: AgentErrorJson;
  latencyMs: number;
  attempt: number;
}

export interface LoopOptions {
  mcp: ToolCaller;
  runId?: string;
  trajectoryPath?: string;
  maxSteps?: number;
  maxRetries?: number;
  backoffMs?: number;
  costBudgetUsd?: number;
}

export interface RunSummary {
  runId: string;
  status: "done" | "failed" | "killed";
  steps: number;
  observations: Observation[];
  totalLatencyMs: number;
}

export interface TrajectoryEvent {
  seq: number;
  ts: string;
  runId: string;
  phase: "plan" | "tool" | "observe" | "done" | "killed";
  step?: number;
  tool?: string;
  args?: Record<string, unknown>;
  observation?: Observation;
  status?: string;
  reason?: string;
}

const DEFAULT_ID = () => `run-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e6).toString(36)}`;

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class AgentLoop {
  private killed = false;
  private killReason = "";
  private seq = 0;
  readonly runId: string;

  constructor(private readonly opts: LoopOptions) {
    this.runId = opts.trajectoryPath ? (opts.runId ?? DEFAULT_ID()) : (opts.runId ?? DEFAULT_ID());
    if (opts.trajectoryPath) {
      mkdirSync(dirname(opts.trajectoryPath), { recursive: true });
    }
  }

  kill(reason = "manual"): void {
    this.killed = true;
    this.killReason = reason;
  }

  get isKilled(): boolean {
    return this.killed;
  }

  backoffFor(attempt: number): number {
    return (this.opts.backoffMs ?? 500) * 2 ** (attempt - 1);
  }

  private emit(ev: Omit<TrajectoryEvent, "seq" | "ts" | "runId">): void {
    const full: TrajectoryEvent = {
      seq: ++this.seq,
      ts: new Date().toISOString(),
      runId: this.runId,
      ...ev,
    };
    if (this.opts.trajectoryPath) {
      appendFileSync(this.opts.trajectoryPath, JSON.stringify(full) + "\n", "utf-8");
    }
  }

  /** Single tool call with retry x3 (configurable) + exponential backoff. */
  async callToolWithRetry(tool: string, args: Record<string, unknown>, step: number): Promise<Observation> {
    const maxRetries = this.opts.maxRetries ?? 3;
    const started = Date.now();
    let lastError: AgentErrorJson | undefined;
    for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
      if (this.killed) {
        const err = AgentError.killed(tool).toJSON();
        const obs: Observation = { step, tool, ok: false, error: err, latencyMs: Date.now() - started, attempt };
        this.emit({ phase: "observe", step, tool, observation: obs });
        return obs;
      }
      this.emit({ phase: "tool", step, tool, args });
      try {
        const output = await this.opts.mcp.call(tool, args);
        const obs: Observation = { step, tool, ok: true, output, latencyMs: Date.now() - started, attempt };
        this.emit({ phase: "observe", step, tool, observation: obs });
        return obs;
      } catch (err) {
        const agentErr = err instanceof AgentError ? err : new AgentError("TOOL_ERROR", String(err), { tool });
        agentErr.attempt = attempt;
        lastError = agentErr.toJSON();
        if (!agentErr.retryable || attempt > maxRetries) break;
        await sleep(this.backoffFor(attempt));
      }
    }
    const obs: Observation = {
      step,
      tool,
      ok: false,
      error: lastError,
      latencyMs: Date.now() - started,
      attempt: maxRetries + 1,
    };
    this.emit({ phase: "observe", step, tool, observation: obs });
    return obs;
  }

  /** Full plan -> tool -> observe loop until the planner returns null. */
  async run(task: string, planner: Planner): Promise<RunSummary> {
    const maxSteps = this.opts.maxSteps ?? 12;
    const observations: Observation[] = [];
    let status: RunSummary["status"] = "done";

    for (let step = 1; step <= maxSteps; step++) {
      if (this.killed) {
        status = "killed";
        this.emit({ phase: "killed", reason: this.killReason || "manual" });
        break;
      }
      const plan = await planner(task, observations);
      if (plan === null) break;
      this.emit({ phase: "plan", step, tool: plan.tool, args: plan.args });
      const obs = await this.callToolWithRetry(plan.tool, plan.args, step);
      observations.push(obs);
      if (this.killed) {
        status = "killed";
        this.emit({ phase: "killed", reason: this.killReason || "manual" });
        break;
      }
      if (!obs.ok && obs.error && !obs.error.retryable) {
        status = "failed";
        break;
      }
    }

    if (status === "done" && observations.length >= maxSteps) {
      status = "failed";
      this.emit({ phase: "done", status, reason: "max_steps_exhausted" });
    } else {
      this.emit({ phase: "done", status });
    }
    return {
      runId: this.runId,
      status,
      steps: observations.length,
      observations,
      totalLatencyMs: observations.reduce((a, o) => a + o.latencyMs, 0),
    };
  }
}
