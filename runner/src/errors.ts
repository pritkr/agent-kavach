/** Structured errors for the agent loop. Every failure carries a machine-readable code. */

export type ErrorCode =
  | "TOOL_ERROR"
  | "TIMEOUT"
  | "INVALID_ARGS"
  | "TRANSPORT"
  | "KILLED"
  | "MAX_STEPS"
  | "BUDGET_EXCEEDED";

export interface AgentErrorJson {
  code: ErrorCode;
  message: string;
  retryable: boolean;
  tool?: string;
  attempt?: number;
}

const RETRYABLE_CODES: ReadonlySet<ErrorCode> = new Set([
  "TOOL_ERROR",
  "TIMEOUT",
  "TRANSPORT",
]);

export class AgentError extends Error {
  readonly code: ErrorCode;
  readonly retryable: boolean;
  readonly tool?: string;
  attempt?: number;

  constructor(code: ErrorCode, message: string, opts: { retryable?: boolean; tool?: string; attempt?: number } = {}) {
    super(message);
    this.name = "AgentError";
    this.code = code;
    this.retryable = opts.retryable ?? RETRYABLE_CODES.has(code);
    this.tool = opts.tool;
    this.attempt = opts.attempt;
  }

  toJSON(): AgentErrorJson {
    return {
      code: this.code,
      message: this.message,
      retryable: this.retryable,
      ...(this.tool !== undefined ? { tool: this.tool } : {}),
      ...(this.attempt !== undefined ? { attempt: this.attempt } : {}),
    };
  }

  static killed(tool?: string): AgentError {
    return new AgentError("KILLED", "run killed by kill-switch", { retryable: false, tool });
  }
}
