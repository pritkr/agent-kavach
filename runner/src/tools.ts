/** Minimal MCP client: POST {baseUrl}/tools/call, map envelopes to AgentError. */

import { AgentError, ErrorCode } from "./errors";

export interface ToolCaller {
  call(tool: string, args: Record<string, unknown>): Promise<unknown>;
}

interface McpEnvelope {
  ok: boolean;
  tool: string;
  result?: unknown;
  error?: { code?: string; message?: string };
  latency_ms?: number;
}

function mapErrorCode(mcpCode: string | undefined, message: string): { code: ErrorCode; retryable: boolean } {
  switch (mcpCode) {
    case "timeout":
      return { code: "TIMEOUT", retryable: true };
    case "fetch_error":
      return { code: "TOOL_ERROR", retryable: true };
    case "invalid_args":
    case "unknown_tool":
    case "path_outside_workspace":
    case "host_not_allowlisted":
    case "not_found":
      return { code: "INVALID_ARGS", retryable: false };
    default:
      return { code: "TOOL_ERROR", retryable: message.includes("timeout") };
  }
}

export class McpClient implements ToolCaller {
  constructor(
    private readonly baseUrl: string,
    private readonly timeoutMs = 35_000,
  ) {}

  async call(tool: string, args: Record<string, unknown>): Promise<unknown> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}/tools/call`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tool, args }),
        signal: ctrl.signal,
      });
    } catch (err) {
      clearTimeout(timer);
      if ((err as Error).name === "AbortError") {
        throw new AgentError("TIMEOUT", `mcp call to ${tool} timed out after ${this.timeoutMs}ms`, {
          retryable: true,
          tool,
        });
      }
      throw new AgentError("TRANSPORT", `mcp transport error: ${(err as Error).message}`, {
        retryable: true,
        tool,
      });
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) {
      throw new AgentError("TRANSPORT", `mcp http ${res.status} for ${tool}`, { retryable: res.status >= 500, tool });
    }
    const env = (await res.json()) as McpEnvelope;
    if (!env.ok) {
      const mapped = mapErrorCode(env.error?.code, env.error?.message ?? "tool failed");
      throw new AgentError(mapped.code, env.error?.message ?? "tool failed", {
        retryable: mapped.retryable,
        tool,
      });
    }
    return env.result;
  }

  async listTools(): Promise<unknown> {
    const res = await fetch(`${this.baseUrl}/tools/list`);
    if (!res.ok) throw new AgentError("TRANSPORT", `mcp http ${res.status} for tools/list`, { retryable: true });
    return res.json();
  }
}
