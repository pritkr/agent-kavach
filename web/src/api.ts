/** API client for the agent-kavach daemon (via TCP bridge — see README). */

export const API_BASE: string =
  (import.meta as unknown as { env?: Record<string, string> }).env?.VITE_KAVACH_API ?? "http://127.0.0.1:8080";

export interface Run {
  id: string;
  command: string[];
  status: string;
  exit_code: number;
  output?: string;
  cost_usd: number;
  duration_ms: number;
  sandbox: string;
}

export interface DaemonEvent {
  type: string;
  run_id?: string;
  data?: unknown;
  at: string;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, init);
  if (!res.ok) throw new Error(`api ${res.status} on ${path}`);
  return (await res.json()) as T;
}

export const api = {
  health: () => req<{ ok: boolean; docker: boolean; killswitch: boolean }>("/healthz"),
  runs: () => req<{ runs: Run[] }>("/v1/runs"),
  run: (id: string) => req<Run>(`/v1/runs/${id}`),
  killRun: (id: string) =>
    req<{ killed: boolean }>(`/v1/runs/${id}/kill`, { method: "POST" }),
  killSwitch: (engaged: boolean, reason = "dashboard") =>
    req<{ engaged: boolean }>(`/v1/killswitch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ engaged, reason }),
    }),
  audit: () => req<{ entries: Record<string, unknown>[]; count: number }>(`/v1/audit`),
};

export function eventsUrl(runId?: string): string {
  return `${API_BASE}/v1/events${runId ? `?run_id=${encodeURIComponent(runId)}` : ""}`;
}
