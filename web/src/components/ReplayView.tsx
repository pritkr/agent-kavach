/** Replay view: paste trajectory JSONL (or load daemon audit) and render it. */

import { useState } from "react";
import { api } from "../api";

interface TrajEvent {
  seq?: number;
  phase?: string;
  step?: number;
  tool?: string;
  status?: string;
  reason?: string;
  observation?: { ok?: boolean; error?: { code?: string; message?: string } };
  [k: string]: unknown;
}

function renderLine(ev: TrajEvent, i: number): string {
  const n = ev.seq ?? i + 1;
  switch (ev.phase) {
    case "plan":
      return `#${n} [plan] step=${ev.step} tool=${ev.tool}`;
    case "tool":
      return `#${n} [tool] step=${ev.step} ${ev.tool}`;
    case "observe":
      return ev.observation?.ok
        ? `#${n} [observe] step=${ev.step} ${ev.tool} ok`
        : `#${n} [observe] step=${ev.step} ${ev.tool} ERROR ${ev.observation?.error?.code}: ${ev.observation?.error?.message}`;
    case "killed":
      return `#${n} [killed] reason=${ev.reason}`;
    case "done":
      return `#${n} [done] status=${ev.status}`;
    default:
      return `#${n} ${JSON.stringify(ev)}`;
  }
}

export default function ReplayView() {
  const [text, setText] = useState("");
  const [lines, setLines] = useState<string[]>([]);
  const [error, setError] = useState("");

  function parse(raw: string): void {
    setError("");
    try {
      const evs = raw
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)
        .map((l) => JSON.parse(l) as TrajEvent);
      setLines(evs.map(renderLine));
    } catch (e) {
      setError(`parse error: ${(e as Error).message}`);
      setLines([]);
    }
  }

  async function loadAudit(): Promise<void> {
    setError("");
    try {
      const { entries } = await api.audit();
      setLines(entries.map((e, i) => `#${i + 1} ${JSON.stringify(e)}`));
    } catch (e) {
      setError(`audit unreachable: ${(e as Error).message}`);
    }
  }

  return (
    <section>
      <h2>Replay</h2>
      <textarea
        rows={6}
        cols={80}
        placeholder="paste trajectory JSONL here…"
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      <div>
        <button onClick={() => parse(text)}>Render trajectory</button>{" "}
        <button onClick={loadAudit}>Load daemon audit log</button>
      </div>
      {error && <p style={{ color: "red" }}>{error}</p>}
      <pre style={{ background: "#f4f4f4", padding: 8, maxHeight: 240, overflowY: "auto" }}>
        {lines.length ? lines.join("\n") : "nothing loaded"}
      </pre>
    </section>
  );
}
