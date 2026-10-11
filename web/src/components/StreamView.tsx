/** Live SSE stream of daemon events. */

import { useEffect, useRef, useState } from "react";
import { eventsUrl, DaemonEvent } from "../api";

export default function StreamView({ runId }: { runId: string }) {
  const [events, setEvents] = useState<DaemonEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState("");
  const boxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setEvents([]);
    setError("");
    const src = new EventSource(eventsUrl(runId || undefined));
    src.onopen = () => setConnected(true);
    src.onerror = () => {
      setConnected(false);
      setError("event stream unreachable — is the TCP bridge up? (see README)");
      src.close();
    };
    const push = (e: MessageEvent) => {
      try {
        const ev = JSON.parse(e.data) as DaemonEvent;
        setEvents((prev) => [...prev.slice(-199), { ...ev, type: e.type || ev.type }]);
      } catch {
        /* keep-alive comment, ignore */
      }
    };
    ["run.queued", "run.started", "run.log", "run.finished", "run.killed", "killswitch"].forEach((t) =>
      src.addEventListener(t, push as EventListener),
    );
    src.onmessage = push;
    return () => src.close();
  }, [runId]);

  useEffect(() => {
    boxRef.current?.scrollTo({ top: boxRef.current.scrollHeight });
  }, [events]);

  return (
    <section>
      <h2>
        Live stream{" "}
        <span style={{ color: connected ? "green" : "red" }}>{connected ? "● connected" : "○ disconnected"}</span>
      </h2>
      {error && <p style={{ color: "red" }}>{error}</p>}
      <div
        ref={boxRef}
        style={{ height: 220, overflowY: "auto", background: "#111", color: "#0f0", padding: 8, fontFamily: "monospace", fontSize: 12 }}
      >
        {events.length === 0 && <div style={{ color: "#666" }}>waiting for events…</div>}
        {events.map((e, i) => (
          <div key={i}>
            [{e.at}] <b>{e.type}</b> {e.run_id?.slice(0, 8) ?? ""} {JSON.stringify(e.data ?? {})}
          </div>
        ))}
      </div>
    </section>
  );
}
