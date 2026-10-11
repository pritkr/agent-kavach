import { useCallback, useEffect, useState } from "react";
import { api, Run } from "./api";
import StreamView from "./components/StreamView";
import CostChart from "./components/CostChart";
import KillButton from "./components/KillButton";
import ReplayView from "./components/ReplayView";

export default function App() {
  const [runs, setRuns] = useState<Run[]>([]);
  const [selected, setSelected] = useState("");
  const [notice, setNotice] = useState("");
  const [health, setHealth] = useState("unknown");

  const refresh = useCallback(async () => {
    try {
      const [h, r] = await Promise.all([api.health(), api.runs()]);
      setHealth(`ok (docker=${h.docker ? "yes" : "no"}, killswitch=${h.killswitch ? "ENGAGED" : "off"})`);
      setRuns(r.runs);
      if (!selected && r.runs.length) setSelected(r.runs[0].id);
    } catch (e) {
      setHealth(`unreachable: ${(e as Error).message}`);
    }
  }, [selected]);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, [refresh]);

  return (
    <main style={{ fontFamily: "system-ui", maxWidth: 900, margin: "0 auto", padding: 16 }}>
      <h1>agent-kavach</h1>
      <p>daemon: {health}</p>
      {notice && <p style={{ background: "#ffe", padding: 8 }}>{notice}</p>}
      <section>
        <h2>Runs</h2>
        <button onClick={refresh}>Refresh</button>
        <ul>
          {runs.map((r) => (
            <li key={r.id}>
              <button
                onClick={() => setSelected(r.id)}
                style={{ fontWeight: r.id === selected ? "bold" : "normal" }}
              >
                {r.id.slice(0, 8)}
              </button>{" "}
              {r.status} {(r.command ?? []).join(" ")} ${Number(r.cost_usd ?? 0).toFixed(4)} {r.duration_ms ?? 0}ms [
              {r.sandbox}]
            </li>
          ))}
        </ul>
      </section>
      <KillButton runId={selected} onAction={setNotice} />
      <StreamView runId={selected} />
      <CostChart runs={runs} />
      <ReplayView />
    </main>
  );
}
