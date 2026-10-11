/** KILL button: per-run kill + global kill-switch engage/release. */

import { useState } from "react";
import { api } from "../api";

export default function KillButton({ runId, onAction }: { runId: string; onAction: (msg: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [engaged, setEngaged] = useState(false);

  async function act(fn: () => Promise<unknown>, label: string): Promise<void> {
    setBusy(true);
    try {
      await fn();
      onAction(`${label}: ok`);
    } catch (e) {
      onAction(`${label}: ${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h2>Kill-switch</h2>
      <button
        disabled={busy || !runId}
        onClick={() => act(() => api.killRun(runId), `kill run ${runId.slice(0, 8)}`)}
        style={{ background: "#c00", color: "#fff", padding: "8px 16px", marginRight: 8 }}
      >
        KILL run
      </button>
      <button
        disabled={busy}
        onClick={() =>
          act(async () => {
            const r = await api.killSwitch(!engaged, "dashboard toggle");
            setEngaged(r.engaged);
          }, engaged ? "kill-switch released" : "kill-switch ENGAGED")
        }
        style={{ padding: "8px 16px" }}
      >
        {engaged ? "Release kill-switch" : "Engage kill-switch"}
      </button>
    </section>
  );
}
