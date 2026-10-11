/** Cost / latency SVG chart over the run ledger. */

import { Run } from "../api";

function bars(values: number[], w: number, h: number, color: string): JSX.Element[] {
  const max = Math.max(1, ...values);
  const bw = w / Math.max(1, values.length);
  return values.map((v, i) => {
    const bh = Math.max(2, (v / max) * (h - 20));
    return (
      <g key={i}>
        <rect x={i * bw + 2} y={h - bh} width={Math.max(1, bw - 4)} height={bh} fill={color} />
        <title>{v.toFixed(4)}</title>
      </g>
    );
  });
}

export default function CostChart({ runs }: { runs: Run[] }) {
  const W = 520;
  const H = 140;
  const costs = runs.map((r) => r.cost_usd ?? 0);
  const lats = runs.map((r) => r.duration_ms ?? 0);
  const totalCost = costs.reduce((a, b) => a + b, 0);
  const p95 = lats.length ? [...lats].sort((a, b) => a - b)[Math.min(lats.length - 1, Math.floor(lats.length * 0.95))] : 0;
  return (
    <section>
      <h2>Cost / latency</h2>
      <p>
        runs={runs.length} total_cost=${totalCost.toFixed(6)} p95_latency={p95}ms
      </p>
      <h3>cost USD per run</h3>
      <svg width={W} height={H} style={{ border: "1px solid #ccc" }}>
        {bars(costs, W, H, "#4f81bd")}
      </svg>
      <h3>duration ms per run</h3>
      <svg width={W} height={H} style={{ border: "1px solid #ccc" }}>
        {bars(lats, W, H, "#c0504d")}
      </svg>
      {runs.length === 0 && <p style={{ color: "#666" }}>no runs yet — submit one via the daemon or runner.</p>}
    </section>
  );
}
