/** CLI: replay a trajectory JSONL file to stdout. Usage: node dist/scripts/replay.js <traj.jsonl> */

import { formatReplay, loadTrajectory, summarizeTrajectory } from "../src/replay";

const [path] = process.argv.slice(2);
if (!path) {
  console.error("usage: replay <trajectory.jsonl>");
  process.exit(2);
}
const events = loadTrajectory(path);
for (const line of formatReplay(events)) console.log(line);
const s = summarizeTrajectory(events);
console.log(
  `-- summary: status=${s.status} steps=${s.steps} toolCalls=${s.toolCalls} errors=${s.errors} killed=${s.killed} latency=${s.totalLatencyMs}ms tools=[${s.toolsUsed.join(",")}]`,
);
