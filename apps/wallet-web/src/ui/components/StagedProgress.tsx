// The staged proving indicator for Send/Withdraw. Shows the three coarse stages
// (assemble → prove → submit) with the current one active and prior ones done, plus
// an HONEST elapsed-seconds clock during the proof. Copy per the brief: never promise
// sub-5s — proving on-device is typically 5–20 s and we say exactly that.

import type { ReactNode } from "react";
import type { SpendStage } from "../../lib/spendFlow.js";

const STAGES: { key: SpendStage; label: string }[] = [
  { key: "assemble", label: "Assembling" },
  { key: "prove", label: "Proving" },
  { key: "submit", label: "Submitting" },
];

function rank(stage: SpendStage): number {
  return STAGES.findIndex((s) => s.key === stage);
}

export function StagedProgress({
  stage,
  elapsed,
}: {
  stage: SpendStage;
  elapsed: number;
}): ReactNode {
  const active = rank(stage);
  return (
    <div className="staged" role="status" aria-live="polite">
      <ol className="staged-steps">
        {STAGES.map((s, i) => {
          const cls = i < active ? "done" : i === active ? "active" : "pending";
          return (
            <li key={s.key} className={`staged-step staged-${cls}`}>
              <span className="staged-bullet">{i < active ? "✓" : i + 1}</span>
              {s.label}
            </li>
          );
        })}
      </ol>
      {stage === "prove" && (
        <p className="staged-note">
          Generating ZK proof on your device… typically 5–20 seconds
          <span className="staged-timer"> · {elapsed}s</span>
        </p>
      )}
      {stage === "submit" && <p className="staged-note">Waiting for the transaction to confirm…</p>}
    </div>
  );
}
