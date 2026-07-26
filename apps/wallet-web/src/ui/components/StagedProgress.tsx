// The staged proving indicator for Send/Withdraw AND Deposit. Shows three coarse stages
// with the current one active and prior ones done, plus an HONEST elapsed-seconds clock
// during the proof. Copy per the brief: never promise sub-5s — proving on-device is
// typically 5–20 s and we say exactly that. The stages default to the spend flow's
// (assemble → prove → submit); the Deposit screen passes its own (approve → prove →
// submit). Every flow keys its proving stage "prove" and its submit stage "submit", so
// the elapsed-clock and confirm notes below stay stage-key driven and flow-agnostic.

import type { ReactNode } from "react";
import { IconCheck } from "./icons.js";

export interface StagedStep {
  key: string;
  label: string;
}

const SPEND_STEPS: StagedStep[] = [
  { key: "assemble", label: "Assembling" },
  { key: "prove", label: "Proving" },
  { key: "submit", label: "Submitting" },
];

export function StagedProgress({
  stage,
  elapsed,
  steps = SPEND_STEPS,
}: {
  stage: string;
  elapsed: number;
  steps?: StagedStep[];
}): ReactNode {
  const active = steps.findIndex((s) => s.key === stage);
  return (
    <div className="staged" role="status" aria-live="polite">
      <ol className="staged-steps">
        {steps.map((s, i) => {
          const cls = i < active ? "done" : i === active ? "active" : "pending";
          return (
            <li key={s.key} className={`staged-step staged-${cls}`}>
              {/* Remix check, not a checkmark character — glyph chars stay banned. */}
              <span className="staged-bullet">{i < active ? <IconCheck size={12} /> : i + 1}</span>
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
