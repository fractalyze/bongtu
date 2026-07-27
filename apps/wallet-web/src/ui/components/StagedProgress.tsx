// The staged proving indicator for Send/Withdraw AND Deposit. Shows three coarse stages
// with the current one active and prior ones done, plus an HONEST elapsed-seconds clock
// during the proof. Copy per the brief: never promise sub-5s — proving on-device is
// typically 5–20 s and we say exactly that. The stages default to the spend flow's
// (assemble → prove → submit); the Deposit screen passes its own (approve → prove →
// submit). Every flow keys its proving stage "prove" and its submit stage "submit", so
// the elapsed-clock and confirm notes below stay stage-key driven and flow-agnostic.

import type { ReactNode } from "react";
import { NEUTRAL_WALLET_NAME } from "../../lib/walletBrand.js";
import { IconCheck } from "./icons.js";

export interface StagedStep {
  key: string;
  label: string;
}

export const SPEND_STEPS: StagedStep[] = [
  { key: "assemble", label: "Assembling" },
  { key: "prove", label: "Proving" },
  { key: "submit", label: "Submitting" },
];

/** Deposit has no membership to assemble; the exact-V ERC-20 approve replaces the
 *  spend's assemble stage (and is skipped when the allowance already covers V). */
export const DEPOSIT_STEPS: StagedStep[] = [
  { key: "approve", label: "Approving" },
  { key: "prove", label: "Proving" },
  { key: "submit", label: "Submitting" },
];

/** The same steps with the wallet-unlock signature in front. Screens switch to this
 *  only when a flow actually reports the "unlock" stage — a run that reuses the key
 *  already held never shows a step the user isn't asked to do. */
export function withUnlock(steps: StagedStep[]): StagedStep[] {
  return [{ key: "unlock", label: "Unlocking" }, ...steps];
}

const STEP_STATE = {
  done: "text-ink",
  active: "text-ink font-semibold",
  pending: "text-muted",
} as const;
const BULLET_STATE = {
  done: "bg-pos border-pos text-white",
  active: "bg-surface border-primary text-primary animate-pulse-soft",
  pending: "bg-surface border-border",
} as const;

export function StagedProgress({
  stage,
  elapsed,
  steps = SPEND_STEPS,
  walletName = NEUTRAL_WALLET_NAME,
}: {
  stage: string;
  elapsed: number;
  steps?: StagedStep[];
  /** The connected wallet's own name for the unlock line — never a hardcoded brand. */
  walletName?: string;
}): ReactNode {
  const active = steps.findIndex((s) => s.key === stage);
  return (
    <div className="flex flex-col gap-3.5 py-1.5" role="status" aria-live="polite">
      <ol className="list-none flex flex-col gap-2.5">
        {steps.map((s, i) => {
          const cls = i < active ? "done" : i === active ? "active" : "pending";
          return (
            <li
              key={s.key}
              className={`flex items-center gap-3 text-[0.95rem] ${STEP_STATE[cls]}`}
            >
              {/* Remix check, not a checkmark character — glyph chars stay banned. */}
              <span
                className={`w-6.5 h-6.5 rounded-full grid place-items-center text-[0.82rem] border flex-none ${BULLET_STATE[cls]}`}
              >
                {i < active ? <IconCheck size={12} /> : i + 1}
              </span>
              {s.label}
            </li>
          );
        })}
      </ol>
      {stage === "unlock" && (
        <p className="text-sm text-muted text-center">
          Confirm in {walletName} to unlock your wallet…
        </p>
      )}
      {stage === "prove" && (
        <p className="text-sm text-muted text-center">
          Preparing your private transaction… usually 5–20 seconds
          <span className="text-primary tabular-nums"> · {elapsed}s</span>
        </p>
      )}
      {stage === "submit" && (
        <p className="text-sm text-muted text-center">Waiting for the transaction to confirm…</p>
      )}
    </div>
  );
}
