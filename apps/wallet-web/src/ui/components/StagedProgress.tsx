// The staged proving indicator for Send/Withdraw AND Deposit. Three coarse steps on a
// vertical progress rail: done steps fill the rail and pop a check, the active step
// spins a ring around its bullet and opens a one-line plain-words explanation under
// itself (the explanation FOLLOWS the active step rather than sitting below the list —
// grill decision 2026-07-28), pending steps wait muted. Copy never promises sub-5s:
// proving on-device is typically 5–20 s and the prove line says exactly that. Every
// flow keys its proving stage "prove" and its submit stage "submit", so the elapsed
// clock and per-step lines stay stage-key driven and flow-agnostic.

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

/** One plain-words line per stage, shown under the ACTIVE step only. The unlock line
 *  names the connected wallet; the prove line carries the honest elapsed clock. */
function stepDescription(key: string, walletName: string, elapsed: number): ReactNode {
  switch (key) {
    case "unlock":
      return <>Confirm once in {walletName} to open your wallet.</>;
    case "assemble":
      return <>Getting your money ready to send.</>;
    case "approve":
      return <>Letting the pool take exactly this amount.</>;
    case "prove":
      return (
        <>
          Creating your privacy proof on this device. Usually 5 to 20 seconds
          <span className="text-primary tabular-nums"> · {elapsed}s</span>
        </>
      );
    case "submit":
      return <>Sending to the network and waiting for it to confirm.</>;
    default:
      return null;
  }
}

const STEP_STATE = {
  done: "text-ink",
  active: "text-ink font-semibold",
  pending: "text-muted",
} as const;
const BULLET_STATE = {
  done: "bg-pos border-pos text-white",
  active: "bg-surface border-primary text-primary",
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
    <div className="flex flex-col py-1.5" role="status" aria-live="polite">
      <ol className="list-none flex flex-col">
        {steps.map((s, i) => {
          const cls = i < active ? "done" : i === active ? "active" : "pending";
          return (
            <li key={s.key} className="flex flex-col">
              {/* Rail segment ABOVE this bullet (none before the first): fills green
                  the moment the step above completes, so progress pours downward. */}
              {i > 0 && (
                <span
                  aria-hidden="true"
                  className={`ml-[12px] h-3.5 w-0.5 rounded-full transition-colors duration-300 ${
                    i <= active ? "bg-pos" : "bg-border"
                  }`}
                />
              )}
              <div className={`flex items-center gap-3 text-[0.95rem] ${STEP_STATE[cls]}`}>
                <span className="relative w-6.5 h-6.5 flex-none">
                  <span
                    className={`absolute inset-0 rounded-full grid place-items-center text-[0.82rem] border ${BULLET_STATE[cls]}`}
                  >
                    {/* Remix check, not a checkmark character — glyph chars stay banned. */}
                    {i < active ? (
                      <span className="animate-check-pop inline-flex">
                        <IconCheck size={12} />
                      </span>
                    ) : (
                      i + 1
                    )}
                  </span>
                  {/* The working ring: only the active bullet spins it. */}
                  {cls === "active" && (
                    <span
                      aria-hidden="true"
                      className="absolute -inset-[3px] rounded-full border-2 border-transparent border-t-primary animate-spin"
                    />
                  )}
                </span>
                {s.label}
              </div>
              {/* The explanation follows the active step (grill: active-only). The li
                  remounts nothing; the p appears only on the active row, so desc-in
                  replays as progress moves down. */}
              {cls === "active" && (
                <p className="animate-desc-in ml-[38px] mt-1 text-sm text-muted">
                  {stepDescription(s.key, walletName, elapsed)}
                </p>
              )}
            </li>
          );
        })}
      </ol>
    </div>
  );
}
