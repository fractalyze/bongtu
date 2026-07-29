// The deposit dialog. Same overlay pattern as the console's other dialogs
// (ConfirmSend/ProgressRail/DoneScreen): a fixed backdrop over the whole console,
// one card, no routing.
//
// Presentational only — every decision it renders comes from lib/depositModal.ts
// (depositModalView), and the console owns the two async handlers. The balance it
// shows is the account's PUBLIC ERC-20 kKRW, deliberately NOT the shielded pool
// balance the session card already shows: this dialog is about what there is left
// to shield.
//
// While a deposit runs the dialog cannot be closed — it is driving wallet popups —
// and its WHOLE body becomes the staged progress view (approve → prove → submit,
// the wallet grammar), never just a relabeled button.

import type { ReactNode } from "react";
import { formatKkrw, groupAmountInput } from "@bongtu/client/money";
import { DEFAULTS } from "../config.js";
import { DEPOSIT_STAGE_LABEL, depositModalView, type DepositModalState } from "../lib/depositModal.js";
import { Button, Spinner } from "./controls.js";
import type { DepositStage } from "@bongtu/client/depositFlow";

export function DepositModal({
  state,
  onAmountChange,
  onClose,
  onDeposit,
  onMint,
}: {
  state: DepositModalState;
  onAmountChange: (amount: string) => void;
  onClose: () => void;
  onDeposit: () => void;
  onMint: () => void;
}): ReactNode {
  const view = depositModalView(state);
  return (
    <div className="fixed inset-0 z-20 bg-backdrop flex items-center justify-center p-6">
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Deposit"
        className="w-full max-w-[420px] bg-surface border border-border rounded-2xl p-6 flex flex-col gap-4"
      >
        <div className="text-[15px] font-semibold">Deposit</div>
        {state.stage !== null ? (
          /* the run in flight: the whole dialog becomes the staged progress view
             (the wallet grammar) — never just a relabeled button */
          <DepositProgress stage={state.stage} />
        ) : (
          <>
        <div className="text-[12.5px] text-muted">
          Converts public kKRW into private pool balance. Up to two wallet confirmations: the
          approval (when needed) and the deposit.
        </div>

        <div className="flex items-baseline justify-between gap-3 border border-border rounded-xl px-3.5 py-3">
          <span className="text-[12px] text-muted">In your wallet</span>
          <span className="text-[15px] font-semibold tabular-nums" aria-live="polite">
            {/* an unread balance is a dash — never a false zero, which would push
                a mint the operator does not need */}
            {state.tokenBalance === null ? "—" : formatKkrw(state.tokenBalance)} kKRW
          </span>
        </div>

        <label className="flex flex-col gap-1">
          <span className="flex items-baseline justify-between gap-3">
            <span className="text-[12px] text-muted">Amount</span>
            {/* the mint rides the label row as a link — a side path off the
                deposit, never a second headline button */}
            <button
              type="button"
              disabled={!view.canMint}
              onClick={onMint}
              className="text-[12px] font-medium text-primary hover:underline cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {state.minting ? "Minting…" : `No kKRW? ${view.mintLabel}`}
            </button>
          </span>
          {/* same scale as the balance box above, ticker inside the field */}
          <span
            className={`flex items-baseline gap-2 border rounded-xl px-3.5 py-3 bg-surface focus-within:border-border-strong ${
              view.amountError !== null ? "border-err" : "border-border"
            }`}
          >
            <input
              type="text"
              aria-label="Deposit amount (kKRW)"
              className="flex-1 min-w-0 bg-transparent outline-none text-[15px] text-right tabular-nums"
              value={state.amount}
              placeholder="0"
              onChange={(e) => onAmountChange(groupAmountInput(e.target.value))}
            />
            <span className="text-[13px] text-muted">kKRW</span>
          </span>
        </label>
        {view.amountError && <div className="text-[12.5px] text-err">{view.amountError}</div>}

        {view.notice && (
          <div className="rounded-xl border border-warn-border bg-warn-bg text-warn px-3.5 py-3 text-[12.5px] flex flex-col gap-1.5">
            <span>{view.notice}</span>
            <a
              className="font-semibold underline self-start"
              href={DEFAULTS.gasFaucet}
              target="_blank"
              rel="noreferrer"
            >
              Get GIWA Sepolia ETH from the faucet
            </a>
          </div>
        )}
        {state.error && <div className="text-[12.5px] text-err">{state.error}</div>}

        <div className="flex gap-2 justify-end items-center">
          <Button variant="ghost" disabled={view.busy} onClick={onClose}>
            Close
          </Button>
          <Button disabled={!view.canDeposit} onClick={onDeposit}>
            Deposit
          </Button>
        </div>
          </>
        )}

      </div>
    </div>
  );
}

/** The deposit run as the wallet-style staged checklist: approve → prove →
 *  submit, with unlock as a transient first row while it happens. */
const DEPOSIT_STAGE_ORDER: DepositStage[] = ["approve", "prove", "submit"];
function DepositProgress({ stage }: { stage: DepositStage }): ReactNode {
  const activeAt = stage === "unlock" ? -1 : DEPOSIT_STAGE_ORDER.indexOf(stage);
  return (
    <div className="flex flex-col gap-3 py-2">
      <ol className="flex flex-col gap-2.5">
        {stage === "unlock" && (
          <li className="flex items-center gap-2.5 text-[13.5px] font-medium">
            <span className="w-5 h-5 rounded-full bg-primary text-primary-ink flex items-center justify-center animate-pulse-soft">
              <Spinner />
            </span>
            {DEPOSIT_STAGE_LABEL.unlock}
          </li>
        )}
        {DEPOSIT_STAGE_ORDER.map((st, i) => {
          const s = i < activeAt ? "done" : i === activeAt ? "active" : "todo";
          return (
            <li
              key={st}
              className={`flex items-center gap-2.5 text-[13.5px] ${
                s === "done" ? "text-pos" : s === "active" ? "font-medium" : "text-muted"
              }`}
            >
              <span
                className={`w-5 h-5 rounded-full flex items-center justify-center text-[11px] font-semibold shrink-0 ${
                  s === "done"
                    ? "bg-pos-bg text-pos animate-check-pop"
                    : s === "active"
                      ? "bg-primary text-primary-ink animate-pulse-soft"
                      : "bg-surface-2 text-muted"
                }`}
              >
                {s === "done" ? "✓" : i + 1}
              </span>
              {DEPOSIT_STAGE_LABEL[st]}
            </li>
          );
        })}
      </ol>
      <div className="text-[12px] text-muted">Confirm the wallet prompts and keep this window open.</div>
    </div>
  );
}
