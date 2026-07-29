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
// While a deposit or mint is in flight the dialog cannot be closed — it is driving
// wallet popups, and the stage line under the button is the only place the run is
// narrated.

import type { ReactNode } from "react";
import { formatKkrw, groupAmountInput } from "@bongtu/client/money";
import { DEFAULTS } from "../config.js";
import { depositModalView, type DepositModalState } from "../lib/depositModal.js";
import { Button, CellInput, Spinner } from "./controls.js";

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
          <span className="text-[11px] text-muted">Amount (kKRW)</span>
          <CellInput
            align="right"
            ariaLabel="Deposit amount (kKRW)"
            value={state.amount}
            placeholder="0"
            invalid={view.amountError !== null}
            onChange={(v) => onAmountChange(groupAmountInput(v))}
          />
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
            {state.stage !== null && <Spinner />}
            {view.depositLabel}
          </Button>
        </div>

        {/* the mint: a side path off the deposit, never the headline — the operator
            came here to shield, not to fund a test token */}
        <div className="border-t border-border pt-3.5 flex items-center gap-3 flex-wrap">
          <span className="text-[12.5px] text-muted flex-1 min-w-[120px]">No kKRW?</span>
          <Button variant="secondary" disabled={!view.canMint} onClick={onMint}>
            {state.minting && <Spinner />}
            {view.mintLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
