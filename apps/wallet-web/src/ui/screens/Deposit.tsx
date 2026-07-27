// The Deposit / shield screen: mint public kKRW into a private note(V) via the
// permissionless BongtuPool.deposit (0-in / 2-out). No recipient and no note selection
// — an amount-only form → confirm → staged run (approve → prove → submit) → success
// with an explorer link.
//
// The phases are not written here: useActionMachine owns form → confirm → running →
// done (and the asset prefetch that rides along), and ActionPanels renders the three
// phases every action screen shares — the same ones Send/Withdraw use. What stays
// below is what a DEPOSIT is: the account's public kKRW balance and pool allowance
// (view calls, no gas) that bound the amount and decide whether the exact-V approve tx
// is needed, and the testnet faucet that gets a first-timer some kKRW to shield.
//
// Amounts: the form takes DECIMAL kKRW (parseKkrw, ≤6 fraction digits, 2^100 belt) and
// converts to raw wei at the UI edge; runDeposit still receives a raw-wei string.

import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { DEFAULTS } from "../../config.js";
import { runDeposit, type DepositOutcome } from "../../lib/depositFlow.js";
import { readTokenState } from "../../lib/metamask.js";
import { useWallet } from "../App.js";
import { useActionMachine } from "../actionMachine.js";
import { formatKkrw, parseKkrw } from "../../lib/money.js";
import { amountError } from "../format.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { SuccessPanel } from "../components/SuccessPanel.js";
import { DEPOSIT_STEPS } from "../components/StagedProgress.js";
import { ConfirmPanel, DownloadingPanel, FlowHint, RunningPanel } from "../components/ActionPanels.js";
import { AmountInput, Button, ErrorBanner, Field, LinkButton, TestnetTag } from "../components/controls.js";
import { MintModal } from "../components/MintModal.js";

export function Deposit(): ReactNode {
  const { session, connection, wallet, refreshAfterAction } = useWallet();

  const [amount, setAmount] = useState("");
  const [tokenBalance, setTokenBalance] = useState<bigint | null>(null);
  const [allowance, setAllowance] = useState<bigint | null>(null);
  const [mintOpen, setMintOpen] = useState(false);
  const action = useActionMachine<DepositOutcome>({ circuit: "deposit", steps: DEPOSIT_STEPS });

  // Re-read balance + allowance on demand (after the faucet mint or a revoke confirms).
  // Best-effort: an RPC hiccup shows "—".
  const refreshTokenState = useCallback(async (): Promise<void> => {
    if (!connection) return;
    try {
      const s = await readTokenState(connection, DEFAULTS.token, connection.address, DEFAULTS.pool);
      setTokenBalance(s.balance);
      setAllowance(s.allowance);
    } catch {
      setTokenBalance(null);
      setAllowance(null);
    }
  }, [connection]);

  useEffect(() => {
    void refreshTokenState();
  }, [refreshTokenState]);

  const amtErr = amountError(amount, tokenBalance, "Amount exceeds your kKRW balance.");
  // Guard on a KNOWN balance: until the token state loads (tokenBalance===null) the
  // over-spend check can't fire, so don't let the user start a proof that would revert.
  const formValid = tokenBalance !== null && !amtErr;

  // The raw-wei amount the flow receives; 0n while the input is invalid.
  const amountWei = useMemo(() => {
    const p = parseKkrw(amount);
    return p.ok ? p.wei : 0n;
  }, [amount]);
  const review = formatKkrw(amountWei);

  // Whether the confirm step will need an approve tx (allowance already covers V => skip).
  const willApprove = allowance === null || amountWei <= 0n || allowance < amountWei;

  function confirm(): void {
    if (!connection || !session) return;
    // The spending key comes from the wallet's lock INSIDE runDeposit — this component
    // never holds it. The session pubkey rides along so the flow can refuse a key that
    // isn't this session's.
    void action.submit(
      (onStage) =>
        runDeposit(
          { connection, sessionPubkey: session.compressedPubkey },
          { amount: amountWei.toString() },
          onStage,
        ),
      refreshAfterAction,
    );
  }

  // --- success ---------------------------------------------------------------
  if (action.phase === "done" && action.outcome) {
    return (
      <SuccessPanel
        title="Deposit"
        headline="Deposit completed"
        amount={review}
        explorerUrl={action.outcome.explorerUrl}
      />
    );
  }

  // --- running ---------------------------------------------------------------
  if (action.phase === "running") {
    return (
      <RunningPanel
        title="Deposit"
        amount={review}
        stage={action.stage}
        elapsed={action.elapsed}
        steps={action.steps}
        walletName={wallet.name}
      />
    );
  }

  // --- confirm ---------------------------------------------------------------
  if (action.phase === "confirm") {
    return (
      <ConfirmPanel
        title="Deposit"
        amount={review}
        hint={<FlowHint from="kKRW in your account" to="Private balance" />}
        note={
          willApprove ? (
            <p className="text-sm text-muted">
              This needs two transactions: first approve the pool to pull this amount, then
              shield it.
            </p>
          ) : undefined
        }
        download={action.download}
        onCancel={action.cancel}
        onConfirm={confirm}
      >
        <dt className="text-muted text-sm">Network</dt>
        <dd className="text-right text-[0.9rem] [overflow-wrap:anywhere]">
          GIWA · chain {DEFAULTS.chainId}
        </dd>
      </ConfirmPanel>
    );
  }

  // --- form ------------------------------------------------------------------
  if (action.download.active) {
    return <DownloadingPanel title="Deposit" download={action.download} />;
  }

  // Two states by what the user actually has: no kKRW => the mint guide IS the
  // screen (nothing to deposit yet); some kKRW => the depositable amount leads
  // and the faucet collapses to a side offer. Allowance is deliberately not
  // shown — the flow approves exactly V when needed; it's plumbing, not a
  // decision the user makes here.
  const noTokens = tokenBalance !== null && tokenBalance === 0n;

  return (
    <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
      <ScreenHeader title="Deposit" />
      <div className="flex flex-col gap-4">
        <p className="text-sm text-muted">
          kKRW in, <strong>private kKRW</strong> out. Then send and withdraw with nothing
          revealed.
        </p>

        <div
          className="flex flex-col gap-0.5 bg-surface border border-border rounded-xl p-3.5"
          aria-live="polite"
        >
          <span className="text-[0.8rem] text-muted">You can deposit</span>
          <span className="text-2xl font-bold tabular-nums">
            {tokenBalance === null ? "—" : formatKkrw(tokenBalance)}{" "}
            <span className="text-[0.9rem] font-semibold text-muted ml-1">kKRW</span>
          </span>
        </div>

        {noTokens ? (
          DEFAULTS.testnet ? (
            <div className="flex flex-col gap-2 bg-surface border border-border-strong rounded-xl p-3.5">
              <div className="flex items-center gap-2">
                <TestnetTag />
                <span className="text-[0.9rem] font-semibold">First, get test kKRW</span>
              </div>
              {/* No amount here: the mint dialog's amount is freeform, and the
                  prefill is a starting point, not an offer. */}
              <p className="text-sm text-muted">
                Mint free test kKRW (you pay only gas), then deposit it here.
              </p>
              <Button variant="primary" block disabled={!connection} onClick={() => setMintOpen(true)}>
                Get Test kKRW
              </Button>
            </div>
          ) : (
            // Non-testnet: no mint to offer — just say what's missing.
            <div className="flex flex-col gap-2 bg-surface border border-border-strong rounded-xl p-3.5">
              <p className="text-sm text-muted">
                Depositing needs kKRW in this account. Fund it first, then come back.
              </p>
            </div>
          )
        ) : (
          // The faucet is a side path off the amount label — visually lighter
          // than the label itself so it never outweighs the amount form.
          <Field
            label="Amount (kKRW)"
            right={
              DEFAULTS.testnet ? (
                <LinkButton small subtle onClick={() => setMintOpen(true)}>
                  Need more test kKRW?
                </LinkButton>
              ) : undefined
            }
            error={amount.trim() ? amtErr : null}
          >
            <AmountInput value={amount} onValueChange={setAmount} />
          </Field>
        )}

        {action.error && <ErrorBanner message={action.error} />}

        {!noTokens && (
          <Button variant="primary" block disabled={!formValid} onClick={action.review}>
            Continue
          </Button>
        )}
      </div>

      {DEFAULTS.testnet && mintOpen && (
        <MintModal
          connection={connection}
          onClose={() => setMintOpen(false)}
          onMinted={refreshTokenState}
        />
      )}
    </div>
  );
}
