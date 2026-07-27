// The Deposit / shield screen: mint public kKRW into a private note(V) via the
// permissionless BongtuPool.deposit (0-in / 2-out). Modeled on SpendScreen but with NO
// recipient and NO note selection — an amount-only form → confirm → staged run
// (approve → prove → submit) → success with an explorer link.
//
// Amounts: the form takes DECIMAL kKRW (parseKkrw, ≤6 fraction digits, 2^100 belt) and
// converts to raw wei at the UI edge; runDeposit still receives a raw-wei string.
//
// On open we PREFETCH the deposit wasm+zkey (the one-time download) and pre-warm the
// bn128 curve, so the heavy I/O overlaps the user typing the amount; we also read the
// account's public kKRW balance + current pool allowance (view calls, no gas) to bound
// the amount and to decide whether the exact-V approve tx is needed.

import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { DEFAULTS } from "../../config.js";
import { ensureCircuitAssets, prewarmProver } from "../../lib/prove.js";
import { runDeposit, type DepositStage, type DepositOutcome } from "../../lib/depositFlow.js";
import { readTokenState, walletErrorMessage } from "../../lib/metamask.js";
import { useWallet } from "../App.js";
import { useCircuitDownload, useElapsedSeconds } from "../hooks.js";
import { formatKkrw, parseKkrw } from "../../lib/money.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { SuccessPanel } from "../components/SuccessPanel.js";
import { StagedProgress, withUnlock, type StagedStep } from "../components/StagedProgress.js";
import { DownloadProgress } from "../components/DownloadProgress.js";
import { AmountInput, Button, ErrorBanner, Field, LinkButton, TestnetTag } from "../components/controls.js";
import { MintModal } from "../components/MintModal.js";

type Phase = "form" | "confirm" | "running" | "done";

// approve → prove → submit (deposit has no membership to assemble; the exact-V ERC-20
// approve replaces the spend's assemble stage and is skipped when allowance >= V).
const DEPOSIT_STEPS: StagedStep[] = [
  { key: "approve", label: "Approving" },
  { key: "prove", label: "Proving" },
  { key: "submit", label: "Submitting" },
];

function amountError(raw: string, balance: bigint | null): string | null {
  const p = parseKkrw(raw);
  if (!p.ok) return p.error;
  if (p.wei <= 0n) return "Amount must be greater than zero.";
  if (balance !== null && p.wei > balance) return "Amount exceeds your kKRW balance.";
  return null;
}

export function Deposit(): ReactNode {
  const { session, connection, wallet, refreshAfterAction, syncing } = useWallet();

  const [amount, setAmount] = useState("");
  const [phase, setPhase] = useState<Phase>("form");
  const [stage, setStage] = useState<DepositStage>("approve");
  // Whether THIS run needs the unlock signature — the flow tells us by reporting
  // "unlock" first, and the step list grows a step to match.
  const [unlocking, setUnlocking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<DepositOutcome | null>(null);
  const [tokenBalance, setTokenBalance] = useState<bigint | null>(null);
  const [allowance, setAllowance] = useState<bigint | null>(null);
  const [mintOpen, setMintOpen] = useState(false);
  const download = useCircuitDownload("deposit");

  const elapsed = useElapsedSeconds(phase === "running" && stage === "prove");

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

  // Prefetch the deposit circuit assets + warm the curve on open (best-effort).
  // Progress/disable state comes from useCircuitDownload — the prove.ts registry —
  // not from this call's promise, so a remount mid-download stays honest.
  useEffect(() => {
    void ensureCircuitAssets("deposit", DEFAULTS.circuitBaseUrl).catch(() => {});
    void prewarmProver();
  }, []);

  useEffect(() => {
    void refreshTokenState();
  }, [refreshTokenState]);

  const amtErr = amountError(amount, tokenBalance);
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

  async function submit(): Promise<void> {
    if (!connection || !session) return;
    setPhase("running");
    setError(null);
    setUnlocking(false);
    try {
      // The spending key comes from the wallet's lock INSIDE runDeposit — this
      // component never holds it. The session pubkey rides along so the flow can
      // refuse a key that isn't this session's.
      const res = await runDeposit(
        { connection, sessionPubkey: session.compressedPubkey },
        { amount: amountWei.toString() },
        (s) => {
          if (s === "unlock") setUnlocking(true);
          setStage(s);
        },
      );
      setOutcome(res);
      setPhase("done");
      // Poll until the indexer reflects this tx (not fire-and-forget: one refresh
      // here would usually read the pre-action state).
      void refreshAfterAction(res.txHash);
    } catch (e) {
      setError(walletErrorMessage(e));
      setPhase("form");
    }
  }

  // --- success ---------------------------------------------------------------
  if (phase === "done" && outcome) {
    return (
      <SuccessPanel
        title="Deposit"
        headline="Deposit completed"
        amount={review}
        explorerUrl={outcome.explorerUrl}
        syncing={syncing}
      />
    );
  }

  // --- running ---------------------------------------------------------------
  if (phase === "running") {
    return (
      <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
        <ScreenHeader title="Deposit" />
        <div className="flex flex-col gap-4">
          <div className="text-center text-[1.9rem] [font-weight:750] py-2 tabular-nums">
            {review} <span className="text-[0.62em] font-semibold text-muted ml-1">kKRW</span>
          </div>
          <StagedProgress
            stage={stage}
            elapsed={elapsed}
            steps={unlocking ? withUnlock(DEPOSIT_STEPS) : DEPOSIT_STEPS}
            walletName={wallet.name}
          />
        </div>
      </div>
    );
  }

  // --- confirm ---------------------------------------------------------------
  if (phase === "confirm") {
    return (
      <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
        <ScreenHeader title="Confirm Deposit" />
        <div className="flex flex-col gap-4">
          <div className="text-center text-[1.9rem] [font-weight:750] py-2 tabular-nums">
            {review} <span className="text-[0.62em] font-semibold text-muted ml-1">kKRW</span>
          </div>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3.5 gap-y-2 p-3.5 bg-surface border border-border rounded-xl">
            <dt className="text-muted text-sm">From</dt>
            <dd className="text-right text-[0.9rem] [overflow-wrap:anywhere]">Your public kKRW</dd>
            <dt className="text-muted text-sm">To</dt>
            <dd className="text-right text-[0.9rem] [overflow-wrap:anywhere]">
              Your private balance
            </dd>
            <dt className="text-muted text-sm">Network</dt>
            <dd className="text-right text-[0.9rem] [overflow-wrap:anywhere]">
              GIWA · chain {DEFAULTS.chainId}
            </dd>
          </dl>
          {willApprove && (
            <p className="text-sm text-muted">
              This needs two transactions: first approve the pool to pull this amount, then
              shield it.
            </p>
          )}
          <DownloadProgress view={download} />
          <div className="flex gap-2.5">
            <Button variant="ghost" className="flex-1" onClick={() => setPhase("form")}>
              Cancel
            </Button>
            <Button
              variant="primary"
              className="flex-1"
              disabled={download.active}
              onClick={submit}
            >
              {download.active ? "Preparing…" : "Confirm"}
            </Button>
          </div>
        </div>
      </div>
    );
  }

  // --- form ------------------------------------------------------------------
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
          kKRW in, <strong>private kKRW</strong> out — then send and withdraw with nothing
          revealed.
        </p>

        {download.active ? (
          // The one-time key download IS the screen: no inputs, no buttons, just
          // the filling bar — everything the user could press needs these assets.
          <DownloadProgress view={download} />
        ) : (
          <>
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
                    Depositing needs kKRW in this account — fund it first, then come back.
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

            {error && <ErrorBanner message={error} />}

            {!noTokens && (
              <Button
                variant="primary"
                block
                disabled={!formValid}
                onClick={() => {
                  setError(null);
                  setPhase("confirm");
                }}
              >
                Continue
              </Button>
            )}
          </>
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
