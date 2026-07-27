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
import { readTokenState, mintTestToken } from "../../lib/metamask.js";
import { FAUCET_AMOUNT } from "../../lib/faucet.js";
import { useWallet } from "../App.js";
import { navigate, useCircuitDownload, useElapsedSeconds } from "../hooks.js";
import { formatKkrw, parseKkrw } from "../../lib/money.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { SuccessMark } from "../components/SuccessMark.js";
import { StagedProgress, type StagedStep } from "../components/StagedProgress.js";
import { DownloadProgress } from "../components/DownloadProgress.js";

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
  const { identity, connection, refresh } = useWallet();

  const [amount, setAmount] = useState("");
  const [phase, setPhase] = useState<Phase>("form");
  const [stage, setStage] = useState<DepositStage>("approve");
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<DepositOutcome | null>(null);
  const [tokenBalance, setTokenBalance] = useState<bigint | null>(null);
  const [allowance, setAllowance] = useState<bigint | null>(null);
  const [faucetPending, setFaucetPending] = useState(false);
  const [faucetTxUrl, setFaucetTxUrl] = useState<string | null>(null);
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

  // DEV FAUCET: self-mint test kKRW from the connected wallet (MockERC20.mint is
  // permissionless; the user pays their own gas), then refresh balance/allowance.
  // Always offered — a tester with a non-zero balance still needs a way to mint more.
  async function getTestTokens(): Promise<void> {
    if (!connection) return;
    setFaucetPending(true);
    setError(null);
    setFaucetTxUrl(null);
    try {
      const res = await mintTestToken(connection, DEFAULTS.token, connection.address, FAUCET_AMOUNT);
      setFaucetTxUrl(res.explorerUrl);
      await refreshTokenState();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setFaucetPending(false);
    }
  }

  async function submit(): Promise<void> {
    if (!identity || !connection) return;
    setPhase("running");
    setError(null);
    try {
      const res = await runDeposit(
        { identity, connection },
        { amount: amountWei.toString() },
        (s) => setStage(s),
      );
      setOutcome(res);
      setPhase("done");
      void refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setPhase("form");
    }
  }

  // --- success ---------------------------------------------------------------
  if (phase === "done" && outcome) {
    return (
      <div className="screen">
        <ScreenHeader title="Deposit" />
        <div className="success">
          <SuccessMark />
          <h2 className="success-title">Deposit shielded</h2>
          <p className="success-amount">
            {review} <span className="unit">kKRW</span>
          </p>
          <a className="success-link" href={outcome.explorerUrl} target="_blank" rel="noreferrer">
            View on explorer
          </a>
          <p className="success-change">Now in your private balance.</p>
          <button className="btn btn-primary btn-block" onClick={() => navigate("home")}>
            Done
          </button>
        </div>
      </div>
    );
  }

  // --- running ---------------------------------------------------------------
  if (phase === "running") {
    return (
      <div className="screen">
        <ScreenHeader title="Deposit" />
        <div className="spend-body">
          <div className="review-amount">
            {review} <span className="unit">kKRW</span>
          </div>
          <StagedProgress stage={stage} elapsed={elapsed} steps={DEPOSIT_STEPS} />
        </div>
      </div>
    );
  }

  // --- confirm ---------------------------------------------------------------
  if (phase === "confirm") {
    return (
      <div className="screen">
        <ScreenHeader title="Confirm deposit" />
        <div className="spend-body">
          <div className="review-amount">
            {review} <span className="unit">kKRW</span>
          </div>
          <dl className="review">
            <dt>From</dt>
            <dd>Your public kKRW</dd>
            <dt>To</dt>
            <dd>Your private balance</dd>
            <dt>Network</dt>
            <dd>GIWA · chain {DEFAULTS.chainId}</dd>
          </dl>
          <p className="hint">
            Your proof is generated on this device — your key never leaves the browser.{" "}
            {willApprove
              ? "This needs two transactions: first approve the pool to pull this amount, then shield it."
              : ""}
          </p>
          <DownloadProgress view={download} />
          <div className="btn-row">
            <button className="btn btn-ghost" onClick={() => setPhase("form")}>
              Back
            </button>
            <button className="btn btn-primary" disabled={download.active} onClick={submit}>
              {download.active ? "Preparing keys…" : "Confirm & prove"}
            </button>
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
    <div className="screen">
      <ScreenHeader title="Deposit" />
      <div className="spend-body">
        <p className="hint deposit-explainer">
          kKRW in, <strong>private kKRW</strong> out — then send and withdraw with nothing
          revealed.
        </p>

        <div className="deposit-avail" aria-live="polite">
          <span className="deposit-avail-label">You can deposit</span>
          <span className="deposit-avail-amount">
            {tokenBalance === null ? "—" : formatKkrw(tokenBalance)}{" "}
            <span className="unit">kKRW</span>
          </span>
        </div>

        {noTokens ? (
          <div className="faucet faucet-hero">
            <div className="faucet-head">
              <span className="testnet-tag">Testnet</span>
              <span className="faucet-title">First, get test kKRW</span>
            </div>
            <p className="hint">
              Mint {formatKkrw(FAUCET_AMOUNT)} free test kKRW (you pay only gas), then deposit
              it here.
            </p>
            <button
              className="btn btn-primary btn-block"
              disabled={faucetPending || !connection}
              onClick={() => void getTestTokens()}
            >
              {faucetPending ? "Minting test kKRW…" : "Get test kKRW"}
            </button>
            {faucetTxUrl && (
              <a className="success-link" href={faucetTxUrl} target="_blank" rel="noreferrer">
                Minted — view on explorer
              </a>
            )}
          </div>
        ) : (
          <>
            <label className="field">
              <span className="field-label">Amount (kKRW)</span>
              <input
                className="input"
                inputMode="decimal"
                placeholder="0.00"
                value={amount}
                onChange={(e) => setAmount(e.target.value.replace(/[^\d.,]/g, ""))}
              />
              {amount.trim() && amtErr && <span className="field-err">{amtErr}</span>}
            </label>

            <div className="faucet">
              <div className="faucet-head">
                <span className="testnet-tag">Testnet</span>
                <span className="faucet-title">Need more test kKRW?</span>
              </div>
              <button
                className="btn btn-ghost btn-block"
                disabled={faucetPending || !connection}
                onClick={() => void getTestTokens()}
              >
                {faucetPending ? "Minting test kKRW…" : `Mint ${formatKkrw(FAUCET_AMOUNT)} test kKRW`}
              </button>
              {faucetTxUrl && (
                <a className="success-link" href={faucetTxUrl} target="_blank" rel="noreferrer">
                  Minted — view on explorer
                </a>
              )}
            </div>
          </>
        )}

        {error && <div className="banner banner-err">{error}</div>}
        <DownloadProgress view={download} />

        {!noTokens && (
          <button
            className="btn btn-primary btn-block"
            disabled={!formValid || download.active}
            onClick={() => {
              setError(null);
              setPhase("confirm");
            }}
          >
            {download.active ? "Preparing keys…" : "Review deposit"}
          </button>
        )}
      </div>
    </div>
  );
}
