// The Deposit / shield screen: mint public kKRW into a private note(V) via the
// permissionless BongtuPool.deposit (0-in / 2-out). Modeled on SpendScreen but with NO
// recipient and NO note selection — an amount-only form → confirm → staged run
// (approve → prove → submit) → success with an explorer link.
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
import { FAUCET_AMOUNT, shouldOfferFaucet } from "../../lib/faucet.js";
import { useWallet } from "../App.js";
import { navigate, useElapsedSeconds } from "../hooks.js";
import { formatAmount } from "../format.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { StagedProgress, type StagedStep } from "../components/StagedProgress.js";

type Phase = "form" | "confirm" | "running" | "done";

// approve → prove → submit (deposit has no membership to assemble; the exact-V ERC-20
// approve replaces the spend's assemble stage and is skipped when allowance >= V).
const DEPOSIT_STEPS: StagedStep[] = [
  { key: "approve", label: "Approving" },
  { key: "prove", label: "Proving" },
  { key: "submit", label: "Submitting" },
];

function amountError(raw: string, balance: bigint | null): string | null {
  const v = raw.trim();
  if (!v) return "Enter an amount.";
  if (!/^\d+$/.test(v)) return "Amount must be a whole number.";
  const amt = BigInt(v);
  if (amt <= 0n) return "Amount must be greater than zero.";
  if (balance !== null && amt > balance) return "Amount exceeds your kKRW balance.";
  return null;
}

export function Deposit(): ReactNode {
  const { identity, connection, refresh } = useWallet();

  const [amount, setAmount] = useState("");
  const [phase, setPhase] = useState<Phase>("form");
  const [stage, setStage] = useState<DepositStage>("approve");
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<DepositOutcome | null>(null);
  const [tokenBalance, setTokenBalance] = useState<bigint | null>(null);
  const [allowance, setAllowance] = useState<bigint | null>(null);
  const [faucetPending, setFaucetPending] = useState(false);
  const [faucetTxUrl, setFaucetTxUrl] = useState<string | null>(null);

  const elapsed = useElapsedSeconds(phase === "running" && stage === "prove");

  // Re-read balance + allowance on demand (after the faucet mint confirms, so the user
  // can immediately deposit the freshly minted kKRW). Best-effort: an RPC hiccup shows "—".
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
  useEffect(() => {
    void ensureCircuitAssets("deposit", DEFAULTS.circuitBaseUrl, {
      onDownloadStart: () => setDownloading(true),
    })
      .then(() => setDownloading(false))
      .catch(() => setDownloading(false));
    void prewarmProver();
  }, []);

  // Read the public kKRW balance + pool allowance on open (view calls; the deposit flow
  // re-reads the allowance at submit time to decide skip-approve).
  useEffect(() => {
    if (!connection) return;
    let alive = true;
    void readTokenState(connection, DEFAULTS.token, connection.address, DEFAULTS.pool)
      .then((s) => {
        if (alive) {
          setTokenBalance(s.balance);
          setAllowance(s.allowance);
        }
      })
      .catch(() => {
        if (alive) {
          setTokenBalance(null);
          setAllowance(null);
        }
      });
    return () => {
      alive = false;
    };
  }, [connection]);

  const amtErr = amountError(amount, tokenBalance);
  // Guard on a KNOWN balance: until the token state loads (tokenBalance===null) the
  // over-spend check can't fire, so don't let the user start a proof that would revert.
  const formValid = tokenBalance !== null && !amtErr;

  const review = useMemo(() => {
    const amt = /^\d+$/.test(amount.trim()) ? BigInt(amount.trim()) : 0n;
    return formatAmount(amt);
  }, [amount]);

  // Whether the confirm step will need an approve tx (allowance already covers V => skip).
  const willApprove = useMemo(() => {
    if (allowance === null || !/^\d+$/.test(amount.trim())) return true;
    return allowance < BigInt(amount.trim());
  }, [allowance, amount]);

  // DEV FAUCET: self-mint test kKRW from the connected wallet (MockERC20.mint is
  // permissionless; the user pays their own gas), then refresh balance/allowance so the
  // deposit form unlocks immediately. Only offered when the public balance is 0.
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
        { amount: amount.trim() },
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
          <div className="success-check">✓</div>
          <h2 className="success-title">Deposit shielded</h2>
          <p className="success-amount">
            {review} <span className="unit">kKRW</span>
          </p>
          <a className="success-link" href={outcome.explorerUrl} target="_blank" rel="noreferrer">
            View on explorer ↗
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
            {downloading
              ? "Preparing proving keys (one-time download)… "
              : "Your proof is generated on this device — your key never leaves the browser. "}
            {willApprove
              ? "This needs two transactions: first approve the pool to pull this amount, then shield it."
              : ""}
          </p>
          <div className="btn-row">
            <button className="btn btn-ghost" onClick={() => setPhase("form")}>
              Back
            </button>
            <button className="btn btn-primary" onClick={submit}>
              Confirm & prove
            </button>
          </div>
        </div>
      </div>
    );
  }

  // --- form ------------------------------------------------------------------
  return (
    <div className="screen">
      <ScreenHeader title="Deposit" />
      <div className="spend-body">
        <label className="field">
          <span className="field-label">Amount (kKRW)</span>
          <input
            className="input"
            inputMode="numeric"
            placeholder="0"
            value={amount}
            onChange={(e) => setAmount(e.target.value.replace(/[^\d]/g, ""))}
          />
          <span className="field-hint">
            kKRW balance: {tokenBalance === null ? "—" : formatAmount(tokenBalance)} · Pool
            allowance: {allowance === null ? "—" : formatAmount(allowance)}
          </span>
          {amount.trim() && amtErr && <span className="field-err">{amtErr}</span>}
        </label>

        {/* Dev faucet: only when the public balance is 0 — a fresh wallet with nothing to
            shield. Self-mint test kKRW (user pays gas), then the balance/allowance refresh
            unlocks the form. */}
        {tokenBalance !== null && shouldOfferFaucet(tokenBalance) && (
          <div className="faucet">
            <p className="hint">
              You have no kKRW yet. Mint some test kKRW to try a deposit — you only pay gas.
            </p>
            <button
              className="btn btn-ghost btn-block"
              disabled={faucetPending}
              onClick={() => void getTestTokens()}
            >
              {faucetPending ? "Minting test kKRW…" : "Get test kKRW"}
            </button>
            {faucetTxUrl && (
              <a className="success-link" href={faucetTxUrl} target="_blank" rel="noreferrer">
                Minted ✓ View on explorer ↗
              </a>
            )}
          </div>
        )}

        {error && <div className="banner banner-err">{error}</div>}
        {downloading && (
          <div className="banner banner-info">Downloading proving keys (one-time)…</div>
        )}

        <button
          className="btn btn-primary btn-block"
          disabled={!formValid}
          onClick={() => {
            setError(null);
            setPhase("confirm");
          }}
        >
          Review deposit
        </button>
      </div>
    </div>
  );
}
