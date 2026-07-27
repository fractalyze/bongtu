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
import { mintTestToken, readGasBalance, readTokenState, walletErrorMessage } from "../../lib/metamask.js";
import { FAUCET_AMOUNT } from "../../lib/faucet.js";
import { useWallet } from "../App.js";
import { navigate, useCircuitDownload, useElapsedSeconds } from "../hooks.js";
import { formatKkrw, parseKkrw } from "../../lib/money.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { SuccessMark } from "../components/SuccessMark.js";
import { StagedProgress, type StagedStep } from "../components/StagedProgress.js";
import { DownloadProgress } from "../components/DownloadProgress.js";
import { Button, LinkButton, TestnetTag } from "../components/controls.js";

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
  const [showFaucet, setShowFaucet] = useState(false);
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
      // The mint is permissionless but still a tx: an account with ZERO gas ETH
      // fails inside MetaMask with an opaque object — say it plainly instead.
      if ((await readGasBalance(connection)) === 0n) {
        throw new Error(
          "This account has no GIWA Sepolia ETH to pay gas — get a little testnet ETH onto GIWA Sepolia first, then mint.",
        );
      }
      const res = await mintTestToken(connection, DEFAULTS.token, connection.address, FAUCET_AMOUNT);
      setFaucetTxUrl(res.explorerUrl);
      await refreshTokenState();
    } catch (e) {
      setError(walletErrorMessage(e));
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
      setError(walletErrorMessage(e));
      setPhase("form");
    }
  }

  // --- success ---------------------------------------------------------------
  if (phase === "done" && outcome) {
    return (
      <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
        <ScreenHeader title="Deposit" />
        <div className="flex flex-col items-center gap-2.5 text-center pt-4.5">
          <SuccessMark />
          <h2 className="mt-1.5 text-xl font-bold">Deposit shielded</h2>
          <p className="text-[1.8rem] [font-weight:750] my-0.5 tabular-nums">
            {review} <span className="text-[0.62em] font-semibold text-muted ml-1">kKRW</span>
          </p>
          <a
            className="text-primary no-underline text-[0.9rem] font-semibold"
            href={outcome.explorerUrl}
            target="_blank"
            rel="noreferrer"
          >
            View on explorer
          </a>
          <p className="text-muted text-[0.82rem] mt-0.5 mb-2.5">Now in your private balance.</p>
          <Button variant="primary" block className="mt-2" onClick={() => navigate("home")}>
            Done
          </Button>
        </div>
      </div>
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
          <StagedProgress stage={stage} elapsed={elapsed} steps={DEPOSIT_STEPS} />
        </div>
      </div>
    );
  }

  // --- confirm ---------------------------------------------------------------
  if (phase === "confirm") {
    return (
      <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
        <ScreenHeader title="Confirm deposit" />
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
          <p className="text-sm text-muted">
            Your proof is generated on this device — your key never leaves the browser.{" "}
            {willApprove
              ? "This needs two transactions: first approve the pool to pull this amount, then shield it."
              : ""}
          </p>
          <DownloadProgress view={download} />
          <div className="flex gap-2.5">
            <Button variant="ghost" className="flex-1" onClick={() => setPhase("form")}>
              Back
            </Button>
            <Button
              variant="primary"
              className="flex-1"
              disabled={download.active}
              onClick={submit}
            >
              {download.active ? "Preparing keys…" : "Confirm & prove"}
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
              <div className="flex flex-col gap-2 bg-surface border border-border-strong rounded-xl p-3.5">
                <div className="flex items-center gap-2">
                  <TestnetTag />
                  <span className="text-[0.9rem] font-semibold">First, get test kKRW</span>
                </div>
                <p className="text-sm text-muted">
                  Mint {formatKkrw(FAUCET_AMOUNT)} free test kKRW (you pay only gas), then
                  deposit it here.
                </p>
                <Button
                  variant="primary"
                  block
                  disabled={faucetPending || !connection}
                  onClick={() => void getTestTokens()}
                >
                  {faucetPending ? "Minting test kKRW…" : "Get test kKRW"}
                </Button>
                {faucetTxUrl && (
                  <a
                    className="text-primary no-underline text-[0.9rem] font-semibold"
                    href={faucetTxUrl}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Minted — view on explorer
                  </a>
                )}
              </div>
            ) : (
              <>
                <label className="flex flex-col gap-1.5">
                  <span className="text-[0.82rem] text-muted font-semibold">Amount (kKRW)</span>
                  <input
                    className="bg-surface border border-border rounded-xl px-3.5 py-[13px] text-ink text-[0.98rem] w-full tabular-nums focus:outline-none focus:border-primary focus:shadow-[0_0_0_3px_rgba(18,58,92,0.12)]"
                    inputMode="decimal"
                    placeholder="0.00"
                    value={amount}
                    onChange={(e) => setAmount(e.target.value.replace(/[^\d.,]/g, ""))}
                  />
                  {amount.trim() && amtErr && (
                    <span className="text-[0.8rem] text-err">{amtErr}</span>
                  )}
                </label>

                {/* With a balance the faucet is a side path — one extra tap keeps
                    it from outweighing the amount form. */}
                {showFaucet ? (
                  <div className="flex flex-col gap-2 bg-surface border border-border rounded-xl p-3.5">
                    <div className="flex items-center gap-2">
                      <TestnetTag />
                      <span className="text-[0.9rem] font-semibold">Get more test kKRW</span>
                    </div>
                    <Button
                      variant="ghost"
                      block
                      disabled={faucetPending || !connection}
                      onClick={() => void getTestTokens()}
                    >
                      {faucetPending
                        ? "Minting test kKRW…"
                        : `Mint ${formatKkrw(FAUCET_AMOUNT)} test kKRW`}
                    </Button>
                    {faucetTxUrl && (
                      <a
                        className="text-primary no-underline text-[0.9rem] font-semibold"
                        href={faucetTxUrl}
                        target="_blank"
                        rel="noreferrer"
                      >
                        Minted — view on explorer
                      </a>
                    )}
                  </div>
                ) : (
                  <LinkButton small className="self-start" onClick={() => setShowFaucet(true)}>
                    Need more test kKRW?
                  </LinkButton>
                )}
              </>
            )}

            {error && (
              <div className="rounded-xl px-3.5 py-3 text-[0.88rem] flex gap-2.5 items-center justify-between flex-wrap border border-err-border bg-err-bg text-err">
                {error}
                {/GIWA Sepolia ETH/.test(error) && (
                  <a
                    className="font-semibold underline text-err"
                    href={DEFAULTS.gasFaucet}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Get GIWA Sepolia ETH from the faucet
                  </a>
                )}
              </div>
            )}

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
                Review deposit
              </Button>
            )}
          </>
        )}
      </div>
    </div>
  );
}
