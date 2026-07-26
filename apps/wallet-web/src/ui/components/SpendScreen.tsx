// The shared Send (transfer) / Withdraw screen. Both are a 2-in spend that proves in
// the browser and submits via MetaMask; the ONLY difference is transfer needs a
// recipient pubkey and withdraw does not. Keeping them one component means the
// validate → confirm → staged-prove → success flow lives in exactly one place.
//
// Amounts: the form takes DECIMAL kKRW (parseKkrw, ≤6 fraction digits, 2^100 belt) and
// converts to raw wei at the UI edge — the flow/witness layer still receives raw wei
// strings, unchanged.
//
// On open we PREFETCH the circuit's wasm+zkey (the ~28 MB one-time download) and
// pre-warm the bn128 curve, so the heavy I/O overlaps the user typing the amount.

import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { unpackPubkey } from "@bongtu/core/pubkey";
import { DEFAULTS } from "../../config.js";
import { ensureCircuitAssets, prewarmProver } from "../../lib/prove.js";
import { runSpend, type SpendStage, type SpendOutcome } from "../../lib/spendFlow.js";
import { useWallet } from "../App.js";
import { navigate, useElapsedSeconds } from "../hooks.js";
import { formatKkrw, parseKkrw } from "../../lib/money.js";
import { normalizePubkey } from "../format.js";
import { ScreenHeader } from "./ScreenHeader.js";
import { StagedProgress } from "./StagedProgress.js";
import { SuccessMark } from "./SuccessMark.js";

type Phase = "form" | "confirm" | "running" | "done";

// Reject an obviously-bad recipient before proving (the pure spend.ts rejects it too,
// but a 28 MB proof is a bad place to learn you fat-fingered a key). unpackPubkey
// throws on a malformed compressed bjj pubkey; a self-send is a two-time pad (§11-8).
function recipientError(raw: string, selfPubkey: string): string | null {
  const v = raw.trim();
  if (!v) return "Enter a recipient.";
  try {
    unpackPubkey(v);
  } catch {
    return "That doesn't look like a valid bongtu address.";
  }
  if (normalizePubkey(v) === normalizePubkey(selfPubkey)) {
    return "You can't send to your own address.";
  }
  return null;
}

function amountError(raw: string, balance: bigint | null): string | null {
  const p = parseKkrw(raw);
  if (!p.ok) return p.error;
  if (p.wei <= 0n) return "Amount must be greater than zero.";
  if (balance !== null && p.wei > balance) return "Amount exceeds your balance.";
  return null;
}

export function SpendScreen({ kind }: { kind: "transfer" | "withdraw" }): ReactNode {
  const { identity, connection, indexerUrl, notes, balance, refresh } = useWallet();
  const isTransfer = kind === "transfer";

  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  const [phase, setPhase] = useState<Phase>("form");
  const [stage, setStage] = useState<SpendStage>("assemble");
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<SpendOutcome | null>(null);

  const elapsed = useElapsedSeconds(phase === "running" && stage === "prove");

  // Prefetch the circuit assets + warm the curve on open (best-effort, non-blocking).
  useEffect(() => {
    void ensureCircuitAssets(kind, DEFAULTS.circuitBaseUrl, {
      onDownloadStart: () => setDownloading(true),
    })
      .then(() => setDownloading(false))
      .catch(() => setDownloading(false));
    void prewarmProver();
  }, [kind]);

  const rcptErr = isTransfer && identity ? recipientError(recipient, identity.compressedPubkey) : null;
  const amtErr = amountError(amount, balance);
  // Guard on a KNOWN balance: until /notes loads (balance===null) amountError can't
  // catch over-spend, so don't let the user start a proof that would revert on-chain.
  const formValid = balance !== null && !amtErr && (!isTransfer || !rcptErr);

  const title = isTransfer ? "Send" : "Withdraw";

  // The raw-wei amount the protocol layer receives; 0n while the input is invalid.
  const amountWei = useMemo(() => {
    const p = parseKkrw(amount);
    return p.ok ? p.wei : 0n;
  }, [amount]);
  const review = formatKkrw(amountWei);

  async function submit(): Promise<void> {
    if (!identity || !connection) return;
    setPhase("running");
    setError(null);
    try {
      const res = await runSpend(
        kind,
        { identity, connection, indexerUrl, notes },
        { to: isTransfer ? recipient.trim() : undefined, amount: amountWei.toString() },
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
        <ScreenHeader title={title} />
        <div className="success">
          <SuccessMark />
          <h2 className="success-title">{isTransfer ? "Payment sent" : "Withdrawal sent"}</h2>
          <p className="success-amount">
            {review} <span className="unit">kKRW</span>
          </p>
          <a className="success-link" href={outcome.explorerUrl} target="_blank" rel="noreferrer">
            View on explorer
          </a>
          <p className="success-change">Change kept: {formatKkrw(outcome.changeValue)} kKRW</p>
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
        <ScreenHeader title={title} />
        <div className="spend-body">
          <div className="review-amount">
            {review} <span className="unit">kKRW</span>
          </div>
          <StagedProgress stage={stage} elapsed={elapsed} />
        </div>
      </div>
    );
  }

  // --- confirm ---------------------------------------------------------------
  if (phase === "confirm") {
    return (
      <div className="screen">
        <ScreenHeader title={`Confirm ${title.toLowerCase()}`} />
        <div className="spend-body">
          <div className="review-amount">
            {review} <span className="unit">kKRW</span>
          </div>
          <dl className="review">
            {isTransfer && (
              <>
                <dt>To</dt>
                <dd className="mono">{recipient.trim()}</dd>
              </>
            )}
            <dt>{isTransfer ? "From" : "Source"}</dt>
            <dd>Your private balance</dd>
            <dt>Network</dt>
            <dd>GIWA · chain {DEFAULTS.chainId}</dd>
          </dl>
          <p className="hint">
            {downloading
              ? "Preparing proving keys (one-time download)…"
              : "Your proof is generated on this device — your key never leaves the browser."}
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
      <ScreenHeader title={title} />
      <div className="spend-body">
        {isTransfer && (
          <label className="field">
            <span className="field-label">Recipient address</span>
            <input
              className="input mono"
              placeholder="0x… compressed bongtu pubkey"
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
            />
            {recipient.trim() && rcptErr && <span className="field-err">{rcptErr}</span>}
          </label>
        )}

        <label className="field">
          <span className="field-label">Amount (kKRW)</span>
          <input
            className="input"
            inputMode="decimal"
            placeholder="0.00"
            value={amount}
            onChange={(e) => setAmount(e.target.value.replace(/[^\d.,]/g, ""))}
          />
          <span className="field-hint">
            Balance: {balance === null ? "—" : formatKkrw(balance)} kKRW
          </span>
          {amount.trim() && amtErr && <span className="field-err">{amtErr}</span>}
        </label>

        {error && <div className="banner banner-err">{error}</div>}
        {downloading && (
          <div className="banner banner-info">Downloading proving keys (one-time, ~28 MB)…</div>
        )}

        <button
          className="btn btn-primary btn-block"
          disabled={!formValid}
          onClick={() => {
            setError(null);
            setPhase("confirm");
          }}
        >
          Review {title.toLowerCase()}
        </button>
      </div>
    </div>
  );
}
