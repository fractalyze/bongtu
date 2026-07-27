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
import { walletErrorMessage } from "../../lib/metamask.js";
import { runSpend, type SpendStage, type SpendOutcome } from "../../lib/spendFlow.js";
import { useWallet } from "../App.js";
import { navigate, useCircuitDownload, useElapsedSeconds } from "../hooks.js";
import { formatKkrw, parseKkrw } from "../../lib/money.js";
import { normalizePubkey } from "../format.js";
import { ScreenHeader } from "./ScreenHeader.js";
import { StagedProgress } from "./StagedProgress.js";
import { SuccessMark } from "./SuccessMark.js";
import { DownloadProgress } from "./DownloadProgress.js";
import { Button } from "./controls.js";

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
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<SpendOutcome | null>(null);
  const download = useCircuitDownload(kind);

  const elapsed = useElapsedSeconds(phase === "running" && stage === "prove");

  // Prefetch the circuit assets + warm the curve on open (best-effort, non-blocking).
  // Progress/disable state comes from useCircuitDownload — the prove.ts registry —
  // not from this call's promise, so a remount mid-download stays honest.
  useEffect(() => {
    void ensureCircuitAssets(kind, DEFAULTS.circuitBaseUrl).catch(() => {});
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
      setError(walletErrorMessage(e));
      setPhase("form");
    }
  }

  // --- success ---------------------------------------------------------------
  if (phase === "done" && outcome) {
    return (
      <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
        <ScreenHeader title={title} />
        <div className="flex flex-col items-center gap-2.5 text-center pt-4.5">
          <SuccessMark />
          <h2 className="mt-1.5 text-xl font-bold">
            {isTransfer ? "Payment sent" : "Withdrawal sent"}
          </h2>
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
          <p className="text-muted text-[0.82rem] mt-0.5 mb-2.5">
            Change kept: {formatKkrw(outcome.changeValue)} kKRW
          </p>
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
        <ScreenHeader title={title} />
        <div className="flex flex-col gap-4">
          <div className="text-center text-[1.9rem] [font-weight:750] py-2 tabular-nums">
            {review} <span className="text-[0.62em] font-semibold text-muted ml-1">kKRW</span>
          </div>
          <StagedProgress stage={stage} elapsed={elapsed} />
        </div>
      </div>
    );
  }

  // --- confirm ---------------------------------------------------------------
  if (phase === "confirm") {
    return (
      <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
        <ScreenHeader title={`Confirm ${title.toLowerCase()}`} />
        <div className="flex flex-col gap-4">
          <div className="text-center text-[1.9rem] [font-weight:750] py-2 tabular-nums">
            {review} <span className="text-[0.62em] font-semibold text-muted ml-1">kKRW</span>
          </div>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3.5 gap-y-2 p-3.5 bg-surface border border-border rounded-xl">
            {isTransfer && (
              <>
                <dt className="text-muted text-sm">To</dt>
                <dd className="font-mono text-right text-[0.9rem] [overflow-wrap:anywhere]">
                  {recipient.trim()}
                </dd>
              </>
            )}
            <dt className="text-muted text-sm">{isTransfer ? "From" : "Source"}</dt>
            <dd className="text-right text-[0.9rem] [overflow-wrap:anywhere]">
              Your private balance
            </dd>
            <dt className="text-muted text-sm">Network</dt>
            <dd className="text-right text-[0.9rem] [overflow-wrap:anywhere]">
              GIWA · chain {DEFAULTS.chainId}
            </dd>
          </dl>
          <p className="text-sm text-muted">
            Your proof is generated on this device — your key never leaves the browser.
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
  // The one-time key download IS the screen (no inputs/buttons until it lands):
  // everything the user could press here needs these assets anyway.
  if (download.active) {
    return (
      <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
        <ScreenHeader title={title} />
        <div className="flex flex-col gap-4">
          <DownloadProgress view={download} />
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
      <ScreenHeader title={title} />
      <div className="flex flex-col gap-4">
        {isTransfer && (
          <label className="flex flex-col gap-1.5">
            <span className="text-[0.82rem] text-muted font-semibold">Recipient address</span>
            <input
              className="bg-surface border border-border rounded-xl px-3.5 py-[13px] text-ink font-mono text-[0.98rem] w-full tabular-nums focus:outline-none focus:border-primary focus:shadow-[0_0_0_3px_rgba(18,58,92,0.12)]"
              placeholder="0x… compressed bongtu pubkey"
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
            />
            {recipient.trim() && rcptErr && (
              <span className="text-[0.8rem] text-err">{rcptErr}</span>
            )}
          </label>
        )}

        <label className="flex flex-col gap-1.5">
          <span className="text-[0.82rem] text-muted font-semibold">Amount (kKRW)</span>
          <input
            className="bg-surface border border-border rounded-xl px-3.5 py-[13px] text-ink text-[0.98rem] w-full tabular-nums focus:outline-none focus:border-primary focus:shadow-[0_0_0_3px_rgba(18,58,92,0.12)]"
            inputMode="decimal"
            placeholder="0.00"
            value={amount}
            onChange={(e) => setAmount(e.target.value.replace(/[^\d.,]/g, ""))}
          />
          <span className="text-[0.78rem] text-muted">
            Balance: {balance === null ? "—" : formatKkrw(balance)} kKRW
          </span>
          {amount.trim() && amtErr && <span className="text-[0.8rem] text-err">{amtErr}</span>}
        </label>

        {error && (
          <div className="rounded-xl px-3.5 py-3 text-[0.88rem] flex gap-2.5 items-center justify-between flex-wrap border border-err-border bg-err-bg text-err">
            {error}
          </div>
        )}

        <Button
          variant="primary"
          block
          disabled={!formValid}
          onClick={() => {
            setError(null);
            setPhase("confirm");
          }}
        >
          Review {title.toLowerCase()}
        </Button>
      </div>
    </div>
  );
}
