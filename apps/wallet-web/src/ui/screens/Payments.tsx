// Received payments (hash route #/payments): the per-payment rows behind the
// wallet's receive identity — one row per pay-page issuance that was actually
// funded, with the status ladder received -> swept -> shielded (design canvas
// "Stealth Receive Screens", Payments artboard). Every read is a PUBLIC
// endpoint: the attribution-free announce feed, the wallet's OWN view-key scan
// deciding which rows are ours (lib/payments.ts), the token balance for
// unswept rows, and the self-scan's note set for the shielded flip — the
// consumer wallet's tokenless/no-arbiter contract holds through this screen.
//
// The stealth unlock (view key) rides keyCache like every other key use: it
// takes the page's one-op slot while it may pop a signature, and the derived
// keys never live in this component past the fold.

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import type { Address } from "viem";
import { parseAbi } from "viem";

import { getPortalAnnouncements } from "@bongtu/core/indexerApi";
import { ERC20_ABI_FRAGMENTS } from "@bongtu/core/network";
import { formatToken } from "@bongtu/client/money";
import { keyCache } from "@bongtu/ui/keyCache";

import { DEFAULTS, TOKEN } from "../../config.js";
import { consumerErrorMessage } from "../../lib/errors.js";
import {
  buildPaymentRows,
  shortDestination,
  type PaymentRow,
  type PaymentStatus,
} from "../../lib/payments.js";
import { opGate, OP_IN_FLIGHT_MESSAGE } from "../actionMachine.js";
import { useWallet } from "../App.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { IconReceived, IconShieldCheck } from "../components/icons.js";
import { Banner } from "@bongtu/ui/Banner";

const BALANCE_ABI = parseAbi([ERC20_ABI_FRAGMENTS.balanceOf]);

/** The status pill's words + treatment (the design's three states). */
const STATUS_PILL: Record<PaymentStatus, { label: string; className: string }> = {
  received: { label: "Received", className: "bg-surface-2 text-muted" },
  swept: { label: "Shielding", className: "bg-surface-2 text-muted" },
  shielded: { label: "Shielded", className: "bg-primary text-white" },
};

const EMPTY_LINE = "No payments yet. Share your payment name — each payment arrives at a fresh address.";

function Row({ row }: { row: PaymentRow }): ReactNode {
  const pill = STATUS_PILL[row.status];
  const at = new Date(row.createdAt * 1000);
  return (
    <div className="flex items-center gap-3 py-[11px] border-t border-border">
      <span
        className={`w-[34px] h-[34px] rounded-full grid place-items-center flex-none ${
          row.status === "shielded" ? "bg-pos-bg text-pos" : "bg-surface-2 text-muted"
        }`}
      >
        {row.status === "shielded" ? <IconShieldCheck size={16} /> : <IconReceived size={16} />}
      </span>
      <span className="flex-1 min-w-0 flex flex-col gap-0.5">
        <span className="font-semibold text-[0.92rem]">Payment received</span>
        <span className="font-mono text-[0.74rem] text-muted overflow-hidden text-ellipsis whitespace-nowrap" title={row.destination}>
          {shortDestination(row.destination)} · {at.toLocaleDateString()} {at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
        </span>
      </span>
      <span className="flex flex-col items-end gap-1 flex-none">
        <span className="font-bold tabular-nums text-[0.92rem] leading-[1.25] text-pos">
          +{formatToken(row.amount, TOKEN.decimals)}
          <span className="text-muted font-semibold text-[0.72rem] ml-1">{TOKEN.symbol}</span>
        </span>
        <span className={`rounded-full px-2 py-0.5 text-[0.68rem] font-semibold ${pill.className}`}>
          {pill.label}
        </span>
      </span>
    </div>
  );
}

export function Payments(): ReactNode {
  const { connection, session, notes, indexerUrl } = useWallet();
  const [rows, setRows] = useState<PaymentRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!connection || !session) return;
    const alive = { current: true };
    // The stealth unlock may pop a wallet signature: same one-op-slot rule as
    // every other signature train (Receive's register precedent). A busy gate
    // is a message here, not a queue — navigating back re-runs the effect.
    const opToken = Symbol("payments-scan");
    if (!opGate.tryAcquire(opToken)) {
      setError(OP_IN_FLIGHT_MESSAGE);
      return;
    }
    void (async () => {
      try {
        const stealth = await keyCache.unlockStealth(connection, session.compressedPubkey);
        const records = await getPortalAnnouncements(indexerUrl);
        const noteTxHashes = new Set(notes.map((n) => n.txHash));
        const built = await buildPaymentRows(
          records,
          { viewPriv: stealth.viewPriv, spendPub: stealth.meta.spendPub },
          noteTxHashes,
          async (destination) =>
            (await connection.publicClient.readContract({
              address: DEFAULTS.token as Address,
              abi: BALANCE_ABI,
              functionName: "balanceOf",
              args: [destination as Address],
            })) as bigint,
        );
        if (!alive.current) return;
        setRows(built);
        setError(null);
      } catch (e) {
        if (!alive.current) return;
        setError(consumerErrorMessage(e));
      } finally {
        opGate.release(opToken);
      }
    })();
    return () => {
      alive.current = false;
    };
  }, [connection, session, notes, indexerUrl]);

  return (
    <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
      <ScreenHeader title="Payments" />
      {error && <Banner message={error} />}
      <p className="text-muted text-[0.85rem] px-0.5">
        Each payment arrives at its own fresh address; nothing on-chain links them to you.
      </p>
      <div className="bg-surface border border-border rounded-xl px-4 pb-1">
        {rows === null && !error && <p className="text-muted text-sm py-4">Scanning…</p>}
        {rows !== null && rows.length === 0 && <p className="text-muted text-sm py-4">{EMPTY_LINE}</p>}
        {rows !== null && rows.map((row) => <Row key={row.seq} row={row} />)}
      </div>
      {rows !== null && rows.length > 0 && (
        <p className="text-muted text-[0.8rem] px-0.5">
          Once shielded, a payment joins your balance and its onward use is invisible on-chain.
        </p>
      )}
    </div>
  );
}
