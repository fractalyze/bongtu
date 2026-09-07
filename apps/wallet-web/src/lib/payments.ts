// The received-payments fold: from the PUBLIC announce feed to the per-payment
// rows the Payments screen renders. Pure of React and of transport — the feed
// page, the wallet's stealth keys, the discovered-note set and the balance
// reader all enter as arguments, so the whole decision table gates headlessly
// (test/payments.test.ts).
//
// WHY EVERY INPUT IS PUBLIC-ENDPOINT DATA: the feed serves no attribution
// (spec R4), so ownership is decided HERE, by the wallet's own view key
// re-deriving each announcement (scanStealthAnnouncement) — the consumer
// wallet's tokenless/no-arbiter contract holds through this screen.
//
// The status ladder (spec R6): `received` (funded destination, sweep not yet
// landed) -> `swept` (the factory swept it; the note is minted but this
// wallet's self-scan has not surfaced it yet) -> `shielded` (the self-scan
// found the note: it is in the balance). An UNFUNDED unswept row — a pay-page
// visit that never paid, or spam — is dropped entirely: rendering it would
// show phantom incoming money.

import type { PortalPublicRecord } from "@bongtu/core/indexerApi";
import { isStealthAnnouncement, scanStealthAnnouncement } from "@bongtu/core/stealth";

export type PaymentStatus = "received" | "swept" | "shielded";

export interface PaymentRow {
  seq: number;
  /** the CREATE2 destination the payer funded (what the row names). */
  destination: string;
  /** decimal token amount: the swept amount, or the live balance for a
   *  not-yet-swept payment. */
  amount: string;
  status: PaymentStatus;
  /** unix seconds (issuance server clock / sweep block time for backfills). */
  createdAt: number;
  sweptTxHash: string | null;
}

/** The two key halves the ownership scan needs — from the wallet's stealth
 *  unlock, never persisted here. */
export interface ScanKeys {
  viewPriv: bigint;
  /** compressed secp256k1 stealth SPEND pubkey (meta.spendPub). */
  spendPub: string;
}

/** Is this (attribution-free) announcement OURS? The view key recomputes the
 *  (viewTag, address) the ephemeral would have produced for this identity;
 *  both must match. Malformed rows (the unauthenticated announce surface can
 *  hold garbage) are simply not ours — never a throw. */
export function isOwnAnnouncement(keys: ScanKeys, record: PortalPublicRecord): boolean {
  if (!isStealthAnnouncement(record.ephemeralPub)) return false;
  const scanned = ((): { viewTag: number; address: string } | null => {
    try {
      return scanStealthAnnouncement(keys.viewPriv, keys.spendPub, record.ephemeralPub);
    } catch {
      return null; // a well-formed-looking ephemeral that still fails to unpack
    }
  })();
  return (
    scanned !== null &&
    scanned.viewTag === record.viewTag &&
    scanned.address.toLowerCase() === record.stealthAddr.toLowerCase()
  );
}

/**
 * Fold the feed into this wallet's rows, newest first. `noteTxHashes` is the
 * self-scan's discovered-note tx set — a swept row whose sweep tx has surfaced
 * there is `shielded` (the mint is in the balance); `readBalance` is consulted
 * ONLY for unswept rows (funded => `received`, unfunded => dropped).
 */
export async function buildPaymentRows(
  records: PortalPublicRecord[],
  keys: ScanKeys,
  noteTxHashes: ReadonlySet<string>,
  readBalance: (destination: string) => Promise<bigint>,
): Promise<PaymentRow[]> {
  const own = records.filter((r) => isOwnAnnouncement(keys, r));
  const rows: PaymentRow[] = [];
  for (const r of own) {
    if (r.swept) {
      rows.push({
        seq: r.seq,
        destination: r.destination,
        amount: r.sweptAmount ?? "0",
        status: r.sweptTxHash !== null && noteTxHashes.has(r.sweptTxHash) ? "shielded" : "swept",
        createdAt: r.createdAt,
        sweptTxHash: r.sweptTxHash,
      });
      continue;
    }
    const balance = await readBalance(r.destination);
    if (balance === 0n) continue; // unfunded issuance: noise, not money
    rows.push({
      seq: r.seq,
      destination: r.destination,
      amount: balance.toString(),
      status: "received",
      createdAt: r.createdAt,
      sweptTxHash: null,
    });
  }
  return rows.sort((a, b) => b.seq - a.seq);
}

/** "0x7f3A…9c4E" — the row's destination form. */
export function shortDestination(addr: string): string {
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

/** The shareable per-recipient payment link (spec R1): the pay page's /p route
 *  over the registered name. One joiner so the wallet and any future surface
 *  agree on the shape (trailing-slash tolerant). */
export function paymentLink(payBaseUrl: string, name: string): string {
  return `${payBaseUrl.replace(/\/$/, "")}/p/${name}`;
}
