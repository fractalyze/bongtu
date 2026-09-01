// Small presentation helpers (PURE, no React): what a form says about what the user
// typed, and how a value reads on screen. Money formatting/PARSING itself lives in
// @bongtu/client/money (the single raw-wei <-> kKRW edge) — amountError below only judges
// what that parser returns.

import { decodeAddress } from "@bongtu/core/pubkey";
import { normalizeName } from "@bongtu/client/indexerClient";
import { parseKkrw } from "@bongtu/client/money";

/**
 * Why an amount can't be spent yet, or null when it can: the parse rules (money.ts —
 * ≤6 fraction digits, 2^100 belt), positivity, and the balance it must fit inside.
 * `tooMuch` names WHICH balance — the private one for a spend, the account's public
 * kKRW for a deposit. A null balance means "not loaded yet" and cannot judge: the
 * screens keep their own Continue-button guard for that.
 */
export function amountError(
  raw: string,
  balance: bigint | null,
  tooMuch = "Amount exceeds your balance.",
): string | null {
  const p = parseKkrw(raw);
  if (!p.ok) return p.error;
  if (p.wei <= 0n) return "Amount must be greater than zero.";
  if (balance !== null && p.wei > balance) return tooMuch;
  return null;
}

/** Shorten a compressed bjj pubkey / address for display: `0x05c818…1f96`. */
export function shortenPubkey(hex: string): string {
  const h = hex.trim();
  if (h.length <= 14) return h;
  return `${h.slice(0, 8)}…${h.slice(-4)}`;
}

/** Relative time from a unix-seconds timestamp: "just now", "12 min ago", "3h ago",
 *  "5d ago", else a locale date. */
export function relativeTime(unixSeconds: number): string {
  const diff = Math.max(0, Date.now() / 1000 - unixSeconds);
  if (diff < 45) return "just now";
  if (diff < 90) return "1 min ago";
  const mins = Math.round(diff / 60);
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(diff / 3600);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(diff / 86400);
  if (days < 7) return `${days}d ago`;
  return new Date(unixSeconds * 1000).toLocaleDateString();
}

/**
 * The download card's subtitle: sized from the REAL asset total when known
 * (config.CIRCUIT_ASSET_BYTES via the live download view — the per-circuit
 * bundles differ, so no hardcoded number), size-free while the total is still
 * unknown (first render before the byte counts arrive).
 */
export function downloadOnceSubtitle(totalBytes: number | null): string {
  const base = "Runs on your device. Downloads only once";
  if (totalBytes === null || totalBytes <= 0) return base;
  return `${base} (${Math.round(totalBytes / (1024 * 1024))} MB)`;
}

/**
 * The pay-by-name reading of a recipient input, or null when the input is meant
 * as an address. Name vs address is unambiguous BY LENGTH: a name normalizes to
 * <=32 chars (core normalizeName, the one grammar the registry registers under),
 * while both address encodings are longer — legacy hex is 0x + 64 chars,
 * base58check 51 — so no address can ever normalize into a name. The extra 0x
 * guard is intent, not disambiguation: a "0x…" input declares an ADDRESS, and a
 * fat-fingered hex address must die on the checksum below, not quietly turn
 * into a directory lookup for someone else's short name.
 */
export function recipientName(raw: string): string | null {
  const v = raw.trim();
  if (v.startsWith("0x") || v.startsWith("0X")) return null;
  return normalizeName(v);
}

/**
 * Reject an obviously-bad recipient before proving (the pure spend.ts rejects it
 * too, but a 28 MB proof is a bad place to learn you fat-fingered a key).
 * A name-shaped input (recipientName above) passes as-is: whether the name is
 * actually REGISTERED is the Continue-time resolve step's judgment, not a form
 * shape's. Everything else goes to decodeAddress — the one normalization point:
 * it accepts base58check AND legacy hex, and its checksum catches typos. The
 * address is judged on its own: sending to YOUR OWN address is allowed, since
 * the transfer circuit's per-output receiver nonce (§11-8 v1.1, U-X3) removed
 * the two-time pad that used to make a self-send unsafe — which is why this
 * takes no self-pubkey to compare against.
 */
export function recipientError(raw: string): string | null {
  const v = raw.trim();
  if (!v) return "Enter a recipient.";
  if (recipientName(v) !== null) return null;
  try {
    decodeAddress(v);
  } catch {
    return "That doesn't look like a valid bongtu address.";
  }
  return null;
}
