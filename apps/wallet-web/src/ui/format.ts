// Small presentation helpers (PURE, no React). Money formatting/parsing lives in
// src/lib/money.ts (the single raw-wei <-> kKRW edge); these are the non-money bits.

import { decodeAddress } from "@bongtu/core/pubkey";

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
  const base = "Runs on your device — downloads once";
  if (totalBytes === null || totalBytes <= 0) return base;
  return `${base} (${Math.round(totalBytes / (1024 * 1024))} MB)`;
}

/**
 * Reject an obviously-bad recipient before proving (the pure spend.ts rejects it
 * too, but a 28 MB proof is a bad place to learn you fat-fingered a key).
 * decodeAddress is the one normalization point — it accepts base58check AND
 * legacy hex, and its checksum catches typos. The address is judged on its own:
 * sending to YOUR OWN address is allowed, since the transfer circuit's per-output
 * receiver nonce (§11-8 v1.1, U-X3) removed the two-time pad that used to make a
 * self-send unsafe — which is why this takes no self-pubkey to compare against.
 */
export function recipientError(raw: string): string | null {
  const v = raw.trim();
  if (!v) return "Enter a recipient.";
  try {
    decodeAddress(v);
  } catch {
    return "That doesn't look like a valid bongtu address.";
  }
  return null;
}
