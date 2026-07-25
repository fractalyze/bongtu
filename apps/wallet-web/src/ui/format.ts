// Small presentation helpers (PURE, no React). Amounts are raw integer field values
// (BigInt-safe decimal strings), so grouping is done on the string — never via Number,
// which would lose precision on large balances.

/** Group a non-negative integer decimal string with thousands separators. */
export function formatAmount(raw: string | bigint): string {
  let s = typeof raw === "bigint" ? raw.toString() : raw;
  const neg = s.startsWith("-");
  if (neg) s = s.slice(1);
  s = s.replace(/^0+(?=\d)/, ""); // trim leading zeros, keep a lone "0"
  const grouped = s.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return (neg ? "-" : "") + grouped;
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

/** Normalise a compressed pubkey hex for equality (lowercase, 0x-prefixed). */
export function normalizePubkey(hex: string): string {
  const h = hex.trim().toLowerCase();
  return h.startsWith("0x") ? h : "0x" + h;
}
