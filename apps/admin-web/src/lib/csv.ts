// CSV -> recipient rows. One convenience input for the employer recipients editor
// (the form is the other); NOT required. Format: two columns `pubkey,amount` per
// line, where pubkey is a compressed bjj pubkey (32-byte hex). A header row naming
// a "pubkey"/"amount"-ish column is skipped; blank lines and `#` comments ignored.

import type { RecipientRow } from "./disburse.js";

export function parseRecipientsCsv(text: string): RecipientRow[] {
  const rows: RecipientRow[] = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) return;
    const parts = line.split(",").map((p) => p.trim());
    if (parts.length < 2) throw new Error(`CSV line ${i + 1}: expected "pubkey,amount", got ${JSON.stringify(raw)}`);
    const [pubkey, amount] = parts;
    // Skip an obvious header row (first line whose amount is not a number).
    if (i === 0 && !/^\d+$/.test(amount)) return;
    if (!/^\d+$/.test(amount)) throw new Error(`CSV line ${i + 1}: amount must be a non-negative integer, got ${JSON.stringify(amount)}`);
    rows.push({ pubkey, amount });
  });
  return rows;
}
