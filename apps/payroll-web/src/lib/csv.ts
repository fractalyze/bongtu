// CSV -> recipient rows. One convenience input for the employer recipients editor
// (the form is the other); NOT required. Format: EXACTLY two comma-separated
// columns `pubkey,amount` per line, where pubkey is a bongtu address —
// base58check OR legacy 32-byte hex, both normalized here to canonical hex via the
// core decodeAddress (the ONE address normalization point). A header row naming a
// "pubkey"/"amount"-ish column is skipped; blank lines and `#` comments ignored.
//
// Every rejection names its line number and is worded for the operator, because a
// payroll is the worst place to learn about a parse rule from a stack trace.

import { decodeAddress } from "@bongtu/core/pubkey";

import type { RecipientRow } from "./disburse.js";

/** Amounts are whole kKRW here (a pasted export, not a typed cell). */
const isWholeAmount = (cell: string | undefined): boolean => cell !== undefined && /^\d+$/.test(cell);

/** Whether a cell reads as a bongtu address at all — the header heuristic's real
 *  question, and the reason it cannot be asked of the amount cell alone. */
function isAddressCell(cell: string | undefined): boolean {
  if (cell === undefined) return false;
  try {
    decodeAddress(cell);
    return true;
  } catch {
    return false;
  }
}

export function parseRecipientsCsv(text: string): RecipientRow[] {
  const rows: RecipientRow[] = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) return;
    const parts = line.split(",").map((p) => p.trim());

    // A header row is skipped only when NEITHER cell is data. The amount cell alone
    // cannot decide it: `<address>,1.5` is a real payee whose amount breaks the
    // whole-kKRW rule, and dropping it as a "header" would silently drop a person.
    if (i === 0 && parts.length === 2 && !isAddressCell(parts[0]) && !isWholeAmount(parts[1])) return;

    // Cell COUNT is checked before the cells: `<address>,1,000` splits into three,
    // and reading just the first two would pay 1 kKRW instead of 1,000 — a 1000x
    // underpay that nothing downstream can notice.
    if (parts.length !== 2) {
      throw new Error(
        `CSV line ${i + 1}: expected the two cells "address,amount", got ${parts.length} cells.` +
          (parts.length > 2 ? " Remove thousands commas from the amount, or quote it." : ""),
      );
    }

    const [pubkey, amount] = parts;
    if (!isWholeAmount(amount)) {
      throw new Error(
        `CSV line ${i + 1}: the amount must be a whole number of kKRW (0 or more). Got: ${JSON.stringify(amount)}`,
      );
    }
    // Normalize base58check/hex here so downstream (assembly, the editor table)
    // only ever sees canonical hex — and a typo'd address fails with its line number.
    let canonical: string;
    try {
      canonical = decodeAddress(pubkey);
    } catch (e) {
      throw new Error(`CSV line ${i + 1}: could not read the address. (${(e as Error).message})`);
    }
    rows.push({ pubkey: canonical, amount });
  });
  return rows;
}
