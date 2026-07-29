// The pay worksheet's PURE core: row editing rules, per-row validation, and the
// footer's 3-state readiness verdict. Framework-free so the whole table's
// behavior gates headlessly (test/worksheet.test.ts); the Console view only
// renders what these functions decide. Rows come from the random generator
// (lib/randomRecipients.ts) and stay editable — nothing here persists them: a
// test worksheet is regenerated, not drafted.
//
// Amounts are typed in kKRW (the wallet's money grammar — @bongtu/client/money
// parseKkrw/formatKkrw, 18 decimals) and validated to raw wei here; the disburse
// builder and the merge planner only ever see wei. Addresses are bongtu addresses
// (base58check or legacy 32-byte hex), normalized to canonical hex through the
// sdk's ONE normalization point (decodeAddress) — the same rule the wallet's
// recipient field applies.

import { decodeAddress } from "@bongtu/core/pubkey";
import { parseKkrw } from "@bongtu/client/money";
import { planDisburseChain, SpendSelectionError, type SelectableNote } from "@bongtu/client/spend";
import type { RecipientRow } from "./disburse.js";

/** One worksheet row, exactly as typed (validation never rewrites the cells). */
export interface WorksheetRow {
  address: string;
  amount: string;
}

/** B = 256 outputs per disburse, and ONE slot is reserved for the employer's
 *  change note — so a worksheet holds at most 255 recipients. */
export const MAX_ROWS = 255;

export const blankRow = (): WorksheetRow => ({ address: "", amount: "" });

/** Remove row `i`. Deleting the last row leaves an EMPTY list — the view
 *  renders zero rows as the generator's empty state, not a blank cell. */
export function removeRow(rows: WorksheetRow[], i: number): WorksheetRow[] {
  return rows.filter((_, j) => j !== i);
}

/** A row-anchored problem, worded for the cell it belongs to. */
export interface RowIssue {
  index: number;
  field: "address" | "amount";
  message: string;
}

/** What validation makes of the worksheet: the issues to show inline, the
 *  builder-ready recipient list (canonical hex + raw wei — only meaningful when
 *  there are no issues), and the total the footer verdict is computed against. */
export interface WorksheetCheck {
  issues: RowIssue[];
  /** rows that carry anything at all (blank rows are neither errors nor rows). */
  filledCount: number;
  recipients: RecipientRow[];
  totalWei: bigint;
}

/** Paying yourself is refused by the disburse assembly's distinct-owner guard —
 *  but only at the very end, after every merge leg has been signed. */
export const SELF_PAY_MESSAGE = "You can't pay your own address.";

/**
 * Validate every filled row: address must decode (base58check/hex -> canonical
 * hex), amount must parse as positive kKRW, and no two rows may pay the same
 * address — a duplicate owner is rejected by the circuit's §11-8 two-time-pad
 * guard anyway, so it is caught here with a row number instead of at prove time.
 * A fully blank row is skipped (it is the [+] affordance, not data); a
 * half-filled one is an error on its empty half.
 *
 * `selfAddress` is the logged-in employer's own address when the caller knows it
 * (the Console passes the session pubkey). A row paying it is flagged inline for
 * the same reason duplicates are: assembly rejects it, and by then the operator
 * has already sat through the merges and signed for them.
 */
export function checkWorksheet(rows: WorksheetRow[], selfAddress?: string): WorksheetCheck {
  const issues: RowIssue[] = [];
  const recipients: RecipientRow[] = [];
  const seen = new Map<string, number>(); // canonical address -> first row index
  let totalWei = 0n;
  let filledCount = 0;
  // Compared in canonical form, so the employer's own address is caught whichever
  // way either side spells it (hex or base58check).
  let self: string | null = null;
  if (selfAddress !== undefined && selfAddress.trim() !== "") {
    try {
      self = decodeAddress(selfAddress);
    } catch {
      self = null; // an unreadable session address only disables this one check
    }
  }

  rows.forEach((row, index) => {
    const address = row.address.trim();
    const amount = row.amount.trim();
    if (address === "" && amount === "") return; // blank row — not data
    filledCount++;

    let canonical: string | null = null;
    if (address === "") {
      issues.push({ index, field: "address", message: "Enter a recipient address." });
    } else {
      try {
        canonical = decodeAddress(address);
      } catch {
        issues.push({ index, field: "address", message: "Not a valid bongtu address." });
      }
    }
    if (canonical !== null && canonical === self) {
      issues.push({ index, field: "address", message: SELF_PAY_MESSAGE });
    }
    if (canonical !== null) {
      const first = seen.get(canonical);
      if (first !== undefined) {
        issues.push({ index, field: "address", message: `Same address as row ${first + 1}.` });
      } else {
        seen.set(canonical, index);
      }
    }

    let wei: bigint | null = null;
    if (amount === "") {
      issues.push({ index, field: "amount", message: "Enter an amount." });
    } else {
      const parsed = parseKkrw(amount);
      if (!parsed.ok) {
        issues.push({ index, field: "amount", message: "Enter a valid amount, like 1000 or 1.5." });
      } else if (parsed.wei <= 0n) {
        issues.push({ index, field: "amount", message: "Enter an amount above zero." });
      } else {
        wei = parsed.wei;
      }
    }

    if (canonical !== null && wei !== null) {
      recipients.push({ pubkey: canonical, amount: wei.toString() });
      totalWei += wei;
    }
  });

  if (filledCount > MAX_ROWS) {
    issues.push({
      index: MAX_ROWS,
      field: "address",
      message: `At most ${MAX_ROWS} payees per run.`,
    });
  }
  return { issues, filledCount, recipients, totalWei };
}

// --- the footer's verdict ---------------------------------------------------------

/** What the footer may do right now. `loading` is "the balance is not known yet";
 *  `blocked` is "fix the sheet first" (issues, or nothing typed); the other three
 *  are the LOCKED 3-state design: covered by one note -> send; covered but
 *  fragmented -> send, the run inserts merge legs; not covered -> the deposit
 *  call-to-action takes over, with the shortfall. */
export type SendReadiness =
  | { kind: "loading" }
  | { kind: "blocked" }
  | { kind: "ready"; mergeCount: 0 }
  | { kind: "ready-fragmented"; mergeCount: number }
  | { kind: "insufficient"; shortfallWei: bigint };

/**
 * Decide the footer state from the validated sheet and the live balance. The
 * single-vs-fragmented split comes from the SAME planner the run will execute
 * (@bongtu/client planDisburseChain), so the footer can promise "N merges, then
 * the payout" and the run delivers exactly that — the verdict and the plan
 * cannot drift.
 *
 * `notes === null` means the balance has NOT been read yet — the first paint, or an
 * indexer the console cannot reach. That is its own verdict, never an empty wallet:
 * reading "not loaded" as "zero" would tell a fully funded employer they are short
 * by the entire payroll, and push a deposit they do not need.
 */
export function sendReadiness(check: WorksheetCheck, notes: SelectableNote[] | null): SendReadiness {
  if (notes === null) return { kind: "loading" };
  if (check.filledCount === 0 || check.issues.length > 0 || check.totalWei <= 0n) {
    return { kind: "blocked" };
  }
  try {
    const plan = planDisburseChain(notes, check.totalWei.toString());
    return plan.merges.length === 0
      ? { kind: "ready", mergeCount: 0 }
      : { kind: "ready-fragmented", mergeCount: plan.merges.length };
  } catch (e) {
    if (e instanceof SpendSelectionError && e.blocker === "insufficient") {
      const unspent = notes.filter((n) => !n.spent).reduce((s, n) => s + BigInt(n.value), 0n);
      return { kind: "insufficient", shortfallWei: check.totalWei - unspent };
    }
    throw e;
  }
}
