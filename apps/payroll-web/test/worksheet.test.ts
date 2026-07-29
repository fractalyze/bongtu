// Headless gate for the pay worksheet's pure core (lib/worksheet.ts): row
// editing rules (add/remove/cap-255), per-row validation (address decode,
// duplicates, amounts), the CSV paste fill, the injected-storage draft, and the
// footer's 3-state verdict — including the single-note vs fragmented split,
// which must come from the SAME planner the run executes.

import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveKeypair } from "@bongtu/core/note";
import { packPubkey, encodeAddress } from "@bongtu/core/pubkey";
import type { StorageLike } from "@bongtu/client/session";
import {
  MAX_ROWS,
  WORKSHEET_DRAFT_KEY,
  addRow,
  blankRow,
  checkWorksheet,
  clearDraft,
  loadDraft,
  removeRow,
  rowsFromCsv,
  saveDraft,
  sendReadiness,
  SELF_PAY_MESSAGE,
  type WorksheetRow,
} from "../src/lib/worksheet.js";

const KKRW = 10n ** 18n;
const ADDR_A = packPubkey(deriveKeypair(4000000019n).publicKey);
const ADDR_B = packPubkey(deriveKeypair(4001000022n).publicKey);
const ADDR_C = packPubkey(deriveKeypair(4002000033n).publicKey);

const row = (address: string, amount: string): WorksheetRow => ({ address, amount });
const notes = (values: bigint[]) =>
  values.map((v, i) => ({ value: v.toString(), salt: `5${i}`, leafIndex: i, spent: false }));

// ---------------------------- rows: add / remove / cap ----------------------------

test("addRow appends a blank row and refuses past the 255 cap", () => {
  assert.equal(addRow([blankRow()]).length, 2);
  const full = Array.from({ length: MAX_ROWS }, () => blankRow());
  assert.equal(addRow(full).length, MAX_ROWS, "the [+] button's rule: no 256th row");
  assert.equal(MAX_ROWS, 255, "B=256 outputs minus the employer's change slot");
});

test("removeRow drops the row but an emptied sheet keeps one blank row to type into", () => {
  const rows = [row(ADDR_A, "100"), row(ADDR_B, "200")];
  assert.deepEqual(removeRow(rows, 0), [row(ADDR_B, "200")]);
  assert.deepEqual(removeRow([row(ADDR_A, "100")], 0), [blankRow()]);
});

// ---------------------------- validation ------------------------------------------

test("valid rows normalize to canonical hex + raw wei, and total up", () => {
  const check = checkWorksheet([
    row(ADDR_A, "100"),
    row(encodeAddress(ADDR_B), "1,000.5"), // base58 + grouped decimal both legal
    blankRow(), // the [+] affordance — not data, not an error
  ]);
  assert.deepEqual(check.issues, []);
  assert.equal(check.filledCount, 2);
  assert.deepEqual(check.recipients, [
    { pubkey: ADDR_A.toLowerCase(), amount: (100n * KKRW).toString() },
    { pubkey: ADDR_B.toLowerCase(), amount: (10005n * KKRW / 10n).toString() },
  ]);
  assert.equal(check.totalWei, 100n * KKRW + 10005n * KKRW / 10n);
});

test("a malformed address is an inline address issue on its row", () => {
  const check = checkWorksheet([row(ADDR_A, "10"), row("0xnotakey", "10")]);
  assert.deepEqual(
    check.issues.map((i) => [i.index, i.field]),
    [[1, "address"]],
  );
});

test("a duplicate address is flagged on the LATER row, naming the first", () => {
  // hex and base58 forms of the same key are the same recipient — the circuit's
  // §11-8 two-time-pad guard rejects the duplicate anyway, so catch it here.
  const check = checkWorksheet([row(ADDR_A, "10"), row(encodeAddress(ADDR_A), "20")]);
  assert.equal(check.issues.length, 1);
  assert.equal(check.issues[0].index, 1);
  assert.equal(check.issues[0].field, "address");
  assert.match(check.issues[0].message, /1행/);
});

test("a row paying the logged-in employer is flagged in the cell, in either address form", () => {
  // Without this, self-pay only fails inside the terminal assemble's distinct-owner
  // guard — after every merge leg has been signed and proved.
  for (const self of [ADDR_A, encodeAddress(ADDR_A)]) {
    for (const typed of [ADDR_A, encodeAddress(ADDR_A)]) {
      const check = checkWorksheet([row(ADDR_B, "10"), row(typed, "20")], self);
      assert.deepEqual(
        check.issues.map((i) => [i.index, i.field, i.message]),
        [[1, "address", SELF_PAY_MESSAGE]],
        `self=${self.slice(0, 8)} typed=${typed.slice(0, 8)}`,
      );
    }
  }
});

test("without a session address, and for other people's addresses, nothing is flagged", () => {
  assert.deepEqual(checkWorksheet([row(ADDR_A, "10")]).issues, [], "the param is optional");
  assert.deepEqual(checkWorksheet([row(ADDR_A, "10")], ADDR_B).issues, []);
  assert.deepEqual(
    checkWorksheet([row(ADDR_A, "10")], "not an address").issues,
    [],
    "an unreadable session address disables the check, it does not break the sheet",
  );
});

test("bad amounts are inline amount issues: garbage, zero, and a half-filled row", () => {
  const check = checkWorksheet([
    row(ADDR_A, "abc"),
    row(ADDR_B, "0"),
    row(ADDR_C, ""), // half-filled: address without amount
    row("", "50"), // half-filled the other way
  ]);
  assert.deepEqual(
    check.issues.map((i) => [i.index, i.field]),
    [
      [0, "amount"],
      [1, "amount"],
      [2, "amount"],
      [3, "address"],
    ],
  );
});

test("more than 255 filled rows is an issue even if every row is individually fine", () => {
  const rows = Array.from({ length: MAX_ROWS + 1 }, (_, i) =>
    row(packPubkey(deriveKeypair(5000000000n + BigInt(i) * 1009n).publicKey), "1"),
  );
  const check = checkWorksheet(rows);
  assert.ok(check.issues.some((i) => i.message.includes(`${MAX_ROWS}`)));
});

// ---------------------------- CSV paste fill --------------------------------------

test("CSV paste fills rows through the one csv parser (base58/hex normalized)", () => {
  const rows = rowsFromCsv(`${ADDR_A},100\n${encodeAddress(ADDR_B)},250`);
  assert.deepEqual(rows, [
    { address: ADDR_A.toLowerCase(), amount: "100" },
    { address: ADDR_B.toLowerCase(), amount: "250" },
  ]);
  // …and what it fills validates exactly like typed cells (amounts are kKRW).
  const check = checkWorksheet(rows);
  assert.deepEqual(check.issues, []);
  assert.equal(check.totalWei, 350n * KKRW);
});

test("CSV paste rejects an empty paste, a bad line, and an over-cap sheet", () => {
  assert.throws(() => rowsFromCsv("# comments only\n"), /행이 없습니다/);
  assert.throws(() => rowsFromCsv(`${ADDR_A}`), /1행/);
  const over = Array.from(
    { length: MAX_ROWS + 1 },
    (_, i) => `${packPubkey(deriveKeypair(6000000000n + BigInt(i) * 1013n).publicKey)},1`,
  ).join("\n");
  assert.throws(() => rowsFromCsv(over), new RegExp(`${MAX_ROWS}`));
});

// ---------------------------- draft save/restore ----------------------------------

function memoryStorage(): StorageLike & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => void map.set(k, v),
    removeItem: (k) => void map.delete(k),
  };
}

test("the draft round-trips through the injected storage seam", () => {
  const storage = memoryStorage();
  const rows = [row(ADDR_A, "1,000"), row("half typed", "")];
  saveDraft(rows, storage);
  assert.ok(storage.map.has(WORKSHEET_DRAFT_KEY));
  assert.deepEqual(loadDraft(storage), rows, "typed cells restore verbatim, valid or not");
  clearDraft(storage);
  assert.deepEqual(loadDraft(storage), [blankRow()]);
});

test("a missing, malformed, or hostile draft restores as one blank row", () => {
  assert.deepEqual(loadDraft(null), [blankRow()]);
  assert.deepEqual(loadDraft(memoryStorage()), [blankRow()]);
  const bad = memoryStorage();
  bad.map.set(WORKSHEET_DRAFT_KEY, "{not json");
  assert.deepEqual(loadDraft(bad), [blankRow()]);
  assert.equal(bad.map.has(WORKSHEET_DRAFT_KEY), false, "malformed records are dropped");
  const wrongShape = memoryStorage();
  wrongShape.map.set(WORKSHEET_DRAFT_KEY, JSON.stringify([{ address: 5 }, { address: "a", amount: "1" }]));
  assert.deepEqual(loadDraft(wrongShape), [{ address: "a", amount: "1" }]);
});

// ---------------------------- footer 3-state --------------------------------------

const wei = (n: bigint) => n * KKRW;

test("footer: covered by a single note -> ready with zero merges", () => {
  const check = checkWorksheet([row(ADDR_A, "100"), row(ADDR_B, "200")]);
  const verdict = sendReadiness(check, notes([wei(500n), wei(10n)]));
  assert.deepEqual(verdict, { kind: "ready", mergeCount: 0 });
});

test("footer: covered but fragmented -> ready with the planner's merge count", () => {
  const check = checkWorksheet([row(ADDR_A, "300")]);
  // four notes of 100: no single note covers 300, one 10-note-max fold does.
  const verdict = sendReadiness(check, notes([wei(100n), wei(100n), wei(100n), wei(100n)]));
  assert.deepEqual(verdict, { kind: "ready-fragmented", mergeCount: 1 });
});

test("footer: insufficient -> the deposit CTA state, carrying the exact shortfall", () => {
  const check = checkWorksheet([row(ADDR_A, "300")]);
  const verdict = sendReadiness(check, notes([wei(100n), wei(50n)]));
  assert.deepEqual(verdict, { kind: "insufficient", shortfallWei: wei(150n) });
});

test("footer: a balance that has not loaded yet is its OWN state, never 부족", () => {
  // The bug this pins: null (first paint, or an unreachable indexer) read as an
  // empty balance told a funded employer they were short by the whole payroll and
  // pushed a deposit for it.
  const check = checkWorksheet([row(ADDR_A, "300")]);
  assert.deepEqual(sendReadiness(check, null), { kind: "loading" });
  assert.deepEqual(sendReadiness(check, []), { kind: "insufficient", shortfallWei: wei(300n) }, "an actually EMPTY balance is still 부족");
  // …and the verdict never claims sendability while the balance is unknown.
  for (const rows of [[blankRow()], [row(ADDR_A, "300")], [row("bad", "10")]]) {
    assert.equal(sendReadiness(checkWorksheet(rows), null).kind, "loading");
  }
});

test("footer: issues or an empty sheet block the send outright", () => {
  assert.deepEqual(sendReadiness(checkWorksheet([blankRow()]), notes([wei(500n)])), { kind: "blocked" });
  assert.deepEqual(
    sendReadiness(checkWorksheet([row("bad address", "10")]), notes([wei(500n)])),
    { kind: "blocked" },
  );
});
