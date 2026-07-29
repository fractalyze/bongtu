// CSV recipient parsing gate: base58check and legacy-hex address rows must
// normalize to the SAME canonical hex (core decodeAddress is the one
// normalization point), and a typo'd address must fail with its line number —
// an employer batch is a bad place for a silently-wrong recipient.

import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveKeypair } from "@bongtu/core/note";
import { packPubkey, encodeAddress } from "@bongtu/core/pubkey";
import { parseRecipientsCsv } from "../src/lib/csv.js";

const HEX_A = packPubkey(deriveKeypair(4000000019n).publicKey);
const HEX_B = packPubkey(deriveKeypair(4001000022n).publicKey);

test("base58 rows parse to the same rows as hex rows", () => {
  const viaHex = parseRecipientsCsv(`${HEX_A},100\n${HEX_B},250`);
  const viaB58 = parseRecipientsCsv(`${encodeAddress(HEX_A)},100\n${encodeAddress(HEX_B)},250`);
  assert.deepEqual(viaB58, viaHex);
  assert.deepEqual(viaHex, [
    { pubkey: HEX_A.toLowerCase(), amount: "100" },
    { pubkey: HEX_B.toLowerCase(), amount: "250" },
  ]);
});

test("mixed base58/hex rows, header, comments and blanks", () => {
  const text = [
    "pubkey,amount", // header — skipped
    "# a comment",
    "",
    `${encodeAddress(HEX_A)},100`,
    `${HEX_B},250`,
  ].join("\n");
  assert.deepEqual(parseRecipientsCsv(text), [
    { pubkey: HEX_A.toLowerCase(), amount: "100" },
    { pubkey: HEX_B.toLowerCase(), amount: "250" },
  ]);
});

test("a tampered base58 address fails loudly with its line number", () => {
  const addr = encodeAddress(HEX_A);
  const last = addr[addr.length - 1];
  const tampered = addr.slice(0, -1) + (last === "2" ? "5" : "2");
  assert.throws(() => parseRecipientsCsv(`${addr},100\n${tampered},250`), /line 2.*could not read the address/s);
});

// ---------------------------- cell COUNT ------------------------------------------

test("a third comma is rejected, not silently truncated to the first two cells", () => {
  // The 1000x underpay: '<address>,1,000' used to parse as amount "1". The employer
  // would have paid one kKRW and had no way to see it before the chain.
  assert.throws(
    () => parseRecipientsCsv(`${HEX_A},100\n${HEX_B},1,000`),
    (e: Error) =>
      /line 2/.test(e.message) && /got 3 cells/.test(e.message) && /thousands commas/.test(e.message),
    "the line, the cell count, and the likely cause",
  );
  // …and it never reaches the row list, even though line 1 was fine.
  assert.throws(() => parseRecipientsCsv(`${HEX_A},1,000`), /line 1/);
});

test("a line missing its amount cell names the line too", () => {
  assert.throws(() => parseRecipientsCsv(`${HEX_A},100\n${HEX_B}`), /line 2.*got 1 cell/s);
});

// ---------------------------- the header heuristic --------------------------------

test("line 1 is skipped as a header only when its ADDRESS is not an address either", () => {
  // A real first payee with a rejected amount is an ERROR, not a header: dropping
  // it would drop a person from the payroll with no message at all.
  assert.throws(() => parseRecipientsCsv(`${HEX_A},1.5\n${HEX_B},250`), /line 1.*whole number/s);
  assert.throws(() => parseRecipientsCsv(`${encodeAddress(HEX_A)},1.5`), /line 1.*whole number/s);

  // Whereas neither cell being data is exactly what a header looks like —
  // whatever language the export wrote it in.
  for (const header of ["recipient address,amount", "받는 주소,금액"]) {
    assert.deepEqual(parseRecipientsCsv(`${header}\n${HEX_B},250`), [
      { pubkey: HEX_B.toLowerCase(), amount: "250" },
    ]);
  }
  // A first row that IS data survives the heuristic untouched.
  assert.deepEqual(parseRecipientsCsv(`${HEX_A},100`), [{ pubkey: HEX_A.toLowerCase(), amount: "100" }]);
});
