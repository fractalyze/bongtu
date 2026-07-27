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
  assert.throws(() => parseRecipientsCsv(`${addr},100\n${tampered},250`), /line 2.*bad address/s);
});
