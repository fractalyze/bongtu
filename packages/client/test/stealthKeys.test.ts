// Stealth KDF + funds-discovery gates: determinism, separation from the
// spending KDF, and the local recompute-before-trust rule discovery lives by.

import { test } from "node:test";
import assert from "node:assert/strict";

import { SUBGROUP_ORDER } from "@bongtu/core/babyjub";
import { SECP256K1_ORDER, deriveStealthAddress } from "@bongtu/core/stealth";
import { scalarFromSignature } from "../src/derive.js";
import { stealthKeysFromKdfSignature, stealthKeyTypedData } from "../src/stealthKeys.js";
import { discoverStealthFunds, exportStealthFundKey } from "../src/stealthFunds.js";
import type { WithdrawAnnouncementRecord } from "@bongtu/core/indexerApi";

// A syntactically valid 65-byte signature hex (deterministic test input).
const SIG = "0x" + "ab".repeat(64) + "1b";

test("stealth KDF: deterministic, in-range, and both scalars differ", () => {
  const a = stealthKeysFromKdfSignature(SIG);
  const b = stealthKeysFromKdfSignature(SIG);
  assert.deepEqual(a.meta, b.meta);
  assert.ok(a.viewPriv > 0n && a.viewPriv < SUBGROUP_ORDER);
  assert.ok(a.spendPriv > 0n && a.spendPriv < SECP256K1_ORDER);
  assert.notEqual(a.viewPriv, a.spendPriv);
});

test("stealth KDF is separated from the spending KDF over the same signature", () => {
  const stealth = stealthKeysFromKdfSignature(SIG);
  const spending = scalarFromSignature(SIG);
  assert.notEqual(stealth.viewPriv, spending);
  assert.notEqual(stealth.spendPriv, spending);
});

test("the stealth struct is a distinct EIP-712 primary type", () => {
  const typed = stealthKeyTypedData(84532, "0x" + "11".repeat(20), "1");
  assert.equal(typed.primaryType, "BongtuStealthKey");
  assert.ok(typed.types.BongtuStealthKey);
});

function record(partial: Partial<WithdrawAnnouncementRecord>): WithdrawAnnouncementRecord {
  return {
    seq: 0, txHash: "0xaa", blockNumber: 1,
    recipient: "0x" + "00".repeat(20),
    ephemeralPub: "0x" + "00".repeat(32),
    viewTag: 0,
    ...partial,
  };
}

test("discovery keeps only records the view key reproduces, and prices them", async () => {
  const keys = stealthKeysFromKdfSignature(SIG);
  const other = stealthKeysFromKdfSignature("0x" + "cd".repeat(64) + "1c");
  const mine = deriveStealthAddress(keys.meta, 777777777n);
  const notMine = deriveStealthAddress(other.meta, 888888888n);

  const feed: WithdrawAnnouncementRecord[] = [
    record({ seq: 1, txHash: "0xmine", recipient: mine.address, ephemeralPub: mine.ephemeralPub, viewTag: mine.viewTag }),
    record({ seq: 2, txHash: "0xother", recipient: notMine.address, ephemeralPub: notMine.ephemeralPub }),
    record({ seq: 3, txHash: "0xplain" }), // zero ephemeral: plain withdraw, skipped
    // Tampered: my R but someone else's recipient — must NOT be claimed.
    record({ seq: 4, txHash: "0xtamper", recipient: notMine.address, ephemeralPub: mine.ephemeralPub }),
    record({ seq: 5, txHash: "0xgarbage", recipient: mine.address, ephemeralPub: "0x" + "ff".repeat(32) }),
  ];
  const { funds, total } = await discoverStealthFunds(keys, {
    fetchMine: async () => feed,
    balanceOf: async (addr) => (addr === mine.address ? 12345n : 0n),
  });
  assert.equal(funds.length, 1);
  assert.equal(funds[0].address, mine.address);
  assert.equal(funds[0].balance, 12345n);
  assert.equal(total, 12345n);
});

test("the exported key controls exactly the discovered address", () => {
  const keys = stealthKeysFromKdfSignature(SIG);
  const sent = deriveStealthAddress(keys.meta, 424242424242n);
  const rec = exportStealthFundKey(keys, sent.ephemeralPub);
  assert.equal(rec.address, sent.address);
  assert.match(rec.privateKey, /^0x[0-9a-f]{64}$/);
});
