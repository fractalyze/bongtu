// Stealth KDF + funds-discovery gates: determinism, separation from the
// spending KDF, and the local recompute-before-trust rule discovery lives by.

import { test } from "node:test";
import assert from "node:assert/strict";

import { SUBGROUP_ORDER } from "@bongtu/core/babyjub";
import { SECP256K1_ORDER, deriveStealthAddress, scanStealthAnnouncement } from "@bongtu/core/stealth";
import { scalarFromSignature } from "@bongtu/client/derive";
import type { KeyDerivationTypedData } from "@bongtu/client-evm/derive";
import type { Connection } from "@bongtu/client-evm/connection";
import {
  prepareStealthDestination,
  stealthKeysFromKdfSignature,
  stealthKeyTypedData,
} from "@bongtu/client-evm/stealthKeys";
import { discoverStealthFunds, exportStealthFundKey } from "@bongtu/client-evm/stealthFunds";
import { KEY_DERIVATION } from "@bongtu/client/identity";
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

test("the stealth KDF version lives in the deployment KDF config, pinned at 1", () => {
  // ONE home for the domain facts (identity.ts KEY_DERIVATION): rotating this
  // value orphans announced-but-unswept addresses, so it is pinned beside
  // keyVersion, never carried by the stealth module itself.
  assert.equal(KEY_DERIVATION.stealthKeyVersion, "1");
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

// prepareStealthDestination only ever hands the connection to the injected
// sign, so a bare cast is the entire fake wallet.
const CONNECTION = {} as Connection;

test("prepareStealthDestination: the paid address IS what the view key rediscovers from the announced R", async () => {
  const signed: KeyDerivationTypedData[] = [];
  const sign = async (_c: Connection, typed: KeyDerivationTypedData): Promise<string> => {
    signed.push(typed);
    return SIG;
  };
  const d = await prepareStealthDestination(CONNECTION, { sign });
  // The seam signed the STEALTH struct — a spending-key signature here would
  // derive addresses no later scan could ever reproduce.
  assert.equal(signed.length, 1);
  assert.equal(signed[0].primaryType, "BongtuStealthKey");
  // THE invariant, headless: re-derive the view key from the SAME signature and
  // reproduce the destination from nothing but the announcement half.
  const keys = stealthKeysFromKdfSignature(SIG);
  const rescanned = scanStealthAnnouncement(keys.viewPriv, keys.meta.spendPub, d.ephemeralPub);
  assert.equal(rescanned.address, d.address);
  assert.equal(rescanned.viewTag, d.viewTag);
});

test("prepareStealthDestination: keys supplied through getKeys (the lock's path) sign nothing", async () => {
  // The wallet hands the meta keys in from its lock (keyCache.unlockStealth):
  // the derivation-with-popup default must then never run — same invariant,
  // different supply.
  const keys = stealthKeysFromKdfSignature(SIG);
  const sign = async (): Promise<string> => {
    throw new Error("an unlocked wallet must not be asked to sign");
  };
  const d = await prepareStealthDestination(CONNECTION, {
    sign,
    getKeys: async () => keys,
    drawEphemeral: () => 555555555n,
  });
  const rescanned = scanStealthAnnouncement(keys.viewPriv, keys.meta.spendPub, d.ephemeralPub);
  assert.equal(rescanned.address, d.address);
  assert.equal(rescanned.viewTag, d.viewTag);
});

test("prepareStealthDestination: a pinned ephemeral is used verbatim; the default draw is fresh per call", async () => {
  const sign = async (): Promise<string> => SIG;
  const keys = stealthKeysFromKdfSignature(SIG);
  const pinned = await prepareStealthDestination(CONNECTION, { sign, drawEphemeral: () => 777777777n });
  assert.deepEqual(pinned, deriveStealthAddress(keys.meta, 777777777n));
  // No draw seam: WebCrypto entropy — two runs must never announce (or pay)
  // the same one-time place.
  const a = await prepareStealthDestination(CONNECTION, { sign });
  const b = await prepareStealthDestination(CONNECTION, { sign });
  assert.notEqual(a.ephemeralPub, b.ephemeralPub);
  assert.notEqual(a.address, b.address);
});
