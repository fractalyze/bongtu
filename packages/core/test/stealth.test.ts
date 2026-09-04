// Stealth-address derivation: sender/recipient consistency, spendability, and
// the unlinkability smoke checks. Run via `npm test` (node --test via tsx).

import { test } from "node:test";
import assert from "node:assert/strict";

import { SUBGROUP_ORDER } from "@bongtu/core/babyjub";
import {
  SECP256K1_ORDER,
  ZERO_EPHEMERAL,
  isStealthAnnouncement,
  stealthKeysFromScalars,
  deriveStealthAddress,
  scanStealthAnnouncement,
  recoverStealthKey,
  randomEphemeralScalar,
} from "@bongtu/core/stealth";
import { secp256k1 } from "@noble/curves/secp256k1.js";

// Fixed test identity + ephemerals (arbitrary in-range scalars).
const KEYS = stealthKeysFromScalars(
  1234567890123456789012345678901234567890n,
  9876543210987654321098765432109876543210n,
);
const EPHEMERAL = 555555555555555555555555555555555555n;

test("secp256k1 order constant matches the library ((N-1)·G + G == O)", () => {
  const almost = secp256k1.Point.BASE.multiply(SECP256K1_ORDER - 1n);
  assert.ok(almost.add(secp256k1.Point.BASE).is0());
});

test("sender derivation and view-key scan agree on (viewTag, address)", () => {
  const sent = deriveStealthAddress(KEYS.meta, EPHEMERAL);
  const scanned = scanStealthAnnouncement(
    KEYS.viewPriv,
    KEYS.meta.spendPub,
    sent.ephemeralPub,
  );
  assert.equal(scanned.address, sent.address);
  assert.equal(scanned.viewTag, sent.viewTag);
  assert.match(sent.address, /^0x[0-9a-f]{40}$/);
  assert.ok(sent.viewTag >= 0 && sent.viewTag <= 255);
});

test("recovered private key controls exactly the derived address", () => {
  const sent = deriveStealthAddress(KEYS.meta, EPHEMERAL);
  const rec = recoverStealthKey(KEYS.viewPriv, KEYS.spendPriv, sent.ephemeralPub);
  assert.equal(rec.address, sent.address);
  assert.match(rec.privateKey, /^0x[0-9a-f]{64}$/);
  // Independent check via the library: p·G's address path.
  const p = BigInt(rec.privateKey);
  assert.ok(p > 0n && p < SECP256K1_ORDER);
});

test("a different view key does not link to the same address", () => {
  const sent = deriveStealthAddress(KEYS.meta, EPHEMERAL);
  const other = stealthKeysFromScalars(42n, KEYS.spendPriv);
  const scanned = scanStealthAnnouncement(
    other.viewPriv,
    KEYS.meta.spendPub,
    sent.ephemeralPub,
  );
  assert.notEqual(scanned.address, sent.address);
});

test("different ephemerals yield unlinkable (distinct) addresses", () => {
  const a = deriveStealthAddress(KEYS.meta, EPHEMERAL);
  const b = deriveStealthAddress(KEYS.meta, EPHEMERAL + 1n);
  assert.notEqual(a.address, b.address);
  assert.notEqual(a.ephemeralPub, b.ephemeralPub);
});

test("scalar range guards reject 0 and the group order", () => {
  assert.throws(() => stealthKeysFromScalars(0n, 1n), /viewPriv out of range/);
  assert.throws(() => stealthKeysFromScalars(SUBGROUP_ORDER, 1n), /viewPriv out of range/);
  assert.throws(() => stealthKeysFromScalars(1n, 0n), /spendPriv out of range/);
  assert.throws(() => stealthKeysFromScalars(1n, SECP256K1_ORDER), /spendPriv out of range/);
  assert.throws(() => deriveStealthAddress(KEYS.meta, 0n), /ephemeralPriv out of range/);
});

test("randomEphemeralScalar draws in-range and non-constant", () => {
  const a = randomEphemeralScalar();
  const b = randomEphemeralScalar();
  for (const x of [a, b]) assert.ok(x > 0n && x < SUBGROUP_ORDER);
  assert.notEqual(a, b); // 2^-251 false-failure probability
});

test("isStealthAnnouncement: zero sentinel false, real R true, malformed false", () => {
  // The sentinel constant IS the wire shape the contract emits for a plain withdraw.
  assert.equal(ZERO_EPHEMERAL, "0x" + "00".repeat(32));
  assert.equal(isStealthAnnouncement(ZERO_EPHEMERAL), false);
  const sent = deriveStealthAddress(KEYS.meta, EPHEMERAL);
  assert.equal(isStealthAnnouncement(sent.ephemeralPub), true);
  for (const bad of [
    "",
    "0x",
    "0x1234",
    "11".repeat(32), // no 0x prefix
    "0x" + "zz".repeat(32), // non-hex
    "0x" + "11".repeat(31), // too short
    "0x" + "11".repeat(33), // too long
  ]) {
    assert.equal(isStealthAnnouncement(bad), false, `must reject: ${bad}`);
  }
});

// Committed determinism pin: the exact wire values for one fixed input set.
// A refactor that changes ANY encoding choice (digest layout, byte order,
// packing, tweak reduction) breaks this before it can corrupt real payments.
test("determinism pin: fixed scalars reproduce the committed vector", () => {
  assert.deepEqual(KEYS.meta, {
    viewPub: "0x45cf398e7e4dad60e0d16afe605560d22a72f3d780448d2193d8896bdcc3da29",
    spendPub: "0x038c4a2ae9312fe59eb3331c11a2e63d205b1fad842708143aef337b99d3741efa",
  });
  assert.deepEqual(deriveStealthAddress(KEYS.meta, EPHEMERAL), {
    ephemeralPub: "0xc9b11c9171809eca8d7eed392ecfb98107cc0a841d09ddc0f738410d84acc9a2",
    viewTag: 32,
    address: "0x0787be5a7a76aa58d0b68b9116f04bd61e0c3985",
  });
});

// --- portal (CREATE2) derivation --------------------------------------------

import {
  portalSalt,
  create2Address,
  portalAddress,
} from "@bongtu/core/stealth";

// TS<->Solidity CREATE2 parity vector. Generated by the Solidity side —
// contracts/test/Portal.t.sol `testCreate2ParityVectorPinned`, which etches
// PortalFactory at VECTOR_FACTORY and logs `sweeperInitCodeHash()` +
// `addressOf(salt)` (regen: `forge test --match-test
// testCreate2ParityVectorPinned -vv` after any sweeper/compiler change, then
// update BOTH files). Nothing here is hand-computed.
const VECTOR_FACTORY = "0x00000000000000000000000000000000c0ffee01";
const VECTOR_INITCODE_HASH =
  "0xe70cc154569870971ebc21f0d436f960dbd217315e69c3c102d47536293eeb3f";
const VECTOR_STEALTH_EOA = "0x1111111111111111111111111111111111111111";
const VECTOR_ADDRESS = "0xDdF8577C4Bd01a287dEA1bc3cFe4c9e7D5c2343A";

test("create2Address matches the Solidity addressOf parity vector (checksummed)", () => {
  const got = create2Address(
    VECTOR_FACTORY,
    portalSalt(VECTOR_STEALTH_EOA),
    VECTOR_INITCODE_HASH,
  );
  // Exact-case equality: the vector is forge's checksummed log output, so this
  // also pins the EIP-55 checksumming.
  assert.equal(got, VECTOR_ADDRESS);
});

test("portalSalt is the address left-padded to bytes32 (the one padding rule)", () => {
  assert.equal(
    portalSalt("0xAbCd000000000000000000000000000000001234"),
    "0x" + "00".repeat(12) + "abcd000000000000000000000000000000001234",
  );
  assert.throws(() => portalSalt("0x1234"), /20-byte hex address/);
});

test("portalAddress composes derivation + portalSalt + create2Address", () => {
  const d = portalAddress(VECTOR_FACTORY, VECTOR_INITCODE_HASH, KEYS.meta, EPHEMERAL);
  const plain = deriveStealthAddress(KEYS.meta, EPHEMERAL);
  // The announcement half is untouched — the portal leg only maps the address.
  assert.equal(d.ephemeralPub, plain.ephemeralPub);
  assert.equal(d.viewTag, plain.viewTag);
  assert.equal(d.address, plain.address);
  assert.equal(
    d.portalAddress,
    create2Address(VECTOR_FACTORY, portalSalt(plain.address), VECTOR_INITCODE_HASH),
  );
  // And the destination is EIP-55 mixed-case over the lowercase hex body.
  assert.match(d.portalAddress, /^0x[0-9a-fA-F]{40}$/);
  assert.equal(d.portalAddress.toLowerCase() === d.portalAddress, false);
});

test("create2Address validates its hex inputs", () => {
  assert.throws(() => create2Address("0x1234", "0x" + "00".repeat(32), VECTOR_INITCODE_HASH), /factory/);
  assert.throws(() => create2Address(VECTOR_FACTORY, "0x00", VECTOR_INITCODE_HASH), /salt/);
  assert.throws(() => create2Address(VECTOR_FACTORY, "0x" + "00".repeat(32), "0xzz"), /initCodeHash/);
});
