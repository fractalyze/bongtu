// Headless gates for the PURE deposit/shield witness builder (src/lib/deposit.ts) —
// the 0-in / 2-out mint this unit adds. MetaMask, the ERC-20 approve, and live snarkjs
// are out of scope (network edge, covered elsewhere); what IS covered is the whole
// security-critical witness assembly:
//
//   (1) BUILDER — buildDepositRequest mints note(V) at output 0 + note(0) at output 1,
//       BOTH owned by the depositor; each output commitment == sdk commitment(value,
//       salt, owner); outputValues == [V, 0] (sum == V, == pub[0] on-chain); note(0) is a
//       REAL non-zero commitment (passes the contract's ZeroOutputCommitment check); the
//       request is {circuit:"deposit", backend:"cpu"} and JSON-serialisable (POST-able).
//   (2) GUARD — a non-positive amount is rejected before any proving.
//   (3) PER-TX CRYPTO — freshDepositCrypto draws EXACTLY four fields (ecdhPrivateKey,
//       encryptionNonce, salt0, salt1) from the injected randomness — never the arbiter
//       key — and no two share a draw (two-time-pad guard on the ephemeral key + nonce).

import { test } from "node:test";
import assert from "node:assert/strict";

import { commitment } from "@bongtu/core/note";
import type { Point } from "@bongtu/core/babyjub";

import { deriveIdentityFromSignature } from "../src/lib/derive.js";
import {
  buildDepositRequest,
  freshDepositCrypto,
  type DepositCrypto,
} from "../src/lib/deposit.js";
import { DEFAULTS } from "../src/config.js";

// A fixed stand-in for eth_signTypedData_v4 (65-byte ECDSA sig) — a fixed account.
const SIG = "0x" + "a1".repeat(32) + "b2".repeat(32) + "1c";

// Deterministic per-tx crypto for the builder tests (the flow injects a CSPRNG instead).
const CRYPTO: DepositCrypto = {
  ecdhPrivateKey: "800000000000000000003",
  encryptionNonce: "222222222222",
  salt0: "7000001",
  salt1: "7000002",
  authorityPubKey: DEFAULTS.arbiterPubKey,
};

// ============================ (1) BUILDER ====================================

test("deposit: mints note(V)+note(0), both self-owned, commitments == sdk commitment()", () => {
  const wallet = deriveIdentityFromSignature(SIG);
  const { request, meta } = buildDepositRequest(wallet, "600", CRYPTO);

  assert.equal(request.circuit, "deposit");
  assert.equal(request.backend, "cpu");
  const inp = request.input;

  // shapes: 0-in / 2-out — two commitments, values, salts, owners; NO nullifiers/membership.
  assert.equal(inp.outputCommitments.length, 2);
  assert.equal(inp.outputValues.length, 2);
  assert.equal(inp.outputSalts.length, 2);
  assert.equal(inp.outputOwnerPublicKeys.length, 2);
  assert.equal("nullifiers" in inp, false);
  assert.equal("root" in inp, false);

  // values are exactly [V, 0] and conserve to V (== pub[0] on-chain).
  assert.deepEqual(inp.outputValues, ["600", "0"]);
  const outSum = (inp.outputValues as string[]).reduce((a, x) => a + BigInt(x), 0n);
  assert.equal(outSum, 600n);
  assert.equal(meta.amount, "600");
  assert.deepEqual(meta.outputValues, ["600", "0"]);

  // BOTH outputs owned by the depositor (deposit has no two-time-pad hazard: single
  // authority envelope, no per-recipient ciphertext — duplicate owners are fine).
  const self = wallet.keypair.publicKey;
  const owner0 = (inp.outputOwnerPublicKeys as [string, string][])[0];
  const owner1 = (inp.outputOwnerPublicKeys as [string, string][])[1];
  assert.deepEqual(owner0, [self[0].toString(), self[1].toString()]);
  assert.deepEqual(owner1, [self[0].toString(), self[1].toString()]);

  // output commitments recomputed independently with the sdk commitment().
  const selfPoint: Point = self;
  assert.equal(
    inp.outputCommitments[0],
    commitment(600n, BigInt(inp.outputSalts[0]), selfPoint).toString(),
    "note(V) commitment must match sdk",
  );
  assert.equal(
    inp.outputCommitments[1],
    commitment(0n, BigInt(inp.outputSalts[1]), selfPoint).toString(),
    "note(0) commitment must match sdk",
  );
  assert.deepEqual(meta.outputCommitments, [inp.outputCommitments[0], inp.outputCommitments[1]]);

  // note(0) is a REAL commitment of value 0 — NON-zero, so the contract's
  // ZeroOutputCommitment check accepts it (mirrors withdraw's full-withdrawal change).
  assert.notEqual(inp.outputCommitments[1], "0");

  // the authority envelope targets the pool's stored arbiter key (contract injects it).
  assert.deepEqual(inp.authorityPublicKey, [
    DEFAULTS.arbiterPubKey[0],
    DEFAULTS.arbiterPubKey[1],
  ]);

  // JSON-serialisable (POST-able to the prover; no bigints leak).
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(request)));
});

test("deposit: salts flow through to the exact output commitments", () => {
  const wallet = deriveIdentityFromSignature(SIG);
  const { request } = buildDepositRequest(wallet, "1", CRYPTO);
  const inp = request.input;
  // the two output salts are the injected salt0/salt1 (decimal strings).
  assert.equal(inp.outputSalts[0], "7000001");
  assert.equal(inp.outputSalts[1], "7000002");
});

// ============================ (2) GUARD ======================================

test("deposit: rejects a non-positive amount before proving", () => {
  const wallet = deriveIdentityFromSignature(SIG);
  assert.throws(() => buildDepositRequest(wallet, "0", CRYPTO), /positive/i);
  assert.throws(() => buildDepositRequest(wallet, "-5", CRYPTO), /positive/i);
});

// ==================== (3) PER-TX CRYPTO ======================================

test("freshDepositCrypto draws exactly four fields from the injected randomness", () => {
  let i = 0;
  const rand = (): string => String(++i * 1111);
  const c = freshDepositCrypto(rand);
  assert.equal(i, 4); // ecdh key, nonce, salt0, salt1 — one fresh draw each; NOT the arbiter key
  const drawn = [c.ecdhPrivateKey, c.encryptionNonce, c.salt0, c.salt1];
  assert.equal(new Set(drawn).size, 4, "no two fields share a draw (two-time-pad guard)");
  // the arbiter key is the pool's fixed stored key, not drawn from randomness.
  assert.deepEqual([...c.authorityPubKey], [...DEFAULTS.arbiterPubKey]);

  // and the drawn material is accepted by the builder.
  const wallet = deriveIdentityFromSignature(SIG);
  assert.doesNotThrow(() => buildDepositRequest(wallet, "100", freshDepositCrypto(rand)));
});
