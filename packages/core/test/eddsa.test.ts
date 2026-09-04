// BabyJubJub EdDSA-Poseidon sign/verify round-trips (SPEC §6b v2 /notes read-auth).
// Run via `npm test` (node --test via tsx) alongside the U1/U2 suites.

import { test } from "node:test";
import assert from "node:assert/strict";

import { Base8, mulPointEscalar, IDENTITY } from "@bongtu/core/babyjub";
import { deriveKeypair } from "@bongtu/core/note";
import {
  SUBGROUP_ORDER,
  signNotesAuth,
  verifyNotesAuth,
  notesAuthMessage,
  packSignature,
  parseSignature,
} from "@bongtu/core/eddsa";

test("SUBGROUP_ORDER is Base8's order (L·Base8 == identity)", () => {
  assert.deepEqual(mulPointEscalar(Base8, SUBGROUP_ORDER), [IDENTITY[0], IDENTITY[1]]);
});

test("a valid signature verifies against its own key + message", () => {
  const kp = deriveKeypair(555555555555555555555555n);
  const msg = notesAuthMessage(kp.publicKey, 1721800000n);
  const sig = signNotesAuth(kp.formattedPrivateKey, msg);
  assert.ok(verifyNotesAuth(kp.publicKey, msg, sig), "valid sig rejected");
  // S is a canonical subgroup scalar.
  assert.ok(sig.S >= 0n && sig.S < SUBGROUP_ORDER, "S not reduced mod L");
});

test("signing is deterministic (Poseidon nonce, no RNG)", () => {
  const kp = deriveKeypair(777n);
  const msg = notesAuthMessage(kp.publicKey, 42n);
  const a = signNotesAuth(kp.formattedPrivateKey, msg);
  const b = signNotesAuth(kp.formattedPrivateKey, msg);
  assert.deepEqual(a.R8, b.R8, "R8 differs across runs");
  assert.equal(a.S, b.S, "S differs across runs");
});

test("a wrong key does not verify (the /notes attack: attacker signs victim-bound msg)", () => {
  const victim = deriveKeypair(555555555555555555555555n);
  const attacker = deriveKeypair(999n);
  const msg = notesAuthMessage(victim.publicKey, 1721800000n); // bound to the VICTIM
  const forged = signNotesAuth(attacker.formattedPrivateKey, msg); // signed by attacker
  assert.equal(verifyNotesAuth(victim.publicKey, msg, forged), false, "forged sig accepted");
});

test("a tampered message does not verify (timestamp or owner changed)", () => {
  const kp = deriveKeypair(123456789n);
  const msg = notesAuthMessage(kp.publicKey, 1721800000n);
  const sig = signNotesAuth(kp.formattedPrivateKey, msg);
  const msg2 = notesAuthMessage(kp.publicKey, 1721800001n); // ts+1
  assert.equal(verifyNotesAuth(kp.publicKey, msg2, sig), false, "sig verified against a different ts");
});

test("verifyNotesAuth returns false (never throws) on a structurally-bad signature", () => {
  const kp = deriveKeypair(31337n);
  const msg = notesAuthMessage(kp.publicKey, 100n);
  assert.equal(verifyNotesAuth(kp.publicKey, msg, { R8: [1n, 1n], S: 5n }), false, "off-curve R8 accepted");
  assert.equal(
    verifyNotesAuth(kp.publicKey, msg, { R8: [Base8[0], Base8[1]], S: SUBGROUP_ORDER }),
    false,
    "non-canonical S accepted",
  );
});

test("packSignature/parseSignature round-trips", () => {
  const kp = deriveKeypair(2000000011n);
  const msg = notesAuthMessage(kp.publicKey, 1721800000n);
  const sig = signNotesAuth(kp.formattedPrivateKey, msg);
  const packed = packSignature(sig);
  assert.match(packed, /^0x[0-9a-f]{192}$/, `bad packed sig: ${packed}`);
  const round = parseSignature(packed);
  assert.deepEqual(round.R8, sig.R8);
  assert.equal(round.S, sig.S);
  assert.ok(verifyNotesAuth(kp.publicKey, msg, round), "parsed sig fails to verify");
});

test("parseSignature rejects malformed encodings", () => {
  assert.throws(() => parseSignature("0xabc"), /192 hex/, "short sig accepted");
  assert.throws(() => parseSignature("0x" + "zz".repeat(96)), /192 hex/, "non-hex sig accepted");
});
