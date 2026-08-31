// Pure-logic gate for the employer-mode assembly (SPEC §7 / §6). Given recipient
// rows + an input note + a membership root/path, buildDisburseRequest must produce
// a well-formed disburse ProvingRequest: correct field shapes, distinct
// output owner pubkeys, output commitments that match sdk commitment(), and the
// 2054-element ciphertext (disburseCiphertextLen for B=256). No proving, no chain.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  deriveKeypair,
  commitment,
  nullifier,
  assertDistinctOwnerPubkeys,
} from "@bongtu/core/note";
import { packPubkey, encodeAddress } from "@bongtu/core/pubkey";
import { ImtTree } from "@bongtu/core/imt";
import { ml_kem768, kemSsToLimbs, kemHexToBytes, kemBytesToHex } from "@bongtu/core/kem";
import { ARBITER_KEM_PK } from "@bongtu/core/network";
import { SUBGROUP_ORDER, type Point } from "@bongtu/core/babyjub";
import {
  buildDisburseRequest,
  freshDisburseKem,
  type DisburseEntropy,
  type RecipientRow,
} from "../src/lib/disburse.js";
import { DEFAULTS, H, B } from "../src/config.js";

// A DETERMINISTIC entropy double (an LCG) so the byte-pinned / cross-form-equality
// tests below stay reproducible run-to-run now that production draws ecdh/nonce/
// salts/pads/shuffle from the CSPRNG. Two `seededEntropy(s)` instances with the
// same seed emit the identical stream. Production uses `cryptoEntropy` (the CSPRNG).
function seededEntropy(seed = 1n): DisburseEntropy {
  const lcg = { s: seed & ((1n << 128n) - 1n) };
  const next = (): bigint => {
    lcg.s = (lcg.s * 6364136223846793005n + 1442695040888963407n) & ((1n << 128n) - 1n);
    return lcg.s;
  };
  return {
    randField: () => {
      const v = next();
      return (v === 0n ? 1n : v).toString();
    },
    randScalar: () => {
      const v = next() % SUBGROUP_ORDER;
      return v === 0n ? 1n : v;
    },
  };
}

// Deterministic ML-KEM material (fixed encapsulation randomness against the real
// arbiter pk) so the wire-byte pin below stays reproducible run-to-run.
const FIXED_ENCAP = ml_kem768.encapsulate(kemHexToBytes(ARBITER_KEM_PK), new Uint8Array(32).fill(5));
const FIXED_KEM = {
  kemSs: kemSsToLimbs(FIXED_ENCAP.sharedSecret).map(String) as [string, string],
  kemCiphertext: kemBytesToHex(FIXED_ENCAP.cipherText),
};

// A live-tree fixture: two leaves, the second is the employer's input note.
function fixture(recipientCount: number, value = 100000n) {
  const employer = deriveKeypair(313131313131313131313131n);
  const inSalt = 777n;
  const inCommit = commitment(value, inSalt, employer.publicKey);

  const tree = new ImtTree(H, B);
  tree.appendLeaf(commitment(1n, 1n, employer.publicKey)); // leaf 0 (an unrelated note)
  tree.appendLeaf(inCommit); // leaf 1 = the input note
  const leafIndex = 1;
  const { siblings } = tree.merklePath(leafIndex);

  const recipients: RecipientRow[] = Array.from({ length: recipientCount }, (_, i) => {
    const kp = deriveKeypair(4000000019n + BigInt(i) * 1000003n);
    return { pubkey: packPubkey(kp.publicKey), amount: (100n + BigInt(i)).toString() };
  });

  const inputNote = {
    value: value.toString(),
    salt: inSalt.toString(),
    ownerPrivateKey: employer.formattedPrivateKey.toString(),
  };
  const membership = { root: tree.getRoot().toString(), pathElements: siblings.map(String), leafIndex };
  const crypto = {
    authorityPubKey: DEFAULTS.arbiterPubKey,
    kemSs: FIXED_KEM.kemSs,
    kemCiphertext: FIXED_KEM.kemCiphertext,
  };
  return { employer, value, inSalt, inCommit, recipients, inputNote, membership, crypto };
}

test("assembles a well-formed disburse ProvingRequest (shapes + tag)", () => {
  const f = fixture(3);
  const { request, meta } = buildDisburseRequest(f.inputNote, f.membership, f.recipients, f.crypto);

  assert.equal(request.circuit, "disburse");
  assert.equal(request.backend, "gpu");
  const inp = request.input;
  assert.equal(inp.nullifiers.length, 1);
  assert.equal(inp.inputCommitments.length, 1);
  assert.equal(inp.inputValues.length, 1);
  assert.equal(inp.inputSalts.length, 1);
  assert.deepEqual(inp.enabled, ["1"]); // disburse's single input is always real
  assert.equal(inp.pathElements.length, 1);
  assert.equal((inp.pathElements as unknown[][])[0].length, H);
  assert.equal(inp.leafIndices.length, 1);
  assert.equal(inp.outputCommitments.length, B);
  assert.equal(inp.outputValues.length, B);
  assert.equal(inp.outputSalts.length, B);
  assert.equal(inp.outputOwnerPublicKeys.length, B);
  for (const pk of inp.outputOwnerPublicKeys as unknown as [string, string][]) assert.equal(pk.length, 2);

  // input commitment + nullifier are the sdk values for the employer's note.
  assert.equal(inp.inputCommitments[0], f.inCommit.toString());
  assert.equal(inp.nullifiers[0], nullifier(f.value, f.inSalt, f.employer.formattedPrivateKey).toString());
  assert.equal(meta.membershipOk, true); // the path folds to root
});

test("output owner pubkeys are all distinct (§11-8 two-time-pad guard)", () => {
  const f = fixture(5);
  const { request } = buildDisburseRequest(f.inputNote, f.membership, f.recipients, f.crypto);
  const owners: Point[] = (request.input.outputOwnerPublicKeys as [string, string][]).map((p) => [
    BigInt(p[0]),
    BigInt(p[1]),
  ]);
  assert.equal(owners.length, B);
  assert.doesNotThrow(() => assertDistinctOwnerPubkeys(owners)); // no collision among 256
});

test("output commitments match sdk commitment(value, salt, owner)", () => {
  const f = fixture(4);
  const { request } = buildDisburseRequest(f.inputNote, f.membership, f.recipients, f.crypto);
  const inp = request.input;
  // check a spread: recipients (0..3), the change note (4), and a padding slot (255)
  for (const i of [0, 1, 2, 3, 4, 100, B - 1]) {
    const owner: Point = [
      BigInt((inp.outputOwnerPublicKeys as [string, string][])[i][0]),
      BigInt((inp.outputOwnerPublicKeys as [string, string][])[i][1]),
    ];
    const expect = commitment(BigInt(inp.outputValues[i]), BigInt(inp.outputSalts[i]), owner);
    assert.equal(inp.outputCommitments[i], expect.toString(), `commitment mismatch at output ${i}`);
  }
});

test("value conserved: sum(outputs) == input value; change + padding fill B", () => {
  const f = fixture(3);
  const { request, meta } = buildDisburseRequest(f.inputNote, f.membership, f.recipients, f.crypto);
  const sum = (request.input.outputValues as string[]).reduce((a, x) => a + BigInt(x), 0n);
  assert.equal(sum, f.value); // CheckSum satisfiability
  assert.equal(meta.realCount, 3);
  assert.equal(meta.changeCount, 1); // disbursed (100+101+102) < 100000 -> a change note
  assert.equal(meta.padCount, B - 3 - 1);
  assert.equal(BigInt(meta.disbursed) + BigInt(meta.changeValue), f.value);
});

test("envelope bytes are pinned (hybrid authority tail — the PQ wire, design doc §2)", () => {
  // sha256 of the decimal-string JSON of the full 2054-element ciphertext on
  // fixture(3) under FIXED_KEM. Re-pinned when the authority tail switched from
  // the raw-ECDH key to the hybrid Poseidon fold (the deliberate wire-byte
  // change of the PQ envelope; the pre-hybrid pin was 6a967498…, main 875c179).
  // A change here is a WIRE-BYTE change: auditor decryption of live envelopes
  // breaks — the hybrid derivation itself is pinned against the circuit
  // fixtures in packages/core/test/envelope.test.ts.
  const f = fixture(3);
  // Fixed entropy double so the pinned wire bytes are reproducible (production
  // draws these from the CSPRNG; the pin catches an unintended codec change).
  const { ciphertext, meta, kemCiphertext } = buildDisburseRequest(
    f.inputNote,
    f.membership,
    f.recipients,
    f.crypto,
    seededEntropy(20260728n),
  );
  const sha = createHash("sha256").update(JSON.stringify(ciphertext)).digest("hex");
  assert.equal(sha, "7d4affde8553378992ba8798edb52a9065a0ca9ae2fa86a73bc2cefb64c19867");
  assert.equal(
    meta.disclosureHash,
    "17084268192408823093351289529088636825592421255378748703516419180244404484699",
  );
  // the tx's KEM ct is the injected encapsulation, passed through untouched.
  assert.equal(kemCiphertext, FIXED_KEM.kemCiphertext);
});

test("freshDisburseKem draws fresh 1088-byte material against ARBITER_KEM_PK", () => {
  const a = freshDisburseKem();
  const b = freshDisburseKem();
  for (const k of [a, b]) {
    assert.match(k.kemCiphertext, /^0x[0-9a-f]{2176}$/);
    assert.ok(BigInt(k.kemSs[0]) < 1n << 128n && BigInt(k.kemSs[1]) < 1n << 128n);
  }
  assert.notEqual(a.kemCiphertext, b.kemCiphertext, "every batch encapsulates fresh (no ct reuse)");
});

test("rejects a wrong-length kemCiphertext before assembly completes", () => {
  const f = fixture(1);
  const bad = { ...f.crypto, kemCiphertext: "0xdeadbeef" };
  assert.throws(() => buildDisburseRequest(f.inputNote, f.membership, f.recipients, bad), /1088/);
});

test("ciphertext accounts for the 2054 rule (1024 receiver ++ 1030 authority)", () => {
  const f = fixture(7);
  const { ciphertext, meta } = buildDisburseRequest(f.inputNote, f.membership, f.recipients, f.crypto);
  assert.equal(ciphertext.length, 2054);
  assert.equal(meta.ciphertextLen, 2054);
  assert.equal(ciphertext.length, 4 * B + 1030); // 4*256 receiver + authority envelope
  for (const x of ciphertext) assert.match(x, /^\d+$/); // decimal field elements
});

test("subtreeRoot equals ImtTree.computeSubtreeRoot(outputCommitments)", () => {
  const f = fixture(10);
  const { request, meta } = buildDisburseRequest(f.inputNote, f.membership, f.recipients, f.crypto);
  const commits = (request.input.outputCommitments as string[]).map((x) => BigInt(x));
  const sub = new ImtTree(H, B).computeSubtreeRoot(commits);
  assert.equal(meta.subtreeRoot, sub.toString());
});

test("the whole batch is JSON-serialisable (no bigints leak into the request)", () => {
  const f = fixture(2);
  const { request } = buildDisburseRequest(f.inputNote, f.membership, f.recipients, f.crypto);
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(request))); // POST-able as-is
});

test("rejects a duplicate recipient pubkey (would be a two-time pad)", () => {
  const f = fixture(2);
  const dup = [...f.recipients, { ...f.recipients[0] }]; // repeat recipient 0
  assert.throws(() => buildDisburseRequest(f.inputNote, f.membership, dup, f.crypto), /duplicate/i);
});

test("rejects disbursing more than the input note holds", () => {
  const f = fixture(1, 50n); // input note worth 50
  const tooMuch: RecipientRow[] = [{ pubkey: f.recipients[0].pubkey, amount: "1000" }];
  assert.throws(() => buildDisburseRequest(f.inputNote, f.membership, tooMuch, f.crypto), /exceeds input note value/);
});

test("rejects a malformed recipient compressed pubkey", () => {
  const f = fixture(1);
  const bad: RecipientRow[] = [{ pubkey: "0xdeadbeef", amount: "100" }];
  assert.throws(() => buildDisburseRequest(f.inputNote, f.membership, bad, f.crypto), /pubkey invalid/);
});

test("base58check recipient rows assemble the identical request as hex rows", () => {
  const f = fixture(2);
  // Same seed on both calls -> identical entropy stream -> identical request; the
  // only variable is the recipient row form (hex vs base58check).
  const viaHex = buildDisburseRequest(f.inputNote, f.membership, f.recipients, f.crypto, seededEntropy(42n));
  const b58Rows: RecipientRow[] = f.recipients.map((r) => ({ ...r, pubkey: encodeAddress(r.pubkey) }));
  const viaB58 = buildDisburseRequest(f.inputNote, f.membership, b58Rows, f.crypto, seededEntropy(42n));
  assert.deepEqual(viaB58.request, viaHex.request);
  // The operator-facing ledger shows canonical hex regardless of the input form.
  assert.deepEqual(viaB58.ledger, viaHex.ledger);
});
