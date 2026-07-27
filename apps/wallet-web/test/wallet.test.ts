// Headless gates for the public wallet's PURE logic (SPEC §6/§7). MetaMask and live
// circuit assets are not in the build env, so the connect/prove/submit edge is out of
// scope here; what IS covered is everything security-critical:
//
//   (1) DETERMINISTIC DERIVATION — a fixed signature hex through the KDF yields a
//       stable bjj keypair (identical twice), and a different signature a different
//       key. This is the whole self-custody hinge (same account -> same key).
//   (2) BALANCE — a mock set of the owner's notes (some spent) sums to the right
//       unspent balance; and the key-only /events trial-decrypt discovers exactly the
//       wallet's notes (rejecting a stranger's envelope) with correct spent flags.
//   (3) SPEND WITNESS — transfer (2×2) and withdraw (2×1) assembly produce a
//       ProvingRequest whose output commitments == sdk commitment(), whose
//       value is conserved, whose owners are distinct, and whose membership folds to
//       root; plus the padded single-input path (enabled=[1,0]).
//   (4) SELECTION + PER-TX CRYPTO — amount-aware largest-first note selection
//       (incl. the [10,20,5000]/4000 regression the old amount-blind slice(0,2)
//       failed on) with its distinct insufficient-balance vs needs-more-than-2
//       errors, and the freshSpendCrypto factory drawing every field from the
//       injected randomness.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  deriveKeypair,
  commitment,
  nullifier,
  poseidonEncrypt,
  ecdhSharedSecret,
} from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import { ImtTree } from "@bongtu/core/imt";
import type { Point } from "@bongtu/core/babyjub";

import {
  deriveIdentityFromSignature,
  scalarFromSignature,
  keyDerivationTypedData,
  type WalletIdentity,
} from "../src/lib/derive.js";
import { sumUnspent, trialDecryptEvents } from "../src/lib/balance.js";
import type { FeedEvent } from "../src/lib/indexerClient.js";
import {
  buildTransferRequest,
  buildWithdrawRequest,
  selectInputNotes,
  freshSpendCrypto,
  type SelectableNote,
  type WalletInputNote,
  type MembershipWitness,
} from "../src/lib/spend.js";
import { DEFAULTS, H, B } from "../src/config.js";
import { ml_kem768, kemSsToLimbs, kemHexToBytes, kemBytesToHex } from "@bongtu/core/kem";
import { ARBITER_KEM_PK } from "@bongtu/core/network";
import type { KemMaterial } from "../src/lib/spend.js";
import { resolveIndexerProxy } from "../vite.config.js";

// Deterministic ML-KEM material (fixed encapsulation randomness against the real
// arbiter pk) — the spend-fixture equivalent of the fixed ecdh/nonce scalars.
const FIXED_SPEND_ENCAP = ml_kem768.encapsulate(kemHexToBytes(ARBITER_KEM_PK), new Uint8Array(32).fill(7));
const FIXED_KEM: KemMaterial = {
  kemSs: kemSsToLimbs(FIXED_SPEND_ENCAP.sharedSecret).map(String) as [string, string],
  kemCiphertext: kemBytesToHex(FIXED_SPEND_ENCAP.cipherText),
};

// A fixed stand-in for what eth_signTypedData_v4 returns (65-byte ECDSA sig). MetaMask
// is deterministic per (account, domain, message), so a fixed hex models a fixed account.
const SIG = "0x" + "a1".repeat(32) + "b2".repeat(32) + "1c";
// Pinned regression anchors (recomputed by src/lib/derive.ts, cross-checked below).
const PIN_SCALAR = 2232542207878167874305209947598685605095785653266525372150719396610432433903n;
const PIN_COMPRESSED = "0x05c818db6e4feb82639a2170ec769abcdbfc9077833153ed2266a52b653c1f96";

// ============================ (1) DERIVATION =================================

test("derivation is deterministic: a fixed signature yields a stable keypair", () => {
  const a = deriveIdentityFromSignature(SIG);
  const b = deriveIdentityFromSignature(SIG);
  assert.equal(a.keypair.formattedPrivateKey, b.keypair.formattedPrivateKey);
  assert.equal(a.compressedPubkey, b.compressedPubkey);
  // pinned values (guards against an accidental KDF change / hash-endianness drift).
  assert.equal(a.keypair.formattedPrivateKey, PIN_SCALAR);
  assert.equal(a.compressedPubkey, PIN_COMPRESSED);
});

test("KDF = keccak256(sig) mod L; scalar is a valid in-subgroup spending key", () => {
  const s = scalarFromSignature(SIG);
  assert.equal(s, PIN_SCALAR);
  // deriveKeypair accepts it (0 < s < field prime) and A = s·Base8 matches the identity.
  const kp = deriveKeypair(s);
  assert.equal(kp.publicKey[0], deriveIdentityFromSignature(SIG).keypair.publicKey[0]);
  assert.equal(packPubkey(kp.publicKey), PIN_COMPRESSED);
});

test("a different signature derives a different key", () => {
  const other = "0x" + "cd".repeat(32) + "ef".repeat(32) + "1b";
  const a = deriveIdentityFromSignature(SIG);
  const b = deriveIdentityFromSignature(other);
  assert.notEqual(a.keypair.formattedPrivateKey, b.keypair.formattedPrivateKey);
  assert.notEqual(a.compressedPubkey, b.compressedPubkey);
});

test("the default indexer base is same-origin relative (Vite proxy contract)", () => {
  // Guards the remote-dev contract: the wallet must call the indexer SAME-ORIGIN by
  // default so one SSH tunnel (the wallet port) suffices and no CORS wall appears — the
  // Vite server+preview proxy forwards `/indexer/*` to the real indexer. A revert to an
  // absolute `http://localhost:8600` would silently reintroduce cross-origin + a 2nd
  // tunnel, so pin the default to a root-relative path.
  assert.ok(DEFAULTS.indexerUrl.startsWith("/"), `indexerUrl must be root-relative, got ${DEFAULTS.indexerUrl}`);
  assert.ok(!/^https?:/i.test(DEFAULTS.indexerUrl), "indexerUrl default must not be an absolute origin");
});

test("the Vite indexer proxy is on in development and auto-disabled in production", () => {
  // The proxy is a dev-only convenience; in production the app is a static build served
  // behind an Nginx/ingress reverse-proxy that owns `/indexer/*`. `vite preview` defaults
  // to production mode, so gating on `mode` is what keeps a live proxy from masking a
  // missing prod route. Pin both ends of that contract.
  const dev = resolveIndexerProxy("development");
  assert.ok(dev && "/indexer" in dev, "development must proxy /indexer");
  assert.equal(resolveIndexerProxy("production"), undefined, "production must not proxy — infra owns /indexer");
});

test("the key-derivation struct is domain-separated (chainId, pool, version)", () => {
  const t = keyDerivationTypedData(DEFAULTS.chainId, DEFAULTS.pool, DEFAULTS.keyVersion);
  assert.equal(t.domain.chainId, 91342);
  assert.equal(t.domain.verifyingContract, DEFAULTS.pool);
  assert.equal(t.domain.version, DEFAULTS.keyVersion);
  assert.equal(t.primaryType, "BongtuSpendingKey");
  assert.ok(t.types.BongtuSpendingKey.length >= 1);
});

// ============================ (2) BALANCE ====================================

test("balance sums unspent notes only", () => {
  const notes = [
    { value: "100", spent: false },
    { value: "250", spent: true }, // spent — excluded
    { value: "40", spent: false },
    { value: "9", spent: true }, // spent — excluded
  ];
  assert.equal(sumUnspent(notes), 140n); // 100 + 40
  assert.equal(sumUnspent([]), 0n);
  assert.equal(sumUnspent(notes.map((n) => ({ ...n, spent: true }))), 0n);
});

test("trial-decrypt discovers exactly the wallet's notes from the /events feed", () => {
  const wallet = deriveIdentityFromSignature(SIG);
  const stranger = deriveKeypair(9876543210123456789n);
  const ecdhPriv = 700000000000000000001n;
  const nonce = 111111111111n;
  const ephemeralPub = deriveKeypair(ecdhPriv).publicKey; // ecdhPublicKey the event carries

  // one envelope to the wallet (leaf 5), one to a stranger (leaf 6).
  const mine = { value: 321n, salt: 6000001n };
  const theirs = { value: 999n, salt: 6000002n };
  const ctMine = poseidonEncrypt([mine.value, mine.salt], ecdhSharedSecret(ecdhPriv, wallet.keypair.publicKey), nonce);
  const ctTheirs = poseidonEncrypt([theirs.value, theirs.salt], ecdhSharedSecret(ecdhPriv, stranger.publicKey), nonce);
  const myCommit = commitment(mine.value, mine.salt, wallet.keypair.publicKey);
  const theirCommit = commitment(theirs.value, theirs.salt, stranger.publicKey);
  const myNullifier = nullifier(mine.value, mine.salt, wallet.keypair.formattedPrivateKey);

  const ev: FeedEvent = {
    seq: 0,
    txHash: "0xabc",
    blockNumber: 1,
    kind: "transfer",
    epoch: 0,
    ecdhPublicKey: [ephemeralPub[0].toString(), ephemeralPub[1].toString()],
    encryptionNonce: nonce.toString(),
    slices: [
      { offset: 0, elts: 4, leafIndex: 5 },
      { offset: 4, elts: 4, leafIndex: 6 },
    ],
    ciphertext: [...ctMine, ...ctTheirs].map((x) => x.toString()),
  };
  const leafCommitments = new Map<number, string>([
    [5, myCommit.toString()],
    [6, theirCommit.toString()],
  ]);

  // unspent
  let found = trialDecryptEvents([ev], wallet, { leafCommitments, spentNullifiers: new Set() });
  assert.equal(found.length, 1, "only the wallet's own envelope is discovered");
  assert.equal(found[0].value, "321");
  assert.equal(found[0].leafIndex, 5);
  assert.equal(found[0].commitment, myCommit.toString());
  assert.equal(found[0].nullifier, myNullifier.toString());
  assert.equal(found[0].spent, false);
  assert.equal(sumUnspent(found), 321n);

  // once its nullifier is in the spent set, it is flagged spent -> balance 0
  found = trialDecryptEvents([ev], wallet, {
    leafCommitments,
    spentNullifiers: new Set([myNullifier.toString()]),
  });
  assert.equal(found[0].spent, true);
  assert.equal(sumUnspent(found), 0n);
});

// ============================ (3) SPEND WITNESS ==============================

// A live-tree fixture: the wallet's two notes are leaves 1 and 2 of the tree.
function fixture(values: bigint[]) {
  const wallet = deriveIdentityFromSignature(SIG);
  const salts = values.map((_, i) => 500000n + BigInt(i));
  const tree = new ImtTree(H, B);
  tree.appendLeaf(commitment(7n, 7n, wallet.keypair.publicKey)); // leaf 0 (unrelated)
  const leafIndices: number[] = [];
  values.forEach((v, i) => {
    tree.appendLeaf(commitment(v, salts[i], wallet.keypair.publicKey));
    leafIndices.push(i + 1);
  });
  const root = tree.getRoot().toString();
  const inputs: WalletInputNote[] = values.map((v, i) => ({ value: v.toString(), salt: salts[i].toString(), leafIndex: leafIndices[i] }));
  const memberships: MembershipWitness[] = leafIndices.map((li) => ({
    root,
    pathElements: tree.merklePath(li).siblings.map(String),
    leafIndex: li,
  }));
  const recipient = packPubkey(deriveKeypair(4242424242424242n).publicKey);
  const crypto = {
    ecdhPrivateKey: "800000000000000000003",
    encryptionNonce: "222222222222",
    authorityPubKey: DEFAULTS.arbiterPubKey,
    kemSs: FIXED_KEM.kemSs,
    kemCiphertext: FIXED_KEM.kemCiphertext,
    changeSalt: "7000002",
    padSalt: "7100001",
    payeeSalt: "7000001",
  };
  return { wallet, inputs, memberships, recipient, crypto, salts };
}

test("transfer: output commitments == sdk commitment() and value is conserved", () => {
  const f = fixture([1000n, 500n]); // input total 1500
  const { request, meta } = buildTransferRequest(f.wallet, f.inputs, f.memberships, f.recipient, "600", f.crypto);

  assert.equal(request.circuit, "transfer");
  assert.equal(request.backend, "cpu");
  const inp = request.input;
  // shapes
  assert.equal(inp.nullifiers.length, 2);
  assert.equal(inp.inputCommitments.length, 2);
  assert.equal(inp.outputCommitments.length, 2);
  assert.equal(inp.outputOwnerPublicKeys.length, 2);
  assert.deepEqual(inp.enabled, ["1", "1"]); // both inputs real
  assert.equal((inp.pathElements as unknown[][])[0].length, H);

  // output commitments recomputed independently with sdk commitment()
  const payee: Point = [
    BigInt((inp.outputOwnerPublicKeys as [string, string][])[0][0]),
    BigInt((inp.outputOwnerPublicKeys as [string, string][])[0][1]),
  ];
  const self = f.wallet.keypair.publicKey;
  assert.equal(inp.outputCommitments[0], commitment(BigInt(inp.outputValues[0]), BigInt(inp.outputSalts[0]), payee).toString());
  assert.equal(inp.outputCommitments[1], commitment(BigInt(inp.outputValues[1]), BigInt(inp.outputSalts[1]), self).toString());

  // value conserved: sum(inputs) == payment + change (CheckSum satisfiability)
  const inSum = (inp.inputValues as string[]).reduce((a, x) => a + BigInt(x), 0n);
  const outSum = (inp.outputValues as string[]).reduce((a, x) => a + BigInt(x), 0n);
  assert.equal(inSum, 1500n);
  assert.equal(outSum, 1500n);
  assert.equal(inp.outputValues[0], "600"); // paid amount
  assert.equal(inp.outputValues[1], "900"); // change
  assert.equal(meta.membershipOk, true);
  assert.equal(meta.changeValue, "900");

  // input nullifiers/commitments are the sdk values for the wallet's notes
  assert.equal(inp.inputCommitments[0], commitment(1000n, f.salts[0], self).toString());
  assert.equal(inp.nullifiers[0], nullifier(1000n, f.salts[0], f.wallet.keypair.formattedPrivateKey).toString());

  // JSON-serialisable (POST-able to the prover; no bigints leak)
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(request)));
});

test("transfer: single input note pads input[1] (enabled=[1,0], value 0)", () => {
  const f = fixture([1000n]); // one note
  const { request, meta } = buildTransferRequest(f.wallet, f.inputs, f.memberships, f.recipient, "250", f.crypto);
  const inp = request.input;
  assert.deepEqual(inp.enabled, ["1", "0"]);
  assert.equal(inp.nullifiers[1], "0"); // padded input carries a zero nullifier
  assert.equal(inp.inputValues[1], "0"); // value belt: disabled input has value 0
  assert.equal(meta.realInputCount, 1);
  const inSum = (inp.inputValues as string[]).reduce((a, x) => a + BigInt(x), 0n);
  const outSum = (inp.outputValues as string[]).reduce((a, x) => a + BigInt(x), 0n);
  assert.equal(inSum, 1000n);
  assert.equal(outSum, 1000n); // 250 paid + 750 change
});

test("transfer: rejects a self-pay (two-time pad) and an over-spend", () => {
  const f = fixture([1000n]);
  const selfPay = f.wallet.compressedPubkey; // paying yourself collides the two output owners
  assert.throws(() => buildTransferRequest(f.wallet, f.inputs, f.memberships, selfPay, "10", f.crypto), /duplicate|distinct/i);
  assert.throws(() => buildTransferRequest(f.wallet, f.inputs, f.memberships, f.recipient, "5000", f.crypto), /exceeds/i);
});

test("withdraw: out == amount, change conserved, single output to self", () => {
  const f = fixture([1000n, 500n]); // total 1500
  const { request, meta } = buildWithdrawRequest(f.wallet, f.inputs, f.memberships, "1200", f.crypto);
  assert.equal(request.circuit, "withdraw");
  const inp = request.input;
  assert.equal(inp.outputCommitments.length, 1);
  assert.equal(inp.outputValues.length, 1);
  assert.equal(inp.outputValues[0], "300"); // change = 1500 - 1200
  assert.equal(meta.amount, "1200"); // ERC-20 out
  assert.equal(meta.changeValue, "300");
  // out == sum(inputs) - sum(outputs)
  const inSum = (inp.inputValues as string[]).reduce((a, x) => a + BigInt(x), 0n);
  const outSum = (inp.outputValues as string[]).reduce((a, x) => a + BigInt(x), 0n);
  assert.equal(inSum - outSum, 1200n);
  // change commitment == sdk commitment(change, salt, self)
  const self = f.wallet.keypair.publicKey;
  assert.equal(inp.outputCommitments[0], commitment(300n, BigInt(inp.outputSalts[0]), self).toString());
  assert.equal(meta.membershipOk, true);
});

test("withdraw: full withdrawal leaves a value-0 (non-zero commitment) change note", () => {
  const f = fixture([1000n]);
  const { request } = buildWithdrawRequest(f.wallet, f.inputs, f.memberships, "1000", f.crypto);
  const inp = request.input;
  assert.equal(inp.outputValues[0], "0"); // full withdrawal
  assert.notEqual(inp.outputCommitments[0], "0"); // commitment(0,salt,self) != 0 -> contract accepts
});

// ==================== (4) SELECTION + PER-TX CRYPTO ==========================

// Selection fixtures: only value/spent/leafIndex matter; salts are arbitrary.
function note(value: string, leafIndex: number, spent = false): SelectableNote {
  return { value, salt: `9${leafIndex}`, leafIndex, spent };
}

test("selection is amount-aware: [10,20,5000]/4000 spends the 5000 note (regression)", () => {
  // The old amount-blind slice(0,2) picked 10+20 here and the builder rejected a
  // perfectly fundable payment ("amount exceeds spendable input total").
  const notes = [note("10", 1), note("20", 2), note("5000", 3)];
  const picked = selectInputNotes(notes, "4000");
  assert.equal(picked.length, 1);
  assert.deepEqual(picked[0], { value: "5000", salt: "93", leafIndex: 3 });
});

test("selection repro end-to-end: the [10,20,5000]/4000 transfer now assembles", () => {
  const f = fixture([10n, 20n, 5000n]);
  const selectable: SelectableNote[] = f.inputs.map((n) => ({ ...n, spent: false }));
  const picked = selectInputNotes(selectable, "4000");
  const memberships = picked.map((n) => f.memberships[f.inputs.findIndex((i) => i.leafIndex === n.leafIndex)]);
  const { request, meta } = buildTransferRequest(f.wallet, picked, memberships, f.recipient, "4000", f.crypto);
  assert.equal(request.input.outputValues[0], "4000"); // paid
  assert.equal(meta.changeValue, "1000"); // 5000 - 4000
  assert.equal(meta.membershipOk, true);
});

test("selection covers with one note when the largest suffices, two otherwise (largest-first)", () => {
  const notes = [note("10", 1), note("30", 2), note("20", 3)];
  // largest alone covers
  assert.deepEqual(selectInputNotes(notes, "30").map((n) => n.leafIndex), [2]);
  // largest alone does not cover -> the two largest, largest first
  assert.deepEqual(selectInputNotes(notes, "45").map((n) => n.leafIndex), [2, 3]);
  // pair covers exactly
  assert.deepEqual(selectInputNotes(notes, "50").map((n) => n.leafIndex), [2, 3]);
});

test("selection skips spent notes", () => {
  const notes = [note("5000", 1, true), note("20", 2), note("10", 3)];
  assert.deepEqual(selectInputNotes(notes, "25").map((n) => n.leafIndex), [2, 3]);
  assert.throws(() => selectInputNotes(notes, "4000"), /insufficient balance/);
});

test("selection errors are distinct: insufficient balance vs needs-more-than-2-notes", () => {
  // total 30 < 1000 — the balance genuinely cannot fund it
  assert.throws(() => selectInputNotes([note("10", 1), note("20", 2)], "1000"), /insufficient balance/);
  // total 90 >= 80 but the best pair is 60 — needs consolidation, NOT more funds
  const thirds = [note("30", 1), note("30", 2), note("30", 3)];
  assert.throws(() => selectInputNotes(thirds, "80"), /more than 2 notes/);
  assert.doesNotThrow(() => selectInputNotes(thirds, "60")); // pair covers
});

test("selection rejects empty/all-spent wallets and malformed amounts", () => {
  assert.throws(() => selectInputNotes([], "10"), /no spendable notes/);
  assert.throws(() => selectInputNotes([note("10", 1, true)], "10"), /no spendable notes/);
  assert.throws(() => selectInputNotes([note("10", 1)], "0"), /positive/);
  assert.throws(() => selectInputNotes([note("10", 1)], "-5"), /positive/);
  assert.throws(() => selectInputNotes([note("10", 1)], "abc"), /positive/);
});

test("freshSpendCrypto draws every field from the injected randomness", () => {
  let i = 0;
  const rand = (): string => String(++i * 1111);
  const c = freshSpendCrypto(rand);
  assert.equal(i, 5); // ecdh key, nonce, change/pad/payee salts — one fresh draw each
  const drawn = [c.ecdhPrivateKey, c.encryptionNonce, c.changeSalt, c.padSalt, c.payeeSalt];
  assert.equal(new Set(drawn).size, 5, "no two fields share a draw (two-time-pad guard)");
  assert.deepEqual([...c.authorityPubKey], [...DEFAULTS.arbiterPubKey]); // pool's stored arbiter key
  // and the material is accepted by the builders
  const f = fixture([1000n]);
  assert.doesNotThrow(() => buildTransferRequest(f.wallet, f.inputs, f.memberships, f.recipient, "100", freshSpendCrypto(rand)));
});

test("freshSpendCrypto: kem draw — deterministic injection, fresh by default, limbs reach the witness", () => {
  // deterministic injection: the injected material passes through untouched and
  // never consumes a field draw.
  let i = 0;
  const rand = (): string => String(++i * 2222);
  let kemDraws = 0;
  const injected = freshSpendCrypto(rand, () => {
    kemDraws++;
    return FIXED_KEM;
  });
  assert.equal(kemDraws, 1, "exactly one KEM encapsulation per crypto bundle");
  assert.equal(i, 5, "the kem draw does not consume field randomness");
  assert.deepEqual(injected.kemSs, FIXED_KEM.kemSs);
  assert.equal(injected.kemCiphertext, FIXED_KEM.kemCiphertext);

  // the limbs land in BOTH spend witnesses exactly as drawn (the ct stays out —
  // it is the tx's separate bytes arg).
  const f = fixture([1000n, 500n]);
  const t = buildTransferRequest(f.wallet, f.inputs, f.memberships, f.recipient, "100", injected);
  assert.deepEqual(t.request.input.kemSs, [FIXED_KEM.kemSs[0], FIXED_KEM.kemSs[1]]);
  assert.equal("kemCiphertext" in t.request.input, false);
  const w = buildWithdrawRequest(f.wallet, f.inputs, f.memberships, "100", injected);
  assert.deepEqual(w.request.input.kemSs, [FIXED_KEM.kemSs[0], FIXED_KEM.kemSs[1]]);

  // default draw: a real fresh encapsulation against ARBITER_KEM_PK per call.
  const a = freshSpendCrypto(rand);
  const b = freshSpendCrypto(rand);
  assert.match(a.kemCiphertext, /^0x[0-9a-f]{2176}$/);
  assert.ok(BigInt(a.kemSs[0]) < 1n << 128n && BigInt(a.kemSs[1]) < 1n << 128n);
  assert.notEqual(a.kemCiphertext, b.kemCiphertext, "every tx encapsulates fresh");
});

test("freshSpendCrypto clamps the encryption nonce below 2^128 (circuit constraint)", () => {
  // Same constraint as deposit: SymmetricEncrypt (both the receiver ciphertexts and
  // the authority envelope) requires nonce < 2^128; the browser randField draws
  // 248-bit fields, so the factory must clamp the nonce and ONLY the nonce.
  const wide = ((1n << 247n) + 54321n).toString();
  const c = freshSpendCrypto(() => wide);
  assert.ok(BigInt(c.encryptionNonce) < 1n << 128n, "nonce must satisfy nonce < 2^128");
  assert.equal(c.changeSalt, wide, "salts keep the full draw");
  assert.equal(c.ecdhPrivateKey, wide, "ephemeral key keeps the full draw");
});
