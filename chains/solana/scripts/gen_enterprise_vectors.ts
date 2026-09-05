// gen_enterprise_vectors.ts — per-op mollusk harness fixtures for the S3
// enterprise instruction set (SOLR §3.3 / §5.2; OPEN-1: deposit, withdraw,
// disburse256), the enterprise sibling of gen_vectors.ts.
//
// Run from the repo root:
//   node_modules/.bin/tsx chains/solana/scripts/gen_enterprise_vectors.ts
//
// Reads   chains/evm/test/fixtures/realproofs.json          (committed EVM
//         enterprise realproof fixtures: deposit, withdraw — kem-enveloped
//         publics, one shared arbiter key),
//         chains/evm/test/fixtures/disburse256.oracle.json  (the GPU-proven
//         production-arity disburse fixture + its ImtTree(32,256) oracle),
//         chains/evm/test/fixtures/disburse256.input.json   (the witness
//         input the committed disburse256 proof was generated from — the
//         source the 2054-element disclosure blob is re-derived from),
//         circuits/fixtures/fixture_lib.ts                  (the fixture KEM
//         material: deterministic arbiter ML-KEM keypair + per-label draws)
// Writes  chains/solana/conformance/deposit_fixture.json
//         chains/solana/conformance/withdraw_fixture.json
//         chains/solana/conformance/disburse256_fixture.json
//
// Every value is asserted against the fixture's own committed anchors before
// anything is written: membership-root and rootAfter replays through the
// ImtTree oracle, the enabled-derivation rule, the one-arbiter-key rule
// (every enterprise proof binds realproofs.arbiterKey — the Deploy.s.sol
// default, chain-agnostic bjj material), kemBinding vs the deterministic KEM
// draw, and disclosureChain(re-derived blob) == the proof's disclosureHash
// public (the packages/core envelope.test.ts p2 recipe). A drifted core or
// fixture fails here, not in mollusk.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ImtTree } from "@bongtu/core/imt";
import {
  authorityCiphertextLen,
  buildAuthorityPlaintext,
  disclosureChain,
} from "@bongtu/core/envelope";
import { hybridEnvelopeKey, kemBindingOf, kemBytesToHex } from "@bongtu/core/kem";
import { deriveKeypair, ecdhSharedSecret, poseidonEncrypt } from "@bongtu/core/note";
import type { Point } from "@bongtu/core/babyjub";

import { kemDraw } from "../../../circuits/fixtures/fixture_lib.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO, "chains", "evm", "test", "fixtures");
const CONFORMANCE = join(HERE, "..", "conformance");

// Enterprise profile tree shape: height 32 protocol-wide, B=256 (the
// production disburse arity — Deploy.s.sol BATCH_SIZE default). LOG_B = 8.
const H = 32;
const B = 256;
const LOG_B = 8;

const hex32 = (v: bigint): string => "0x" + v.toString(16).padStart(64, "0");

function assertEq<T>(got: T, want: T, what: string): void {
  if (got !== want) throw new Error(`gen_enterprise_vectors: ${what}: got ${got}, want ${want}`);
}

interface TreeSnapshot {
  nextLeafIndex: number;
  currentRoot: string;
  filledSubtrees: string[];
}

function snapshot(t: ImtTree): TreeSnapshot {
  return {
    nextLeafIndex: t.getNextLeafIndex(),
    currentRoot: hex32(t.getRoot()),
    filledSubtrees: t.filledSubtrees.map(hex32),
  };
}

interface EvmFixture {
  a: string[];
  b: string[][];
  c: string[];
  pub: string[];
  seedLeaves?: string[];
  rootAfter: string;
  kemCiphertext: string;
  kemBinding: string;
}

// Proof wire bytes (256 B): a.x||a.y || b || c.x||c.y — the committed
// fixtures already store b in EVM/EIP-197 limb order (the snarkjs
// exportSolidityCallData swap), which is the alt_bn128 syscall encoding.
function proofHex(fx: { a: string[]; b: string[][]; c: string[] }): string {
  const strip = (h: string): string => h.replace(/^0x/, "");
  const out =
    "0x" +
    [fx.a[0], fx.a[1], fx.b[0][0], fx.b[0][1], fx.b[1][0], fx.b[1][1], fx.c[0], fx.c[1]]
      .map(strip)
      .join("");
  if ((out.length - 2) / 2 !== 256) throw new Error("gen_enterprise_vectors: proof is not 256 bytes");
  return out;
}

function checkKemCt(hex: string): void {
  assertEq((hex.length - 2) / 2, 1088, "kem ciphertext length");
}

/** The one-arbiter-key rule: every enterprise fixture proof binds the SAME
 *  key (realproofs.arbiterKey == the Deploy.s.sol default). */
function checkArbiterKey(pubX: string, pubY: string, key: [string, string], what: string): void {
  assertEq(BigInt(pubX), BigInt(key[0]), `${what} arbiter key x`);
  assertEq(BigInt(pubY), BigInt(key[1]), `${what} arbiter key y`);
}

// deposit publics (19): [0]=out [1..2]=ecdhPub [3..12]=cipherTextAuthority[10]
// [13]=kemBinding [14..15]=oc [16]=nonce [17..18]=authorityPubKey (injected)
function depositFixture(fx: EvmFixture, arbiterKey: [string, string]): object {
  assertEq(fx.pub.length, 19, "deposit pub len");
  checkKemCt(fx.kemCiphertext);
  assertEq(BigInt(fx.kemBinding), BigInt(fx.pub[13]), "deposit kemBinding public");
  checkArbiterKey(fx.pub[17], fx.pub[18], arbiterKey, "deposit");

  const t = new ImtTree(H, B);
  const pre = snapshot(t);
  t.appendLeaf(BigInt(fx.pub[14]));
  t.appendLeaf(BigInt(fx.pub[15]));
  const post = snapshot(t);
  assertEq(post.currentRoot, hex32(BigInt(fx.rootAfter)), "deposit rootAfter replay");

  return {
    comment:
      "GENERATED by chains/solana/scripts/gen_enterprise_vectors.ts from the committed EVM " +
      "enterprise deposit realproof fixture (chains/evm/test/fixtures/realproofs.json) + the " +
      "packages/core ImtTree oracle. Mollusk gates 2/5 input — SOLR §5.2.",
    proof: proofHex(fx),
    publicsCarried: fx.pub.slice(0, 17),
    publicsFull: fx.pub,
    kemCiphertexts: [fx.kemCiphertext],
    outputCommitments: [fx.pub[14], fx.pub[15]],
    amount: fx.pub[0],
    newRoot: fx.rootAfter,
    startLeafIndex: 0,
    preState: pre,
    postState: post,
  };
}

// withdraw publics (27): [0]=out [1..2]=ecdhPub [3..15]=cipherTextAuthority[13]
// [16]=kemBinding [17..18]=nf [19]=root [20..21]=enabled [22]=oc0(change)
// [23]=nonce [24..25]=authorityPubKey [26]=recipient.
// The fixture's pub[26] is a uint160 EVM address; on this rail the program
// injects the OPEN-3 truncate-253 binding of the recipient token account, and
// any 253-bit value IS a reachable token-account address (top 3 bits zero),
// so the SAME committed proof replays at op level with the recipient token
// account placed at address BE32(pub[26]) — no re-proving (unlike
// withdrawPriv, whose op-level fixture needed a Solana-bound re-prove only
// because its S2 harness predates this trick and pins a realistic address).
function withdrawFixture(fx: EvmFixture, arbiterKey: [string, string]): object {
  assertEq(fx.pub.length, 27, "withdraw pub len");
  checkKemCt(fx.kemCiphertext);
  assertEq(BigInt(fx.kemBinding), BigInt(fx.pub[16]), "withdraw kemBinding public");
  checkArbiterKey(fx.pub[24], fx.pub[25], arbiterKey, "withdraw");
  for (const i of [0, 1]) {
    assertEq(
      BigInt(fx.pub[20 + i]),
      BigInt(fx.pub[17 + i]) === 0n ? 0n : 1n,
      `withdraw enabled[${i}] derivation`,
    );
  }
  const recipient = BigInt(fx.pub[26]);
  if (recipient === 0n || recipient >= 1n << 160n) {
    throw new Error("gen_enterprise_vectors: withdraw pub[26] is not a uint160 address");
  }

  const t = new ImtTree(H, B);
  for (const leaf of fx.seedLeaves!) t.appendLeaf(BigInt(leaf));
  const pre = snapshot(t);
  assertEq(pre.currentRoot, hex32(BigInt(fx.pub[19])), "withdraw membership root replay");
  t.appendLeaf(BigInt(fx.pub[22]));
  const post = snapshot(t);
  assertEq(post.currentRoot, hex32(BigInt(fx.rootAfter)), "withdraw rootAfter replay");

  const carried = [...fx.pub.slice(0, 20), fx.pub[22], fx.pub[23]];
  assertEq(carried.length, 22, "withdraw carried publics");
  return {
    comment:
      "GENERATED by chains/solana/scripts/gen_enterprise_vectors.ts from the committed EVM " +
      "enterprise withdraw realproof fixture + the packages/core ImtTree oracle. The recipient " +
      "token account address is BE32(pub[26]) so the truncate-253 binding reproduces the " +
      "proof-bound recipient exactly. Mollusk gates 2/5 input — SOLR §5.2.",
    proof: proofHex(fx),
    publicsCarried: carried,
    publicsFull: fx.pub,
    kemCiphertexts: [fx.kemCiphertext],
    nullifiers: [fx.pub[17], fx.pub[18]],
    changeCommitment: fx.pub[22],
    amount: fx.pub[0],
    recipientTokenAccount: hex32(recipient),
    stealthEphemeralPub: hex32(0n),
    stealthViewTag: 0,
    spentRoot: fx.pub[19],
    newRoot: fx.rootAfter,
    startLeafIndex: pre.nextLeafIndex,
    preState: pre,
    postState: post,
  };
}

// disburse256 publics (11): [0..1]=ecdhPub [2]=disclosureHash [3]=subtreeRoot
// [4]=kemBinding [5]=nullifier [6]=root [7]=enabled [8]=nonce
// [9..10]=authorityPubKey.
interface DisburseOracle {
  inputCommitment: string;
  seedRoot: string;
  oracleRoot: string;
  nextLeafIndexBeforeAttach: number;
  finalNextLeafIndex: number;
  arbiterKey: string[];
  a: string[];
  b: string[][];
  c: string[];
  pub: string[];
}

interface Disburse256Input {
  inputValues: string[];
  inputSalts: string[];
  inputOwnerPrivateKey: string;
  ecdhPrivateKey: string;
  encryptionNonce: string;
  outputValues: string[];
  outputSalts: string[];
  outputOwnerPublicKeys: [string, string][];
  authorityPublicKey: [string, string];
}

/** Re-derive the 65,728 B disclosure blob (receiverCts[1024] ++
 *  authorityEnvelope[1030]) from the committed witness input — the
 *  packages/core test/envelope.test.ts p2 recipe — and pin its fold to the
 *  proof's disclosureHash public. This blob is what the institution serves
 *  (SOLR §3.3.2); the refold gate checks it against DisburseBatch. */
function disclosureBlob(input: Disburse256Input, kemSs: [bigint, bigint]): bigint[] {
  const ecdh = BigInt(input.ecdhPrivateKey);
  const nonce = BigInt(input.encryptionNonce);
  const owners: Point[] = input.outputOwnerPublicKeys.map((p) => [BigInt(p[0]), BigInt(p[1])]);
  const receiverFlat = owners.flatMap((owner, i) =>
    poseidonEncrypt(
      [BigInt(input.outputValues[i]), BigInt(input.outputSalts[i])],
      ecdhSharedSecret(ecdh, owner),
      nonce,
    ),
  );
  const inOwner = deriveKeypair(BigInt(input.inputOwnerPrivateKey)).publicKey;
  const authPlain = buildAuthorityPlaintext("disburse", {
    inputs: [
      { owner: inOwner, value: BigInt(input.inputValues[0]), salt: BigInt(input.inputSalts[0]) },
    ],
    outputs: owners.map((owner, i) => ({
      owner,
      value: BigInt(input.outputValues[i]),
      salt: BigInt(input.outputSalts[i]),
    })),
  });
  const authorityCt = poseidonEncrypt(
    authPlain,
    hybridEnvelopeKey(
      ecdhSharedSecret(ecdh, [
        BigInt(input.authorityPublicKey[0]),
        BigInt(input.authorityPublicKey[1]),
      ]),
      kemSs,
    ),
    nonce,
  );
  const full = [...receiverFlat, ...authorityCt];
  assertEq(full.length, 4 * B + authorityCiphertextLen("disburse", B), "disclosure blob length");
  assertEq(full.length, 2054, "disclosure blob is 2054 elements");
  return full;
}

function disburse256Fixture(
  oracle: DisburseOracle,
  input: Disburse256Input,
  arbiterKey: [string, string],
): object {
  const pub = oracle.pub;
  assertEq(pub.length, 11, "disburse256 pub len");
  assertEq(BigInt(pub[7]), 1n, "disburse256 enabled public is 1");
  checkArbiterKey(pub[9], pub[10], arbiterKey, "disburse256");
  assertEq(BigInt(oracle.arbiterKey[0]), BigInt(arbiterKey[0]), "oracle arbiter key x");
  assertEq(BigInt(oracle.arbiterKey[1]), BigInt(arbiterKey[1]), "oracle arbiter key y");

  // The deterministic fixture KEM draw for this proof: the label-derived
  // encapsulation whose shared-secret limbs the witness carried, so the
  // 1088 B ct regenerates byte-stable and the binding pins it to pub[4].
  const draw = kemDraw("disburse256");
  assertEq(kemBindingOf(draw.kemSs), BigInt(pub[4]), "disburse256 kemBinding vs fixture KEM draw");
  const kemCiphertext = "0x" + kemBytesToHex(draw.kemCiphertext).replace(/^0x/, "");
  checkKemCt(kemCiphertext);

  const blob = disclosureBlob(input, draw.kemSs);
  assertEq(disclosureChain(blob), BigInt(pub[2]), "disclosureChain(blob) vs disclosureHash public");

  const t = new ImtTree(H, B);
  t.appendLeaf(BigInt(oracle.inputCommitment));
  const pre = snapshot(t);
  assertEq(pre.currentRoot, hex32(BigInt(pub[6])), "disburse256 membership root replay");
  assertEq(pre.nextLeafIndex, oracle.nextLeafIndexBeforeAttach, "pre nextLeafIndex");
  t.attachSubtree(BigInt(pub[3]));
  const post = snapshot(t);
  assertEq(post.currentRoot, hex32(BigInt(oracle.oracleRoot)), "disburse256 oracleRoot replay");
  assertEq(post.nextLeafIndex, oracle.finalNextLeafIndex, "post nextLeafIndex");

  // Sub-LOG_B frontier splice: the program's attach closes the pending
  // partial block in O(LOG_B) folds and leaves filled_subtrees[i < LOG_B]
  // STALE (the EVM _attachSubtree shape — reads them, never writes), while
  // the JS oracle pads leaf-by-leaf and rewrites them. Both yield the same
  // root and the same frontier at levels >= LOG_B; the expected post-state
  // account image therefore carries the PRE values below LOG_B.
  const postProgram = {
    ...post,
    filledSubtrees: post.filledSubtrees.map((s, i) => (i < LOG_B ? pre.filledSubtrees[i] : s)),
  };

  const start = post.nextLeafIndex - B;
  assertEq(start, 256, "batch start leaf index");
  const carried = [pub[0], pub[1], pub[2], pub[3], pub[4], pub[5], pub[6], pub[8]];
  return {
    comment:
      "GENERATED by chains/solana/scripts/gen_enterprise_vectors.ts from the committed GPU " +
      "disburse256 fixture (chains/evm/test/fixtures/disburse256.{oracle,input}.json) + the " +
      "packages/core ImtTree oracle and envelope.ts disclosureChain (the test/envelope.test.ts " +
      "p2 recipe). disclosureElements is the 2054-element served-blob fixture the refold gate " +
      "checks against DisburseBatch.disclosureHash — SOLR §3.3.2 / §5.2. postState carries the " +
      "program's stale sub-LOG_B frontier (see the generator's splice note).",
    proof: proofHex(oracle),
    publicsCarried: carried,
    publicsFull: pub,
    kemCiphertexts: [kemCiphertext],
    nullifier: pub[5],
    spentRoot: pub[6],
    subtreeRoot: pub[3],
    disclosureHash: pub[2],
    kemBinding: pub[4],
    newRoot: hex32(BigInt(oracle.oracleRoot)),
    startLeafIndex: start,
    batchEpoch: 0,
    preState: pre,
    postState: postProgram,
    disclosureElements: blob.map(hex32),
  };
}

function writeJson(name: string, obj: object): void {
  writeFileSync(join(CONFORMANCE, name), JSON.stringify(obj, null, 1) + "\n");
}

function main(): void {
  const real = JSON.parse(readFileSync(join(FIXTURES, "realproofs.json"), "utf8")) as {
    deposit: EvmFixture;
    withdraw: EvmFixture;
    arbiterKey: [string, string];
  };
  const oracle = JSON.parse(
    readFileSync(join(FIXTURES, "disburse256.oracle.json"), "utf8"),
  ) as DisburseOracle;
  const input = JSON.parse(
    readFileSync(join(FIXTURES, "disburse256.input.json"), "utf8"),
  ) as Disburse256Input;

  writeJson("deposit_fixture.json", depositFixture(real.deposit, real.arbiterKey));
  writeJson("withdraw_fixture.json", withdrawFixture(real.withdraw, real.arbiterKey));
  writeJson(
    "disburse256_fixture.json",
    disburse256Fixture(oracle, input, real.arbiterKey),
  );
  console.log(
    "wrote deposit_fixture.json, withdraw_fixture.json, disburse256_fixture.json (anchors verified)",
  );
}

main();
