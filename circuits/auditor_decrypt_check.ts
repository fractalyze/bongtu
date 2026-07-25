// §6b v2 auditor-decryptability gate (deliverable-defining, not optional).
//
// The product promise is ENFORCED AUDITOR DISCLOSURE: every note's creation
// (deposit) and destruction (withdraw) must be openable by the single arbiter
// key from ON-CHAIN data alone. This script PROVES that end to end for a
// FRESHLY-proven deposit and withdraw:
//
//   1. build fresh witnesses with a FRESH ephemeral ecdh key + nonce per tx
//      (SPEC §4 two-time-pad rule), encrypting the authority envelope to the
//      arbiter public key;
//   2. groth16-prove (CPU snarkjs) against the committed zkeys;
//   3. as the AUDITOR (holding ONLY the arbiter PRIVATE key + the public
//      signals a chain would carry: ecdhPublicKey + cipherTextAuthority +
//      nonce), ECDH with the emitted ecdhPublicKey, derive the shared secret,
//      and poseidon-decrypt cipherTextAuthority;
//   4. assert the recovered fields EQUAL the known plaintext:
//        deposit  -> each output note's (ownerPub, value, salt);
//        withdraw -> the input owner + each input (value,salt) + the change
//                    note (ownerPub, value, salt).
//
//   npx tsx auditor_decrypt_check.ts   # exits 0 iff both decrypts match
//
// Requires out/{deposit,withdraw}.zkey + the *_js wasm (bash prove_all.sh, or
// the deposit/withdraw setup this unit ran). Proving is CPU-only.

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

import { ImtTree } from "@bongtu/sdk/imt";
import {
  deriveKeypair,
  commitment,
  nullifier,
  ecdhSharedSecret,
  poseidonDecrypt,
} from "@bongtu/sdk/note";
import type { Keypair } from "@bongtu/sdk/note";
import type { FieldInput } from "@bongtu/sdk/babyjub";

const require = createRequire(import.meta.url);
const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "out");
const NODE_MODULES =
  process.env.BONGTU_NODE_MODULES || "/home/a41/Workspace/zkx-snap/circuits/node_modules";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const snarkjs: any = require(join(NODE_MODULES, "snarkjs/build/main.cjs"));

const H = 32;

let failures = 0;
function ok(cond: unknown, msg: string): void {
  const pass = !!cond;
  if (!pass) failures++;
  console.log(`   ${pass ? "PASS" : "FAIL"}  ${msg}`);
}
function eq(a: FieldInput, b: FieldInput, msg: string): void {
  ok(BigInt(a) === BigInt(b), `${msg} (got ${a}, want ${b})`);
}
function strify(v: unknown): unknown {
  if (typeof v === "bigint") return v.toString();
  if (Array.isArray(v)) return v.map(strify);
  if (v && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(v)) o[k] = strify((v as Record<string, unknown>)[k]);
    return o;
  }
  return v;
}
async function prove(name: string, input: unknown): Promise<bigint[]> {
  const wasm = join(OUT, `${name}_js`, `${name}.wasm`);
  const zkey = join(OUT, `${name}.zkey`);
  const { publicSignals } = await snarkjs.groth16.fullProve(strify(input), wasm, zkey);
  return (publicSignals as string[]).map((x) => BigInt(x));
}

// The single arbiter (auditor). The auditor holds ONLY formattedPrivateKey.
const AUTHORITY = deriveKeypair(555555555555555555555555n);

async function checkDeposit(): Promise<void> {
  console.log("\n=== DEPOSIT auditor-decrypt (outputs: 2 * (ownerPub, value, salt)) ===");
  const owner0 = deriveKeypair(31111111n);
  const owner1 = deriveKeypair(42222222n);
  const values = [1234n, 5678n];
  const salts = [900001n, 900002n];
  const oc = [
    commitment(values[0], salts[0], owner0.publicKey),
    commitment(values[1], salts[1], owner1.publicKey),
  ];
  // FRESH ephemeral ecdh key + nonce for THIS tx (SPEC §4 two-time-pad rule).
  const ecdhPrivateKey = 12121212121212121212121n;
  const encryptionNonce = 707070707070n;

  const pub = await prove("deposit", {
    outputCommitments: oc,
    outputValues: values,
    outputSalts: salts,
    outputOwnerPublicKeys: [owner0.publicKey, owner1.publicKey],
    ecdhPrivateKey,
    encryptionNonce,
    authorityPublicKey: AUTHORITY.publicKey,
  });
  ok(pub.length === 18, `deposit publics length == 18 (got ${pub.length})`);

  // What a chain would carry: ecdhPublicKey = pub[1..2]; cipherTextAuthority = pub[3..12].
  const ecdhPublicKey: [bigint, bigint] = [pub[1], pub[2]];
  const cipherTextAuthority = pub.slice(3, 3 + 10);

  // AUDITOR: ECDH(arbiterPriv, ecdhPublicKey) == the circuit's Ecdh(ecdhPriv, arbiterPub).
  const shared = ecdhSharedSecret(AUTHORITY.formattedPrivateKey, ecdhPublicKey);
  const m = poseidonDecrypt(cipherTextAuthority, shared, encryptionNonce, 8);
  // plaintext layout: [own0.x, own0.y, own1.x, own1.y, val0, salt0, val1, salt1]
  eq(m[0], owner0.publicKey[0], "recovered output0 ownerPub.x");
  eq(m[1], owner0.publicKey[1], "recovered output0 ownerPub.y");
  eq(m[2], owner1.publicKey[0], "recovered output1 ownerPub.x");
  eq(m[3], owner1.publicKey[1], "recovered output1 ownerPub.y");
  eq(m[4], values[0], "recovered output0 value");
  eq(m[5], salts[0], "recovered output0 salt");
  eq(m[6], values[1], "recovered output1 value");
  eq(m[7], salts[1], "recovered output1 salt");
  // the recovered (value, salt, owner) reproduce the on-chain output commitments.
  eq(commitment(m[4], m[5], [m[0], m[1]]), oc[0], "recovered output0 rebuilds its on-chain commitment");
  eq(commitment(m[6], m[7], [m[2], m[3]]), oc[1], "recovered output1 rebuilds its on-chain commitment");
}

// Insert commitments as single leaves; return root + per-leaf membership witness.
function membership(commitments: bigint[]): { root: bigint; pathElements: bigint[][]; leafIndices: bigint[] } {
  const tree = new ImtTree(H, 16);
  const idxs = commitments.map((c) => {
    const i = tree.getNextLeafIndex();
    tree.appendLeaf(c);
    return i;
  });
  const pathElements: bigint[][] = [];
  const leafIndices: bigint[] = [];
  for (const i of idxs) {
    pathElements.push(tree.merklePath(i).siblings);
    leafIndices.push(BigInt(i));
  }
  return { root: tree.getRoot(), pathElements, leafIndices };
}

async function checkWithdraw(): Promise<void> {
  console.log("\n=== WITHDRAW auditor-decrypt (inputOwner + 2*(inVal,inSalt) + change note) ===");
  const sender: Keypair = deriveKeypair(98765432109876n);
  const changeOwner = deriveKeypair(55550000n);
  const inValues = [600n, 500n];
  const inSalts = [800001n, 800002n];
  const inCommits = inValues.map((v, i) => commitment(v, inSalts[i], sender.publicKey));
  const { root, pathElements, leafIndices } = membership(inCommits);
  const outValue = 100n; // change; withdrawn amount out = 1100 - 100 = 1000
  const outSalt = 800003n;
  const outCommit = commitment(outValue, outSalt, changeOwner.publicKey);

  const ecdhPrivateKey = 34343434343434343434343n;
  const encryptionNonce = 818181818181n;

  const pub = await prove("withdraw", {
    nullifiers: inValues.map((v, i) => nullifier(v, inSalts[i], sender.formattedPrivateKey)),
    inputCommitments: inCommits,
    inputValues: inValues,
    inputSalts: inSalts,
    inputOwnerPrivateKey: sender.formattedPrivateKey,
    root,
    pathElements,
    leafIndices,
    enabled: [1n, 1n],
    outputCommitments: [outCommit],
    outputValues: [outValue],
    outputSalts: [outSalt],
    outputOwnerPublicKeys: [changeOwner.publicKey],
    ecdhPrivateKey,
    encryptionNonce,
    authorityPublicKey: AUTHORITY.publicKey,
  });
  ok(pub.length === 25, `withdraw publics length == 25 (got ${pub.length})`);
  eq(pub[0], 1000n, "withdraw out (pub[0]) == 1100 - 100 == 1000");

  // chain-carried: ecdhPublicKey = pub[1..2]; cipherTextAuthority = pub[3..15].
  const ecdhPublicKey: [bigint, bigint] = [pub[1], pub[2]];
  const cipherTextAuthority = pub.slice(3, 3 + 13);

  const shared = ecdhSharedSecret(AUTHORITY.formattedPrivateKey, ecdhPublicKey);
  const m = poseidonDecrypt(cipherTextAuthority, shared, encryptionNonce, 10);
  // layout: [inOwner.x, inOwner.y, inVal0, inSalt0, inVal1, inSalt1, outOwner.x, outOwner.y, outVal0, outSalt0]
  eq(m[0], sender.publicKey[0], "recovered input owner pub.x");
  eq(m[1], sender.publicKey[1], "recovered input owner pub.y");
  eq(m[2], inValues[0], "recovered input0 value");
  eq(m[3], inSalts[0], "recovered input0 salt");
  eq(m[4], inValues[1], "recovered input1 value");
  eq(m[5], inSalts[1], "recovered input1 salt");
  eq(m[6], changeOwner.publicKey[0], "recovered change ownerPub.x");
  eq(m[7], changeOwner.publicKey[1], "recovered change ownerPub.y");
  eq(m[8], outValue, "recovered change value");
  eq(m[9], outSalt, "recovered change salt");
  // recovered input (value,salt,owner) reproduce the spent commitments; change rebuilds too.
  eq(commitment(m[2], m[3], [m[0], m[1]]), inCommits[0], "recovered input0 rebuilds its commitment");
  eq(commitment(m[4], m[5], [m[0], m[1]]), inCommits[1], "recovered input1 rebuilds its commitment");
  eq(commitment(m[8], m[9], [m[6], m[7]]), outCommit, "recovered change rebuilds its on-chain commitment");
}

async function main(): Promise<void> {
  await checkDeposit();
  await checkWithdraw();
  console.log(
    `\n${failures === 0
      ? "AUDITOR-DECRYPT GATE: PASS — deposit + withdraw notes are recoverable from on-chain data by the arbiter key alone"
      : `AUDITOR-DECRYPT GATE: FAIL — ${failures} assertion(s)`}`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("\nAUDITOR-DECRYPT ERROR:", e && e.stack ? e.stack : e);
  process.exit(1);
});
