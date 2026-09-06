// Dedicated ct-free enterprise pool leg — driven by deploy/gates/ctf_pool_local.sh
// against a pool the VERIFIER_PROFILE=ctf deploy just created (B=256).
//
// What it proves, in order:
//   WIRING    the pool's disburse slot holds the DisburseCtf256Verifier BYTES
//             (extcodehash-style compare against the forge artifact) — the
//             record's addresses alone cannot prove the swap, because a fresh
//             chain replays the same CREATE nonces as a standard deploy;
//   READBACK  B()==256, currentEpoch()==0, every verifier getter == its record
//             field;
//   DEPOSIT   a fresh CPU deposit whose output 0 IS the committed disburseCtf256
//             fixture's input note (the fixture material is deterministic), so
//             the proof's single-leaf membership root enters root history —
//             per-leaf root recording is what makes a committed single-leaf
//             fixture replayable after a 2-leaf deposit;
//   DISBURSE  the committed REAL GPU ct-free proof settles: 256-subtree
//             attaches, root == an in-process ImtTree oracle, nullifier marked;
//   BINDING   the served blob is zeros(4·B) ++ the authority ciphertext
//             (recomputed from the fixture witness through the SDK sponge), and
//             its Poseidon(2) fold equals the proof's disclosureHash public —
//             the ct-free disclosure invariant, checked end to end.
//
//   E2E_RPC=<anvil url> RECORD=<addresses.ctf.json> npx tsx deploy/gates/ctf_leg.ts

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ImtTree } from "@bongtu/core/imt";
import { commitment, deriveKeypair, ecdhSharedSecret, poseidonEncrypt } from "@bongtu/core/note";
import { hybridEnvelopeKey, kemBindingOf } from "@bongtu/core/kem";
import { disclosureChain, buildAuthorityPlaintext } from "@bongtu/core/envelope";
import type { ParsedEnvelope } from "@bongtu/core/envelope";

import {
  H, connectAnvil, artifact, prove, ok, step, failureCount, kemDraw, kemCtHex,
} from "../live/lib/e2e_harness.js";
import { proofArgs } from "../live/lib/viem_client.js";
// The committed disburse256 fixture's KEM draw comes from the CIRCUITS fixture
// preamble, not the harness kemDraw (the two derive from different label
// domains; the fixture proofs were encapsulated under this one).
import { kemDraw as fixtureKemDraw } from "../../circuits/fixtures/fixture_lib.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const FIXTURES = join(ROOT, "chains", "evm", "test", "fixtures");

const B = 256;
const rd = (p: string): any => JSON.parse(readFileSync(p, "utf8"));

// The disburse256 fixture's employer (circuits/fixtures/gen_disburse256_input.ts
// key material — deterministic, PRNG-free); belted against the committed input
// below so a drifted transcription fails loudly instead of misproving.
const EMPLOYER256 = deriveKeypair(313131313131313131313131n);

async function main(): Promise<void> {
  const record = rd(process.env.RECORD ?? join(ROOT, "deploy", "addresses.ctf.31337.json"));
  const input = rd(join(FIXTURES, "disburse256.input.json"));
  const cd = rd(join(FIXTURES, "disburseCtf256.calldata.json"));
  const pub = (cd.pub as string[]).map(BigInt);

  const rig = connectAnvil();
  const pool = rig.at(record.pool, artifact("BongtuPool", "BongtuPool").abi);
  const token = rig.at(record.token, artifact("MockERC20", "MockERC20").abi);

  // ============================ WIRING ====================================
  step("WIRING: disburse slot code == DisburseCtf256Verifier artifact bytes");
  const want = JSON.parse(
    readFileSync(join(ROOT, "chains", "evm", "out", "DisburseCtf256Verifier.sol", "DisburseCtf256Verifier.json"), "utf8"),
  ).deployedBytecode.object as string;
  const got = await rig.publicClient.getCode({ address: record.disburseVerifier });
  ok(got === want, "on-chain disburse verifier bytecode == DisburseCtf256Verifier artifact");

  // ============================ READBACK ==================================
  step("READBACK: pool shape and record fields");
  ok((await pool.read("B")).toString() === String(B), "B() == 256");
  ok((await pool.read("currentEpoch")).toString() === "0", "currentEpoch() == 0 (fresh pool)");
  for (const [getter, field] of [
    ["depositVerifier", "depositVerifier"],
    ["withdrawVerifier", "withdrawVerifier"],
    ["disburseVerifier", "disburseVerifier"],
    ["transferVerifier", "transferVerifier"],
    ["transfer10Verifier", "transfer10Verifier"],
    ["transfer10x2Verifier", "transfer10x2Verifier"],
  ] as const) {
    const on = (await pool.read(getter)) as string;
    ok(on.toLowerCase() === String(record[field]).toLowerCase(), `${getter}() == record.${field}`);
  }

  // ============================ DEPOSIT ===================================
  step("DEPOSIT: fresh CPU proof seeding the committed fixture's input note");
  const V = BigInt(input.inputValues[0]);
  const inSalt = BigInt(input.inputSalts[0]);
  const inCommit = commitment(V, inSalt, EMPLOYER256.publicKey);
  ok(inCommit === BigInt(input.inputCommitments[0]), "commitment(V, salt, EMPLOYER256) == fixture inputCommitments[0]");
  ok(BigInt(input.inputOwnerPrivateKey) === EMPLOYER256.formattedPrivateKey, "EMPLOYER256 scalar == fixture inputOwnerPrivateKey");

  const oracle = new ImtTree(H, B);
  const fillerSalt = 9500001n;
  const filler = commitment(0n, fillerSalt, EMPLOYER256.publicKey);
  const KEM_DEP = kemDraw("ctf/gate/deposit");
  const depositInput = {
    outputCommitments: [inCommit, filler],
    outputValues: [V, 0n],
    outputSalts: [inSalt, fillerSalt],
    outputOwnerPublicKeys: [EMPLOYER256.publicKey, EMPLOYER256.publicKey],
    ecdhPrivateKey: 700000000000000000009n,
    kemSs: KEM_DEP.kemSs,
    encryptionNonce: 515151515151n,
    authorityPublicKey: [BigInt(input.authorityPublicKey[0]), BigInt(input.authorityPublicKey[1])],
  };
  await token.write("mint", [rig.address, V]);
  await token.write("approve", [record.pool, V]);
  const dep = await prove("deposit", depositInput);
  await pool.write("deposit", [...proofArgs(dep), kemCtHex(KEM_DEP.kemCiphertext)]);
  oracle.appendLeaf(inCommit);
  const singleLeafRoot = oracle.getRoot();
  oracle.appendLeaf(filler);
  ok((await pool.read("root")).toString() === oracle.getRoot().toString(), "post-deposit root == 2-leaf oracle");
  ok(singleLeafRoot === pub[6], "single-leaf root == ctf proof's membership root (pub[6])");
  ok((await pool.read("isKnownRoot", [singleLeafRoot])) === true, "per-leaf history holds the single-leaf root");

  // ============================ DISBURSE ==================================
  step("DISBURSE: committed GPU ct-free proof settles the 256 batch");
  // The served blob: zeros in the whole receiver run (ct-free), the authority
  // envelope recomputed from the fixture witness through the SDK sponge.
  const env: ParsedEnvelope = {
    inputs: [{ owner: EMPLOYER256.publicKey as [bigint, bigint], value: V, salt: inSalt }],
    outputs: Array.from({ length: B }, (_, i) => ({
      owner: [BigInt(input.outputOwnerPublicKeys[i][0]), BigInt(input.outputOwnerPublicKeys[i][1])] as [bigint, bigint],
      value: BigInt(input.outputValues[i]),
      salt: BigInt(input.outputSalts[i]),
    })),
  };
  const kemSs: [bigint, bigint] = [BigInt(input.kemSs[0]), BigInt(input.kemSs[1])];
  ok(kemBindingOf(kemSs) === pub[4], "fixture kemSs binds to the proof's kemBinding public");
  const shared = ecdhSharedSecret(BigInt(input.ecdhPrivateKey), [
    BigInt(input.authorityPublicKey[0]),
    BigInt(input.authorityPublicKey[1]),
  ]);
  const authCt = poseidonEncrypt(
    buildAuthorityPlaintext("disburse", env),
    hybridEnvelopeKey(shared, kemSs),
    BigInt(input.encryptionNonce),
  );
  const blob = [...Array.from({ length: 4 * B }, () => 0n), ...authCt];
  ok(blob.length === 2054, "blob length == disburseCiphertextLen (2054)");
  ok(disclosureChain(blob) === pub[2], "fold(zeros ++ authorityCt) == disclosureHash public (ct-free binding)");

  const KEM_256 = fixtureKemDraw("disburse256");
  ok(kemBindingOf(KEM_256.kemSs) === pub[4], "fixture kemDraw('disburse256') reproduces the proof's KEM draw");
  await pool.write("disburseWithCiphertexts", [
    cd.a.map(BigInt), [cd.b[0].map(BigInt), cd.b[1].map(BigInt)], cd.c.map(BigInt),
    pub, blob, kemCtHex(KEM_256.kemCiphertext),
  ]);
  oracle.attachSubtree(pub[3]);
  ok((await pool.read("root")).toString() === oracle.getRoot().toString(), "post-disburse root == oracle (pad + attach)");
  ok((await pool.read("nextLeafIndex")).toString() === String(2 * B), "nextLeafIndex == 512 (block close + subtree)");
  ok((await pool.read("nullifierUsed", [pub[5]])) === true, "disburse nullifier marked");

  const n = failureCount();
  console.log(n === 0 ? "\nCTF POOL LEG: PASS" : `\nCTF POOL LEG: FAIL (${n} failed assertions)`);
  process.exit(n === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("FATAL:", e);
  process.exit(1);
});
