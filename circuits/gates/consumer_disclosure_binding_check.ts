// OPMOD §2.1 consumer gate #2 — commitment-publication binding (disbursePriv).
//
// The consumer batch publishes its whole disclosure — receiverCts[4B] ++
// viewTags[B] ++ outputCommitments[B] (OPMOD §4.1) — as module calldata, bound
// by the proof's extended Poseidon(2) fold (§4.2) and by the subtreeRoot
// output. This gate asserts, against the REAL proved disbursePriv artifacts:
//
//   (a) fold(disclosure)          == the proof's disclosureHash public;
//   (b) merkle-fold(commitment run) == the proof's subtreeRoot public
//       (the §4.4 check-2 that makes the PUBLIC indexer batch-fill safe);
//   (c) tampering ANY of the 6B disclosure elements changes the fold
//       (a bad publish is an alarm, not a silent path corruption);
//   (d) tampering the disclosureHash or subtreeRoot public makes
//       `groth16 verify` FAIL (a prover cannot claim a fold or root that
//       mismatches its own witnesses).
//
// disbursePriv (1x16) instantiates the SAME BongtuConsumerDisburse template as
// disbursePriv256, so this is the CPU-tractable witness of the production
// batch path (OPMOD §9 dev-loop arity).
//
// Requires a built out/ (bash build/prove_all.sh disbursePriv).
//
//   npx tsx circuits/gates/consumer_disclosure_binding_check.ts   # exits 0 iff bound

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { consumerDisclosureElements } from "@bongtu/core/consumer";
import { disclosureChain } from "@bongtu/core/envelope";
import { loadSnarkjs } from "@bongtu/core/extern";
import { poseidonN } from "@bongtu/core/poseidon";

import { disbursePrivPlan, sealPlan, DISBURSE_PRIV_B } from "../fixtures/consumer_lib.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "..", "out");

const need = ["disbursePriv.public.json", "disbursePriv.proof.json", "disbursePriv.vkey.json"].map(
  (f) => join(OUT, f),
);
for (const p of need) {
  if (!existsSync(p)) {
    console.error(`FATAL: ${p} missing — run bash build/prove_all.sh disbursePriv first.`);
    process.exit(1);
  }
}
const pub: string[] = JSON.parse(readFileSync(need[0], "utf8"));
const proof = JSON.parse(readFileSync(need[1], "utf8"));
const vkey = JSON.parse(readFileSync(need[2], "utf8"));

const failures = { count: 0 };
const fail = (msg: string): void => {
  console.error(`FAIL: ${msg}`);
  failures.count++;
};

// OPMOD §2 disbursePriv layout: [2]=disclosureHash [3]=subtreeRoot.
const disclosureHash = BigInt(pub[2]);
const subtreeRoot = BigInt(pub[3]);

// The published disclosure, rebuilt from the shared deterministic plan — the
// exact array the ConsumerDisburseModule would carry as calldata.
const sealed = sealPlan("disbursePriv", disbursePrivPlan());
const disclosure = consumerDisclosureElements(
  sealed.map((s) => s.seal.cipherText),
  sealed.map((s) => s.seal.viewTag),
  sealed.map((s) => s.commitment),
);
if (disclosure.length !== 6 * DISBURSE_PRIV_B) {
  fail(`disclosure is ${disclosure.length} elements, want 6B = ${6 * DISBURSE_PRIV_B}`);
}

// (a) the extended fold matches the proof-bound public.
if (disclosureChain(disclosure) !== disclosureHash) {
  fail(`fold(disclosure) != proof disclosureHash (${disclosureChain(disclosure)} vs ${disclosureHash})`);
} else {
  console.log("OK: fold(disclosure) == proof disclosureHash (OPMOD §4.2 layout, 6B elements)");
}

// (b) the commitment run folds pairwise to the proof's subtreeRoot (§4.4 #2).
const merkleFold = (nodes: bigint[]): bigint =>
  nodes.length === 1
    ? nodes[0]
    : merkleFold(
        Array.from({ length: nodes.length / 2 }, (_, i) => poseidonN([nodes[2 * i], nodes[2 * i + 1]])),
      );
const leaves = disclosure.slice(5 * DISBURSE_PRIV_B); // elements 5B..6B-1
if (merkleFold(leaves) !== subtreeRoot) {
  fail(`fold(leaves) != proof subtreeRoot (${merkleFold(leaves)} vs ${subtreeRoot})`);
} else {
  console.log("OK: fold(leaves) == proof subtreeRoot (public batch-fill is safe)");
}

// (c) every single-element tamper changes the fold.
const surviving = disclosure.reduce((acc, _, i) => {
  const tampered = disclosure.map((x, j) => (j === i ? x + 1n : x));
  return disclosureChain(tampered) === disclosureHash ? acc + 1 : acc;
}, 0);
if (surviving > 0) {
  fail(`${surviving} of ${disclosure.length} single-element tampers left the fold UNCHANGED`);
} else {
  console.log(`OK: all ${disclosure.length} single-element tampers change the fold (mismatch -> alarm)`);
}

// (d) tampering either bound public breaks groth16 verification.
async function tamperGate(): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const snarkjs: any = loadSnarkjs();
  if (!(await snarkjs.groth16.verify(vkey, pub, proof))) {
    fail("honest disbursePriv proof does not verify (stale out/?)");
    return;
  }
  for (const [at, name] of [
    [2, "disclosureHash"],
    [3, "subtreeRoot"],
  ] as [number, string][]) {
    const tampered = [...pub];
    tampered[at] = (BigInt(pub[at]) + 1n).toString();
    if (await snarkjs.groth16.verify(vkey, tampered, proof)) {
      fail(`proof verified with a TAMPERED ${name} (pub[${at}]+1)`);
    } else {
      console.log(`OK: tampered ${name} (pub[${at}]+1) -> groth16 verify FAILS`);
    }
  }
}
await tamperGate();

if (failures.count) {
  console.error(`\nCOMMITMENT-PUBLICATION BINDING GATE: FAIL (${failures.count})`);
  process.exit(1);
}
console.log(
  "\nCOMMITMENT-PUBLICATION BINDING GATE: PASS — the disclosure is elementwise proof-bound and its commitment run folds to subtreeRoot",
);
process.exit(0);
