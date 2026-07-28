// U3 soundness gate (SPEC §5.2): prove the value-belt closes mint-from-nothing
// at the CIRCUIT level. Regenerates the attack/padded fixtures, then asserts:
//
//   withdraw_mint       (nf=0,  value=X, enabled=0)      -> generate_witness THROWS
//   withdraw_attack     (nf!=0, value=X, enabled=0)      -> generate_witness THROWS
//   transfer10_attack   (nf!=0, value=X, enabled=0 in a  -> generate_witness THROWS
//   transfer10x2_attack  padded slot of a 10-input spend)
//   withdraw_padded     (nf=0,  value=0, enabled=0)      -> generate_witness SUCCEEDS
//   transfer10          (6 zero-value disabled pads)     -> generate_witness SUCCEEDS
//   transfer10x2        (6 zero-value disabled pads)     -> generate_witness SUCCEEDS
//
// The throwing fixtures fail on the belt constraint
// `(1 - enabled[i]) * inputValues[i] === 0` in the spending base.
// Requires out/{withdraw,transfer10,transfer10x2}_js (compile them first, e.g. via prove_all.sh).
//
// PLUS the PQ-envelope binding gate (pq-envelope-design.md §2/§6): for every
// proved fixture in out/, TAMPERING the kemBinding public signal makes
// `groth16 verify` FAIL — a prover cannot claim a binding that mismatches its
// own kemSs witness, so the on-chain binding is exactly what the proof fixed.
//
//   npx tsx assert_attacks_throw.ts    # exits 0 iff all assertions hold

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadSnarkjs } from "@bongtu/core/extern";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "out");
const wasmOf = (c: string): string => join(OUT, `${c}_js`, `${c}.wasm`);
const genwitOf = (c: string): string => join(OUT, `${c}_js`, "generate_witness.js");
const inp = (n: string): string => join(HERE, "inputs", `${n}.json`);
const wtns = (n: string): string => join(OUT, `${n}.wtns`);

for (const c of ["withdraw", "transfer10", "transfer10x2"]) {
  if (!existsSync(wasmOf(c))) {
    console.error(`FATAL: ${wasmOf(c)} missing — compile ${c} first (bash prove_all.sh).`);
    process.exit(1);
  }
}

// circom's generate_witness.js is CommonJS; the repo root is an ESM package, so
// mark the (gitignored) out/ tree as CommonJS to load the helper unchanged.
writeFileSync(join(OUT, "package.json"), '{ "type": "commonjs" }\n');

// Regenerate the fixtures so the gate is self-contained. Run the TS generator
// through tsx regardless of how this script itself was launched.
execFileSync(process.execPath, ["--import", "tsx", join(HERE, "gen_attack_inputs.ts")], {
  stdio: "inherit",
});

interface WitnessResult {
  ok: boolean;
  out: string;
}

function witness(circuit: string, name: string): WitnessResult {
  try {
    // generate_witness.js is snarkjs-emitted plain CommonJS — run it with node directly.
    execFileSync(process.execPath, [genwitOf(circuit), wasmOf(circuit), inp(name), wtns(name)], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, out: "" };
  } catch (e) {
    const err = e as { stdout?: Buffer | string; stderr?: Buffer | string };
    return { ok: false, out: `${err.stdout ?? ""}${err.stderr ?? ""}` };
  }
}

let failures = 0;

// Each throwing fixture, with the spending base whose belt assertion must name it.
const MUST_THROW: [circuit: string, fixture: string, belt: string][] = [
  ["withdraw", "withdraw_mint", "CheckNullifiersInputsOutputsValueIMT"],
  ["withdraw", "withdraw_attack", "CheckNullifiersInputsOutputsValueIMT"],
  ["transfer10", "transfer10_attack", "ZetoTransferSmall"],
  ["transfer10x2", "transfer10x2_attack", "ZetoTransferSmall"],
];

for (const [circuit, name, belt] of MUST_THROW) {
  const r = witness(circuit, name);
  if (r.ok) {
    console.error(`FAIL: ${name} generated a witness but the value-belt should make it UNSATISFIABLE`);
    failures++;
  } else if (!r.out.includes("Assert Failed") || !r.out.includes(belt)) {
    console.error(`FAIL: ${name} threw, but not on the belt assertion. Output:\n${r.out}`);
    failures++;
  } else {
    console.log(`OK: ${name} witness-gen THROWS on the value-belt (Assert Failed in ${belt})`);
  }
}

// Positive controls: a zero-value disabled slot must still prove, at every arity.
for (const [circuit, name] of [
  ["withdraw", "withdraw_padded"],
  ["transfer10", "transfer10"],
  ["transfer10x2", "transfer10x2"],
]) {
  const r = witness(circuit, name);
  if (!r.ok) {
    console.error(`FAIL: ${name} (genuine zero-value pads) must satisfy the belt. Output:\n${r.out}`);
    failures++;
  } else {
    console.log(`OK: ${name} witness-gen SUCCEEDS (zero-value pads satisfy the belt)`);
  }
}

// --- PQ kemBinding tamper gate ---------------------------------------------
// kemBinding public-signal index per proof fixture (pq-envelope-design.md §3
// layouts), with the circuit whose vkey verifies it — transfer10 and
// transfer10x2 each carry two fixtures against one vkey.
const KEM_BINDING_AT: [fixture: string, circuit: string, at: number][] = [
  ["deposit", "deposit", 13],
  ["withdraw", "withdraw", 16],
  ["transfer", "transfer", 26],
  ["transfer10", "transfer10", 106],
  ["transfer10_consolidate", "transfer10", 106],
  ["transfer10x2", "transfer10x2", 41],
  ["transfer10x2_merge", "transfer10x2", 41],
  ["disburse", "disburse", 4],
  ["disburse256", "disburse256", 4],
];

async function kemBindingTamperGate(): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const snarkjs: any = loadSnarkjs();
  const rd = (p: string): any => JSON.parse(readFileSync(p, "utf8"));
  for (const [name, circuit, at] of KEM_BINDING_AT) {
    const vkeyP = join(OUT, `${circuit}.vkey.json`);
    const pubP = join(OUT, `${name}.public.json`);
    const proofP = join(OUT, `${name}.proof.json`);
    if (!existsSync(vkeyP) || !existsSync(pubP) || !existsSync(proofP)) {
      console.log(`SKIP: ${name} kemBinding tamper (missing out/ artifacts)`);
      continue;
    }
    const vkey = rd(vkeyP);
    const pub: string[] = rd(pubP);
    const proof = rd(proofP);
    if (!(await snarkjs.groth16.verify(vkey, pub, proof))) {
      console.error(`FAIL: ${name} honest proof does not verify (stale out/?)`);
      failures++;
      continue;
    }
    const tampered = [...pub];
    tampered[at] = (BigInt(pub[at]) + 1n).toString();
    if (await snarkjs.groth16.verify(vkey, tampered, proof)) {
      console.error(`FAIL: ${name} verified with a TAMPERED kemBinding (pub[${at}]+1)`);
      failures++;
    } else {
      console.log(`OK: ${name} tampered kemBinding (pub[${at}]+1) -> groth16 verify FAILS`);
    }
  }
}

await kemBindingTamperGate();

if (failures) {
  console.error(`\nBELT GATE: FAIL (${failures})`);
  process.exit(1);
}
console.log("\nBELT GATE: PASS — mint-from-nothing is unsatisfiable at the circuit level; kemBinding is proof-bound");
process.exit(0);
