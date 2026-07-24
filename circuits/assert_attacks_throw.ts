// U3 soundness gate (SPEC §5.2): prove the value-belt closes mint-from-nothing
// at the CIRCUIT level. Regenerates the attack/padded fixtures, then asserts:
//
//   withdraw_mint    (nf=0,  value=X, enabled=0) -> generate_witness THROWS
//   withdraw_attack  (nf!=0, value=X, enabled=0) -> generate_witness THROWS
//   withdraw_padded  (nf=0,  value=0, enabled=0) -> generate_witness SUCCEEDS
//
// The two throwing fixtures fail on the belt constraint
// `(1 - enabled[i]) * inputValues[i] === 0` in CheckNullifiersInputsOutputsValueIMT.
// Requires out/withdraw_js (compile withdraw first, e.g. via prove_all.sh).
//
//   npx tsx assert_attacks_throw.ts    # exits 0 iff all three assertions hold

import { execFileSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "out");
const WASM = join(OUT, "withdraw_js", "withdraw.wasm");
const GENWIT = join(OUT, "withdraw_js", "generate_witness.js");
const inp = (n: string): string => join(HERE, "inputs", `${n}.json`);
const wtns = (n: string): string => join(OUT, `${n}.wtns`);

if (!existsSync(WASM)) {
  console.error(`FATAL: ${WASM} missing — compile withdraw first (bash prove_all.sh).`);
  process.exit(1);
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

function witness(name: string): WitnessResult {
  try {
    // generate_witness.js is snarkjs-emitted plain CommonJS — run it with node directly.
    execFileSync(process.execPath, [GENWIT, WASM, inp(name), wtns(name)], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, out: "" };
  } catch (e) {
    const err = e as { stdout?: Buffer | string; stderr?: Buffer | string };
    return { ok: false, out: `${err.stdout ?? ""}${err.stderr ?? ""}` };
  }
}

let failures = 0;
const BELT = "CheckNullifiersInputsOutputsValueIMT";

for (const name of ["withdraw_mint", "withdraw_attack"]) {
  const r = witness(name);
  if (r.ok) {
    console.error(`FAIL: ${name} generated a witness but the value-belt should make it UNSATISFIABLE`);
    failures++;
  } else if (!r.out.includes("Assert Failed") || !r.out.includes(BELT)) {
    console.error(`FAIL: ${name} threw, but not on the belt assertion. Output:\n${r.out}`);
    failures++;
  } else {
    console.log(`OK: ${name} witness-gen THROWS on the value-belt (Assert Failed in ${BELT})`);
  }
}

{
  const r = witness("withdraw_padded");
  if (!r.ok) {
    console.error(`FAIL: withdraw_padded (a genuine zero-value pad) must satisfy the belt. Output:\n${r.out}`);
    failures++;
  } else {
    console.log("OK: withdraw_padded witness-gen SUCCEEDS (zero-value pad satisfies the belt)");
  }
}

if (failures) {
  console.error(`\nBELT GATE: FAIL (${failures})`);
  process.exit(1);
}
console.log("\nBELT GATE: PASS — mint-from-nothing is unsatisfiable at the circuit level");
