// The stack-agnostic half of the repo's proving drivers: read a forge artifact,
// turn a witness input into verifier-ready calldata, and report assertions.
//
// Nothing here knows which chain it is talking to, or that there is a chain at
// all — that is the point. Three drivers had transcribed some subset of it:
//
//   deploy/gates/e2e_orchestrator.ts  M0 cross-circuit e2e on a fresh anvil
//   deploy/live/payroll_e2e.ts        the LIVE payroll pay run
//   apps/indexer/test/scenario.ts     the indexer conformance scenario
//
// The anvil-specific half — connecting, deploying the stack, the shared actor
// and salt fixtures — stays in e2e_harness.ts, which the two anvil drivers use
// and the live driver deliberately does not (it drives the canonical live pool,
// not a stack it just deployed).
//
// TEST/OPS INFRASTRUCTURE, reached by relative import; not an npm package
// export. It loads snarkjs but NEVER ethers: a CI-run test that touches the
// ethers loader breaks on a clean runner (CLAUDE.md).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { FieldInput } from "@bongtu/core/babyjub";
import { toWire } from "@bongtu/core/proving";
import { loadSnarkjs } from "@bongtu/core/extern";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", ".."); // deploy/live/lib -> repo root
const CIRC_OUT = join(ROOT, "circuits", "out");
const CONTRACTS_OUT = join(ROOT, "chains", "evm", "out");

// snarkjs comes back `any` from the shared external loader — we type OUR code
// (notes, keys, tree), not theirs.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const snarkjs: any = loadSnarkjs();

/** BigInt -> decimal string, the form snarkjs and ethers both take. */
export const dec = (x: FieldInput): string => BigInt(x).toString();

/** A compiled contract from `chains/evm/out` (forge's artifact layout). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function artifact(sol: string, contract: string): { abi: any; bytecode: any } {
  const j = JSON.parse(readFileSync(join(CONTRACTS_OUT, `${sol}.sol`, `${contract}.json`), "utf8"));
  return { abi: j.abi, bytecode: j.bytecode.object };
}

/** Witness + groth16 prove + solidity calldata for `circuits/out/<name>`, all
 *  in-process on CPU. `verbose` prints the per-circuit timing the human-watched
 *  DoD gate keeps; the scenario sibling runs it silent. */
export async function prove(name: string, input: unknown, opts: { verbose?: boolean } = {}) {
  const wasm = join(CIRC_OUT, `${name}_js`, `${name}.wasm`);
  const zkey = join(CIRC_OUT, `${name}.zkey`);
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(toWire(input), wasm, zkey);
  const cd = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
  const [a, b, c, pub] = JSON.parse("[" + cd + "]");
  if (opts.verbose) {
    console.log(`   proved ${name} (${publicSignals.length} publics) in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  }
  return { a, b, c, pub, publicSignals };
}

// ---------------------------------------------------------------------------
// assertion reporting — every driver prints the same PASS/FAIL ledger and exits
// on its failure count
// ---------------------------------------------------------------------------

const failures = { count: 0 };

/** Section header in the driver's transcript. */
export function step(title: string): void {
  console.log(`\n=== ${title} ===`);
}

/** Record + print one assertion. Throws on failure so the driver stops at the
 *  first broken invariant rather than cascading; the count is what the caller
 *  exits on. */
export function ok(cond: unknown, msg: string): void {
  const pass = !!cond;
  if (!pass) failures.count++;
  console.log(`   ${pass ? "PASS" : "FAIL"}  ${msg}`);
  if (!pass) throw new Error(`assertion failed: ${msg}`);
}

/** How many `ok()` assertions failed — the driver's exit code. */
export const failureCount = (): number => failures.count;
