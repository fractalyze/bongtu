// Headless gate for the CPU-circuit gate in src/lib/prove.ts. The proving edge itself
// (snarkjs wtns.calculate + groth16.prove) needs a browser + live zkey and is out of
// scope here; what IS pure and security-relevant is the circuit ALLOW-LIST: the public
// wallet proves ONLY transfer/withdraw/deposit in-browser (disburse is GPU-only, prover/),
// so isCpuCircuit must accept exactly those three and assertCpuCircuit must throw on
// anything else. Adding deposit to that list is the load-bearing change this unit makes.

import { test } from "node:test";
import assert from "node:assert/strict";

import { isCpuCircuit, assertCpuCircuit } from "../src/lib/prove.js";

test("isCpuCircuit accepts the three in-browser circuits, incl. deposit", () => {
  assert.equal(isCpuCircuit("transfer"), true);
  assert.equal(isCpuCircuit("withdraw"), true);
  assert.equal(isCpuCircuit("deposit"), true);
  // disburse is GPU-only; anything unknown is rejected.
  assert.equal(isCpuCircuit("disburse"), false);
  assert.equal(isCpuCircuit("nonsense"), false);
});

test("assertCpuCircuit passes deposit and throws on a GPU/unknown circuit", () => {
  assert.doesNotThrow(() => assertCpuCircuit("deposit"));
  assert.doesNotThrow(() => assertCpuCircuit("transfer"));
  assert.doesNotThrow(() => assertCpuCircuit("withdraw"));
  assert.throws(() => assertCpuCircuit("disburse"), /only proves/i);
  assert.throws(() => assertCpuCircuit("nonsense"), /only proves/i);
});
