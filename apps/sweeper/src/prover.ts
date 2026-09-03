// CPU snarkjs deposit prover — witness + groth16 + solidity calldata for
// circuits/out's deposit circuit.
//
// RESTATED from deploy/live/lib/proof_toolbox.ts `prove()` (the pattern owner
// alongside circuits/gates/auditor_decrypt_check.ts): that module is test/ops
// infrastructure reached by relative import — deliberately NOT a package
// export — and it calls loadSnarkjs() at module top, which would make this
// app's BOOT (and the headless spawn tests) require the external
// BONGTU_NODE_MODULES tree. Here snarkjs loads LAZILY inside the first prove
// call instead, so a booted-but-idle sweeper (and CI's clean runners, see
// .dev/ci.md) never touch the seam; the load path itself is the shared
// @bongtu/core/extern loadSnarkjs, the one owner of the createRequire seam.

import { join } from "node:path";

import { loadSnarkjs } from "@bongtu/core/extern";
import type { Calldata, ProvingRequest } from "@bongtu/core/proving";

/**
 * A deposit prover bound to one circuits/out directory (env CIRCUITS_OUT).
 * The request's input is already wire-form (buildDepositRequest applies
 * toWire), so it feeds snarkjs' witness calculator as-is.
 */
export function makeDepositProver(circuitsOut: string): (request: ProvingRequest) => Promise<Calldata> {
  return async (request: ProvingRequest): Promise<Calldata> => {
    if (request.circuit !== "deposit") {
      throw new Error(`sweeper prover only proves deposit, got ${request.circuit}`);
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const snarkjs: any = loadSnarkjs(); // lazy: see module header
    const wasm = join(circuitsOut, "deposit_js", "deposit.wasm");
    const zkey = join(circuitsOut, "deposit.zkey");
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(request.input, wasm, zkey);
    const cd = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
    const [a, b, c, pub] = JSON.parse("[" + cd + "]");
    return { a, b, c, pub };
  };
}
