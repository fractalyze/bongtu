// CPU snarkjs prover — witness + groth16 + solidity calldata for one of
// circuits/out's circuits (deposit for the enterprise portal mode, depositPriv
// for the priv mode).
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
 * A prover bound to one circuits/out directory (env CIRCUITS_OUT) and ONE
 * circuit — the mode decides which at boot, and a request for any other
 * circuit is refused loudly (a mode mismatch must never prove the wrong
 * family). The request's input is already wire-form (the builders apply
 * toWire), so it feeds snarkjs' witness calculator as-is. Artifact layout is
 * the repo convention: <name>_js/<name>.wasm + <name>.zkey.
 */
export function makeCircuitProver(circuitsOut: string, circuit: string): (request: ProvingRequest) => Promise<Calldata> {
  return async (request: ProvingRequest): Promise<Calldata> => {
    if (request.circuit !== circuit) {
      throw new Error(`sweeper prover only proves ${circuit}, got ${request.circuit}`);
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const snarkjs: any = loadSnarkjs(); // lazy: see module header
    const wasm = join(circuitsOut, `${circuit}_js`, `${circuit}.wasm`);
    const zkey = join(circuitsOut, `${circuit}.zkey`);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(request.input, wasm, zkey);
    const cd = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
    const [a, b, c, pub] = JSON.parse("[" + cd + "]");
    return { a, b, c, pub };
  };
}

/** The enterprise portal mode's prover (the original sweeper surface). */
export function makeDepositProver(circuitsOut: string): (request: ProvingRequest) => Promise<Calldata> {
  return makeCircuitProver(circuitsOut, "deposit");
}
