// NOTE: this declaration deliberately exists in THREE copies (packages/ui/src
// plus both apps' src): under the raw-source exports model each tsc program
// follows imports into packages/ui/src/prove.ts and needs its own in-program
// ambient module declaration.
// Ambient declaration for snarkjs (GPL-3.0). The wallet ships snarkjs to the page
// (SPEC §6 browser GPL decision (a): accepted for the public app) and loads it via
// a dynamic import in src/lib/prove.ts so nothing else in the bundle pulls it in.
// snarkjs ships no types; this minimal surface is the only API the wallet touches.
//
// prove.ts drives the two-step (`wtns.calculate` + `groth16.prove`) path rather than
// `groth16.fullProve`, so the KEPT wasm/zkey ArrayBuffers are passed in memory and the
// ~27 MB zkey is fetched once per session instead of re-downloaded per proof. The
// `wtns` handle is snarkjs's in-memory witness file: `{ type: "mem" }` in, populated
// (`.data`) by `wtns.calculate`, consumed by `groth16.prove` — exactly what
// `groth16.fullProve` does internally (snarkjs 0.7.x groth16_fullprove.js).
declare module "snarkjs" {
  /** snarkjs's in-memory FastFile handle: `{ type: "mem" }` before `wtns.calculate`
   *  writes the witness into `.data`. Passed straight into `groth16.prove`. */
  export interface MemWtns {
    type: "mem";
    data?: Uint8Array;
  }

  export const wtns: {
    /** Compute the witness for `input` against the circuit `wasm`, into `wtnsFile`
     *  (a `{ type: "mem" }` handle for browser proving). ~150 ms for these circuits. */
    calculate(
      input: unknown,
      wasm: Uint8Array | string,
      wtnsFile: MemWtns,
    ): Promise<void>;
  };

  export const groth16: {
    fullProve(
      input: unknown,
      wasm: Uint8Array | string,
      zkey: Uint8Array | string,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
    /** Prove a precomputed witness against `zkey`. Reuses the KEPT zkey buffer so a
     *  session's second proof does not re-fetch the 27 MB key. */
    prove(
      zkey: Uint8Array | string,
      wtnsFile: MemWtns,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
    exportSolidityCallData(proof: unknown, publicSignals: string[]): Promise<string>;
  };
}
