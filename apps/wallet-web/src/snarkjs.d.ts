// Ambient declaration for snarkjs (GPL-3.0). The wallet ships snarkjs to the page
// (SPEC §6 browser GPL decision (a): accepted for the public app) and loads it via
// a dynamic import in src/lib/prove.ts so nothing else in the bundle pulls it in.
// snarkjs ships no types; this minimal surface is the only API the wallet touches.
declare module "snarkjs" {
  export const groth16: {
    fullProve(
      input: unknown,
      wasm: Uint8Array | string,
      zkey: Uint8Array | string,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
    exportSolidityCallData(proof: unknown, publicSignals: string[]): Promise<string>;
  };
}
