// Generates the circomlibjs Poseidon(2) creation bytecode and a reference hash.
// Writes:
//   test/poseidon2.hex     -> 0x-hex creation bytecode of poseidonContract(2)
//   test/poseidon_ref.txt  -> decimal Poseidon([1,2]) reference (circomlib)
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const HERE = dirname(fileURLToPath(import.meta.url));

// Single toolchain-node_modules constant (see TOOLCHAIN.md); override with
// BONGTU_NODE_MODULES. Default = the verified TOOLCHAIN.md path.
const NODE_MODULES =
  process.env.BONGTU_NODE_MODULES || "/home/a41/Workspace/zkx-snap/circuits/node_modules";
const CIRCOMLIBJS = join(NODE_MODULES, "circomlibjs");
// circomlibjs ships no types and is loaded via createRequire, so it is `any`.
const { poseidonContract, buildPoseidon } = require(CIRCOMLIBJS);

const OUT_DIR = HERE;

async function main(): Promise<void> {
  // Creation bytecode for the on-chain Poseidon with 2 inputs.
  let code: string = poseidonContract.createCode(2);
  if (!code.startsWith("0x")) code = "0x" + code;
  writeFileSync(join(OUT_DIR, "poseidon2.hex"), code);

  // Reference hash Poseidon([1,2]) as a decimal string, computed with the
  // same circomlib constants.
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const ref: string = F.toObject(poseidon([1, 2])).toString(10);
  writeFileSync(join(OUT_DIR, "poseidon_ref.txt"), ref);

  console.log("wrote test/poseidon2.hex (" + code.length + " chars)");
  console.log("wrote test/poseidon_ref.txt = " + ref);
}

main()
  .then(() => process.exit(0))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
