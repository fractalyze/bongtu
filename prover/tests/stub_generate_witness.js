// Stand-in for circom's generate_witness.js so test_witness_seam.py can drive
// engine._generate_witness through a REAL node subprocess (same argv contract:
// <wasm> <input.json> <output.wtns>) without any circuit artifacts. The mode
// travels inside the input JSON — the same channel a real request's witness
// input takes — selecting which failure shape to reproduce:
//
//   success   write the .wtns, exit 0
//   assert    circom's unsatisfiable-constraint signature on stderr, exit 1
//   infra     a non-assert crash (e.g. missing wasm) on stderr, exit 1
//   no-wtns   exit 0 WITHOUT writing the .wtns (truncated/killed calculator)
//   hang      never exit (wedged subprocess; the engine's timeout must fire)

// ESM: the repo root package.json declares "type": "module", so a .js file
// under the repo tree cannot use require().
import fs from "node:fs";

const [, , , inputPath, wtnsPath] = process.argv;
const mode = JSON.parse(fs.readFileSync(inputPath, "utf8")).mode || "success";

switch (mode) {
  case "success":
    fs.writeFileSync(wtnsPath, "stub-wtns");
    process.exit(0);
  case "assert":
    // The exact phrasing circom's calculator emits for an unsatisfiable input
    // (see circuits/assert_attacks_throw.ts, which matches the same string).
    console.error("Error: Assert Failed.\nError in template Zeto_75 line: 118");
    process.exit(1);
  case "infra":
    console.error("Error: ENOENT: no such file or directory, open 'disburse256.wasm'");
    process.exit(1);
  case "no-wtns":
    process.exit(0);
  case "hang":
    setTimeout(() => {}, 60_000);
    break;
  default:
    console.error(`unknown stub mode: ${mode}`);
    process.exit(2);
}
