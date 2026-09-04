// OPMOD §2.1 consumer gate #3 — viewTag canonicality: circuit-vs-TS equality
// (alias-sensitive edges included), the UNSAT half, and a strictness drift pin.
//
// The consumer circuits derive viewTag_i as bits 0..7 of a Num2Bits_strict
// decomposition (OPMOD §3.2); the TS side masks (`tagField mod 2^8`, canonical
// because BigInt arithmetic never leaves [0, p)). This gate drives the EXACT
// in-circuit construction — gates/viewtag_harness.circom, the verbatim bit
// extraction of lib/consumer-encrypt-outputs.circom over a direct input — and
// checks three things:
//
//   1. EQUALITY: circuit tag == TS tag on
//      - the low-alias band [0, 2^254 − p): the values where a plain
//        Num2Bits(254) WOULD admit the second decomposition (tagField + p)
//        whose low byte differs (p is odd) — the silent-undiscoverability
//        class the strict form closes;
//      - the high band [p − 2^8, p): the top of the field, where the wrap of
//        the alternate decomposition lands inside the low byte;
//      - plain and pseudo-random (sha-derived, PRNG-free) field elements.
//
//   2. UNSAT (the §2.1 second half): for an alias-band vector, a witness
//      asserting the ALTERNATE decomposition — the bits of tagField + p, and
//      the flipped low-8 tag they imply — must be UNSATISFIABLE. Witness
//      generation always emits the canonical bits, so the alternate witness is
//      materialized by binary-patching the honest .wtns (bit wires + tag wire,
//      wire ids read from the harness .sym) and `snarkjs wtns check` must
//      REJECT it, while accepting the untouched honest witness as a control.
//      The recomposition constraint alone cannot catch the patch (tagField + p
//      ≡ tagField mod p, and the patched tag matches the patched low byte) —
//      rejection is Num2Bits_strict's AliasCheck subtree earning its keep.
//      The TS-side pins (packages/core/test/consumer.test.ts p3) still cover
//      the arithmetic half of the tag derivation.
//
//   3. DRIFT PIN: lib/consumer-encrypt-outputs.circom must still instantiate
//      Num2Bits_strict (comment-stripped source match). A silent swap to plain
//      Num2Bits(254) would keep every EQUALITY vector green — witness
//      generation always emits canonical bits — and quietly reopen the alias
//      class; this pin fails the gate instead.
//
// Compiles the harness on demand (no zkey needed — witness/r1cs/sym only).
//
//   npx tsx circuits/gates/consumer_viewtag_canonicality_check.ts   # exits 0 iff all three checks pass

import { createHash } from "node:crypto";
import { execSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { viewTagFromField } from "@bongtu/core/consumer";
import { EXTERN_NODE_MODULES, loadSnarkjs } from "@bongtu/core/extern";
import { FIELD_PRIME } from "@bongtu/core/poseidon";

const HERE = dirname(fileURLToPath(import.meta.url));
const CIRCUITS = join(HERE, ".."); // circuits/gates -> circuits
const OUT = join(CIRCUITS, "out");
const WASM = join(OUT, "viewtag_harness_js", "viewtag_harness.wasm");
const R1CS = join(OUT, "viewtag_harness.r1cs");
const SYM = join(OUT, "viewtag_harness.sym");

// Overridable toolchain, same defaults as build/prove_all.sh (docs/toolchain.md).
const CIRCOM = process.env.CIRCOM ?? "/lib64/ld-linux-x86-64.so.2 /usr/local/bin/circom";
const ZETO = process.env.ZETO ?? "/home/a41/Workspace/research/disclosure-poc/zeto/zkp/circuits";
const CIRCOMLIB = process.env.CIRCOMLIB ?? `${ZETO}/node_modules`;

if (!existsSync(WASM) || !existsSync(R1CS) || !existsSync(SYM)) {
  console.log("-- compiling viewtag_harness (artifact missing)");
  execSync(`${CIRCOM} gates/viewtag_harness.circom --wasm --r1cs --sym -o out/ -l "${ZETO}" -l "${CIRCOMLIB}" -l lib`, {
    cwd: CIRCUITS,
    stdio: "inherit",
  });
}
writeFileSync(join(OUT, "package.json"), '{ "type": "commonjs" }\n');

const P = FIELD_PRIME;
const ALIAS_BOUND = (1n << 254n) - P; // v in [0, ALIAS_BOUND): v + p still fits 254 bits

const shaField = (label: string): bigint =>
  BigInt("0x" + createHash("sha256").update(label).digest("hex")) % P;

// [vector, why]
const VECTORS: [bigint, string][] = [
  [0n, "zero"],
  [1n, "one"],
  [255n, "low byte all-ones"],
  [256n, "first zero-tag nonzero value"],
  [65537n, "plain small"],
  // low-alias band [0, 2^254 - p) — where Num2Bits(254) would alias:
  [ALIAS_BOUND - 1n, "top of the alias band"],
  [ALIAS_BOUND - 256n, "alias band, one byte down"],
  [ALIAS_BOUND >> 1n, "middle of the alias band"],
  [ALIAS_BOUND, "first NON-aliasable value (boundary)"],
  // high band [p - 2^8, p):
  [P - 1n, "p - 1"],
  [P - 255n, "bottom of the high band"],
  [P - 128n, "middle of the high band"],
  // pseudo-random (deterministic):
  ...Array.from({ length: 8 }, (_, k): [bigint, string] => [
    shaField(`bongtu/viewtag-canonicality/vec/${k}`),
    `sha-derived #${k}`,
  ]),
];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const snarkjs: any = loadSnarkjs();

// ---------------------------------------------------------------- 1. EQUALITY

const failures = { count: 0 };
for (const [i, [v, why]] of VECTORS.entries()) {
  const wtnsPath = join(OUT, `viewtag_vec_${i}.wtns`);
  await snarkjs.wtns.calculate({ in: v.toString() }, WASM, wtnsPath);
  const witness: (string | bigint)[] = await snarkjs.wtns.exportJson(wtnsPath);
  const circuitTag = BigInt(witness[1]); // [0] = 1, [1] = the single output `tag`
  const tsTag = viewTagFromField(v);
  if (circuitTag !== tsTag) {
    console.error(`FAIL: vector ${i} (${why}): circuit tag ${circuitTag} != TS tag ${tsTag} (in = ${v})`);
    failures.count++;
  } else {
    console.log(`OK: vector ${i} (${why}) -> tag ${tsTag}`);
  }
}
if (failures.count) {
  console.error(`\nVIEWTAG CANONICALITY GATE: FAIL (${failures.count} equality vectors)`);
  process.exit(1);
}

// --------------------------------------------------------------- 2. DRIFT PIN

console.log("\n-- drift pin: consumer-encrypt-outputs.circom must instantiate Num2Bits_strict");
const LIB_CIRCOM = join(CIRCUITS, "lib", "consumer-encrypt-outputs.circom");
// Comment-stripped before matching: the file's provenance header MENTIONS
// Num2Bits_strict in prose, so a bare substring match would survive the very
// swap this pin exists to catch. The instantiation form `Num2Bits_strict()`
// (empty argument list) only occurs in code.
const libCode = readFileSync(LIB_CIRCOM, "utf8")
  .split("\n")
  .map((line) => line.replace(/\/\/.*$/u, ""))
  .join("\n");
if (!/Num2Bits_strict\s*\(\s*\)/u.test(libCode)) {
  console.error(
    `FAIL: no Num2Bits_strict() instantiation in ${LIB_CIRCOM} — a swap to plain Num2Bits(254) reopens the alias class silently`,
  );
  console.error("\nVIEWTAG CANONICALITY GATE: FAIL (drift pin)");
  process.exit(1);
}
console.log("OK: Num2Bits_strict() instantiation present (comment-stripped match)");

// ------------------------------------------------------------------- 3. UNSAT

// WHY binary patching: witness generation always emits the canonical
// decomposition, so the alternate witness is not reachable through
// generate_witness — snarkjs has no wtns-import either. Patching the honest
// .wtns is the minimal stdlib-only way to materialize it. Container layout
// (snarkjs binFileUtils): "wtns" magic, u32 version, u32 nSections, then per
// section u32 id + u64 LE byte length + payload. Section 1 leads with n8 (the
// field-element byte width); section 2 is the flat wire->value array, n8 LE
// bytes per wire, in wire order — wire w lives at section2 + w*n8.
const patchWitnessFile = (srcPath: string, dstPath: string, assignments: [number, bigint][]): void => {
  const bytes = Buffer.from(readFileSync(srcPath)); // copy — the honest file stays intact
  if (bytes.toString("latin1", 0, 4) !== "wtns") throw new Error(`${srcPath}: not a wtns file`);
  const sections = new Map<number, number>(); // section id -> payload offset
  Array.from({ length: bytes.readUInt32LE(8) }).reduce((off: number) => {
    sections.set(bytes.readUInt32LE(off), off + 12);
    return off + 12 + Number(bytes.readBigUInt64LE(off + 4));
  }, 12);
  const headerOff = sections.get(1);
  const dataOff = sections.get(2);
  if (headerOff === undefined || dataOff === undefined) throw new Error(`${srcPath}: missing wtns section 1/2`);
  const n8 = bytes.readUInt32LE(headerOff);
  for (const [wire, value] of assignments) {
    for (const b of Array(n8).keys()) {
      bytes[dataOff + wire * n8 + b] = Number((value >> BigInt(8 * b)) & 0xffn);
    }
  }
  writeFileSync(dstPath, bytes);
};

// Harness wire ids from the circom-emitted .sym (label,wire,component,name;
// a negative wire is an optimized-out alias, never a witness slot).
const symWires = (() => {
  const wires = new Map<string, number>();
  for (const line of readFileSync(SYM, "utf8").split("\n")) {
    const cols = line.split(",");
    const wire = Number(cols[1]);
    if (cols.length === 4 && wire >= 0 && !wires.has(cols[3])) wires.set(cols[3], wire);
  }
  return wires;
})();
const wireOf = (name: string): number => {
  const wire = symWires.get(name);
  if (wire === undefined) throw new Error(`${SYM}: no wire for ${name}`);
  return wire;
};

const wtnsCheckExitCode = (wtnsPath: string): number => {
  try {
    execSync(
      `"${process.execPath}" "${join(EXTERN_NODE_MODULES, "snarkjs", "build", "cli.cjs")}" wtns check "${R1CS}" "${wtnsPath}"`,
      { stdio: "pipe" },
    );
    return 0;
  } catch (err) {
    return (err as { status?: number }).status ?? 1;
  }
};

console.log("\n-- UNSAT: the alternate (in + p) decomposition must be rejected");
const UNSAT_V = ALIAS_BOUND >> 1n; // alias band: UNSAT_V + p still fits 254 bits
const ALT = UNSAT_V + P;
const honestTag = viewTagFromField(UNSAT_V);
const altTag = ALT & 0xffn;
if (altTag === honestTag) {
  // p is odd, so the low bytes MUST differ — this guards the gate's own premise.
  console.error(`FAIL: alternate low byte ${altTag} equals canonical ${honestTag} — bad UNSAT vector`);
  console.error("\nVIEWTAG CANONICALITY GATE: FAIL (UNSAT premise)");
  process.exit(1);
}
const honestWtns = join(OUT, "viewtag_unsat_honest.wtns");
const patchedWtns = join(OUT, "viewtag_unsat_patched.wtns");
await snarkjs.wtns.calculate({ in: UNSAT_V.toString() }, WASM, honestWtns);
patchWitnessFile(honestWtns, patchedWtns, [
  [wireOf("main.tag"), altTag],
  ...Array.from({ length: 254 }, (_, j): [number, bigint] => [
    wireOf(`main.bits.out[${j}]`),
    (ALT >> BigInt(j)) & 1n,
  ]),
]);

if (wtnsCheckExitCode(honestWtns) !== 0) {
  console.error("FAIL: control — the HONEST witness failed wtns check (gate/toolchain broken, not the circuit)");
  console.error("\nVIEWTAG CANONICALITY GATE: FAIL (UNSAT control)");
  process.exit(1);
}
console.log("OK: control — honest witness (alias-band midpoint) passes wtns check");
if (wtnsCheckExitCode(patchedWtns) === 0) {
  console.error(
    `FAIL: the alternate-decomposition witness (bits of in + p, tag ${honestTag} -> ${altTag}) was ACCEPTED — Num2Bits_strict's AliasCheck is not binding`,
  );
  console.error("\nVIEWTAG CANONICALITY GATE: FAIL (UNSAT)");
  process.exit(1);
}
console.log(`OK: alternate decomposition (bits of in + p, tag ${honestTag} -> ${altTag}) REJECTED by wtns check`);

console.log(
  `\nVIEWTAG CANONICALITY GATE: PASS — equality on all ${VECTORS.length} vectors (alias edges included), Num2Bits_strict pin intact, alternate decomposition unsatisfiable`,
);
process.exit(0);
