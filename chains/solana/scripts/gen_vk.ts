// gen_vk.ts — generate Rust Groth16 VK constants from the committed snarkjs
// verification keys (SOLR §4.1: VK constants are GENERATED from
// verification_key.json, never hand-ported).
//
// Run from the repo root:
//   node_modules/.bin/tsx chains/solana/scripts/gen_vk.ts
//
// Reads  circuits/out/{depositPriv,transferPriv,transfer10x2Priv,withdrawPriv}.vkey.json
// Writes chains/solana/program/src/generated/vk_<snake_name>.rs (one per circuit)
//        chains/solana/program/src/generated/fields.rs (BN254 moduli, shared)
//
// Encoding: every field element is 32-byte BIG-ENDIAN (the alt_bn128 syscall /
// EIP-197 convention). G1 = x || y (64 B). G2 = x_c1 || x_c0 || y_c1 || y_c0
// (128 B): snarkjs stores G2 coordinates as [c0, c1] (real, imaginary); the
// EVM-compatible pairing input wants the imaginary limb FIRST — the same swap
// snarkjs' exportSolidityCallData applies to proof `b`, applied here to the
// verification key's G2 points.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const OUT_DIR = join(HERE, "..", "program", "src", "generated");

/** The circuits the Solana rail verifies: the four consumer P2P circuits
 *  (SOLR §2.3) plus the S3 enterprise set decided under OPEN-1 — deposit,
 *  withdraw, and disburse256 itself (SOLR §3.3 / issue #8). `vkeyPath`
 *  overrides the default circuits/out location: the disburse256 vkey is
 *  committed beside the EVM fixtures (the GPU-proven production-arity
 *  artifact, chains/evm/test/fixtures). */
const CIRCUITS: { name: string; snake: string; nPublic: number; vkeyPath?: string }[] = [
  { name: "depositPriv", snake: "deposit_priv", nPublic: 16 },
  { name: "transferPriv", snake: "transfer_priv", nPublic: 20 },
  { name: "transfer10x2Priv", snake: "transfer10x2_priv", nPublic: 36 },
  { name: "withdrawPriv", snake: "withdraw_priv", nPublic: 16 },
  { name: "deposit", snake: "deposit", nPublic: 19 },
  { name: "withdraw", snake: "withdraw", nPublic: 27 },
  { name: "transfer", snake: "transfer", nPublic: 37 },
  { name: "transfer10x2", snake: "transfer10x2", nPublic: 68 },
  {
    name: "disburse256",
    snake: "disburse256",
    nPublic: 11,
    vkeyPath: join("chains", "evm", "test", "fixtures", "disburse256.vkey.json"),
  },
];

interface SnarkjsVkey {
  protocol: string;
  curve: string;
  nPublic: number;
  vk_alpha_1: string[];
  vk_beta_2: string[][];
  vk_gamma_2: string[][];
  vk_delta_2: string[][];
  IC: string[][];
}

const P_BASE = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const R_SCALAR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function be32(dec: string): number[] {
  const v = BigInt(dec);
  if (v < 0n || v >= P_BASE * 2n) throw new Error(`gen_vk: out-of-range coordinate ${dec}`);
  const hexStr = v.toString(16).padStart(64, "0");
  return Array.from({ length: 32 }, (_, i) => parseInt(hexStr.slice(2 * i, 2 * i + 2), 16));
}

// G1 from snarkjs projective [x, y, "1"]. The trailing "1" is asserted, not dropped
// silently — a non-affine point would mean the vkey is not in the expected form.
function g1(coords: string[], what: string): number[] {
  if (coords.length !== 3 || BigInt(coords[2]) !== 1n) {
    throw new Error(`gen_vk: ${what} is not an affine snarkjs G1 point`);
  }
  return [...be32(coords[0]), ...be32(coords[1])];
}

// G2 from snarkjs [[x_c0, x_c1], [y_c0, y_c1], ["1","0"]] -> EVM limb order.
function g2(coords: string[][], what: string): number[] {
  if (coords.length !== 3 || BigInt(coords[2][0]) !== 1n || BigInt(coords[2][1]) !== 0n) {
    throw new Error(`gen_vk: ${what} is not an affine snarkjs G2 point`);
  }
  return [...be32(coords[0][1]), ...be32(coords[0][0]), ...be32(coords[1][1]), ...be32(coords[1][0])];
}

function rustArray(bytes: number[], perLine = 16): string {
  const lines: string[] = [];
  for (const i of Array(Math.ceil(bytes.length / perLine)).keys()) {
    lines.push(
      "    " +
        bytes
          .slice(i * perLine, (i + 1) * perLine)
          .map((b) => `0x${b.toString(16).padStart(2, "0")}`)
          .join(", ") +
        ",",
    );
  }
  return lines.join("\n");
}

function emitCircuit(
  name: string,
  snake: string,
  wantPublics: number,
  vkeyOverride?: string,
): void {
  const vkeyPath = vkeyOverride
    ? join(REPO, vkeyOverride)
    : join(REPO, "circuits", "out", `${name}.vkey.json`);
  const vk = JSON.parse(readFileSync(vkeyPath, "utf8")) as SnarkjsVkey;
  if (vk.protocol !== "groth16" || vk.curve !== "bn128") {
    throw new Error(`gen_vk: ${name}: unexpected vkey protocol/curve ${vk.protocol}/${vk.curve}`);
  }
  if (vk.nPublic !== wantPublics) {
    throw new Error(`gen_vk: ${name}: nPublic ${vk.nPublic}, expected ${wantPublics}`);
  }
  if (vk.IC.length !== vk.nPublic + 1) {
    throw new Error(`gen_vk: ${name}: IC length ${vk.IC.length} != nPublic+1 (${vk.nPublic + 1})`);
  }

  const ic = vk.IC.map((p, i) => g1(p, `IC[${i}]`));
  const source = vkeyOverride ?? join("circuits", "out", `${name}.vkey.json`);
  const out = `// GENERATED by chains/solana/scripts/gen_vk.ts from ${source}
// — DO NOT EDIT (SOLR §4.1: VK constants are generated, never hand-ported).
// Regenerate: node_modules/.bin/tsx chains/solana/scripts/gen_vk.ts
//
// Encoding: 32-byte big-endian field elements; G1 = x || y; G2 in EVM/EIP-197
// limb order (imaginary limb first): x_c1 || x_c0 || y_c1 || y_c0.

use crate::groth16::Vk;

/// ${name} public-signal count (snarkjs nPublic).
pub const N_PUBLIC: usize = ${vk.nPublic};

pub const VK_ALPHA_G1: [u8; 64] = [
${rustArray(g1(vk.vk_alpha_1, "vk_alpha_1"))}
];

pub const VK_BETA_G2: [u8; 128] = [
${rustArray(g2(vk.vk_beta_2, "vk_beta_2"))}
];

pub const VK_GAMMA_G2: [u8; 128] = [
${rustArray(g2(vk.vk_gamma_2, "vk_gamma_2"))}
];

pub const VK_DELTA_G2: [u8; 128] = [
${rustArray(g2(vk.vk_delta_2, "vk_delta_2"))}
];

/// IC[0..=N_PUBLIC]: vk_x = IC[0] + sum(pub[i] * IC[i+1]).
pub const VK_IC: [[u8; 64]; ${vk.IC.length}] = [
${ic.map((p) => `    [\n${rustArray(p).replace(/^ {4}/gm, "        ")}\n    ],`).join("\n")}
];

/// The assembled verifying key for crate::groth16::verify.
pub const VK: Vk = Vk {
    alpha_g1: &VK_ALPHA_G1,
    beta_g2: &VK_BETA_G2,
    gamma_g2: &VK_GAMMA_G2,
    delta_g2: &VK_DELTA_G2,
    ic: &VK_IC,
};
`;
  const outPath = join(OUT_DIR, `vk_${snake}.rs`);
  writeFileSync(outPath, out);
  console.log(`wrote ${outPath} (nPublic=${vk.nPublic}, IC=${vk.IC.length})`);
}

function emitFields(): void {
  const out = `// GENERATED by chains/solana/scripts/gen_vk.ts — DO NOT EDIT.
// BN254 field moduli, 32-byte big-endian (shared across every generated VK).
// Regenerate: node_modules/.bin/tsx chains/solana/scripts/gen_vk.ts

/// BN254 scalar field modulus r, big-endian (public inputs must be < r).
pub const SCALAR_FIELD_R_BE: [u8; 32] = [
${rustArray(be32(R_SCALAR.toString()))}
];

/// BN254 base field modulus q, big-endian (for G1 y-negation).
pub const BASE_FIELD_Q_BE: [u8; 32] = [
${rustArray(be32(P_BASE.toString()))}
];
`;
  const outPath = join(OUT_DIR, "fields.rs");
  writeFileSync(outPath, out);
  console.log(`wrote ${outPath}`);
}

function main(): void {
  emitFields();
  for (const c of CIRCUITS) emitCircuit(c.name, c.snake, c.nPublic, c.vkeyPath);
}

main();
