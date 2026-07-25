// The pure prover: ProvingRequest -> Groth16 solidity calldata {a, b, c, pub}.
//
// prove(req) is the whole job. It does NO resolution (no CSV, no addr->pubkey, no
// membership building, no tx) — the request already carries a complete circom
// witness input (see types.ts / SPEC §6). prove() only:
//   1. picks a backend (per-circuit default, or req.backend),
//   2. runs the two-time-pad guard for multi-output circuits (§11-8),
//   3. computes the witness + Groth16 proof, and
//   4. returns exportSolidityCallData-form calldata.
//
// Backends (mirrors deploy/e2e_orchestrator.ts::prove + deploy/giwa_disburse256.ts):
//   cpu  — snarkjs groth16.fullProve against circuits/out/<c>.wasm + <c>.zkey.
//          Used for deposit / transfer / withdraw (and disburse if forced).
//   gpu  — disburse only (1×256, ~1.66M constraints): snarkjs witness via
//          circuits/out/disburse256_js/generate_witness.js, then rabbitsnark
//          `circom prove` on CUDA device 0 against the 1.24GB artifacts/circuit.zkey.
//
// External toolchain (no repo dep): snarkjs loads via createRequire from
// BONGTU_NODE_MODULES; the GPU path shells out to node (witness) + the rabbitsnark
// venv python (proof). All paths are env-overridable (see resolveConfig).

import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";

import { assertDistinctOwnerPubkeys } from "@bongtu/sdk/note";
import type { PointInput } from "@bongtu/sdk/babyjub";
import type { Backend, Calldata, Circuit, ProvingRequest } from "./types.js";

const require = createRequire(import.meta.url);
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", ".."); // repo root (packages/prover-cli/src -> repo)
const DISCLO = join(ROOT, ".."); // the disclosure-poc parent (holds artifacts/)

// snarkjs ships no usable types and loads from an EXTERNAL node_modules (repo
// convention, shared with deploy/ and indexer/), so it comes back as `any`.
const NODE_MODULES =
  process.env.BONGTU_NODE_MODULES || "/home/a41/Workspace/zkx-snap/circuits/node_modules";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const snarkjs: any = require(join(NODE_MODULES, "snarkjs/build/main.cjs"));

/** Default backend per circuit: only disburse (1×256) is GPU. */
const DEFAULT_BACKEND: Record<Circuit, Backend> = {
  deposit: "cpu",
  transfer: "cpu",
  withdraw: "cpu",
  disburse: "gpu",
};

/** circuit tag -> the artifact base name in circuits/out (disburse's production
 *  1×256 build is `disburse256`, not `disburse`). */
const CPU_ARTIFACT: Record<Circuit, string> = {
  deposit: "deposit",
  transfer: "transfer",
  withdraw: "withdraw",
  disburse: "disburse256",
};

/** Resolved filesystem + toolchain paths (all env-overridable). */
export interface ProverConfig {
  circuitsOut: string; // circuits/out
  gpuWasm: string; // disburse256 witness-calculator wasm
  gpuGenWitness: string; // disburse256 generate_witness.js
  gpuZkey: string; // 1.24GB rabbitsnark proving key (artifacts/circuit.zkey)
  rabbitDir: string; // rabbitsnark-py checkout (cwd + PYTHONPATH)
  rabbitPython: string; // venv python that runs rabbitsnark.cli
  scratchDir: string; // scratch for the GPU input/witness/proof files
}

function resolveConfig(overrides: Partial<ProverConfig> = {}): ProverConfig {
  const circuitsOut = overrides.circuitsOut ?? join(ROOT, "circuits", "out");
  return {
    circuitsOut,
    gpuWasm:
      overrides.gpuWasm ?? join(circuitsOut, "disburse256_js", "disburse256.wasm"),
    gpuGenWitness:
      overrides.gpuGenWitness ?? join(circuitsOut, "disburse256_js", "generate_witness.js"),
    gpuZkey: overrides.gpuZkey ?? process.env.PROVER_CLI_GPU_ZKEY ?? join(DISCLO, "artifacts", "circuit.zkey"),
    rabbitDir: overrides.rabbitDir ?? process.env.PROVER_CLI_RABBIT_DIR ?? "/home/a41/Workspace/rabbitsnark-py",
    rabbitPython:
      overrides.rabbitPython ?? process.env.PROVER_CLI_RABBIT_PY ?? "/home/a41/Workspace/jolt-zorch/.venv/bin/python",
    scratchDir: overrides.scratchDir ?? process.env.PROVER_CLI_SCRATCH ?? mkdtempSync(join(tmpdir(), "bongtu-prover-")),
  };
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** Recursively turn BigInt into a decimal string so snarkjs' witness calculator
 *  (and generate_witness.js JSON) get plain decimals. Strings/numbers pass through
 *  (a request deserialized from JSON already has decimal-string field elements). */
function strify(v: unknown): unknown {
  if (typeof v === "bigint") return v.toString();
  if (Array.isArray(v)) return v.map(strify);
  if (v && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(v)) o[k] = strify((v as Record<string, unknown>)[k]);
    return o;
  }
  return v;
}

/** Parse an exportSolidityCallData string into typed {a, b, c, pub}. snarkjs already
 *  applies the G2 inner-swap on `b`, so this is verifier-ready as-is. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parseCallData(cd: string): Calldata {
  const [a, b, c, pub] = JSON.parse("[" + cd + "]") as [
    [string, string],
    [[string, string], [string, string]],
    [string, string],
    string[],
  ];
  return { a, b, c, pub };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function callDataFromProof(proof: any, publicSignals: any): Promise<Calldata> {
  const cd: string = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
  return parseCallData(cd);
}

/** §11-8 two-time-pad guard: transfer + disburse fan one ephemeral key + nonce over
 *  every output, so two outputs to the same owner pubkey leak m1−m2. The prover MUST
 *  reject duplicate output owner pubkeys before proving (SPEC §4). deposit (one
 *  authority envelope, no per-output ciphertext) and withdraw (single output) are
 *  exempt. */
function guardTwoTimePad(req: ProvingRequest): void {
  if (req.circuit === "transfer" || req.circuit === "disburse") {
    assertDistinctOwnerPubkeys(req.input.outputOwnerPublicKeys as PointInput[]);
  }
}

// ---------------------------------------------------------------------------
// backends
// ---------------------------------------------------------------------------

/** CPU: snarkjs full prove against circuits/out/<base>.wasm + <base>.zkey. */
async function proveCpu(circuit: Circuit, input: unknown, cfg: ProverConfig): Promise<Calldata> {
  const base = CPU_ARTIFACT[circuit];
  const wasm = join(cfg.circuitsOut, `${base}_js`, `${base}.wasm`);
  const zkey = join(cfg.circuitsOut, `${base}.zkey`);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(strify(input), wasm, zkey);
  return callDataFromProof(proof, publicSignals);
}

/** GPU (disburse only): snarkjs generate_witness.js (disburse256) then rabbitsnark
 *  `circom prove` on CUDA device 0. Copies deploy/giwa_disburse256.ts::proveDisburse256
 *  exactly. Cold zkey-compile is ~116s (> the 2-min default Bash timeout — see
 *  CLAUDE.md); warm proof ~0.5s. The 1.24GB zkey + GPU are required. */
async function proveGpuDisburse(input: unknown, cfg: ProverConfig): Promise<Calldata> {
  const inPath = join(cfg.scratchDir, "disb_input.json");
  const wtns = join(cfg.scratchDir, "disb.wtns");
  const proofP = join(cfg.scratchDir, "disb_proof.json");
  const pubP = join(cfg.scratchDir, "disb_public.json");

  writeFileSync(inPath, JSON.stringify(strify(input)));
  // witness (CPU, node) — the disburse256 witness calculator
  execFileSync("node", [cfg.gpuGenWitness, cfg.gpuWasm, inPath, wtns], { stdio: "inherit" });
  // proof (GPU, rabbitsnark) — pinned to device 0, run from the rabbitsnark checkout
  execFileSync(
    cfg.rabbitPython,
    ["-m", "rabbitsnark.cli", "circom", "prove", cfg.gpuZkey, proofP, pubP, "--wtns", wtns],
    {
      cwd: cfg.rabbitDir,
      env: { ...process.env, CUDA_VISIBLE_DEVICES: "0", PYTHONPATH: cfg.rabbitDir },
      stdio: "inherit",
    },
  );

  const proof = JSON.parse(readFileSync(proofP, "utf8"));
  const publicSignals = JSON.parse(readFileSync(pubP, "utf8"));
  return callDataFromProof(proof, publicSignals);
}

// ---------------------------------------------------------------------------
// entry
// ---------------------------------------------------------------------------

/** Prove a complete, resolved ProvingRequest and return solidity calldata.
 *  `cfg` overrides filesystem/toolchain paths (tests point it at fixtures). */
export async function prove(req: ProvingRequest, cfg?: Partial<ProverConfig>): Promise<Calldata> {
  const backend: Backend = req.backend ?? DEFAULT_BACKEND[req.circuit];
  guardTwoTimePad(req);
  const resolved = resolveConfig(cfg);

  if (backend === "gpu") {
    if (req.circuit !== "disburse") {
      throw new Error(`prove: the GPU backend only supports 'disburse', not '${req.circuit}'`);
    }
    return proveGpuDisburse(req.input, resolved);
  }
  return proveCpu(req.circuit, req.input, resolved);
}
