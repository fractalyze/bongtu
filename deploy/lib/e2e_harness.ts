// bongtu shared anvil-driver harness — the deploy-and-drive skeleton common to
// the repo's two HEAVY gates:
//
//   deploy/e2e_orchestrator.ts     the M0 DoD cross-circuit e2e (deploy/e2e_m0.sh)
//   apps/indexer/test/scenario.ts  the indexer conformance scenario (apps/indexer/test/run.sh)
//
// This is TEST/OPS INFRASTRUCTURE shared across the repo by RELATIVE import
// (apps/indexer/test reaches it via ../../../deploy/lib/). It is NOT an npm
// package export: nothing under apps/ runtime code or packages/ may depend on
// it, and it must never import from apps/ (the gates it serves test those apps
// from the outside).
//
// It owns exactly the material the two drivers duplicated verbatim:
//   - the anvil connection (E2E_RPC + anvil dev account #0),
//   - the forge-artifact deploy helpers artifact() / deploy() / deployPoolProxy()
//     — the ONE TS restatement of Deploy.s.sol's UUPS + initialize wiring, so a
//     pool-initializer change is Deploy.s.sol plus one TS site, not three,
//   - deployStack(): Poseidon-v1 + the 4 Groth16 verifiers + mock kKRW +
//     BongtuPool behind its UUPS proxy on a live anvil, then driver-wallet
//     funding (mint + approve),
//   - the CPU snarkjs prove() wrapper (witness + groth16 + solidity calldata),
//   - the shared actor / salt / amount fixture material both drivers assume.
//
// What deliberately does NOT live here: each driver's scenario legs and
// assertions, its per-tx ECDH ephemeral keys + encryption nonces (driver-local;
// every (key, nonce) pair is unique across both gates — the two-time-pad
// rule), and the scenario's tamper legs and extra salt families — that
// material is load-bearing per driver and stays in the drivers.
// deploy/giwa_disburse256.ts also stays independent on purpose: it drives the
// canonical LIVE GIWA pool (B=256), not a fresh anvil stack.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { deriveKeypair } from "@bongtu/core/note";
import type { Keypair } from "@bongtu/core/note";
import type { FieldInput, PointInput } from "@bongtu/core/babyjub";
import { toWire } from "@bongtu/core/proving";
import { loadEthers, loadSnarkjs } from "@bongtu/core/extern";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", ".."); // deploy/lib -> repo root
const CIRC_OUT = join(ROOT, "circuits", "out");
const CONTRACTS_OUT = join(ROOT, "contracts", "out");
const POSEIDON_HEX = join(ROOT, "contracts", "test", "fixtures", "poseidon2.hex");

// snarkjs + ethers v5 come back `any` from the shared external loader — we type
// OUR code (notes, keys, tree), not theirs.
const snarkjs = loadSnarkjs();
const ethers = loadEthers();

export const RPC = process.env.E2E_RPC || "http://127.0.0.1:8545";
// anvil default account #0 (deterministic dev key — testnet fake money only).
const PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

export { H } from "@bongtu/core/network"; // IMT depth — protocol constant, one home
// The GATE stack's batch size. Deliberately NOT named B: @bongtu/core/network
// exports the LIVE pool's B=256, and a same-name different-value export pair
// invites the wrong import.
export const GATE_B = 16;

export const dec = (x: FieldInput): string => BigInt(x).toString(); // BigInt -> decimal string for snarkjs / ethers

/** Provider + driver wallet (anvil account #0) on the harness anvil (E2E_RPC). */
export function connectAnvil(): { provider: any; wallet: any } {
  const provider = new ethers.providers.JsonRpcProvider(RPC);
  const wallet = new ethers.Wallet(PK, provider);
  return { provider, wallet };
}

// ---------------------------------------------------------------------------
// proving: witness + groth16 prove + solidity calldata, all in-process
// ---------------------------------------------------------------------------
export async function prove(name: string, input: unknown, opts: { verbose?: boolean } = {}) {
  const wasm = join(CIRC_OUT, `${name}_js`, `${name}.wasm`);
  const zkey = join(CIRC_OUT, `${name}.zkey`);
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(toWire(input), wasm, zkey);
  const cd = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
  const [a, b, c, pub] = JSON.parse("[" + cd + "]");
  if (opts.verbose) {
    console.log(`   proved ${name} (${publicSignals.length} publics) in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  }
  return { a, b, c, pub, publicSignals };
}

// ---------------------------------------------------------------------------
// deployment helpers (ethers v5)
// ---------------------------------------------------------------------------
export function artifact(sol: string, contract: string): { abi: any; bytecode: any } {
  const j = JSON.parse(readFileSync(join(CONTRACTS_OUT, `${sol}.sol`, `${contract}.json`), "utf8"));
  return { abi: j.abi, bytecode: j.bytecode.object };
}

export async function deploy(wallet: any, sol: string, contract: string, args: unknown[] = []): Promise<any> {
  const { abi, bytecode } = artifact(sol, contract);
  const f = new ethers.ContractFactory(abi, bytecode, wallet);
  const inst = await f.deploy(...args);
  await inst.deployed();
  return inst;
}

// Deploy BongtuPool behind a UUPS ERC-1967 proxy (SPEC §5.2), initialized in the
// proxy constructor with the 8-arg initializer. Returns a contract bound to the
// BongtuPool ABI at the PROXY address (the canonical, upgrade-stable pool).
export async function deployPoolProxy(wallet: any, initArgs: unknown[]): Promise<any> {
  const impl = await deploy(wallet, "BongtuPool", "BongtuPool");
  const { abi: poolAbi } = artifact("BongtuPool", "BongtuPool");
  const initData = new ethers.utils.Interface(poolAbi).encodeFunctionData("initialize", initArgs);
  const proxy = await deploy(wallet, "ERC1967Proxy", "ERC1967Proxy", [impl.address, initData]);
  return new ethers.Contract(proxy.address, poolAbi, wallet);
}

export interface DeployedStack {
  poseidon: any; // Poseidon-v1 (raw hex artifact)
  dv: any; // DepositVerifier
  wv: any; // WithdrawVerifier
  dsv: any; // DisburseVerifier
  tv: any; // TransferVerifier
  token: any; // mock kKRW
  pool: any; // BongtuPool bound at the PROXY address
}

/** Deploy the full anvil stack both heavy gates start from: Poseidon-v1, the
 *  4 Groth16 verifiers, mock kKRW, and BongtuPool behind its UUPS proxy —
 *  then fund + approve the driver wallet (deposit pulls from msg.sender via
 *  SafeERC20). The tx sequence is fixed, so contract addresses stay
 *  nonce-deterministic across both drivers. */
export async function deployStack(
  wallet: any,
  opts: { batchSize: number; authorityPublicKey: PointInput; mintAmount: bigint },
): Promise<DeployedStack> {
  const posHex = readFileSync(POSEIDON_HEX, "utf8").trim();
  const posFactory = new ethers.ContractFactory([], posHex, wallet);
  const poseidon = await posFactory.deploy();
  await poseidon.deployed();
  const dv = await deploy(wallet, "DepositVerifier", "DepositVerifier");
  const wv = await deploy(wallet, "WithdrawVerifier", "WithdrawVerifier");
  const dsv = await deploy(wallet, "DisburseVerifier", "DisburseVerifier");
  const tv = await deploy(wallet, "TransferVerifier", "TransferVerifier");
  const token = await deploy(wallet, "MockERC20", "MockERC20");
  const pool = await deployPoolProxy(wallet, [
    poseidon.address, dv.address, wv.address, dsv.address, tv.address, token.address, opts.batchSize,
    [dec(opts.authorityPublicKey[0]), dec(opts.authorityPublicKey[1])],
  ]);
  await (await token.mint(wallet.address, dec(opts.mintAmount))).wait();
  await (await token.approve(pool.address, ethers.constants.MaxUint256)).wait();
  return { poseidon, dv, wv, dsv, tv, token, pool };
}

// ---------------------------------------------------------------------------
// shared fixture material (identical in both drivers BY DESIGN — the scenario
// replays the orchestrator's cast; per-tx ECDH keys/nonces DIFFER and stay
// driver-local)
// ---------------------------------------------------------------------------

// actors (bjj keypairs; scalars are index-derived, PRNG-free)
export const EMPLOYER = deriveKeypair(111111111111111111111111n);
export const AUTHORITY = deriveKeypair(555555555555555555555555n); // arbiter key
export const PAYEE = deriveKeypair(222222222222222222222222n);
const recipient = (i: number): Keypair => deriveKeypair(2000000011n + BigInt(i) * 1000003n);
export const RCPTS: Keypair[] = Array.from({ length: GATE_B }, (_, i) => recipient(i));

// salts (distinct per note)
export const sD0 = 5000001n, sD1 = 5000002n;
export const sR = (i: number): bigint => 6000000n + BigInt(i);
export const sPay = 7000001n, sChg = 7000002n;
export const sPadT = 7100001n, sPadW = 7100002n, sRes = 7200001n;

// amounts: 16 varying positive values; V := their sum.
export const amounts = Array.from({ length: GATE_B }, (_, i) => 100n + BigInt(i) * 3n);
export const V = amounts.reduce((a, x) => a + x, 0n);
