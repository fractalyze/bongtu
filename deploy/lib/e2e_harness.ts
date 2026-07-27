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
// It owns exactly the ANVIL-SPECIFIC material the two drivers duplicated:
//   - the anvil connection (E2E_RPC + anvil dev account #0),
//   - the deploy helpers deploy() / deployPoolProxy() — the ONE TS restatement
//     of Deploy.s.sol's UUPS + initialize wiring, so a pool-initializer change
//     is Deploy.s.sol plus one TS site, not three,
//   - deployStack(): the whole stack on a live anvil, at the initializer version
//     the live pool has reached — a gate stack that lagged it would reject
//     proofs the live pool accepts, and read as a circuit bug,
//   - the shared actor / salt / amount fixture material both drivers assume.
//
// The chain-agnostic half — artifact(), the CPU snarkjs prove() wrapper, dec(),
// and the ok()/step() assertion ledger — lives in ./proof_toolbox.ts, which the
// GIWA live driver shares too. It is re-exported here so the two anvil drivers
// keep one import site.
//
// What deliberately does NOT live here: each driver's scenario legs and
// assertions, its per-tx ECDH ephemeral keys + encryption nonces (driver-local;
// every (key, nonce) pair is unique across both gates — the two-time-pad
// rule), and the scenario's tamper legs and extra salt families — that
// material is load-bearing per driver and stays in the drivers.
// deploy/giwa_disburse256.ts also stays independent on purpose: it drives the
// canonical LIVE GIWA pool (B=256), not a fresh anvil stack.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { deriveKeypair } from "@bongtu/core/note";
import type { Keypair } from "@bongtu/core/note";
import type { PointInput } from "@bongtu/core/babyjub";
import { ml_kem768, kemSsToLimbs } from "@bongtu/core/kem";
import { loadEthers } from "@bongtu/core/extern";

// THE fixture arbiter — bjj scalar and ML-KEM-768 keypair both. Deriving a
// second arbiter here used to make an arbiter-mode indexer's AUTHORITY_KEM_KEY
// depend on which gate had built the stack; there is one fixture arbiter and it
// is declared in circuits/fixture_lib.ts.
import { AUTHORITY_KEM, FIXTURE_ARBITER_SCALAR } from "../../circuits/fixture_lib.js";

import { artifact, dec, prove } from "./proof_toolbox.js";

// One import site for the drivers: the toolbox half of the harness surface.
export { artifact, dec, prove, ok, step, failureCount } from "./proof_toolbox.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", ".."); // deploy/lib -> repo root
const POSEIDON_HEX = join(ROOT, "contracts", "test", "fixtures", "poseidon2.hex");

// ethers v5 comes back `any` from the shared external loader — we type OUR code
// (notes, keys, tree), not theirs.
const ethers = loadEthers();

export const RPC = process.env.E2E_RPC || "http://127.0.0.1:8545";
// anvil default account #0 (deterministic dev key — testnet fake money only).
const PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

export { H } from "@bongtu/core/network"; // IMT depth — protocol constant, one home
// The GATE stack's batch size. Deliberately NOT named B: @bongtu/core/network
// exports the LIVE pool's B=256, and a same-name different-value export pair
// invites the wrong import.
export const GATE_B = 16;

/** Provider + driver wallet (anvil account #0) on the harness anvil (E2E_RPC). */
export function connectAnvil(): { provider: any; wallet: any } {
  const provider = new ethers.providers.JsonRpcProvider(RPC);
  const wallet = new ethers.Wallet(PK, provider);
  return { provider, wallet };
}

// ---------------------------------------------------------------------------
// deployment helpers (ethers v5)
// ---------------------------------------------------------------------------
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
  tv10: any; // Transfer10Verifier (installed by the initializeV4 payload)
  token: any; // mock kKRW
  pool: any; // BongtuPool bound at the PROXY address
}

/** Deploy the full anvil stack both heavy gates start from: Poseidon-v1, the
 *  5 Groth16 verifiers, mock kKRW, and BongtuPool behind its UUPS proxy —
 *  then fund + approve the driver wallet (deposit pulls from msg.sender via
 *  SafeERC20). The tx sequence is fixed, so contract addresses stay
 *  nonce-deterministic across both drivers. Epoch 0 carries the AUTHORITY_KEM
 *  pk hash by default (initialize rejects the zero pre-KEM marker).
 *
 *  The stack lands at initializer version 4, matching the live pool: the
 *  8-arg `initialize` wires the four verifiers it has always taken, and
 *  `initializeV4` then installs the transfer10 verifier — the same payload
 *  deploy/UpgradeTransfer10.s.sol sends, since `transfer10Verifier` is
 *  reachable no other way (it is not an `initialize` argument, so a stack that
 *  skipped this step would revert every `transfer10` on a call to address(0)).
 *  The V2/V3 payloads are deliberately NOT replayed here — they exist to move
 *  an older pool's verifiers onto the current ones, and a fresh stack deploys
 *  the current ones outright. */
export async function deployStack(
  wallet: any,
  opts: { batchSize: number; authorityPublicKey: PointInput; mintAmount: bigint; kemPkHash?: string },
): Promise<DeployedStack> {
  const posHex = readFileSync(POSEIDON_HEX, "utf8").trim();
  const posFactory = new ethers.ContractFactory([], posHex, wallet);
  const poseidon = await posFactory.deploy();
  await poseidon.deployed();
  const dv = await deploy(wallet, "DepositVerifier", "DepositVerifier");
  const wv = await deploy(wallet, "WithdrawVerifier", "WithdrawVerifier");
  const dsv = await deploy(wallet, "DisburseVerifier", "DisburseVerifier");
  const tv = await deploy(wallet, "TransferVerifier", "TransferVerifier");
  const tv10 = await deploy(wallet, "Transfer10Verifier", "Transfer10Verifier");
  const token = await deploy(wallet, "MockERC20", "MockERC20");
  const pool = await deployPoolProxy(wallet, [
    poseidon.address, dv.address, wv.address, dsv.address, tv.address, token.address, opts.batchSize,
    [dec(opts.authorityPublicKey[0]), dec(opts.authorityPublicKey[1])],
    opts.kemPkHash ?? ethers.utils.keccak256(AUTHORITY_KEM.publicKey),
  ]);
  await (await pool.initializeV4(tv10.address)).wait();
  await (await token.mint(wallet.address, dec(opts.mintAmount))).wait();
  await (await token.approve(pool.address, ethers.constants.MaxUint256)).wait();
  return { poseidon, dv, wv, dsv, tv, tv10, token, pool };
}

// ---------------------------------------------------------------------------
// shared fixture material (identical in both drivers BY DESIGN — the scenario
// replays the orchestrator's cast; per-tx ECDH keys/nonces DIFFER and stay
// driver-local)
// ---------------------------------------------------------------------------

// actors (bjj keypairs; scalars are index-derived, PRNG-free)
export const EMPLOYER = deriveKeypair(111111111111111111111111n);
export const AUTHORITY = deriveKeypair(FIXTURE_ARBITER_SCALAR); // arbiter key

// The arbiter's ML-KEM-768 keypair (the PQ half of the hybrid authority
// envelope, pq-envelope-design.md §2) is the FIXTURE one, re-exported: the
// committed proof fixtures, the forge deploy default (Deploy.s.sol reads the
// same key out of realproofs.json) and these gates then all name one arbiter,
// so an arbiter-mode indexer's AUTHORITY_KEM_KEY does not depend on which gate
// built the stack. The DECAPS key (secretKey) is what such a consumer feeds to
// AUTHORITY_KEM_KEY.
export { AUTHORITY_KEM };
const sha = (s: string): Uint8Array => new Uint8Array(createHash("sha256").update(s).digest());

/** Per-tx ML-KEM encapsulation against AUTHORITY_KEM: label-derived randomness
 *  keeps proofs reproducible AND every tx's (ss, ct) distinct — reusing one ct
 *  across ops would collapse the PQ compartment (design doc §6). The label
 *  prefix stays harness-local, so sharing the arbiter KEY with the committed
 *  fixtures does not share a single CIPHERTEXT with them. */
export function kemDraw(label: string): { kemSs: [bigint, bigint]; kemCiphertext: Uint8Array } {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(
    AUTHORITY_KEM.publicKey,
    sha(`bongtu/e2e-harness/kem/encap/${label}`),
  );
  return { kemSs: kemSsToLimbs(sharedSecret), kemCiphertext: cipherText };
}

/** The `bytes calldata kemCiphertext` wire form for ethers. */
export const kemCtHex = (ct: Uint8Array): string => "0x" + Buffer.from(ct).toString("hex");
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
