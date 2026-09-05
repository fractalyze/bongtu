// The deposit op (@bongtu/client/deposit): the whole shield action in one file, in
// two layers around the SPEC §6 prove/submit boundary. The BUILDER layer stops at
// "a valid deposit ProvingRequest"; the RUN layer (runDeposit) proves through the
// app-injected prover, approves exactly V, and submits the permissionless deposit tx.
//
// BUILDER (SPEC §4, 0-in / 2-out mint): PURE witness assembly, framework- and
// network-free so the exact code runs in the browser view AND a headless gate,
// importing the sdk crypto DIRECTLY so every output commitment is byte-identical to
// what snarkjs proves and the contract verifies. The witness object produced here is
// EXACTLY the circom `main` input the deploy/gates/e2e_orchestrator.ts deposit
// section assembles by hand, in ProvingRequest form.
//
// A deposit mints TWO outputs — note(V) at index 0 and note(0) at index 1 — BOTH owned
// by the depositor. Deposit has NO membership and NO nullifiers, and it publishes no
// per-recipient ciphertext (a single authority/arbiter envelope over both outputs), so
// the two outputs sharing one owner is harmless (no two-time-pad, no assertDistinct).
// note(0) is a REAL commitment of value 0 with a random salt+owner — non-zero, so it
// passes the contract's ZeroOutputCommitment check.
//
// RUN (SPEC §7): the approve+prove+submit orchestration for the public wallet's
// deposit/shield action. The guard sequence, stage grammar ("approve" → "prove" →
// "submit" through a callback the React Deposit screen renders as a staged
// progress bar) and approve-landed reassurance rule live in the ONE deposit guard
// driver (./driver.ts runGuardedDeposit) — the same sequence consumerRunDeposit
// runs; this file supplies only the enterprise deltas: the pool's arbiter
// KEM-epoch guard, the authority-envelope deposit builder, and the pool submit.
// A deposit is 0-in / 2-out (mint), so there is NO note selection and NO
// membership fetch — the "approve" stage replaces the spend's "assemble":
// exact-V ERC-20 approve, SKIPPED when the current allowance already covers V
// (one approve tx only when needed, then the permissionless deposit tx). The
// orchestration is gated headlessly (accountBinding.test.ts, opsFacade.test.ts),
// the wallet edges faked through the RunDepositDeps seam.

// ------------------------- builder: PURE witness assembly -------------------------

import { commitment } from "@bongtu/core/note";
import { ARBITER_PUBKEY_X, ARBITER_PUBKEY_Y } from "@bongtu/core/network";
import type { Point } from "@bongtu/core/babyjub";
import { toWire } from "@bongtu/core/proving";
import type { DepositInput, ProvingRequest } from "@bongtu/core/proving";
import type { WalletIdentity } from "@bongtu/client/derive";
// From the ./spend PART file, not the @bongtu/client/spend barrel: that barrel
// carries SpendOps, which binds runDeposit from THIS file — importing the barrel
// back from here would make the two subpaths a cycle.
import { toEncryptionNonce, freshKemMaterial, type KemDrawFn } from "./spend/crypto.js";

/** Fresh per-tx crypto material for one deposit. `ecdhPrivateKey`/`encryptionNonce`
 *  must never be reused across txs (a shared ephemeral key + nonce is a two-time pad);
 *  `salt0`/`salt1` are the fresh salts for note(V) and note(0). `authorityPubKey` is NOT
 *  drawn — it is the pool's fixed stored arbiter PUBLIC key (§6b v2), the envelope target
 *  the contract injects from storage before verifying, so a different target fails. */
export interface DepositCrypto {
  ecdhPrivateKey: string;
  encryptionNonce: string;
  /** salt for output 0 = note(V). */
  salt0: string;
  /** salt for output 1 = note(0). */
  salt1: string;
  /** the pool's stored arbiter PUBLIC key — the authority envelope target. */
  authorityPubKey: [string, string];
  /** ML-KEM-768 shared-secret limbs (decimal) — the PQ half of the hybrid
   *  envelope key, a fresh encapsulation per tx (pq-envelope-design.md §5). */
  kemSs: [string, string];
  /** the matching 1088-byte encapsulation ciphertext, 0x-hex (tx calldata). */
  kemCiphertext: string;
}

export interface DepositMeta {
  /** [note(V), note(0)] commitments as decimal strings. */
  outputCommitments: string[];
  /** [V, 0] as decimal strings. */
  outputValues: string[];
  /** the deposited value V (== outputValues[0], == pub[0] on-chain). */
  amount: string;
}

export interface DepositResult {
  request: Extract<ProvingRequest, { circuit: "deposit" }>;
  meta: DepositMeta;
}

/** A fresh field element (decimal string) per call — the injectable randomness behind
 *  `freshDepositCrypto` (browser CSPRNG in the flow; deterministic in tests). */
export type RandField = () => string;

/**
 * Draw the fresh per-tx crypto material for one deposit. Exactly FOUR draws from
 * `rand` — ecdhPrivateKey, encryptionNonce, salt0, salt1 — since reusing an ephemeral
 * ECDH key + nonce across txs is a two-time pad; plus ONE ML-KEM encapsulation from
 * `drawKem` (fresh per tx — ct reuse collapses the PQ compartment, design doc §6).
 * `authorityPubKey` is NOT drawn: it is the pool's fixed stored arbiter PUBLIC key
 * (the contract injects the same key before verifying, so a different target fails
 * the proof).
 */
export function freshDepositCrypto(rand: RandField, drawKem: KemDrawFn = freshKemMaterial): DepositCrypto {
  const kem = drawKem();
  return {
    ecdhPrivateKey: rand(),
    // clamped: SymmetricEncrypt constrains nonce < 2^128 (see toEncryptionNonce)
    encryptionNonce: toEncryptionNonce(rand()),
    salt0: rand(),
    salt1: rand(),
    authorityPubKey: [ARBITER_PUBKEY_X, ARBITER_PUBKEY_Y],
    kemSs: kem.kemSs,
    kemCiphertext: kem.kemCiphertext,
  };
}

// The affordability precheck is part of the ONE deposit guard sequence now
// (./driver.ts runGuardedDeposit); re-exported so this subpath keeps serving it.
export { assertDepositAffordable } from "./driver.js";

/**
 * Assemble a deposit ProvingRequest: mint `amount` (V) into the pool as note(V) +
 * note(0), BOTH owned by the wallet. Value is exactly [V, 0] (sum == V). The two output
 * commitments are recomputed with the sdk `commitment()` — byte-identical to the
 * circuit / contract. The authority envelope targets `crypto.authorityPubKey` (the
 * pool's stored arbiter key).
 *
 * Throws on a non-positive amount.
 */
export function buildDepositRequest(
  identity: WalletIdentity,
  amount: string,
  crypto: DepositCrypto,
): DepositResult {
  const self = identity.keypair;
  const V = BigInt(amount);
  if (V <= 0n) throw new Error(`deposit amount must be positive, got ${V}`);

  const owner = self.publicKey;
  const salt0 = BigInt(crypto.salt0);
  const salt1 = BigInt(crypto.salt1);
  const outputValues = [V, 0n];
  const outputSalts = [salt0, salt1];
  const outputOwnerPublicKeys: Point[] = [owner, owner];
  const outputCommitments = [
    commitment(V, salt0, owner), // note(V)
    commitment(0n, salt1, owner), // note(0) — real commitment of value 0, non-zero
  ];

  const inputBig: DepositInput = {
    outputCommitments,
    outputValues,
    outputSalts,
    outputOwnerPublicKeys,
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    kemSs: [BigInt(crypto.kemSs[0]), BigInt(crypto.kemSs[1])],
    encryptionNonce: BigInt(crypto.encryptionNonce),
    authorityPublicKey: [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])],
  };

  const request = { circuit: "deposit", input: toWire(inputBig), backend: "cpu" } as const;
  return {
    request,
    meta: {
      outputCommitments: outputCommitments.map((x) => x.toString()),
      outputValues: outputValues.map((x) => x.toString()),
      amount: V.toString(),
    },
  };
}
// ----------------------- run: approve → prove → submit ---------------------------

import type { Calldata } from "@bongtu/core/proving";
import type { Connection, SubmitResult, TokenState } from "@bongtu/client/rail";
import type { KeyCacheLike } from "@bongtu/client/keyCache";
import { randField } from "./spend/crypto.js";
import { runGuardedDeposit, type DepositFamily, type DepositStage } from "./driver.js";

// The stage grammar and the approve-landed money-state wording are the DRIVER's
// (one guard sequence, one rule); re-exported here so this subpath stays the one
// stable public surface the apps and suites import them from.
export { DEPOSIT_FAILURE_REASSURANCE } from "./driver.js";
export type { DepositStage };

export interface DepositContext {
  connection: Connection;
  /** the pool address the deposit approves and submits to (app config). */
  pool: string;
  /** the wrapped kKRW ERC-20 the pool escrows (app config). */
  token: string;
  /** the explorer base URL the success link is built on (app config). */
  explorer: string;
  /** the logged-in session's compressed bjj pubkey — what the just-in-time
   *  derivation must reproduce before any kKRW is shielded. */
  sessionPubkey: string;
}

export interface DepositOutcome {
  txHash: string;
  explorerUrl: string;
  /** the shielded value V (raw kKRW units). */
  amount: string;
  /** whether an ERC-20 approve tx was sent (false when the allowance already covered V). */
  approved: boolean;
}

/** The network/proving I/O runDeposit performs, injectable so the pure orchestration
 *  (guards, stage order, skip-approve decision) is unit-testable with fakes — the same
 *  seam assets.ts uses (PrefetchDeps). The rail members are METHOD-style over the
 *  structural rail seam (@bongtu/client/rail), so the rail client's real edges
 *  (typed over its own wider Connection) are assignable — apps spread
 *  @bongtu/client-evm/ops EVM_ENTERPRISE_IO. */
export interface RunDepositDeps {
  /** the rail's token-state read: balance + allowance to the pool (view, no gas). */
  readTokenState(connection: Connection, tokenAddr: string, owner: string, spender: string): Promise<TokenState>;
  /** the rail's exact-amount ERC-20 approve; resolves after the receipt. */
  approveToken(connection: Connection, tokenAddr: string, spender: string, amount: bigint): Promise<string>;
  /** refuse a pool whose arbiter KEM key the chain does not vouch for. */
  assertPoolKemEpoch(connection: Connection, poolAddr: string): Promise<void>;
  /** put the wallet on the live chain (silent when already there). */
  ensureChain(connection: Connection): Promise<void>;
  /** the wallet's lock — holds the spending key between actions (keyCache.ts). */
  keyCache: KeyCacheLike;
  /** Turn a ProvingRequest into Groth16 calldata. The APP supplies this: treasury-web
   *  injects in-browser snarkjs (prove.ts proveInBrowser with its circuit asset
   *  base URL applied); payroll-web will inject its prover-service adapter. */
  prove: (request: ProvingRequest) => Promise<Calldata>;
  /** the rail's proven-deposit submit. */
  submitDeposit(connection: Connection, poolAddr: string, calldata: Calldata, kemCiphertext: string, explorerBase: string): Promise<SubmitResult>;
}

/** What every deposit must be handed: the app's lock instance, its prover, and
 *  the rail io (the engine has no rail defaults since the split — spread
 *  @bongtu/client-evm/ops EVM_ENTERPRISE_IO at the wiring site). */
export type DepositIo = RunDepositDeps;

/**
 * Approve (if needed) → assemble the deposit witness → prove in-browser → submit the
 * permissionless deposit through the connected wallet — the ONE guard sequence
 * (./driver.ts runGuardedDeposit), with this family's deltas below. `onStage`
 * fires as each coarse stage begins. The approve stage submits an exact-V approve
 * ONLY when the current pool allowance is below V; otherwise it is a no-op
 * tx-wise (the stage still fires so the UI shows it advancing).
 *
 * Guards run cheapest-first, all of them before the approve tx: the pool's KEM epoch
 * (a view call), the depositor's public kKRW balance (assertDepositAffordable — a
 * doomed deposit must not waste an approve tx and a multi-second proof on a
 * safeTransferFrom that would revert), then the unlock, whose session-account check
 * refuses a key that isn't this session's.
 *
 * Throws the same distinct errors the pure lib raises (non-positive amount, insufficient
 * balance) plus any wallet / RPC failure, because the UI shows the thrown message
 * verbatim rather than mapping error codes of its own.
 */
export async function runDeposit(
  ctx: DepositContext,
  args: { amount: string },
  onStage: (stage: DepositStage) => void,
  deps: DepositIo,
): Promise<DepositOutcome> {
  const io: RunDepositDeps = deps;
  const family: DepositFamily<WalletIdentity> = {
    connection: ctx.connection,
    sessionPubkey: ctx.sessionPubkey,
    keyCache: io.keyCache,
    ensureChain: () => io.ensureChain(ctx.connection),
    // Verify the pool's arbiter KEM key hash FIRST among the network guards: a
    // pre-KEM or foreign-keyed pool can never accept this build's proof, so
    // nothing below — not the approve tx, not the signature popup, not the
    // multi-second proof — is worth spending on it.
    guardPool: () => io.assertPoolKemEpoch(ctx.connection, ctx.pool),
    refineIdentity: (identity) => identity,
    readTokenState: () =>
      io.readTokenState(ctx.connection, ctx.token, ctx.connection.address, ctx.pool),
    approveToken: (V) => io.approveToken(ctx.connection, ctx.token, ctx.pool, V),
    buildDeposit: (identity, amount) => {
      const crypto = freshDepositCrypto(randField);
      const built = buildDepositRequest(identity, amount, crypto);
      return {
        request: built.request,
        // The tx carries the SAME encapsulation the proof's kemBinding committed
        // to (crypto.kemCiphertext) — a different ct would decapsulate to
        // mismatching limbs at the arbiter and burn the envelope into an alarm.
        submit: (calldata) =>
          io.submitDeposit(ctx.connection, ctx.pool, calldata, crypto.kemCiphertext, ctx.explorer),
      };
    },
    prove: io.prove,
  };
  return runGuardedDeposit(args.amount, family, onStage);
}
