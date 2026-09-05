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
// deposit/shield action. Modeled on runSpendChain (ops/spend/run.ts): instead of DOM
// status lines it reports a coarse stage ("approve" → "prove" → "submit") through a
// callback the React Deposit screen renders as a staged progress bar. A deposit is
// 0-in / 2-out (mint), so there is NO note selection and NO membership fetch — the
// "approve" stage replaces the spend's "assemble": exact-V ERC-20 approve, SKIPPED
// when the current allowance already covers V (one approve tx only when needed, then
// the permissionless deposit tx). The orchestration is gated headlessly
// (accountBinding.test.ts, opsFacade.test.ts), the wallet edges faked through the
// RunDepositDeps seam.

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

/**
 * Cheap PURE precheck the deposit flow runs right after reading token state: a deposit
 * of `V` raw units cannot succeed if it exceeds the depositor's public kKRW `balance`
 * (the pool pulls exactly V via safeTransferFrom, which would revert). Throwing here —
 * BEFORE the approve tx and the multi-second proof — mirrors selectInputNotes (ops/spend/plan.ts)
 * rejecting an over-spend, and saves a wasted approve + proof on a doomed deposit.
 */
export function assertDepositAffordable(V: bigint, balance: bigint): void {
  if (V > balance) {
    throw new Error(`insufficient kKRW balance: deposit ${V} exceeds balance ${balance}`);
  }
}

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
import type { Connection } from "@bongtu/client/connection";
import {
  approveToken,
  assertPoolKemEpoch,
  ensureChain,
  readTokenState,
  submitDeposit,
  walletErrorMessage,
} from "@bongtu/client/connection";
import type { KeyCacheLike } from "@bongtu/client/keyCache";
import { randField } from "./spend/crypto.js";

/** The coarse stages a deposit passes through. "unlock" is the signature that hands
 *  over the spending key and fires ONLY when the wallet is locked; "approve" is
 *  SKIPPED (no tx) when the pool allowance already covers V; "prove" is the
 *  multi-second in-browser proof. */
export type DepositStage = "unlock" | "approve" | "prove" | "submit";

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
 *  seam assets.ts uses (PrefetchDeps). Defaults are the real MetaMask/snarkjs edges. */
export interface RunDepositDeps {
  readTokenState: typeof readTokenState;
  approveToken: typeof approveToken;
  assertPoolKemEpoch: typeof assertPoolKemEpoch;
  ensureChain: typeof ensureChain;
  /** the wallet's lock — holds the spending key between actions (keyCache.ts). */
  keyCache: KeyCacheLike;
  /** Turn a ProvingRequest into Groth16 calldata. The APP supplies this: treasury-web
   *  injects in-browser snarkjs (prove.ts proveInBrowser with its circuit asset
   *  base URL applied); payroll-web will inject its prover-service adapter. */
  prove: (request: ProvingRequest) => Promise<Calldata>;
  submitDeposit: typeof submitDeposit;
}

/** What every deposit must be handed: the app's lock instance and its prover. The
 *  engine-side edges (token reads, guards, submits) default to the real ones. */
export type DepositIo = Pick<RunDepositDeps, "keyCache" | "prove"> & Partial<RunDepositDeps>;

const DEFAULT_DEPS: Omit<RunDepositDeps, "keyCache" | "prove"> = {
  readTokenState,
  approveToken,
  assertPoolKemEpoch,
  ensureChain,
  submitDeposit,
};

/**
 * Approve (if needed) → assemble the deposit witness → prove in-browser → submit the
 * permissionless deposit through the connected wallet. `onStage` fires as each coarse
 * stage begins. The
 * approve stage submits an exact-V approve ONLY when the current pool allowance is below
 * V; otherwise it is a no-op tx-wise (the stage still fires so the UI shows it advancing).
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
  const io: RunDepositDeps = { ...DEFAULT_DEPS, ...deps };
  const amount = args.amount.trim();
  const V = BigInt(amount);
  if (V <= 0n) throw new Error(`deposit amount must be positive, got ${V}`);

  // Announce the signature stage up front when the wallet is locked, so the progress
  // list never has to step backwards into a popup it didn't predict.
  const locked = !io.keyCache.isUnlocked();
  onStage(locked ? "unlock" : "approve");
  // A silently-restored session may still sit on another chain — align it before
  // the token reads and every tx below (silent when the chain is already selected).
  await io.ensureChain(ctx.connection);
  // Verify the pool's arbiter KEM key hash FIRST: a pre-KEM or foreign-keyed pool
  // can never accept this build's proof, so nothing below — not the approve tx, not
  // the signature popup, not the multi-second proof — is worth spending on it.
  await io.assertPoolKemEpoch(ctx.connection, ctx.pool);
  const { balance, allowance } = await io.readTokenState(
    ctx.connection,
    ctx.token,
    ctx.connection.address,
    ctx.pool,
  );
  // Fail BEFORE the approve tx + proof if the public balance can't cover V (the pool's
  // safeTransferFrom would revert on-chain anyway).
  assertDepositAffordable(V, balance);
  // The spending key comes from the in-memory lock: one signature the first time,
  // reused after that (keyCache.ts). It resolves BEFORE the approve tx so that a
  // mid-session account switch costs the user nothing — minting into a stranger's
  // key must never be preceded by an approve the user paid gas for.
  const identity = await io.keyCache.unlock(ctx.connection, ctx.sessionPubkey);
  if (locked) onStage("approve");
  const approved = allowance < V;
  if (approved) {
    await io.approveToken(ctx.connection, ctx.token, ctx.pool, V);
  }

  try {
    onStage("prove");
    const crypto = freshDepositCrypto(randField);
    const built = buildDepositRequest(identity, amount, crypto);
    const calldata = await io.prove(built.request);

    onStage("submit");
    // The tx carries the SAME encapsulation the proof's kemBinding committed to
    // (crypto.kemCiphertext) — a different ct would decapsulate to mismatching
    // limbs at the arbiter and burn the envelope into an alarm.
    const res = await io.submitDeposit(ctx.connection, ctx.pool, calldata, crypto.kemCiphertext, ctx.explorer);
    return { txHash: res.txHash, explorerUrl: res.explorerUrl, amount, approved };
  } catch (e) {
    // The CHAIN_FAILURE_REASSURANCE pattern generalized (error-surface standard):
    // once the approve tx has landed, a later failure must say where the money
    // stands — an approval went through but nothing moved, and it is reused on
    // retry. A failure with no approve landed stays a plain single-transaction
    // failure (the reassurance would only confuse — nothing partial can exist).
    if (!approved) throw e;
    throw new Error(`${walletErrorMessage(e)} ${DEPOSIT_FAILURE_REASSURANCE}`);
  }
}

/** What a deposit says when it fails AFTER its approve tx landed. Same money-state
 *  rule as the spend run's CHAIN_FAILURE_REASSURANCE (ops/spend/run.ts): name what stands (the approval)
 *  and what didn't move (every token). */
export const DEPOSIT_FAILURE_REASSURANCE =
  "No kKRW left your account. The approval stays in place and is reused when you retry.";
