// The sweep decision: scan the indexer's unswept portal records, and for each
// FUNDED destination build+prove a deposit minting the full balance to the
// announced recipient, then PortalFactory.sweep it. Pure of node:http and of
// the poll timer — index.ts owns the loop cadence, server.ts owns the wire, and
// the viem clients + indexer client + prover enter through the SweeperDeps seam
// so the whole decision table gates headlessly over fakes (test/sweep.test.ts,
// the relayer's relay.ts discipline).
//
// WHY THE BOT NEVER MARKS STATE: the indexer flips `swept` off the factory's
// Swept event (ingest.ts), which is the only truth worth trusting — a local
// "done" set would just desynchronize from a reorg or a crashed receipt wait.
// So a record that stays unswept is simply retried next round (rescan IS the
// retry queue), and a record swept by us re-appears until ingest catches the
// event — at which point its balance is 0 and the funded-only gate skips it.
//
// WHY FUNDED-ONLY: issuance is unauthenticated (api/routes/portal.ts records
// the spam surface), so unswept rows are HINTS. The ERC-20 balance read is the
// proof of payment.
//
// WHY THE RACE WITH A FRESH PAYMENT IS SAFE: the proof binds pub[0] to the
// balance read BEFORE proving; a payment landing during the multi-second proof
// only GROWS the balance past pub[0], which the sweeper contract allows (it
// approves exactly pub[0]) — the remainder is re-swept next round. The pre-send
// re-read guards the other direction (a balance BELOW pub[0] can only mean a
// concurrent sweep of our own already pulled it): skipping there turns the
// factory's SweepExceedsBalance revert into a free no-op.

import { parseAbi, type Abi, type Address } from "viem";

import { ERC20_ABI_FRAGMENTS } from "@bongtu/core/network";
import { portalSalt } from "@bongtu/core/stealth";
import { unpackPubkey } from "@bongtu/core/pubkey";
import type { Calldata, ProvingRequest } from "@bongtu/core/proving";
import type { PortalRecord } from "@bongtu/core/indexerApi";
import { buildDepositRequest, freshDepositCrypto } from "@bongtu/client/deposit";
import type { RandField } from "@bongtu/client/deposit";
import { freshKemMaterial, type KemDrawFn } from "@bongtu/client/spend";
import type { WalletIdentity } from "@bongtu/client/derive";

// The one function this service submits — PortalFactory.sweep (onlyOwner; the
// pool rides as an address arg where Solidity declares IPortalPool). The
// indexer's portalFactoryAbi carries only Swept + addressOf (its whole
// surface), so the sweep fragment has no shared owner yet; the contract
// (contracts/src/PortalFactory.sol) is the source of truth restated here.
export const SWEEP_ABI: Abi = parseAbi([
  "function sweep(bytes32 salt, address pool, uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[19] pub, bytes kemCiphertext)",
]);

const BALANCE_ABI: Abi = parseAbi([ERC20_ABI_FRAGMENTS.balanceOf]);

/** The deposit circuit's public-vector length (POOL_ABI_FRAGMENTS.deposit:
 *  uint[19], pub[0] == V). */
export const DEPOSIT_PUB_LEN = 19;

/** How the sweeper reaches the chain — the viem clients behind a seam, so unit
 *  tests drive the whole loop body with fakes (no RPC, no key). index.ts builds
 *  the real pair from RPC + SWEEPER_KEY. */
export interface SweeperChain {
  /** the sweeper (factory-owner) EOA address — the ONLY public trace of the key. */
  sweeper: string;
  /** the PortalFactory every sweep goes through. */
  factory: string;
  /** the pool the factory's sweep deposits into (the `pool` calldata arg). */
  pool: string;
  /** the ERC-20 whose balance at a portal destination decides "funded". */
  token: string;
  publicClient: {
    readContract(params: unknown): Promise<unknown>;
    getGasPrice(): Promise<bigint>;
    waitForTransactionReceipt(params: { hash: `0x${string}` }): Promise<unknown>;
    getBalance(params: { address: Address }): Promise<bigint>;
  };
  walletClient: {
    writeContract(params: unknown): Promise<`0x${string}`>;
  };
}

/** Everything one sweep round consumes, injectable (the relayer deps posture):
 *  the typed indexer client (@bongtu/core/indexerApi IndexerClient.unswept — never a
 *  hand-rolled fetch), the prover, and the randomness/KEM draws behind the
 *  deposit's fresh crypto material. */
export interface SweeperDeps {
  chain: SweeperChain;
  /** one page of unswept records (index.ts binds the IndexerClient's unswept). */
  fetchUnswept: () => Promise<PortalRecord[]>;
  /** ProvingRequest -> Groth16 calldata (prover.ts CPU snarkjs; a fake in tests). */
  prove: (request: ProvingRequest) => Promise<Calldata>;
  /** fresh field elements for salts/ephemerals (browser-grade CSPRNG in prod). */
  rand: RandField;
  /** fresh ML-KEM encapsulation against ARBITER_KEM_PK (deterministic in tests). */
  drawKem?: KemDrawFn;
}

/** What /health reports beyond the balance: mutated in place by runOnce (a
 *  plain object, one owner — index.ts allocates it once at boot). */
export interface SweeperState {
  lastSweepAt: number | null;
  unswept: number;
}

export const initialState = (): SweeperState => ({ lastSweepAt: null, unswept: 0 });

/**
 * Build the deposit that shields one funded portal destination: outputs
 * [note(balance), note(0)], BOTH owned by the record's announced bjj owner.
 * REUSES the wallet's own builders end to end — freshDepositCrypto draws the
 * authority envelope material exactly as a wallet deposit does (ecdh ephemeral +
 * nonce + ML-KEM encap to ARBITER_KEM_PK, the pool's stored arbiter targets),
 * and buildDepositRequest assembles the witness — so a swept deposit is
 * indistinguishable from a wallet one at the proof.
 *
 * The identity handed to buildDepositRequest carries a ZERO private half ON
 * PURPOSE: deposit is a 0-in mint with no owner secret anywhere in its witness
 * (DepositInput has no private key field), and buildDepositRequest reads only
 * `keypair.publicKey` — the bot holds nothing but the announced PUBLIC key,
 * which is the whole point of the portal design (no recipient secret needed).
 */
export function buildPortalDeposit(
  record: PortalRecord,
  balance: bigint,
  rand: RandField,
  drawKem: KemDrawFn = freshKemMaterial,
): { request: ProvingRequest; kemCiphertext: string } {
  const owner = unpackPubkey(record.owner);
  const identity: WalletIdentity = {
    keypair: { formattedPrivateKey: 0n, publicKey: owner },
    compressedPubkey: record.owner,
  };
  const crypto = freshDepositCrypto(rand, drawKem);
  const built = buildDepositRequest(identity, balance.toString(), crypto);
  return { request: built.request, kemCiphertext: crypto.kemCiphertext };
}

/** The EXACT argument tuple a sweep submits — [salt, pool, a, b, c, pub,
 *  kemCiphertext] with the salt from the ONE padding rule (stealth.ts
 *  portalSalt) and the proof coordinates as bigints (the relayer withdrawArgs
 *  discipline). Kept as its own function so the test can pin deep-equality:
 *  drift here is a different transaction than the factory expects. */
export function sweepArgs(
  stealthAddr: string,
  pool: string,
  calldata: Calldata,
  kemCiphertext: string,
): unknown[] {
  if (calldata.pub.length !== DEPOSIT_PUB_LEN) {
    throw new Error(`deposit calldata must have ${DEPOSIT_PUB_LEN} public signals, got ${calldata.pub.length}`);
  }
  return [
    portalSalt(stealthAddr) as `0x${string}`,
    pool as Address,
    calldata.a.map(BigInt) as [bigint, bigint],
    calldata.b.map((r) => r.map(BigInt)) as [[bigint, bigint], [bigint, bigint]],
    calldata.c.map(BigInt) as [bigint, bigint],
    calldata.pub.map(BigInt),
    kemCiphertext as `0x${string}`,
  ];
}

async function readBalance(chain: SweeperChain, destination: string): Promise<bigint> {
  return (await chain.publicClient.readContract({
    address: chain.token as Address,
    abi: BALANCE_ABI,
    functionName: "balanceOf",
    args: [destination as Address],
  })) as bigint;
}

/**
 * One record: read balance -> skip zero -> build+prove -> re-read -> sweep ->
 * receipt. Returns the sweep tx hash, or null when the record was skipped.
 */
export async function sweepRecord(deps: SweeperDeps, record: PortalRecord): Promise<`0x${string}` | null> {
  const { chain } = deps;
  const balance = await readBalance(chain, record.destination);
  // Unfunded rows are spam-surface hints (issuance is unauthenticated) or
  // already-swept-but-not-yet-ingested — either way, nothing to shield.
  if (balance === 0n) return null;

  const { request, kemCiphertext } = buildPortalDeposit(record, balance, deps.rand, deps.drawKem);
  const calldata = await deps.prove(request);
  const amount = BigInt(calldata.pub[0]); // pub[0] == V, the proof-bound sweep amount

  // Pre-send re-read (see module header): a balance below pub[0] can never be
  // pulled — skipping saves the SweepExceedsBalance revert; a balance ABOVE it
  // is the safe race (the sweep pulls exactly pub[0], the rest re-sweeps).
  const now = await readBalance(chain, record.destination);
  if (now < amount) return null;

  const hash = await chain.walletClient.writeContract({
    address: chain.factory as Address,
    abi: SWEEP_ABI,
    functionName: "sweep",
    args: sweepArgs(record.stealthAddr, chain.pool, calldata, kemCiphertext),
    account: chain.sweeper as Address,
    // 3x headroom over the node's quote — the packages/client chainGasPrice
    // rationale the relayer also follows: eth_gasPrice IS the current floor.
    gasPrice: (await chain.publicClient.getGasPrice()) * 3n,
  });
  await chain.publicClient.waitForTransactionReceipt({ hash });
  // Deliberately NO local swept-marking here: the indexer owns that flip (its
  // ingest reads the factory's Swept event) — see the module header.
  return hash;
}

/**
 * One poll round: fetch the unswept feed and process records SEQUENTIALLY —
 * one record in flight at a time by construction (each await completes before
 * the next record's balance read), so the bot never races itself into
 * double-sweeping one destination. A record's failure is logged and the round
 * moves on: the next rescan retries it (PoC — no queue, no backoff per record).
 */
export async function runOnce(deps: SweeperDeps, state: SweeperState): Promise<void> {
  const records = await deps.fetchUnswept();
  state.unswept = records.length;
  for (const record of records) {
    try {
      const hash = await sweepRecord(deps, record);
      if (hash !== null) state.lastSweepAt = Math.floor(Date.now() / 1000);
    } catch (e) {
      // Message only, never the raw object: the log surface must stay free of
      // anything a library might have folded key material into.
      console.error(`sweep of ${record.destination} (seq ${record.seq}) failed: ${(e as Error).message}`);
    }
  }
}

/** A route-shaped result: HTTP status + JSON body (server.ts owns the wire). */
export interface SweepResult {
  status: number;
  body: unknown;
}

/**
 * GET /health: { ok, sweeper, balanceWei, lastSweepAt, unswept }. ok=false when
 * the gas balance is 0 — an unfunded sweeper silently stops shielding payments,
 * which must be visible before a recipient wonders where their note is. The
 * sweeper ADDRESS is public by nature (it signs on-chain txs); the key never
 * appears anywhere.
 */
export async function handleHealth(chain: SweeperChain, state: SweeperState): Promise<SweepResult> {
  const balance = await chain.publicClient.getBalance({ address: chain.sweeper as Address });
  return {
    status: 200,
    body: {
      ok: balance > 0n,
      sweeper: chain.sweeper,
      balanceWei: balance.toString(),
      lastSweepAt: state.lastSweepAt,
      unswept: state.unswept,
    },
  };
}
