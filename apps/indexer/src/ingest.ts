// Event ingest + IMT mirror (SPEC §6b, §5.1).
//
// Replays BongtuPool events from a start block IN ORDER and drives an SDK
// `ImtTree` mirror that stays byte-identical to the on-chain tree: the mirror is
// the SAME class the contract's Foundry differential test pins against, so
// `mirror.getRoot()` equals `pool.root()` after every insert.
//
// The two low-level tree events are the authoritative drivers:
//   Appended(leafIndex, leaf, root)              -> mirror.appendLeaf(leaf)
//   SubtreeAppended(startLeafIndex, subRoot,root) -> mirror.attachSubtree(subRoot)
// Each carries the resulting on-chain root, so the mirror root is asserted
// per-insert (stronger than the "at HEAD" floor the task requires). The batch
// leaves of a disburse are NOT chain-recoverable (only the subtree root is
// emitted), so attachSubtree records holes; merkle paths into a batch therefore
// fail loudly rather than return a wrong path (SPEC §11-7 convenience layer).
//
// The high-level events (Deposited / Transferred / Disbursed+DisburseCiphertexts
// / Withdrawn) supply the ciphertext feed metadata: ecdhPublicKey, nonce, epoch,
// and the per-slice leafIndex a wallet needs to request a path after it
// trial-decrypts. Every disburse also runs the disclosureHash check (§6b).

import type { Pool } from "pg";
import {
  BaseError,
  ContractFunctionRevertedError,
  ContractFunctionZeroDataError,
  createPublicClient,
  decodeEventLog,
  http,
  keccak256,
  toBytes,
  type Abi,
  type Address,
  type BlockTag,
  type PublicClient,
} from "viem";

import { kemPkFromSecret } from "@bongtu/core/kem";
import { isPreKemProbeError } from "@bongtu/core/network";

import { MirrorTree } from "./tree.js";
import { poolAbi, abiKnowsKem, kemBootGuardError, staleOpAbiError, type ChainConfig } from "./chain.js";
import { InMemoryStore, type StorePort, type Slice } from "./store.js";
import { verifyDisclosure } from "./disclosure.js";
import { connect, PostgresStore, PostgresLedger } from "./postgres.js";

// A block pin for readContract: viem takes a bigint blockNumber or a named
// blockTag, where ethers took a single `{ blockTag }` override.
type BlockOpts = { blockNumber?: bigint; blockTag?: BlockTag };

/**
 * A missing getter (a V1 pool where `arbiterKemPkHash` returns `0x`) or an
 * explicit revert marks a pre-KEM pool — viem surfaces both as CONTRACT-level
 * errors (ContractFunctionZeroDataError / ...RevertedError), distinct from a
 * transport failure, which must still propagate. This is the viem-shaped
 * counterpart to core's `isPreKemProbeError` (which keys on ethers'
 * CALL_EXCEPTION); the boot guard ORs the two so the semantics survive the
 * ethers->viem move without touching core.
 */
function isViemPreKemProbeError(e: unknown): boolean {
  return (
    e instanceof BaseError &&
    e.walk(
      (err) => err instanceof ContractFunctionZeroDataError || err instanceof ContractFunctionRevertedError,
    ) !== null
  );
}

const H = 32; // IMT height — a system-wide constant (SPEC §4)

// A parsed pool log with its chain position, ordered globally by (block, logIndex).
// Exported so the anvil-free unit test (test/ingest.test.ts) can drive
// `applyLogs` with synthetic sequences.
export interface ParsedLog {
  name: string;
  blockNumber: number;
  logIndex: number;
  txHash: string;
  // Unix-seconds timestamp of the block this log landed in — fetched per distinct
  // block (deduped) in getLogsChunked and threaded onto the arbiter history feed
  // (each activity item carries its blockTimestamp). See getLogsChunked below.
  blockTimestamp: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  args: any;
}

const bn = (x: unknown): bigint => BigInt((x as { toString(): string }).toString());
const dec = (x: bigint): string => x.toString();

// The op's hybrid-envelope KEM material, dispatched on event VINTAGE: V2 events
// carry (kemBinding, kemCiphertext); V1 (pre-upgrade) logs decode without them
// -> null -> the ledger's legacy raw-ECDH path, KEM checks skipped (the
// structural pre-KEM gate of pq-envelope-design.md §5 — no false alarms on
// history). Shape-based, not ABI-based, so synthetic ParsedLogs dispatch too.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const kemOf = (args: any): { binding: bigint; ciphertext: Uint8Array } | null =>
  args.kemBinding === undefined || args.kemCiphertext === undefined
    ? null
    : { binding: bn(args.kemBinding), ciphertext: toBytes(args.kemCiphertext) };

export class Indexer {
  readonly cfg: ChainConfig;
  readonly publicClient: PublicClient;
  // The combined dual-ABI (built V2 artifact ++ frozen V1 op fragments) viem
  // decodeEventLog / readContract dispatch on. Exposed so the anvil-free unit
  // test can round-trip raw event encodings through the exact ABI ingest uses.
  readonly abi: Abi;
  // The runtime store is ALWAYS PostgresStore (Postgres-only, U-I4), swapped in
  // by bootPostgres at first ingest. The InMemoryStore default is the pre-boot
  // placeholder (so /health can answer before the first ingest completes) and the
  // pure applyLogs-level double the anvil-free unit test drives — it is the same
  // read-model class PostgresStore itself wraps, never a selectable backend.
  // Not `readonly` — bootPostgres replaces it in place, and the API reads
  // `ix.store` live per request.
  store: StorePort = new InMemoryStore();
  tree!: MirrorTree;
  batchSize = 0;
  // Arbiter mode (SPEC §6b v2): set when the config carries the arbiter private
  // key. The key lives only inside `ledger`; `arbiterMode` is the routing flag
  // the API uses to register /notes + serve within-batch paths. The key itself
  // is NEVER read back out for logging or HTTP.
  readonly arbiterPriv: bigint | null;
  readonly arbiterMode: boolean;
  ledger: PostgresLedger | null = null;
  // The shared Postgres pool (set by bootPostgres; null only before first ingest).
  // Store and ledger are built on this ONE pool, so `persist` can acquire a single
  // client and commit the store rows, ledger rows, and cursor in ONE transaction.
  private pgPool: Pool | null = null;

  // ---- tail-poll operational state (projected by GET /health) --------------
  // Recorded by pollOnce so "wedged since block N" vs "healthy" is machine-
  // visible instead of a swallow-and-log line on a headless service.
  lastError: string | null = null;
  lastErrorAt: number | null = null; // ms epoch
  consecutiveFailures = 0;
  lastSuccessAt: number | null = null; // ms epoch
  private polling = false; // one in-flight tail attempt at a time

  constructor(cfg: ChainConfig) {
    this.cfg = cfg;
    this.abi = poolAbi();
    this.publicClient = createPublicClient({ transport: http(cfg.rpc) });
    this.arbiterPriv = cfg.authorityKey ?? null;
    this.arbiterMode = this.arbiterPriv !== null;
  }

  /** A pinned readContract against the pool (the ONE place the address+ABI meet). */
  private read(functionName: string, args: readonly unknown[] = [], opts: BlockOpts = {}): Promise<unknown> {
    return this.publicClient.readContract({
      address: this.cfg.pool as Address,
      abi: this.abi,
      functionName,
      args,
      ...opts,
      // viem's readContract is heavily generic over a const ABI; the runtime
      // args are correct, so widen the call site rather than fight inference.
    } as Parameters<PublicClient["readContract"]>[0]);
  }

  /** ethers' single `{ blockTag }` override -> viem's bigint blockNumber / tag. */
  private blockOpts(blockTag: number | string): BlockOpts {
    return typeof blockTag === "number" ? { blockNumber: BigInt(blockTag) } : { blockTag: blockTag as BlockTag };
  }

  /** Live head state straight from the contract (the mirror is asserted against it). */
  async head(): Promise<{ root: bigint; nextLeafIndex: number }> {
    return this.headAt("latest");
  }

  /**
   * The KEM boot guard (pq-envelope-design.md §7, mandatory): read the pool's
   * `arbiterKemPkHash(currentEpoch())` and refuse to serve when the chain is in
   * a KEM epoch this process cannot honor (V1-only ABI, or arbiter mode without
   * AUTHORITY_KEM_KEY). A revert/missing getter marks a pre-KEM (V1) pool —
   * the zero hash, guard passes. Returns the fatal one-liner or null; index.ts
   * exits on it (the databaseUrlError fail-fast posture).
   */
  async kemBootGuard(): Promise<string | null> {
    let kemPkHash = "0x" + "0".repeat(64);
    try {
      const epoch = await this.read("currentEpoch");
      kemPkHash = String(await this.read("arbiterKemPkHash", [epoch]));
    } catch (e) {
      // ONLY a contract-level revert / missing getter marks a pre-KEM V1 pool.
      // A transient RPC failure must propagate — folding it into "V1 pool"
      // would disarm the guard exactly when it cannot see the chain. (ethers'
      // CALL_EXCEPTION became viem's ContractFunction*Error — OR both shapes.)
      if (!isPreKemProbeError(e) && !isViemPreKemProbeError(e)) throw e;
    }
    const kemKey = this.cfg.authorityKemKey ?? null;
    // Stale-op-ABI check first: it is unconditional (the fragments ship
    // in-repo), where the KEM guard only arms on a KEM-epoch pool.
    const stale = staleOpAbiError(this.abi);
    if (stale !== null) return stale;
    return kemBootGuardError({
      kemPkHash,
      arbiterMode: this.arbiterMode,
      hasKemKey: kemKey !== null,
      abiKnowsKem: abiKnowsKem(this.abi),
      kemKeyPkHash: kemKey === null ? null : keccak256(kemPkFromSecret(kemKey)),
    });
  }

  /** Contract root + nextLeafIndex pinned to `blockTag` (viem readContract block pin). */
  async headAt(blockTag: number | string): Promise<{ root: bigint; nextLeafIndex: number }> {
    const opts = this.blockOpts(blockTag);
    const [root, nli] = await Promise.all([
      this.read("root", [], opts),
      this.read("nextLeafIndex", [], opts),
    ]);
    return { root: bn(root), nextLeafIndex: Number(bn(nli)) };
  }

  /** getLogs over [from,to], splitting the range on provider limits (RPC-agnostic). */
  private async getLogsChunked(from: number, to: number): Promise<ParsedLog[]> {
    const out: ParsedLog[] = [];
    const walk = async (lo: number, hi: number): Promise<void> => {
      try {
        const raw = await this.publicClient.getLogs({
          address: this.cfg.pool as Address,
          fromBlock: BigInt(lo),
          toBlock: BigInt(hi),
        });
        for (const log of raw) {
          let ev: { eventName: string; args: unknown };
          try {
            // decodeEventLog THROWS on an unknown/ambiguous topic0 — reproducing
            // ethers' parseLog-misses-unknown-topic0 SKIP: a pre-upgrade V1 log,
            // a V2 log a V1 build can't model, or a foreign log all fall through
            // to `continue`, never aborting the batch.
            ev = decodeEventLog({ abi: this.abi, data: log.data, topics: log.topics });
          } catch {
            continue; // not a pool event we model (unknown topic0)
          }
          out.push({
            name: ev.eventName,
            blockNumber: Number(log.blockNumber),
            logIndex: log.logIndex,
            txHash: log.transactionHash,
            blockTimestamp: 0, // filled below, once per distinct block
            args: ev.args,
          });
        }
      } catch (e) {
        if (hi > lo) {
          const mid = Math.floor((lo + hi) / 2);
          await walk(lo, mid);
          await walk(mid + 1, hi);
        } else {
          throw e;
        }
      }
    };
    // Seed the recursion with a coarse chunk so a healthy RPC needs few calls.
    const CHUNK = Number(process.env.LOG_CHUNK || 50000);
    for (let lo = from; lo <= to; lo += CHUNK) {
      await walk(lo, Math.min(lo + CHUNK - 1, to));
    }
    out.sort((a, b) => (a.blockNumber - b.blockNumber) || (a.logIndex - b.logIndex));
    // Block timestamps: the ledger's per-owner history feed stamps each activity
    // item with its block time. Fetch getBlock ONCE per distinct block in the
    // range (a poll batch usually spans a handful of blocks, and one disburse tx
    // can carry many logs) — deduping by blockNumber avoids an RPC round-trip per
    // log. A missing/pending block (should not happen for a scanned range) folds
    // to 0 rather than throwing the whole ingest.
    const blockNums = [...new Set(out.map((l) => l.blockNumber))];
    const tsByBlock = new Map<number, number>();
    // Bounded concurrency: a cold-start backfill can span thousands of active
    // blocks; an unbounded Promise.all would open one socket per block and let a
    // single RPC rejection fail the whole ingest. Fetch in fixed-size waves.
    const CONC = 16;
    for (let i = 0; i < blockNums.length; i += CONC) {
      const wave = blockNums.slice(i, i + CONC);
      // viem getBlock THROWS (BlockNotFoundError) on a missing/pending block,
      // where ethers returned null — catch to null so a phantom block folds to
      // timestamp 0 rather than failing the whole ingest (block time is bigint).
      const blocks = await Promise.all(
        wave.map((n) => this.publicClient.getBlock({ blockNumber: BigInt(n) }).catch(() => null)),
      );
      wave.forEach((n, j) => tsByBlock.set(n, Number(blocks[j]?.timestamp ?? 0)));
    }
    for (const l of out) l.blockTimestamp = tsByBlock.get(l.blockNumber) ?? 0;
    return out;
  }

  /**
   * Replay from `fromBlock` to the current head, driving the mirror and building
   * the feed. Safe to call repeatedly for incremental tails (the mirror + store
   * persist across calls). Asserts mirror == contract per insert and at head.
   *
   * This is the I/O shell: fetch the log range, hand it to the pure-in-memory
   * `applyLogs`, then pin the head invariant and advance the cursor.
   */
  async ingest(fromBlock = this.cfg.startBlock, toBlock?: number): Promise<void> {
    if (!this.tree) {
      // Postgres-only (U-I4): there is no other backend. index.ts fail-fasts on a
      // missing DATABASE_URL before ever constructing an Indexer; this throw is
      // the belt for programmatic callers (tests must pass a databaseUrl).
      if (!this.cfg.databaseUrl) {
        throw new Error("Indexer.ingest: cfg.databaseUrl is required — the indexer is Postgres-only (no in-memory backend)");
      }
      this.batchSize = Number(bn(await this.read("B")));
      this.tree = new MirrorTree(H, this.batchSize);
      // bootPostgres returns a fromBlock bumped past the persisted cursor so the
      // reconstructed state is not re-ingested (the whole point of resume).
      fromBlock = await this.bootPostgres(fromBlock);
    }
    // `toBlock` bounds the replay (used for phased ingest / conformance); default
    // is the live head. The head invariant below is asserted at exactly this block.
    const head = toBlock ?? Number(await this.publicClient.getBlockNumber());
    if (fromBlock > head) return;
    const logs = await this.getLogsChunked(fromBlock, head);

    this.applyLogs(logs);

    // Head invariant (SPEC §6b): mirror == contract root + nextLeafIndex,
    // pinned to the scanned block — a pool tx landing during the (minutes-long
    // on a fresh sync) log replay must not read as a divergence. The cursor
    // advances only after the invariant holds, so a failed pass is retried
    // over the same range (pass 1/pass 2 are replay-idempotent).
    const at = await this.headAt(head);
    if (this.tree.root() !== at.root) {
      throw new Error(`ingest: mirror root ${this.tree.root()} != contract root ${at.root} @block ${head}`);
    }
    if (this.tree.nextLeafIndex() !== at.nextLeafIndex) {
      throw new Error(`ingest: mirror nextLeafIndex ${this.tree.nextLeafIndex()} != contract ${at.nextLeafIndex} @block ${head}`);
    }
    // Persist ALL derived rows for this batch AND advance the block cursor in ONE
    // transaction (see `persist`). The cursor reaches H iff every row for blocks
    // <= H is durable, so a crash can never leave the leaves table ahead of the
    // cursor — the state boot rebuilds is always consistent with the resume point.
    await this.persist(head);
  }

  /**
   * Atomic write-behind persist (Postgres backend) — the crash-safety core.
   *
   * Acquires ONE client from the shared pool and, in a single BEGIN/COMMIT, stages
   * the store rows (events/nullifiers/leaf delta), the ledger rows
   * (notes/history/alarms/applied-ops), and the block cursor. Because leaves and
   * cursor commit together, a crash mid-persist ROLLs BACK both: the durable state
   * is either fully at block H or fully at the previous cursor, never the wedged
   * in-between (leaves at H, cursor behind) that made bootPostgres's reconstructed
   * frontier disagree with the on-chain state at the cursor. Buffers are cleared
   * and the in-memory cursor advanced ONLY after COMMIT, so a rolled-back batch is
   * retried verbatim by the next poll (applyLogs + every module are replay-idempotent).
   */
  private async persist(head: number): Promise<void> {
    // ingest() always runs bootPostgres before its first persist, so the pool is set.
    const client = await this.pgPool!.connect();
    try {
      await client.query("BEGIN");
      await this.store.flushInto!(client);
      await this.ledger?.flushInto(client);
      await this.store.persistCursorInto!(client, head);
      // TEST-ONLY fault injection: crash at the pre-COMMIT point (every row + the
      // cursor staged but not yet durable) so the atomicity window is exercised
      // deterministically. Never set outside test/pg_resume.ts.
      if (process.env.BONGTU_CRASH_BEFORE_COMMIT === String(head)) {
        throw new Error(`crash-before-commit fault injection @block ${head}`);
      }
      await client.query("COMMIT");
    } catch (e) {
      try {
        await client.query("ROLLBACK");
      } catch {
        // The connection may already be dead (real crash) — keep the original error.
      }
      throw e;
    } finally {
      client.release();
    }
    // Durable now: drop the write-behind buffers and advance the in-memory cursor.
    // A COMMIT failure skips this (both untouched), so pollOnce re-ingests the same
    // range from the unadvanced cursor and re-persists.
    this.store.commitFlush?.();
    this.ledger?.commitFlush();
    this.store.lastBlock = head;
  }

  /** Release the Postgres pool on a graceful shutdown (no-op before first ingest). */
  async close(): Promise<void> {
    if (this.pgPool) {
      await this.pgPool.end();
      this.pgPool = null;
    }
  }

  /**
   * Build the Postgres store/ledger and reconstruct state from SQL so a restart
   * RESUMES from the persisted cursor instead of replaying the chain. Returns the
   * effective start block: cursor+1 when a cursor exists (skip what is already
   * reconstructed), else the requested `fromBlock`.
   */
  private async bootPostgres(fromBlock: number): Promise<number> {
    const pool = await connect(this.cfg.databaseUrl!);
    this.pgPool = pool; // the ONE pool store + ledger + `persist` share
    const store = new PostgresStore(pool);
    await store.boot(this.tree);
    this.store = store;
    if (this.arbiterPriv !== null) {
      const ledger = new PostgresLedger(pool, this.arbiterPriv, this.cfg.authorityKemKey ?? null, this.batchSize, this.tree);
      await ledger.boot();
      this.ledger = ledger;
    }
    const cursor = this.store.lastBlock;
    if (cursor >= 0) {
      // A rebuild bug must fail the boot loudly, not serve a wrong root/path: the
      // reconstructed frontier has to equal the on-chain values at the cursor block.
      const at = await this.headAt(cursor);
      if (this.tree.root() !== at.root) {
        throw new Error(`bootPostgres: reconstructed root ${this.tree.root()} != contract root ${at.root} @cursor ${cursor}`);
      }
      if (this.tree.nextLeafIndex() !== at.nextLeafIndex) {
        throw new Error(`bootPostgres: reconstructed nextLeafIndex ${this.tree.nextLeafIndex()} != contract ${at.nextLeafIndex} @cursor ${cursor}`);
      }
    }
    if (cursor >= fromBlock) {
      console.log(`postgres backend: resume from block ${cursor + 1} (cursor=${cursor} root=${this.tree.root()} nextLeafIndex=${this.tree.nextLeafIndex()})`);
      return cursor + 1;
    }
    console.log(`postgres backend: fresh ingest from block ${fromBlock} (no cursor)`);
    return fromBlock;
  }

  /**
   * One guarded tail attempt: re-ingest from the cursor, recording success /
   * failure state for GET /health. Never throws — a failing RPC or a genuine
   * mirror-root divergence lands in `lastError` + `consecutiveFailures` instead
   * of only a log line, and the cursor stays unadvanced so the next attempt
   * retries the same range. Concurrent calls coalesce (one in-flight attempt).
   */
  async pollOnce(): Promise<void> {
    if (this.polling) return;
    this.polling = true;
    try {
      await this.ingest(this.store.lastBlock + 1);
      this.consecutiveFailures = 0;
      this.lastSuccessAt = Date.now();
    } catch (e) {
      this.consecutiveFailures++;
      this.lastError = (e as Error).message;
      this.lastErrorAt = Date.now();
      console.error("tail ingest error:", this.lastError);
    } finally {
      this.polling = false;
    }
  }

  /** Start the incremental tail poll (one pollOnce per `pollMs`); returns a stopper. */
  startTailPolling(pollMs: number): () => void {
    const timer = setInterval(() => {
      void this.pollOnce();
    }, pollMs);
    return () => clearInterval(timer);
  }

  /**
   * Apply an ordered, parsed log range to the in-memory state (mirror + feed +
   * nullifier set + arbiter ledger). Pure of provider I/O — the anvil-free unit
   * test drives this directly with synthetic sequences. Replay-idempotent: every
   * stateful module it feeds (MirrorTree, store, ledger) guards its own
   * replay invariant, so the same range can arrive twice and must converge.
   */
  applyLogs(logs: ParsedLog[]): void {
    // Pass 1: drive the mirror on the low-level tree events (order-sensitive) and
    // collect the authoritative (leafIndex, leaf) pairs + batch attach points per
    // tx for pass-2 correlation. Replay-safe: an insert already below the mirror
    // frontier was applied by an earlier (partially failed) call and is skipped —
    // the poll loop retries from an unadvanced cursor after any throw, so the
    // same log range can arrive twice and must converge, not double-apply.
    const appendedByTx = new Map<string, { leafIndex: number; leaf: bigint }[]>();
    const subtreesByTx = new Map<string, { startLeafIndex: number; subtreeRoot: bigint }[]>();
    for (const l of logs) {
      if (l.name === "Appended") {
        const leafIndex = Number(bn(l.args.leafIndex));
        const leaf = bn(l.args.leaf);
        this.tree.applyAppend(leafIndex, leaf, bn(l.args.root));
        const arr = appendedByTx.get(l.txHash) ?? [];
        arr.push({ leafIndex, leaf });
        appendedByTx.set(l.txHash, arr);
      } else if (l.name === "SubtreeAppended") {
        const startLeafIndex = Number(bn(l.args.startLeafIndex));
        const subtreeRoot = bn(l.args.subtreeRoot);
        this.tree.applyAttach(startLeafIndex, subtreeRoot, bn(l.args.root));
        const arr = subtreesByTx.get(l.txHash) ?? [];
        arr.push({ startLeafIndex, subtreeRoot });
        subtreesByTx.set(l.txHash, arr);
      }
    }

    // Pass 2: build the ciphertext feed from the high-level events, in chain
    // order, consuming the pass-1 pairs as ordered per-tx queues. One tx may
    // hold several pool ops (multicall / Safe / 4337 bundle — transfer and
    // withdraw are permissionless, so third-party wrappers can batch them
    // today): consumption follows each op's OUTPUT arity, not its input arity —
    // Deposited/Transferred/Transferred10x2 take 2 pairs, Transferred10 takes
    // 10, Withdrawn 1, and each Disbursed the next SubtreeAppended. Every
    // consumed pair is cross-checked against the event's own commitment
    // argument — a correlation slip throws instead of recording a wrong leaf.
    const takeAppend = (txHash: string, expected: bigint, what: string): number => {
      const pair = appendedByTx.get(txHash)?.shift();
      if (!pair) throw new Error(`ingest: ${what} in tx ${txHash} has no matching Appended log`);
      if (pair.leaf !== expected) {
        throw new Error(`ingest: ${what} commitment != Appended leaf @${pair.leafIndex} in tx ${txHash}`);
      }
      return pair.leafIndex;
    };
    // A disburse spans Disbursed (epoch/ecdh/nonce/disclosureHash) + optionally
    // DisburseCiphertexts (the bytes; absent for plain disburse()). Both land in
    // the same tx, so pre-index the ciphertext logs by (tx, startLeafIndex) and
    // build the whole feed entry at the Disbursed position — a plain disburse
    // then still yields a feed entry ("withheld" disclosure) in chain order.
    const ciphertextsByTx = new Map<string, Map<number, ParsedLog>>();
    for (const l of logs) {
      if (l.name === "DisburseCiphertexts") {
        const start = Number(bn(l.args.startLeafIndex));
        const m = ciphertextsByTx.get(l.txHash) ?? new Map<number, ParsedLog>();
        m.set(start, l);
        ciphertextsByTx.set(l.txHash, m);
      }
    }
    for (const l of logs) {
      if (l.name === "Deposited") {
        const oc0 = bn(l.args.oc0);
        const oc1 = bn(l.args.oc1);
        const i0 = takeAppend(l.txHash, oc0, "Deposited#oc0");
        const i1 = takeAppend(l.txHash, oc1, "Deposited#oc1");
        this.tree.recordLeaf(i0, oc0);
        this.tree.recordLeaf(i1, oc1);
        // Public feed shape is unchanged (deposit envelope bytes are NOT added to
        // the public /events entry). The arbiter ledger reads the raw Deposited
        // authority envelope (ecdhPublicKey/encryptedValuesForAuthority/nonce)
        // directly. The ledger dedups replays on (txHash, logIndex) itself; the
        // Store first-sight gates here are belt-and-braces.
        const dEntry = this.store.addEvent({
          txHash: l.txHash, blockNumber: l.blockNumber, logIndex: l.logIndex,
          kind: "deposit", epoch: null, ecdhPublicKey: null, encryptionNonce: null,
          slices: [], ciphertext: [],
        });
        if (dEntry && this.ledger) {
          this.ledger.apply({
            kind: "deposit", txHash: l.txHash, logIndex: l.logIndex, blockTimestamp: l.blockTimestamp,
            ecdhPublicKey: [bn(l.args.ecdhPublicKey[0]), bn(l.args.ecdhPublicKey[1])],
            nonce: bn(l.args.encryptionNonce),
            authorityCt: (l.args.encryptedValuesForAuthority as unknown[]).map(bn),
            kem: kemOf(l.args),
            outputLeaves: [{ leafIndex: i0, commitment: oc0 }, { leafIndex: i1, commitment: oc1 }],
          });
        }
      } else if (l.name === "Transferred") {
        const oc0 = bn(l.args.outputCommitments[0]);
        const oc1 = bn(l.args.outputCommitments[1]);
        const i0 = takeAppend(l.txHash, oc0, "Transferred#out0");
        const i1 = takeAppend(l.txHash, oc1, "Transferred#out1");
        this.tree.recordLeaf(i0, oc0);
        this.tree.recordLeaf(i1, oc1);
        // ciphertext layout: receiver0[4] ++ receiver1[4] ++ authority[16]
        const ct: bigint[] = [
          ...(l.args.encryptedValuesForReceiver0 as unknown[]).map(bn),
          ...(l.args.encryptedValuesForReceiver1 as unknown[]).map(bn),
          ...(l.args.encryptedValuesForAuthority as unknown[]).map(bn),
        ];
        const slices: Slice[] = [
          { offset: 0, elts: 4, leafIndex: i0 },
          { offset: 4, elts: 4, leafIndex: i1 },
          { offset: 8, elts: 16, leafIndex: null }, // authority envelope (not a leaf)
        ];
        const tEntry = this.store.addEvent({
          txHash: l.txHash, blockNumber: l.blockNumber, logIndex: l.logIndex,
          kind: "transfer", epoch: Number(bn(l.args.epoch)),
          ecdhPublicKey: [dec(bn(l.args.ecdhPublicKey[0])), dec(bn(l.args.ecdhPublicKey[1]))],
          encryptionNonce: dec(bn(l.args.encryptionNonce)),
          slices, ciphertext: ct.map(dec),
        });
        if (tEntry) {
          this.store.addNullifiers([bn(l.args.nullifiers[0]), bn(l.args.nullifiers[1])]);
          if (this.ledger) {
            this.ledger.apply({
              kind: "transfer", txHash: l.txHash, logIndex: l.logIndex, blockTimestamp: l.blockTimestamp,
              ecdhPublicKey: [bn(l.args.ecdhPublicKey[0]), bn(l.args.ecdhPublicKey[1])],
              nonce: bn(l.args.encryptionNonce),
              // authority envelope = ct[8..23] (receiver0[4] ++ receiver1[4] ++ authority[16])
              authorityCt: (l.args.encryptedValuesForAuthority as unknown[]).map(bn),
              kem: kemOf(l.args),
              outputLeaves: [{ leafIndex: i0, commitment: oc0 }, { leafIndex: i1, commitment: oc1 }],
            });
          }
        }
      } else if (l.name === "Transferred10" || l.name === "Transferred10x2") {
        // The 10-input transfers: same event grammar as Transferred, ten
        // nullifiers, and the receiver ciphertexts arrive as ONE flat run in
        // leaf order — sliced at i*4, the same loop a disburse batch already
        // uses. Transferred10 (V4) publishes ten outputs; Transferred10x2 (V5)
        // is the same ten-input spend but only two outputs (payment + change,
        // receivers uint256[8], authority uint256[31]) — the output commitment
        // count is what the branch dispatches on, everything else is shared.
        // Neither has a V1 vintage to dual-parse: the entry points did not
        // exist before their upgrade, so a log always carries the KEM fields.
        const kind = l.name === "Transferred10" ? ("transfer10" as const) : ("transfer10x2" as const);
        const ocs = (l.args.outputCommitments as unknown[]).map(bn);
        const leaves = ocs.map((oc, i) => ({
          leafIndex: takeAppend(l.txHash, oc, `${l.name}#out${i}`),
          commitment: oc,
        }));
        for (const lf of leaves) this.tree.recordLeaf(lf.leafIndex, lf.commitment);
        const authorityCt = (l.args.encryptedValuesForAuthority as unknown[]).map(bn);
        // ciphertext layout: receivers[nOut][4] (flat) ++ authority tail
        const ct: bigint[] = [...(l.args.encryptedValuesForReceivers as unknown[]).map(bn), ...authorityCt];
        const slices: Slice[] = leaves.map((lf, i) => ({ offset: i * 4, elts: 4, leafIndex: lf.leafIndex }));
        slices.push({ offset: 4 * leaves.length, elts: authorityCt.length, leafIndex: null }); // authority envelope (not a leaf)
        const t10Entry = this.store.addEvent({
          txHash: l.txHash, blockNumber: l.blockNumber, logIndex: l.logIndex,
          kind, epoch: Number(bn(l.args.epoch)),
          ecdhPublicKey: [dec(bn(l.args.ecdhPublicKey[0])), dec(bn(l.args.ecdhPublicKey[1]))],
          encryptionNonce: dec(bn(l.args.encryptionNonce)),
          slices, ciphertext: ct.map(dec),
        });
        if (t10Entry) {
          // Padded slots carry nullifier 0; addNullifiers drops those, exactly as
          // the contract's _spendNullifier skips them.
          this.store.addNullifiers((l.args.nullifiers as unknown[]).map(bn));
          if (this.ledger) {
            this.ledger.apply({
              kind, txHash: l.txHash, logIndex: l.logIndex, blockTimestamp: l.blockTimestamp,
              ecdhPublicKey: [bn(l.args.ecdhPublicKey[0]), bn(l.args.ecdhPublicKey[1])],
              nonce: bn(l.args.encryptionNonce),
              authorityCt,
              kem: kemOf(l.args),
              outputLeaves: leaves,
            });
          }
        }
      } else if (l.name === "Withdrawn") {
        const chg = bn(l.args.changeCommitment);
        const ci = takeAppend(l.txHash, chg, "Withdrawn#change");
        this.tree.recordLeaf(ci, chg);
        // Public feed shape unchanged; the arbiter ledger reads the raw Withdrawn
        // authority envelope directly. Both input nullifiers join the public set.
        const wEntry = this.store.addEvent({
          txHash: l.txHash, blockNumber: l.blockNumber, logIndex: l.logIndex,
          kind: "withdraw", epoch: null, ecdhPublicKey: null, encryptionNonce: null,
          slices: [], ciphertext: [],
        });
        if (wEntry) {
          this.store.addNullifiers([bn(l.args.nullifiers[0]), bn(l.args.nullifiers[1])]);
          if (this.ledger) {
            this.ledger.apply({
              kind: "withdraw", txHash: l.txHash, logIndex: l.logIndex, blockTimestamp: l.blockTimestamp,
              ecdhPublicKey: [bn(l.args.ecdhPublicKey[0]), bn(l.args.ecdhPublicKey[1])],
              nonce: bn(l.args.encryptionNonce),
              authorityCt: (l.args.encryptedValuesForAuthority as unknown[]).map(bn),
              kem: kemOf(l.args),
              outputLeaves: [{ leafIndex: ci, commitment: chg }],
            });
          }
        }
      } else if (l.name === "Disbursed") {
        const st = subtreesByTx.get(l.txHash)?.shift();
        if (!st) throw new Error(`ingest: Disbursed in tx ${l.txHash} has no matching SubtreeAppended log`);
        if (st.subtreeRoot !== bn(l.args.subtreeRoot)) {
          throw new Error(`ingest: Disbursed subtreeRoot != SubtreeAppended @start ${st.startLeafIndex} in tx ${l.txHash}`);
        }
        const start = st.startLeafIndex;
        const B = this.batchSize;
        const ctLog = ciphertextsByTx.get(l.txHash)?.get(start);
        const ct: bigint[] = ctLog ? (ctLog.args.receiverCiphertexts as unknown[]).map(bn) : [];
        const slices: Slice[] = [];
        if (ct.length > 0) {
          for (let i = 0; i < B; i++) slices.push({ offset: i * 4, elts: 4, leafIndex: start + i });
          if (ct.length > B * 4) slices.push({ offset: B * 4, elts: ct.length - B * 4, leafIndex: null });
        }
        const disclosure = verifyDisclosure(ct, bn(l.args.disclosureHash), B, l.txHash, start);
        if (disclosure.status !== "verified") {
          console.error(`ALARM disclosure ${disclosure.status.toUpperCase()} tx=${l.txHash} start=${start} recomputed=${disclosure.recomputed} expected=${disclosure.expected}`);
        }
        const dsEntry = this.store.addEvent({
          txHash: l.txHash, blockNumber: l.blockNumber, logIndex: l.logIndex,
          kind: "disburse", epoch: Number(bn(l.args.epoch)),
          ecdhPublicKey: [dec(bn(l.args.ecdhPublicKey[0])), dec(bn(l.args.ecdhPublicKey[1]))],
          encryptionNonce: dec(bn(l.args.encryptionNonce)),
          slices, ciphertext: ct.map(dec), disclosure,
        });
        if (dsEntry) {
          this.store.addNullifiers([bn(l.args.nullifier)]);
          // Arbiter mode: decrypt the authority TAIL (ct after the 4*B receiver
          // run) to recover every recipient's (owner,value,salt), cross-check the
          // fold against the on-chain subtreeRoot, then fill the batch so /path
          // into it serves a real path. Absent an authority tail (receiver-only /
          // withheld publish) there is nothing to open — skip.
          if (this.ledger && ct.length > B * 4) {
            this.ledger.apply({
              kind: "disburse", txHash: l.txHash, logIndex: l.logIndex, blockTimestamp: l.blockTimestamp,
              ecdhPublicKey: [bn(l.args.ecdhPublicKey[0]), bn(l.args.ecdhPublicKey[1])],
              nonce: bn(l.args.encryptionNonce),
              authorityCt: ct.slice(B * 4),
              kem: kemOf(l.args),
              outputLeaves: [],
              batch: { startLeafIndex: start, subtreeRoot: st.subtreeRoot },
            });
          }
        }
      }
    }

  }
}
