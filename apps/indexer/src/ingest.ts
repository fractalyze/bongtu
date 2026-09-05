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

import {
  BaseError,
  ContractFunctionRevertedError,
  ContractFunctionZeroDataError,
  createPublicClient,
  decodeEventLog,
  decodeFunctionData,
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
import { isStealthAnnouncement } from "@bongtu/core/stealth";

import { MirrorTree } from "./tree.js";
import { poolAbi, abiKnowsKem, kemBootGuardError, staleOpAbiError, portalFactoryAbi, consumerModuleAbi, type ChainConfig } from "./chain.js";
import { type FeedEntry, type Slice } from "./store.js";
import { verifyDisclosure, verifyConsumerDisclosure } from "./disclosure.js";
import { connect, PostgresStore, PostgresLedger } from "./postgres.js";
import { NameRegistry } from "./names.js";
import { PortalRegistry } from "./portal.js";
import { ModuleRegistry } from "./modules.js";
import { KemChunkStore } from "./kemchunks.js";
import { IndexerHostBase } from "./host.js";
import { BlockCursor, persistAtomically, type PersistParticipant } from "./persist.js";

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

// The dispatch gate's emitter→handler map (OPMOD §1.4 mirror invariant):
// decodeEventLog dispatches on topic0 across the COMBINED ABI, so a watched
// module can emit a log that DECODES as any pool/factory event name (and vice
// versa). Which handler a log may reach is therefore decided by its EMITTER,
// never by its name alone. Pool-family events apply only from the pool — the
// registry mirror in particular is driven by POOL-emitted ModuleRegistered/
// ModuleRemoved alone; Swept only from the PortalFactory; the consumer op
// family only from the module watch-set. WithdrawAnnouncement is in BOTH sets:
// the module emits the byte-identical pair for withdrawPriv.
const POOL_EVENT_NAMES = new Set([
  "Appended", "SubtreeAppended", "OpApplied",
  "Deposited", "Transferred", "Transferred10", "Transferred10x2",
  "Withdrawn", "WithdrawAnnouncement", "Disbursed", "DisburseCiphertexts",
  "ModuleRegistered", "ModuleRemoved",
]);
const MODULE_EVENT_NAMES = new Set([
  "DepositedPriv", "TransferredPriv", "Transferred10x2Priv", "WithdrawnPriv",
  "DisbursedPriv", "DisbursePrivDisclosure", "DisburseKemChunkAccepted",
  "WithdrawAnnouncement",
]);

// A parsed pool log with its chain position, ordered globally by (block, logIndex).
// Exported so the anvil-free unit test (test/ingest.test.ts) can drive
// `applyLogs` with synthetic sequences.
export interface ParsedLog {
  name: string;
  blockNumber: number;
  logIndex: number;
  txHash: string;
  // Lowercase emitter address. Consumer-module events dispatch on it (the
  // registry mirror pins OpApplied.module against the emitting module);
  // optional because pre-op-module synthetic sequences never needed it.
  address?: string;
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

/**
 * One block's unix-seconds timestamp, retried with a linear backoff. Pure of
 * viem so the policy gates headlessly: `getBlock` and `sleep` are the injected
 * edges (the same seam the client packages use).
 *
 * A block that a completed log scan returned events for always exists, so a
 * failure here is the RPC (rate limit, transport), never the chain. Returns 0
 * ONLY when every attempt failed; the caller treats that as fatal rather than
 * persisting a zero, because a history row's timestamp is written once and a
 * wrong one reads as 1970-01-01 forever.
 */
export async function fetchBlockTimestamp(
  getBlock: (blockNumber: number) => Promise<number>,
  blockNumber: number,
  attempts = 3,
  sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
): Promise<number> {
  for (const i of Array(attempts).keys()) {
    try {
      const ts = await getBlock(blockNumber);
      // A zero from a "successful" call is as unusable as a throw: treat it the
      // same rather than letting it through as a valid timestamp.
      if (ts > 0) return ts;
    } catch {
      // fall through to the backoff
    }
    if (i < attempts - 1) await sleep(250 * (i + 1));
  }
  return 0;
}

export class Indexer extends IndexerHostBase {
  // The EVM chain plumbing lives HERE, never on the shared host base: a
  // Solana-only process must boot with no viem client and no Foundry artifact
  // on disk (host.ts header).
  readonly publicClient: PublicClient;
  // The combined dual-ABI (built V2 artifact ++ frozen V1 op fragments) viem
  // decodeEventLog / readContract dispatch on. Exposed so the anvil-free unit
  // test can round-trip raw event encodings through the exact ABI ingest uses.
  readonly abi: Abi;
  // The op-module registry mirror (modules.ts, OPMOD §1.4): derived from the
  // pool's balanced ModuleRegistered/ModuleRemoved stream, it drives the
  // module-address log watch-set. bootPostgres swaps in the pool-backed one.
  // EVM-only (no op modules on the Solana rail), so it lives here, not on the
  // host base.
  modules: ModuleRegistry = new ModuleRegistry(null);
  // The DECLARED persist participant set + its cursor (persist.ts), built by
  // bootPostgres in flush == commit order.
  private participants: PersistParticipant[] = [];
  private blockCursor: BlockCursor | null = null;

  constructor(cfg: ChainConfig) {
    super(cfg);
    // Pool ABI ++ the PortalFactory fragments ++ the consumer op-module
    // fragments: decodeEventLog dispatches on topic0 across the set, so Swept
    // logs (scanned only when PORTAL_FACTORY is configured) and module-emitted
    // consumer op logs (scanned from the registry-derived watch-set) decode
    // through the same path as pool events. Extra fragments are inert for pool
    // reads.
    this.abi = [...poolAbi(), ...portalFactoryAbi, ...consumerModuleAbi];
    this.publicClient = createPublicClient({ transport: http(cfg.rpc) });
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

  /**
   * eth_call `PortalFactory.addressOf(salt)` — the issuance route's destination
   * lookup. Goes to the CHAIN (not a local EIP-1014 recompute) because the
   * factory's initcode hash is the chain's fact to own; a drifted local mirror
   * would hand payers an address nobody can sweep.
   */
  async portalAddressOf(salt: string): Promise<string> {
    if (!this.cfg.portalFactory) {
      throw new Error("portalAddressOf: PORTAL_FACTORY is not configured");
    }
    return String(
      await this.publicClient.readContract({
        address: this.cfg.portalFactory as Address,
        abi: portalFactoryAbi,
        functionName: "addressOf",
        args: [salt as `0x${string}`],
      }),
    );
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
    const kemPkHash = await (async (): Promise<string> => {
      try {
        const epoch = await this.read("currentEpoch");
        return String(await this.read("arbiterKemPkHash", [epoch]));
      } catch (e) {
        // ONLY a contract-level revert / missing getter marks a pre-KEM V1 pool.
        // A transient RPC failure must propagate — folding it into "V1 pool"
        // would disarm the guard exactly when it cannot see the chain. (ethers'
        // CALL_EXCEPTION became viem's ContractFunction*Error — OR both shapes.)
        if (!isPreKemProbeError(e) && !isViemPreKemProbeError(e)) throw e;
        return "0x" + "0".repeat(64);
      }
    })();
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

  /** getLogs for one address set over [from,to], splitting the range on
   *  provider limits (RPC-agnostic). Raw: unsorted, timestamps unstamped. */
  private async scanRange(addresses: Address[], from: number, to: number): Promise<ParsedLog[]> {
    const out: ParsedLog[] = [];
    const walk = async (lo: number, hi: number): Promise<void> => {
      try {
        const raw = await this.publicClient.getLogs({
          address: addresses.length === 1 ? addresses[0] : addresses,
          fromBlock: BigInt(lo),
          toBlock: BigInt(hi),
        });
        for (const log of raw) {
          const ev = ((): { eventName: string; args: unknown } | null => {
            try {
              // decodeEventLog THROWS on an unknown/ambiguous topic0 — reproducing
              // ethers' parseLog-misses-unknown-topic0 SKIP: a pre-upgrade V1 log,
              // a V2 log a V1 build can't model, or a foreign log all fall through
              // to `continue`, never aborting the batch.
              return decodeEventLog({ abi: this.abi, data: log.data, topics: log.topics });
            } catch {
              return null;
            }
          })();
          if (ev === null) continue; // not a pool event we model (unknown topic0)
          out.push({
            name: ev.eventName,
            blockNumber: Number(log.blockNumber),
            logIndex: log.logIndex,
            txHash: log.transactionHash,
            address: String(log.address).toLowerCase(),
            blockTimestamp: 0, // filled by getLogsChunked, once per distinct block
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
    const walkChunks = async (lo: number): Promise<void> => {
      if (lo > to) return;
      await walk(lo, Math.min(lo + CHUNK - 1, to));
      await walkChunks(lo + CHUNK);
    };
    await walkChunks(from);
    return out;
  }

  /**
   * The full ordered log range for [from,to]: a base scan over the pool (+
   * PortalFactory when configured), THEN a second scan for the module
   * WATCH-SET over the SAME range — the registered-module set persisted so
   * far, addresses registered INSIDE this range (a module registered at block
   * N can emit op logs at N+1, still inside the range), and removed modules
   * that still owe kem chunk accepts (OPMOD §4.4: `submitDisburseKemChunk`
   * outlives deregistration). Two phases because a getLogs address filter is
   * fixed per call and the watch-set is itself derived from the base scan.
   */
  private async getLogsChunked(from: number, to: number): Promise<ParsedLog[]> {
    const baseAddrs = (this.cfg.portalFactory
      ? [this.cfg.pool, this.cfg.portalFactory]
      : [this.cfg.pool]) as Address[];
    const base = await this.scanRange(baseAddrs, from, to);
    const watch = new Set(this.modules.watchAddresses(this.kem.pendingModules()));
    for (const l of base) {
      if (l.name === "ModuleRegistered") watch.add(String(l.args.module).toLowerCase());
    }
    const moduleLogs = watch.size > 0 ? await this.scanRange([...watch] as Address[], from, to) : [];
    const out = [...base, ...moduleLogs];
    out.sort((a, b) => (a.blockNumber - b.blockNumber) || (a.logIndex - b.logIndex));

    // Consumer-disburse chunk DATA is calldata-only (no event re-emit, OPMOD
    // §5): fetch each accepted chunk's tx and decode the submit calldata here,
    // in the I/O shell, so applyLogs stays pure and the unit suite can inject
    // `chunkData` synthetically. A wrapped submission (multicall) defeats the
    // direct decode — the accept still counts (the chain enforced the keccak),
    // but the bytes stay unassemblable and the batch eventually reads
    // kem-withheld; one warning line names it.
    for (const l of out) {
      if (l.name !== "DisburseKemChunkAccepted" || l.args.chunkData !== undefined) continue;
      const tx = await this.publicClient.getTransaction({ hash: l.txHash as `0x${string}` });
      l.args.chunkData = ((): string | null => {
        try {
          const d = decodeFunctionData({ abi: consumerModuleAbi, data: tx.input });
          return d.functionName === "submitDisburseKemChunk" ? String(d.args[2]) : null;
        } catch {
          console.warn(`kem chunk tx ${l.txHash} calldata is not a direct submitDisburseKemChunk call — chunk bytes unrecoverable from this submission`);
          return null;
        }
      })();
    }
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
    for (const i of Array.from({ length: Math.ceil(blockNums.length / CONC) }, (_, w) => w * CONC)) {
      const wave = blockNums.slice(i, i + CONC);
      const blocks = await Promise.all(wave.map((n) => this.blockTimestamp(n)));
      wave.forEach((n, j) => tsByBlock.set(n, blocks[j]));
    }
    for (const l of out) {
      const ts = tsByBlock.get(l.blockNumber);
      // Refuse to stamp an activity item with a timestamp we do not have. A 0
      // renders as 1970-01-01 in every client, and because history rows are
      // derived once at ingest and persisted, that wrong date is PERMANENT
      // short of a from-scratch rescan — which is exactly how 571 rows came to
      // claim 1970 (a bulk rescan whose getBlock calls were rate-limited and
      // silently folded to 0). Throwing instead leaves the batch uncommitted
      // for the tail loop to retry, and surfaces in /health lastError.
      if (!ts) {
        throw new Error(
          `no timestamp for block ${l.blockNumber} after retries — refusing to persist history with a zero timestamp`,
        );
      }
      l.blockTimestamp = ts;
    }
    return out;
  }

  /** One block's unix-seconds timestamp through the retry policy below. */
  private blockTimestamp(blockNumber: number): Promise<number> {
    return fetchBlockTimestamp(
      async (n) => Number((await this.publicClient.getBlock({ blockNumber: BigInt(n) })).timestamp),
      blockNumber,
    );
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
    // cacheTime: 0 — viem caches getBlockNumber for ~pollingInterval, so a tail
    // poll running inside that window reads a STALE head and early-returns
    // `fromBlock > head`, silently skipping a block that already landed (the
    // same cache hazard the rig's `settle` documents). Chunk-completion txs
    // touch no pool state, so nothing else forces a re-scan of their block.
    const head = toBlock ?? Number(await this.publicClient.getBlockNumber({ cacheTime: 0 }));
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
   * Atomic write-behind persist: the EVM rail's DECLARED participant list
   * (store rows, ledger rows in arbiter mode, portal, modules, kem, then the
   * block cursor) handed to the ONE persistAtomically implementation
   * (persist.ts owns the transaction and the commit-only-after-COMMIT rule).
   * Because rows and cursor commit together, a crash mid-persist ROLLs BACK
   * both: durable state is either fully at block H or fully at the previous
   * cursor, never the wedged in-between (leaves at H, cursor behind) that made
   * bootPostgres's reconstructed frontier disagree with the on-chain state at
   * the cursor; a rolled-back batch is retried verbatim by the next poll
   * (applyLogs + every participant are replay-idempotent).
   */
  private async persist(head: number): Promise<void> {
    // ingest() always runs bootPostgres before its first persist, so the pool,
    // the cursor, and the participant list are set.
    this.blockCursor!.advanceTo(head);
    await persistAtomically(this.pgPool!, this.participants, String(head));
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
    const names = new NameRegistry(pool);
    await names.boot();
    this.names = names;
    const portal = new PortalRegistry(pool);
    await portal.boot();
    this.portal = portal;
    const modules = new ModuleRegistry(pool);
    await modules.boot();
    this.modules = modules;
    const kem = new KemChunkStore(pool);
    await kem.boot();
    this.kem = kem;
    // The DECLARED persist participant set (persist.ts), in flush == commit
    // order; the block cursor is itself a participant, LAST, so every row for
    // block H is staged in the transaction before the cursor that claims H.
    this.blockCursor = new BlockCursor(store);
    // The list captures the boot-time instances on purpose: boot is one-shot,
    // and persist must never desync from the store routes serve — do not
    // reassign this.store after boot without rebuilding this list.
    this.participants = [store, ...(this.ledger ? [this.ledger] : []), this.portal, this.modules, this.kem, this.blockCursor];
    // Accepted-unassembled recovery: an accepted chunk whose submit-tx calldata
    // could not be decoded at ingest time persisted with NULL bytes. Boot
    // re-attempts the fetch+decode once per such chunk — an RPC that failed or
    // lagged then usually serves the tx now; a still-undecodable submission
    // stays accepted-unassembled (warn, never a wedge).
    await this.refetchKemChunkData();
    // Consumer public batch re-fill (OPMOD §4.4): each fold-checked
    // consumer-disburse entry persisted its published commitment run — hand
    // those back to the tree so /path keeps serving consumer batch interiors
    // auth-free after a restart. The fold ran at first ingest;
    // MirrorTree.path's fold-to-root assert is the backstop.
    for (const e of this.store.allEvents()) {
      if (
        e.kind === "disbursePriv" &&
        e.disclosure?.status === "verified" &&
        e.batchId !== undefined &&
        e.outputCommitments !== undefined
      ) {
        this.tree.fillBatch(e.batchId, e.outputCommitments.map(BigInt), "public");
      }
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
   * The boot half of accepted-unassembled recovery (OPMOD §5): for every
   * accepted chunk whose bytes are missing, fetch the accepting tx and decode
   * the submit calldata again. A fetch/decode failure warns and moves on (the
   * batch keeps reading accepted-unassembled; the next boot retries); a keccak
   * mismatch on successfully FETCHED bytes throws — the chain enforced that
   * hash at acceptance, so a mismatch means the RPC lied, and boot must fail
   * loudly rather than serve it. Recovered bytes reach the read model
   * immediately and land durably with the next persist.
   */
  private async refetchKemChunkData(): Promise<void> {
    for (const c of this.kem.unassembledAccepted()) {
      if (c.txHash === null) continue; // pre-tx_hash row: nothing to re-fetch
      const data = await (async (): Promise<string | null> => {
        try {
          const tx = await this.publicClient.getTransaction({ hash: c.txHash as `0x${string}` });
          const d = decodeFunctionData({ abi: consumerModuleAbi, data: tx.input });
          if (d.functionName !== "submitDisburseKemChunk") return null;
          return String(d.args[2]);
        } catch (e) {
          console.warn(`kem chunk re-fetch failed for batch ${c.batchId} chunk ${c.chunkIndex} (tx ${c.txHash}): ${(e as Error).message.split("\n", 1)[0]}`);
          return null;
        }
      })();
      if (data === null) {
        console.warn(`kem chunk batch ${c.batchId} chunk ${c.chunkIndex} stays accepted-unassembled (tx ${c.txHash} not directly decodable)`);
        continue;
      }
      this.kem.attachChunkData(c.batchId, c.chunkIndex, data);
    }
  }

  /**
   * Apply an ordered, parsed log range to the in-memory state (mirror + feed +
   * nullifier set + arbiter ledger). Pure of provider I/O — the anvil-free unit
   * test drives this directly with synthetic sequences. Replay-idempotent: every
   * stateful module it feeds (MirrorTree, store, ledger) guards its own
   * replay invariant, so the same range can arrive twice and must converge.
   */
  applyLogs(rawLogs: ParsedLog[]): void {
    // Pass 0 — the ADDRESS GATE (see POOL_EVENT_NAMES above): every handler
    // below runs only for a log its emitter is entitled to. The module
    // watch-set is tracked in RANGE order off pool-emitted ModuleRegistered
    // logs (a module registered at block N emits ops at N+1, inside the same
    // range); a module removed mid-range stays acceptable — the two-phase
    // retention rule (kem chunk accepts outlive deregistration) governs the
    // getLogs filter, and this gate never widens past what that filter
    // admitted. Non-matching logs are not ours: dropped silently. A log with
    // no address at all is a pre-op-module synthetic sequence (unit tests) and
    // counts as pool-emitted.
    const poolAddr = this.cfg.pool.toLowerCase();
    const factoryAddr = this.cfg.portalFactory ? this.cfg.portalFactory.toLowerCase() : null;
    const logs = ((): ParsedLog[] => {
      const watched = new Set(this.modules.watchAddresses(this.kem.pendingModules()));
      const kept: ParsedLog[] = [];
      for (const l of rawLogs) {
        const from = l.address?.toLowerCase();
        if (from === undefined || from === poolAddr) {
          if (l.name === "ModuleRegistered") watched.add(String(l.args.module).toLowerCase());
          if (POOL_EVENT_NAMES.has(l.name)) kept.push(l);
        } else if (factoryAddr !== null && from === factoryAddr) {
          if (l.name === "Swept") kept.push(l);
        } else if (watched.has(from) && MODULE_EVENT_NAMES.has(l.name)) {
          kept.push(l);
        }
      }
      return kept;
    })();

    // Pass 1: drive the mirror on the low-level tree events (order-sensitive) and
    // collect the authoritative (leafIndex, leaf) pairs + batch attach points per
    // tx for pass-2 correlation. Replay-safe: an insert already below the mirror
    // frontier was applied by an earlier (partially failed) call and is skipped —
    // the poll loop retries from an unadvanced cursor after any throw, so the
    // same log range can arrive twice and must converge, not double-apply.
    const appendedByTx = new Map<string, { leafIndex: number; leaf: bigint; root: bigint }[]>();
    const subtreesByTx = new Map<string, { startLeafIndex: number; subtreeRoot: bigint; root: bigint }[]>();
    for (const l of logs) {
      if (l.name === "Appended") {
        const leafIndex = Number(bn(l.args.leafIndex));
        const leaf = bn(l.args.leaf);
        const root = bn(l.args.root);
        this.tree.applyAppend(leafIndex, leaf, root);
        const arr = appendedByTx.get(l.txHash) ?? [];
        arr.push({ leafIndex, leaf, root });
        appendedByTx.set(l.txHash, arr);
      } else if (l.name === "SubtreeAppended") {
        const startLeafIndex = Number(bn(l.args.startLeafIndex));
        const subtreeRoot = bn(l.args.subtreeRoot);
        const root = bn(l.args.root);
        this.tree.applyAttach(startLeafIndex, subtreeRoot, root);
        const arr = subtreesByTx.get(l.txHash) ?? [];
        arr.push({ startLeafIndex, subtreeRoot, root });
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
    const takeAppend = (txHash: string, expected: bigint, what: string): { leafIndex: number; leaf: bigint; root: bigint } => {
      const pair = appendedByTx.get(txHash)?.shift();
      if (!pair) throw new Error(`ingest: ${what} in tx ${txHash} has no matching Appended log`);
      if (pair.leaf !== expected) {
        throw new Error(`ingest: ${what} commitment != Appended leaf @${pair.leafIndex} in tx ${txHash}`);
      }
      return pair;
    };
    // OpApplied (OPMOD §1.5) is the per-applyOp audit anchor consumer module
    // events correlate against: each consumer op consumes the tx's next
    // OpApplied (the pool emits it inside applyOp, BEFORE the module's own
    // event) and pins module attribution + shape + resulting root against what
    // the op's tree events actually did — the same mirror-invariant posture as
    // the takeAppend commitment cross-check.
    const opAppliedByTx = new Map<string, { module: string; startLeafIndex: number; nullifierCount: number; leafCount: number; subtreeRoot: bigint; root: bigint }[]>();
    for (const l of logs) {
      if (l.name === "OpApplied") {
        const arr = opAppliedByTx.get(l.txHash) ?? [];
        arr.push({
          module: String(l.args.module).toLowerCase(),
          startLeafIndex: Number(bn(l.args.startLeafIndex)),
          nullifierCount: Number(bn(l.args.nullifierCount)),
          leafCount: Number(bn(l.args.leafCount)),
          subtreeRoot: bn(l.args.subtreeRoot),
          root: bn(l.args.root),
        });
        opAppliedByTx.set(l.txHash, arr);
      }
    }
    const takeOpApplied = (
      l: ParsedLog,
      expect: { startLeafIndex: number; nullifierCount: number; leafCount: number; subtreeRoot: bigint; root: bigint },
    ): void => {
      const op = opAppliedByTx.get(l.txHash)?.shift();
      if (!op) throw new Error(`ingest: ${l.name} in tx ${l.txHash} has no matching OpApplied log`);
      if (l.address !== undefined && op.module !== l.address.toLowerCase()) {
        throw new Error(`ingest: ${l.name} emitted by ${l.address} but OpApplied names module ${op.module} in tx ${l.txHash}`);
      }
      if (!this.modules.isKnown(op.module)) {
        throw new Error(`ingest: OpApplied names module ${op.module} the registry stream never registered (tx ${l.txHash})`);
      }
      if (
        op.startLeafIndex !== expect.startLeafIndex ||
        op.nullifierCount !== expect.nullifierCount ||
        op.leafCount !== expect.leafCount ||
        op.subtreeRoot !== expect.subtreeRoot ||
        op.root !== expect.root
      ) {
        throw new Error(
          `ingest: OpApplied disagrees with ${l.name} in tx ${l.txHash} ` +
            `(start ${op.startLeafIndex}/${expect.startLeafIndex}, nfs ${op.nullifierCount}/${expect.nullifierCount}, ` +
            `leaves ${op.leafCount}/${expect.leafCount}, subtree ${op.subtreeRoot}/${expect.subtreeRoot}, root ${op.root}/${expect.root})`,
        );
      }
    };
    // A consumer disburse spans DisbursedPriv (nullifier/subtreeRoot/dh/kem
    // chunk hashes) + DisbursePrivDisclosure (the 6B fill material) in the same
    // tx — pre-index the disclosure halves by (tx, startLeafIndex) like the
    // enterprise DisburseCiphertexts below.
    const privDisclosureByTx = new Map<string, Map<number, ParsedLog>>();
    for (const l of logs) {
      if (l.name === "DisbursePrivDisclosure") {
        const start = Number(bn(l.args.startLeafIndex));
        const m = privDisclosureByTx.get(l.txHash) ?? new Map<number, ParsedLog>();
        m.set(start, l);
        privDisclosureByTx.set(l.txHash, m);
      }
    }
    // A disburse spans Disbursed (epoch/ecdh/nonce/disclosureHash) + optionally
    // DisburseCiphertexts (the bytes; absent for plain disburse()). Both land in
    // the same tx, so pre-index the ciphertext logs by (tx, startLeafIndex) and
    // build the whole feed entry at the Disbursed position — a plain disburse
    // then still yields a feed entry ("withheld" disclosure) in chain order.
    const ciphertextsByTx = new Map<string, Map<number, ParsedLog>>();
    // Withdraw feed entries awaiting their paired WithdrawAnnouncement (emitted
    // in the same tx, directly after Withdrawn — FIFO per tx like the append
    // pairs). A replayed range re-adds nothing (addEvent dedups), so the queue
    // stays empty and the already-attached announcement is left alone.
    const withdrawEntriesByTx = new Map<string, FeedEntry[]>();
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
        const i0 = takeAppend(l.txHash, oc0, "Deposited#oc0").leafIndex;
        const i1 = takeAppend(l.txHash, oc1, "Deposited#oc1").leafIndex;
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
        const i0 = takeAppend(l.txHash, oc0, "Transferred#out0").leafIndex;
        const i1 = takeAppend(l.txHash, oc1, "Transferred#out1").leafIndex;
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
          leafIndex: takeAppend(l.txHash, oc, `${l.name}#out${i}`).leafIndex,
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
        const ci = takeAppend(l.txHash, chg, "Withdrawn#change").leafIndex;
        this.tree.recordLeaf(ci, chg);
        // Public feed shape unchanged; the arbiter ledger reads the raw Withdrawn
        // authority envelope directly. Both input nullifiers join the public set.
        const wEntry = this.store.addEvent({
          txHash: l.txHash, blockNumber: l.blockNumber, logIndex: l.logIndex,
          kind: "withdraw", epoch: null, ecdhPublicKey: null, encryptionNonce: null,
          slices: [], ciphertext: [],
        });
        if (wEntry) {
          const wq = withdrawEntriesByTx.get(l.txHash) ?? [];
          wq.push(wEntry);
          withdrawEntriesByTx.set(l.txHash, wq);
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
      } else if (l.name === "WithdrawAnnouncement") {
        // Metadata on the withdraw entry, not a feed entry of its own. The
        // contract emits this pair for EVERY Withdrawn, so the queue is
        // consumed either way; only a real stealth announcement (the core
        // predicate: 32-byte R, not the zero sentinel) is attached — a plain
        // withdraw's entry stays bare and never reaches /announcements. An
        // announcement with no queued entry means the Withdrawn was deduped
        // (replay) — the durable entry already carries it.
        const w = withdrawEntriesByTx.get(l.txHash)?.shift();
        const eph = String(l.args.stealthEphemeralPub);
        if (w && isStealthAnnouncement(eph)) {
          w.announcement = {
            recipient: "0x" + bn(l.args.recipient).toString(16).padStart(40, "0"),
            ephemeralPub: eph,
            viewTag: Number(l.args.stealthViewTag),
          };
        }
      } else if (l.name === "Swept") {
        // PortalFactory sweep landed: flip the matching issuance record. The
        // salt IS portalSalt(stealthAddr) (the one rule — PortalFactory header);
        // the registry matches on it and no-ops an unknown or replayed salt,
        // keeping this branch replay-idempotent like every sibling.
        this.portal.markSwept(String(l.args.salt), l.txHash, bn(l.args.amount));
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
          for (const i of Array(B).keys()) slices.push({ offset: i * 4, elts: 4, leafIndex: start + i });
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
      } else if (l.name === "ModuleRegistered") {
        // The registry mirror (OPMOD §4.4 obligation 1). Applied inside the
        // ordered pass so a module registered earlier in the range is already
        // mirrored when its first op's OpApplied is cross-checked.
        this.modules.applyRegistered(l.txHash, l.logIndex, String(l.args.module));
      } else if (l.name === "ModuleRemoved") {
        this.modules.applyRemoved(l.txHash, l.logIndex, String(l.args.module));
      } else if (l.name === "DepositedPriv") {
        const oc0 = bn(l.args.oc0);
        const oc1 = bn(l.args.oc1);
        const p0 = takeAppend(l.txHash, oc0, "DepositedPriv#oc0");
        const p1 = takeAppend(l.txHash, oc1, "DepositedPriv#oc1");
        takeOpApplied(l, { startLeafIndex: p0.leafIndex, nullifierCount: 0, leafCount: 2, subtreeRoot: 0n, root: p1.root });
        this.tree.recordLeaf(p0.leafIndex, oc0);
        this.tree.recordLeaf(p1.leafIndex, oc1);
        // Consumer feed shape (OPMOD §3.6): receiver cts ++ viewTags ++ per-
        // output kem cts — everything a scanner needs, and NOTHING for a
        // ledger: consumer ops carry no authority envelope by construction, so
        // the arbiter ledger never sees them (no arbiter key involved).
        const ct = [
          ...(l.args.ctReceiver0 as unknown[]).map(bn),
          ...(l.args.ctReceiver1 as unknown[]).map(bn),
        ];
        this.store.addEvent({
          txHash: l.txHash, blockNumber: l.blockNumber, logIndex: l.logIndex,
          kind: "depositPriv", epoch: null,
          ecdhPublicKey: [dec(bn(l.args.ecdhPublicKey[0])), dec(bn(l.args.ecdhPublicKey[1]))],
          encryptionNonce: dec(bn(l.args.encryptionNonce)),
          slices: [
            { offset: 0, elts: 4, leafIndex: p0.leafIndex },
            { offset: 4, elts: 4, leafIndex: p1.leafIndex },
          ],
          ciphertext: ct.map(dec),
          viewTags: (l.args.viewTags as unknown[]).map((x) => dec(bn(x))),
          kemCiphertexts: (l.args.kemCiphertexts as unknown[]).map(String),
        });
      } else if (l.name === "TransferredPriv") {
        const oc0 = bn(l.args.outputCommitments[0]);
        const oc1 = bn(l.args.outputCommitments[1]);
        const p0 = takeAppend(l.txHash, oc0, "TransferredPriv#out0");
        const p1 = takeAppend(l.txHash, oc1, "TransferredPriv#out1");
        const nfs = (l.args.nullifiers as unknown[]).map(bn);
        // nullifierCount counts NONZERO slots: the module strips padded zeros
        // before crossing the applyOp boundary (OPMOD §1.3 #3).
        takeOpApplied(l, { startLeafIndex: p0.leafIndex, nullifierCount: nfs.filter((x) => x !== 0n).length, leafCount: 2, subtreeRoot: 0n, root: p1.root });
        this.tree.recordLeaf(p0.leafIndex, oc0);
        this.tree.recordLeaf(p1.leafIndex, oc1);
        const ct = [
          ...(l.args.ctReceiver0 as unknown[]).map(bn),
          ...(l.args.ctReceiver1 as unknown[]).map(bn),
        ];
        const entry = this.store.addEvent({
          txHash: l.txHash, blockNumber: l.blockNumber, logIndex: l.logIndex,
          kind: "transferPriv", epoch: null,
          ecdhPublicKey: [dec(bn(l.args.ecdhPublicKey[0])), dec(bn(l.args.ecdhPublicKey[1]))],
          encryptionNonce: dec(bn(l.args.encryptionNonce)),
          slices: [
            { offset: 0, elts: 4, leafIndex: p0.leafIndex },
            { offset: 4, elts: 4, leafIndex: p1.leafIndex },
          ],
          ciphertext: ct.map(dec),
          viewTags: (l.args.viewTags as unknown[]).map((x) => dec(bn(x))),
          kemCiphertexts: (l.args.kemCiphertexts as unknown[]).map(String),
        });
        if (entry) this.store.addNullifiers(nfs);
      } else if (l.name === "Transferred10x2Priv") {
        const oc0 = bn(l.args.outputCommitments[0]);
        const oc1 = bn(l.args.outputCommitments[1]);
        const p0 = takeAppend(l.txHash, oc0, "Transferred10x2Priv#out0");
        const p1 = takeAppend(l.txHash, oc1, "Transferred10x2Priv#out1");
        const nfs = (l.args.nullifiers as unknown[]).map(bn);
        takeOpApplied(l, { startLeafIndex: p0.leafIndex, nullifierCount: nfs.filter((x) => x !== 0n).length, leafCount: 2, subtreeRoot: 0n, root: p1.root });
        this.tree.recordLeaf(p0.leafIndex, oc0);
        this.tree.recordLeaf(p1.leafIndex, oc1);
        const ct = (l.args.ctReceivers as unknown[]).map(bn); // flat [2][4], leaf order
        const entry = this.store.addEvent({
          txHash: l.txHash, blockNumber: l.blockNumber, logIndex: l.logIndex,
          kind: "transfer10x2Priv", epoch: null,
          ecdhPublicKey: [dec(bn(l.args.ecdhPublicKey[0])), dec(bn(l.args.ecdhPublicKey[1]))],
          encryptionNonce: dec(bn(l.args.encryptionNonce)),
          slices: [
            { offset: 0, elts: 4, leafIndex: p0.leafIndex },
            { offset: 4, elts: 4, leafIndex: p1.leafIndex },
          ],
          ciphertext: ct.map(dec),
          viewTags: (l.args.viewTags as unknown[]).map((x) => dec(bn(x))),
          kemCiphertexts: (l.args.kemCiphertexts as unknown[]).map(String),
        });
        if (entry) this.store.addNullifiers(nfs);
      } else if (l.name === "WithdrawnPriv") {
        const chg = bn(l.args.changeCommitment);
        const pc = takeAppend(l.txHash, chg, "WithdrawnPriv#change");
        const nfs = (l.args.nullifiers as unknown[]).map(bn);
        takeOpApplied(l, { startLeafIndex: pc.leafIndex, nullifierCount: nfs.filter((x) => x !== 0n).length, leafCount: 1, subtreeRoot: 0n, root: pc.root });
        this.tree.recordLeaf(pc.leafIndex, chg);
        const entry = this.store.addEvent({
          txHash: l.txHash, blockNumber: l.blockNumber, logIndex: l.logIndex,
          kind: "withdrawPriv", epoch: null,
          ecdhPublicKey: [dec(bn(l.args.ecdhPublicKey[0])), dec(bn(l.args.ecdhPublicKey[1]))],
          encryptionNonce: dec(bn(l.args.encryptionNonce)),
          slices: [{ offset: 0, elts: 4, leafIndex: pc.leafIndex }],
          ciphertext: (l.args.ctChange as unknown[]).map(bn).map(dec),
          viewTags: [dec(bn(l.args.viewTag))],
          kemCiphertexts: (l.args.kemCiphertexts as unknown[]).map(String),
        });
        if (entry) {
          // The module emits the same WithdrawAnnouncement pair as the pool —
          // the existing announcement branch attaches it via this queue.
          const wq = withdrawEntriesByTx.get(l.txHash) ?? [];
          wq.push(entry);
          withdrawEntriesByTx.set(l.txHash, wq);
          this.store.addNullifiers(nfs);
        }
      } else if (l.name === "DisbursedPriv") {
        const st = subtreesByTx.get(l.txHash)?.shift();
        if (!st) throw new Error(`ingest: DisbursedPriv in tx ${l.txHash} has no matching SubtreeAppended log`);
        if (st.subtreeRoot !== bn(l.args.subtreeRoot)) {
          throw new Error(`ingest: DisbursedPriv subtreeRoot != SubtreeAppended @start ${st.startLeafIndex} in tx ${l.txHash}`);
        }
        takeOpApplied(l, { startLeafIndex: st.startLeafIndex, nullifierCount: 1, leafCount: 0, subtreeRoot: st.subtreeRoot, root: st.root });
        const start = st.startLeafIndex;
        const B = this.batchSize;
        const dLog = privDisclosureByTx.get(l.txHash)?.get(start);
        const disclosure = dLog ? (dLog.args.disclosure as unknown[]).map(bn) : [];
        // OPMOD §4.4: canonical form + the §4.2 extended fold vs the proof's
        // disclosureHash + the commitment run folded to the SubtreeAppended
        // subtreeRoot. All three green => the PUBLIC batch fill below.
        const verdict = verifyConsumerDisclosure(disclosure, bn(l.args.disclosureHash), st.subtreeRoot, B, l.txHash, start);
        if (verdict.result.status !== "verified") {
          console.error(`ALARM disclosure ${verdict.result.status.toUpperCase()} (consumer) tx=${l.txHash} start=${start} recomputed=${verdict.result.recomputed} expected=${verdict.result.expected}`);
        }
        const full = disclosure.length === 6 * B;
        const entry = this.store.addEvent({
          txHash: l.txHash, blockNumber: l.blockNumber, logIndex: l.logIndex,
          kind: "disbursePriv", epoch: null,
          ecdhPublicKey: [dec(bn(l.args.ecdhPublicKey[0])), dec(bn(l.args.ecdhPublicKey[1]))],
          encryptionNonce: dec(bn(l.args.encryptionNonce)),
          slices: full
            ? Array.from({ length: B }, (_, i) => ({ offset: i * 4, elts: 4, leafIndex: start + i }))
            : [],
          ciphertext: disclosure.slice(0, 4 * B).map(dec),
          disclosure: verdict.result,
          ...(full
            ? {
                viewTags: disclosure.slice(4 * B, 5 * B).map(dec),
                outputCommitments: disclosure.slice(5 * B, 6 * B).map(dec),
              }
            : {}),
          batchId: start,
        });
        if (entry) {
          this.store.addNullifiers([bn(l.args.nullifier)]);
          this.kem.recordBatch({
            batchId: start,
            module: (l.address ?? "").toLowerCase(),
            txHash: l.txHash,
            logIndex: l.logIndex,
            chunkHashes: (l.args.kemChunkHashes as unknown[]).map(String),
            batchTimestamp: l.blockTimestamp,
            outputs: B,
          });
          // The structural payoff (OPMOD §4.4 #3): both checks green => the
          // published commitments ARE the batch interiors — fill in PUBLIC
          // mode so /path serves them auth-free.
          if (verdict.leaves) this.tree.fillBatch(start, verdict.leaves, "public");
        }
      } else if (l.name === "DisburseKemChunkAccepted") {
        this.kem.acceptChunk({
          batchId: Number(bn(l.args.batchId)),
          chunkIndex: Number(bn(l.args.chunkIndex)),
          dataHex: (l.args.chunkData as string | null | undefined) ?? null,
          txHash: l.txHash,
          logIndex: l.logIndex,
        });
      }
    }

    // Audit-anchor drain (OPMOD §1.5): every OpApplied must have been consumed
    // by a family-event branch above. A leftover means a registered module
    // mutated the tree WITHOUT a decodable family event (a foreign module
    // build, or a module deliberately emitting nothing) — exactly what the
    // anchor exists to expose. The mirror itself still advanced on the
    // pool-emitted tree events, so this is an attribution gap, not a tree
    // divergence: alarm-class warning, never a wedge.
    for (const [txHash, arr] of opAppliedByTx) {
      for (const op of arr) {
        console.warn(
          `ALARM OpApplied unconsumed: module=${op.module} tx=${txHash} start=${op.startLeafIndex} ` +
            `nullifiers=${op.nullifierCount} leaves=${op.leafCount} — a module mutated the tree with no decodable family event`,
        );
      }
    }
  }
}
