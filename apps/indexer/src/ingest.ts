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

import { MirrorTree } from "./tree.js";
import { ethers, poolAbi, type ChainConfig } from "./chain.js";
import { Store, type Slice } from "./store.js";
import { verifyDisclosure } from "./disclosure.js";
import { NoteLedger } from "./ledger.js";

const H = 32; // IMT height — a system-wide constant (SPEC §4)

// A parsed pool log with its chain position, ordered globally by (block, logIndex).
// Exported so the anvil-free unit test (test/ingest.test.ts) can drive
// `applyLogs` with synthetic sequences.
export interface ParsedLog {
  name: string;
  blockNumber: number;
  logIndex: number;
  txHash: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  args: any;
}

const bn = (x: unknown): bigint => BigInt((x as { toString(): string }).toString());
const dec = (x: bigint): string => x.toString();

export class Indexer {
  readonly cfg: ChainConfig;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  readonly provider: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  readonly pool: any;
  readonly store = new Store();
  tree!: MirrorTree;
  batchSize = 0;
  // Arbiter mode (SPEC §6b v2): set when the config carries the arbiter private
  // key. The key lives only inside `ledger`; `arbiterMode` is the routing flag
  // the API uses to register /notes + serve within-batch paths. The key itself
  // is NEVER read back out for logging or HTTP.
  readonly arbiterPriv: bigint | null;
  readonly arbiterMode: boolean;
  ledger: NoteLedger | null = null;

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
    this.provider = new ethers.providers.JsonRpcProvider(cfg.rpc);
    this.pool = new ethers.Contract(cfg.pool, poolAbi(), this.provider);
    this.arbiterPriv = cfg.authorityKey ?? null;
    this.arbiterMode = this.arbiterPriv !== null;
  }

  /** Live head state straight from the contract (the mirror is asserted against it). */
  async head(): Promise<{ root: bigint; nextLeafIndex: number }> {
    return this.headAt("latest");
  }

  /** Contract root + nextLeafIndex pinned to `blockTag` (ethers v5 call override). */
  async headAt(blockTag: number | string): Promise<{ root: bigint; nextLeafIndex: number }> {
    const [root, nli] = await Promise.all([
      this.pool.root({ blockTag }),
      this.pool.nextLeafIndex({ blockTag }),
    ]);
    return { root: bn(root), nextLeafIndex: Number(bn(nli)) };
  }

  /** getLogs over [from,to], splitting the range on provider limits (RPC-agnostic). */
  private async getLogsChunked(from: number, to: number): Promise<ParsedLog[]> {
    const out: ParsedLog[] = [];
    const walk = async (lo: number, hi: number): Promise<void> => {
      try {
        const raw = await this.provider.getLogs({ address: this.cfg.pool, fromBlock: lo, toBlock: hi });
        for (const log of raw) {
          let ev: { name: string; args: unknown } | null = null;
          try {
            ev = this.pool.interface.parseLog(log);
          } catch {
            continue; // not a pool event we model
          }
          out.push({
            name: ev!.name,
            blockNumber: log.blockNumber,
            logIndex: log.logIndex,
            txHash: log.transactionHash,
            args: (ev as { args: unknown }).args,
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
      this.batchSize = Number(bn(await this.pool.B()));
      this.tree = new MirrorTree(H, this.batchSize);
      // Arbiter mode: the ledger holds the arbiter key + owns the note directory
      // and batch fills. Built once, persists across incremental ingest calls.
      if (this.arbiterPriv !== null) this.ledger = new NoteLedger(this.arbiterPriv, this.batchSize, this.tree);
    }
    // `toBlock` bounds the replay (used for phased ingest / conformance); default
    // is the live head. The head invariant below is asserted at exactly this block.
    const head = toBlock ?? (await this.provider.getBlockNumber());
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
    this.store.lastBlock = head;
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
   * stateful module it feeds (MirrorTree, Store, NoteLedger) guards its own
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
    // today): each Deposited/Transferred consumes 2 pairs, each Withdrawn 1,
    // each Disbursed consumes the next SubtreeAppended of its tx. Every
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
            kind: "deposit", txHash: l.txHash, logIndex: l.logIndex,
            ecdhPublicKey: [bn(l.args.ecdhPublicKey[0]), bn(l.args.ecdhPublicKey[1])],
            nonce: bn(l.args.encryptionNonce),
            authorityCt: (l.args.encryptedValuesForAuthority as unknown[]).map(bn),
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
              kind: "transfer", txHash: l.txHash, logIndex: l.logIndex,
              ecdhPublicKey: [bn(l.args.ecdhPublicKey[0]), bn(l.args.ecdhPublicKey[1])],
              nonce: bn(l.args.encryptionNonce),
              // authority envelope = ct[8..23] (receiver0[4] ++ receiver1[4] ++ authority[16])
              authorityCt: (l.args.encryptedValuesForAuthority as unknown[]).map(bn),
              outputLeaves: [{ leafIndex: i0, commitment: oc0 }, { leafIndex: i1, commitment: oc1 }],
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
              kind: "withdraw", txHash: l.txHash, logIndex: l.logIndex,
              ecdhPublicKey: [bn(l.args.ecdhPublicKey[0]), bn(l.args.ecdhPublicKey[1])],
              nonce: bn(l.args.encryptionNonce),
              authorityCt: (l.args.encryptedValuesForAuthority as unknown[]).map(bn),
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
              kind: "disburse", txHash: l.txHash, logIndex: l.logIndex,
              ecdhPublicKey: [bn(l.args.ecdhPublicKey[0]), bn(l.args.ecdhPublicKey[1])],
              nonce: bn(l.args.encryptionNonce),
              authorityCt: ct.slice(B * 4),
              outputLeaves: [],
              batch: { startLeafIndex: start, subtreeRoot: st.subtreeRoot },
            });
          }
        }
      }
    }

  }
}
