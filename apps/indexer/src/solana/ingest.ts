// The Solana ingest backend (SOLR §3.2.2) — the signature-cursor double of the
// EVM block-cursor ingest, feeding the SAME read model.
//
// The seam is deliberate: the EVM Indexer isolates its pure application layer
// as `applyLogs(ParsedLog[])` over {MirrorTree, StorePort, registries};
// `applyLedgerTxs(SolanaLedgerTx[])` below is that layer's Solana double —
// same tree, same store, same feed shapes — with only the fetch layer
// (SolanaChainIo) rail-specific. Nothing here forks the read model: the API
// routes read the inherited members (`store`, `tree`, `disclosures`, health
// state) and cannot tell the backends apart.
//
// Per-op mirror assertion (SOLR §3.2.1): every op's self-CPI event carries the
// program's own resulting root, and the mirror is asserted against it PER OP —
// the granularity the event wire affords (the EVM rail asserts per leaf off
// `Appended`; one event per op is what fits Solana's tx budget). The decoded
// instruction data is additionally cross-checked against the event anchor
// (family, leaf count, nullifier run) — the OpApplied-correlation posture.
//
// Cursor + resume: (slot, signature). The slot rides the existing block
// cursor; the signature (solana_cursor) pins the getSignaturesForAddress
// resume point. Rows and cursor advance in ONE transaction (the EVM persist
// discipline), so a restart rebuilds the frontier from the leaves table and
// replays gap-only from the stored signature. The resume is checked against
// live TreeState: at boot when the chain is at the mirror's own leaf count
// (root equality is decidable), and unconditionally after every gap apply
// (mirror == TreeState at head) — a normal RPC cannot serve historical
// account state, so the at-cursor check completes at the first head assert.

import { MirrorTree } from "../tree.js";
import { Indexer } from "../ingest.js";
import { connect, PostgresStore } from "../postgres.js";
import { NameRegistry } from "../names.js";
import { isStealthAnnouncement } from "@bongtu/core/stealth";
import type { ChainConfig } from "../chain.js";
import type { FeedEntry, Slice } from "../store.js";
import {
  decodeEvent,
  decodeOp,
  programInstructionsOf,
  ARBITER_EPOCH_GENESIS,
  EVENT_DISCRIMINATOR,
  type SolanaEventAnchor,
  type SolanaLedgerTx,
  type SolanaOpIx,
  type StealthTail,
} from "./wire.js";

// IMT height, shared protocol-wide (SOLR §4.1) — the Solana TreeState is the
// same 32-level frontier as the EVM pool.
const TREE_HEIGHT = 32;

/**
 * The rail-specific fetch layer under the pure apply — a live JSON-RPC
 * implementation (rpc.ts) or the conformance suite's recorded-ledger double
 * (SOLR §5.3: no validator in the loop).
 */
export interface SolanaChainIo {
  /** PoolConfig.B — the disburse attach arity the MirrorTree needs. */
  batchSize(): Promise<number>;
  /** Current TreeState (root + nextLeafIndex) — the head-assert oracle. */
  treeHead(): Promise<{ root: bigint; nextLeafIndex: number }>;
  /** Every pool-program tx strictly AFTER `untilSignature` (null = from the
   *  pool's first slot), oldest-first — the gap-only resume read. */
  txsSince(untilSignature: string | null): Promise<SolanaLedgerTx[]>;
}

const dec = (x: bigint): string => x.toString();

export class SolanaIndexer extends Indexer {
  private readonly io: SolanaChainIo;
  /** The pool program id as 0x-hex (the dispatch filter's byte form). */
  readonly solanaProgramId: string;
  /** The signature half of the ledger cursor (slot rides store.lastBlock). */
  cursorSignature: string | null = null;
  private booted = false;

  constructor(cfg: ChainConfig, io: SolanaChainIo, programIdHex: string) {
    super(cfg);
    // KEM-guard posture (pq-envelope-design.md §7): this backend never builds
    // the arbiter ledger, so an AUTHORITY_KEY boot would 503 /notes + /history
    // forever and drop envelope alarms SILENTLY — refuse to serve instead.
    // The message never carries the key.
    if (cfg.authorityKey != null) {
      throw new Error(
        "AUTHORITY_KEY is set but arbiter surfaces are not yet supported on the Solana backend — unset AUTHORITY_KEY (public mode) or run the EVM backend for arbiter mode",
      );
    }
    this.io = io;
    this.solanaProgramId = programIdHex;
  }

  /** The EVM guard probes pool getters that do not exist on this rail, and the
   *  arbiter half of its checklist cannot arise here (the constructor refuses
   *  arbiter mode outright); public-mode KEM epoch discipline is enforced by
   *  the program's config flags instead. */
  override async kemBootGuard(): Promise<string | null> {
    return null;
  }

  override async head(): Promise<{ root: bigint; nextLeafIndex: number }> {
    return this.io.treeHead();
  }

  /**
   * Postgres boot + resume: rebuild the frontier and feed from SQL, read the
   * signature cursor, rebuild the served-blob registry from the persisted
   * disburse anchors, and run the decidable half of the resume check.
   * Public (not folded into ingest) so the conformance suite can pin the
   * rebuilt-at-cursor state before any gap tx applies.
   */
  async boot(): Promise<void> {
    if (this.booted) return;
    if (!this.cfg.databaseUrl) {
      throw new Error("SolanaIndexer.boot: cfg.databaseUrl is required — the indexer is Postgres-only");
    }
    this.batchSize = await this.io.batchSize();
    this.tree = new MirrorTree(TREE_HEIGHT, this.batchSize);
    const pool = await connect(this.cfg.databaseUrl);
    this.pgPool = pool;
    const store = new PostgresStore(pool);
    await store.boot(this.tree);
    this.store = store;
    // The name directory is backend-agnostic (owner-signed POSTs, no chain
    // reads) — boot it durable here exactly as the EVM path does.
    const names = new NameRegistry(pool);
    await names.boot();
    this.names = names;
    const cur = await pool.query("SELECT signature FROM solana_cursor WHERE id = 1");
    this.cursorSignature = cur.rows.length > 0 ? String(cur.rows[0].signature) : null;

    // Served-blob registry rebuild + the per-batch boot invariant: every
    // persisted disburse anchor re-checks its institution-held blob against
    // the chain-committed hash (SOLR §3.3.2).
    for (const e of this.store.allEvents()) {
      if (e.kind === "disburse" && e.disburseAnchor !== undefined && e.batchId !== undefined) {
        this.disclosures.recordBatch(
          {
            startLeafIndex: e.batchId,
            txHash: e.txHash,
            disclosureHash: BigInt(e.disburseAnchor.disclosureHash),
            kemBinding: BigInt(e.disburseAnchor.kemBinding),
            epoch: e.disburseAnchor.epoch,
            recordedAt: e.disburseAnchor.recordedAt,
          },
          this.batchSize,
          { boot: { persistedStatus: e.disclosure?.status } },
        );
      }
    }
    this.disclosures.checkDir(this.batchSize);

    if (this.store.lastBlock >= 0) {
      const at = await this.io.treeHead();
      if (at.nextLeafIndex < this.tree.nextLeafIndex()) {
        throw new Error(
          `SolanaIndexer.boot: chain nextLeafIndex ${at.nextLeafIndex} is BEHIND the rebuilt mirror ${this.tree.nextLeafIndex()} — wrong cluster or database`,
        );
      }
      // Nothing landed since the cursor => the current TreeState IS the
      // at-cursor state and the resume check is decidable now; otherwise the
      // post-apply head assert in ingest() completes it.
      if (at.nextLeafIndex === this.tree.nextLeafIndex() && at.root !== this.tree.root()) {
        throw new Error(
          `SolanaIndexer.boot: rebuilt root ${this.tree.root()} != TreeState root ${at.root} at the cursor`,
        );
      }
      console.log(
        `postgres backend (solana): resume after ${this.cursorSignature} (slot=${this.store.lastBlock} root=${this.tree.root()} nextLeafIndex=${this.tree.nextLeafIndex()})`,
      );
    } else {
      console.log("postgres backend (solana): fresh ingest from the pool's first signature (no cursor)");
    }
    this.booted = true;
  }

  /**
   * One replay pass: fetch the signature gap, apply it (every op already
   * asserted against its own event root), persist rows + both cursor halves
   * atomically, THEN compare heads the way boot does. Persist-first matters:
   * a tx landing between txsSince() and the account read makes TreeState run
   * AHEAD of the applied gap — a benign next-poll condition, not a failure —
   * and a head check placed before persist would throw on it, never advance
   * the cursor, and livelock the poll on a busy chain. Root equality is only
   * decidable when TreeState.nextLeafIndex matches the mirror (a normal RPC
   * cannot serve historical account state); a chain BEHIND the mirror is
   * still fatal (wrong cluster or database). The inherited pollOnce drives
   * this exactly as on the EVM backend (its fromBlock argument is
   * meaningless here and ignored — the signature cursor owns the resume
   * point).
   */
  override async ingest(): Promise<void> {
    await this.boot();
    const txs = await this.io.txsSince(this.cursorSignature);
    this.applyLedgerTxs(txs);
    if (txs.length > 0) {
      const last = txs[txs.length - 1];
      await this.persistSolana(last.slot, last.signature);
    }
    const at = await this.io.treeHead();
    if (at.nextLeafIndex < this.tree.nextLeafIndex()) {
      throw new Error(
        `solana ingest: chain nextLeafIndex ${at.nextLeafIndex} is BEHIND the mirror ${this.tree.nextLeafIndex()} — wrong cluster or database`,
      );
    }
    if (at.nextLeafIndex === this.tree.nextLeafIndex() && this.tree.root() !== at.root) {
      throw new Error(`solana ingest: mirror root ${this.tree.root()} != TreeState root ${at.root} at leaf count ${at.nextLeafIndex}`);
    }
  }

  /**
   * The pure application layer (the applyLogs double): decode every pool
   * instruction (top-level + inner — the dispatch rule is program id +
   * discriminator, SOLR §3.2.2), pair each op with its self-CPI event FIFO
   * per tx, and drive the shared read model. Replay-idempotent through the
   * same guards as the EVM path (tree frontier skip + store first-sight
   * dedup + registry idempotency).
   */
  applyLedgerTxs(txs: SolanaLedgerTx[]): void {
    for (const tx of txs) {
      const ixs = programInstructionsOf(tx, this.solanaProgramId);
      const ops: { op: SolanaOpIx; ordinal: number }[] = [];
      const events: SolanaEventAnchor[] = [];
      for (const ix of ixs) {
        const disc = parseInt(ix.data.slice(2, 4), 16);
        if (disc === EVENT_DISCRIMINATOR) {
          events.push(decodeEvent(ix.data));
        } else {
          const op = decodeOp(ix.data, ix.accounts);
          if (op !== null) ops.push({ op, ordinal: ix.ordinal });
        }
      }
      // Ops and events pair FIFO: the program emits exactly one event at the
      // tail of every op, so within a tx the i-th op's event is the i-th
      // event — an imbalance means a forged/truncated record, never ours.
      if (ops.length !== events.length) {
        throw new Error(`solana ingest: tx ${tx.signature} has ${ops.length} ops but ${events.length} events`);
      }
      for (const [i, { op, ordinal }] of ops.entries()) this.applyOne(tx, op, events[i], ordinal);
    }
  }

  private applyOne(tx: SolanaLedgerTx, op: SolanaOpIx, ev: SolanaEventAnchor, ordinal: number): void {
    if (ev.family !== op.family) {
      throw new Error(`solana ingest: op ${op.kind} paired with family-${ev.family} event in tx ${tx.signature}`);
    }

    if (op.kind === "disburse") {
      if (ev.shape !== "disburse") throw new Error(`solana ingest: disburse op with per-op event in tx ${tx.signature}`);
      // The instruction publics vs the event anchor — the same cross-check
      // posture as the EVM OpApplied correlation: a divergence is a broken
      // record, not a judgement call.
      if (
        ev.subtreeRoot !== op.subtreeRoot ||
        ev.disclosureHash !== op.disclosureHash ||
        ev.kemBinding !== op.kemBinding ||
        ev.nullifier !== op.nullifier
      ) {
        throw new Error(`solana ingest: disburse event anchor disagrees with instruction publics in tx ${tx.signature}`);
      }
      // Rotation tripwire: the disburse event is the ONE place ledger data
      // carries a real arbiter epoch on this rail. Enterprise transfer feed
      // entries below assume the genesis pin (op events omit the field), so
      // the moment a batch disproves the pin, ingest must stop rather than
      // keep writing silently-wrong transfer epochs (issue #44).
      if (ev.epoch !== ARBITER_EPOCH_GENESIS) {
        throw new Error(
          `solana ingest: batch at leaf ${ev.startLeafIndex} records arbiter epoch ${ev.epoch}; this backend pins the genesis epoch ` +
            "(op events carry no epoch field) — plumb the epoch into the op events or this projection before ingesting past a rotation",
        );
      }
      this.tree.applyAttach(ev.startLeafIndex, ev.subtreeRoot, ev.resultingRoot);
      const verdict = this.disclosures.recordBatch(
        {
          startLeafIndex: ev.startLeafIndex,
          txHash: tx.signature,
          disclosureHash: ev.disclosureHash,
          kemBinding: ev.kemBinding,
          epoch: ev.epoch,
          recordedAt: tx.blockTime,
        },
        this.batchSize,
      );
      const entry = this.store.addEvent({
        txHash: tx.signature, blockNumber: tx.slot, logIndex: ordinal,
        kind: "disburse", epoch: ev.epoch,
        ecdhPublicKey: [dec(op.ecdhPublicKey[0]), dec(op.ecdhPublicKey[1])],
        encryptionNonce: dec(op.encryptionNonce),
        // The bytes are institution-served, not ledger data (SOLR §3.3.2):
        // the entry carries the verdict and the anchor, /disclosure carries
        // the blob.
        slices: [], ciphertext: [],
        disclosure: verdict ?? undefined,
        batchId: ev.startLeafIndex,
        disburseAnchor: {
          disclosureHash: dec(ev.disclosureHash),
          kemBinding: dec(ev.kemBinding),
          epoch: ev.epoch,
          recordedAt: tx.blockTime,
        },
      });
      if (entry) this.store.addNullifiers([ev.nullifier]);
      return;
    }

    if (ev.shape !== "op") {
      throw new Error(`solana ingest: ${op.kind} paired with a disburse event in tx ${tx.signature}`);
    }
    const leaves = ((): bigint[] => {
      switch (op.kind) {
        case "withdrawPriv":
        case "withdraw":
          return [op.changeCommitment];
        default:
          return [...op.outputCommitments];
      }
    })();
    if (ev.leafCount !== leaves.length) {
      throw new Error(`solana ingest: ${op.kind} event leafCount ${ev.leafCount} != ${leaves.length} in tx ${tx.signature}`);
    }
    const opNfs = ("nullifiers" in op ? op.nullifiers : []).filter((x) => x !== 0n);
    if (opNfs.length !== ev.nullifiers.length || opNfs.some((x, i) => x !== ev.nullifiers[i])) {
      throw new Error(`solana ingest: ${op.kind} nullifier run disagrees with its event in tx ${tx.signature}`);
    }
    const start = ev.startLeafIndex;
    this.tree.applyOpAppend(start, leaves, ev.resultingRoot);

    const base = { txHash: tx.signature, blockNumber: tx.slot, logIndex: ordinal };
    const ecdh: [string, string] = [dec(op.ecdhPublicKey[0]), dec(op.ecdhPublicKey[1])];
    const nonce = dec(op.encryptionNonce);
    const announcementOf = (stealth: StealthTail, recipient: string | null) =>
      isStealthAnnouncement(stealth.ephemeralPub)
        ? { recipient: recipient ?? "0x" + "0".repeat(64), ephemeralPub: stealth.ephemeralPub, viewTag: stealth.viewTag }
        : undefined;

    const entry = ((): FeedEntry | null => {
      switch (op.kind) {
        case "depositPriv":
        case "transferPriv":
        case "transfer10x2Priv":
          return this.store.addEvent({
            ...base, kind: op.kind, epoch: null,
            ecdhPublicKey: ecdh, encryptionNonce: nonce,
            slices: [
              { offset: 0, elts: 4, leafIndex: start },
              { offset: 4, elts: 4, leafIndex: start + 1 },
            ],
            ciphertext: op.cts.map(dec),
            viewTags: op.viewTags.map(dec),
            kemCiphertexts: op.kemCiphertexts,
          });
        case "withdrawPriv":
          return this.store.addEvent({
            ...base, kind: "withdrawPriv", epoch: null,
            ecdhPublicKey: ecdh, encryptionNonce: nonce,
            slices: [{ offset: 0, elts: 4, leafIndex: start }],
            ciphertext: op.cts.map(dec),
            viewTags: op.viewTags.map(dec),
            kemCiphertexts: op.kemCiphertexts,
            announcement: announcementOf(op.stealth, op.recipientTokenAccount),
          });
        case "deposit":
          // EVM parity: enterprise envelope bytes never join the PUBLIC feed
          // entry for deposit/withdraw (the arbiter ledger reads them
          // separately) — bare entries, byte-identical shape across rails.
          return this.store.addEvent({
            ...base, kind: "deposit", epoch: null,
            ecdhPublicKey: null, encryptionNonce: null, slices: [], ciphertext: [],
          });
        case "withdraw":
          return this.store.addEvent({
            ...base, kind: "withdraw", epoch: null,
            ecdhPublicKey: null, encryptionNonce: null, slices: [], ciphertext: [],
            announcement: announcementOf(op.stealth, op.recipientTokenAccount),
          });
        case "transfer": {
          const slices: Slice[] = [
            { offset: 0, elts: 4, leafIndex: start },
            { offset: 4, elts: 4, leafIndex: start + 1 },
            { offset: 8, elts: op.authorityCt.length, leafIndex: null },
          ];
          // EVM parity gap, pinned on purpose: Transferred events carry the
          // contract's epoch, but the Solana op event omits the field and
          // rotation is not yet an instruction on this rail (state.rs
          // ARBITER_EPOCH_GENESIS, SOLR §3.3.1). The disburse branch's
          // tripwire above fails ingest loudly the moment ledger data
          // disproves this pin.
          return this.store.addEvent({
            ...base, kind: "transfer", epoch: ARBITER_EPOCH_GENESIS,
            ecdhPublicKey: ecdh, encryptionNonce: nonce,
            slices, ciphertext: [...op.receiverCts, ...op.authorityCt].map(dec),
          });
        }
        case "transfer10x2": {
          const slices: Slice[] = [
            { offset: 0, elts: 4, leafIndex: start },
            { offset: 4, elts: 4, leafIndex: start + 1 },
            { offset: 8, elts: op.authorityCt.length, leafIndex: null },
          ];
          return this.store.addEvent({
            ...base, kind: "transfer10x2", epoch: ARBITER_EPOCH_GENESIS,
            ecdhPublicKey: ecdh, encryptionNonce: nonce,
            slices, ciphertext: [...op.receiverCts, ...op.authorityCt].map(dec),
          });
        }
      }
    })();
    if (entry && opNfs.length > 0) this.store.addNullifiers(opNfs);
  }

  /**
   * The atomic persist (EVM `persist` discipline): rows + the slot cursor +
   * the signature cursor in ONE transaction, buffers dropped only after
   * COMMIT — a crash retries the same signature gap verbatim.
   */
  private async persistSolana(slot: number, signature: string): Promise<void> {
    const client = await this.pgPool!.connect();
    try {
      await client.query("BEGIN");
      await this.store.flushInto!(client);
      await this.store.persistCursorInto!(client, slot);
      await client.query(
        `INSERT INTO solana_cursor (id, signature) VALUES (1, $1)
         ON CONFLICT (id) DO UPDATE SET signature = EXCLUDED.signature`,
        [signature],
      );
      await client.query("COMMIT");
    } catch (e) {
      try {
        await client.query("ROLLBACK");
      } catch {
        // dead connection: the original error stands
      }
      throw e;
    } finally {
      client.release();
    }
    this.store.commitFlush?.();
    this.store.lastBlock = slot;
    this.cursorSignature = signature;
  }
}
