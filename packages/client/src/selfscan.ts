// The consumer self-scan discovery engine (OPMOD §3.6, .dev/op-module-design.md):
// balance and activity from the PUBLIC /events feed with only the wallet's own
// keys — no arbiter indexer, no /notes, no read-auth. The normative pipeline,
// implemented exactly:
//
//   per event, per output slice:
//     viewTag prefilter    viewTag_i == Poseidon(3)([TAG_VIEWTAG, viewPriv·ecdhPublicKey]) & 0xff
//                          — a tag miss skips ALL expensive work (~256× filter, OPMOD §3.2);
//     Decaps + open        openConsumerOutput(ct_i, kemCiphertexts[i]) at nonce + i (§3.5);
//     leaf-match           accept iff commitment(value, salt, spendPub) equals the
//                          on-chain leaf — the MAC substitute, the same rule as
//                          balance.ts trialDecryptEvents;
//     spent check          nullifier(value, salt, spendPriv) ∈ GET /nullifiers.
//
// Where the on-chain leaf comes from splits by op shape. A consumer DISBURSE
// publishes its whole commitment run in the feed entry (`outputCommitments`,
// which the indexer refuses to serve unless it folds to the SubtreeAppended
// subtreeRoot — OPMOD §4.4), so a batch note leaf-matches inline and its
// leafIndex is `batchId + outputIndex`.
// A single-append op's feed entry carries the leafIndex but NOT the leaf value,
// so the pure pass emits those decrypts as CANDIDATES and the shell confirms
// each against the indexer's auth-free `GET /path/{leafIndex}`: folding the
// candidate commitment up the served siblings must reproduce the served root
// (collision resistance makes that fold equality exactly leaf equality). A
// wrong-key or junk-KEM decrypt yields garbage whose fold cannot match — the
// S3.3 self-sabotage class surfaces as a dropped candidate, never a throw.
//
// KEM transport states (OPMOD §5): a consumer disburse whose kem cts are not
// yet assembled ("pending"/"withheld"/"accepted-unassembled") or whose
// disclosure run is not full CANNOT be scanned yet — it surfaces as a
// PendingDiscovery ("discovery pending"), never as silently empty, and the
// shell re-reads exactly those seqs on every later scan until they resolve.
//
// Enterprise coexistence: the same wallet may also hold enterprise-envelope-era
// notes (receiver cts ECDH-encrypted to the SPEND key, no viewTags). Events
// without consumer view material go through the deferred-acceptance twin of
// balance.ts trialDecryptEvents — same slice grammar, same two-nonce rule
// (event nonce + the §11-8 v1.1 per-output offset), same leaf-match, only the
// acceptance is deferred to the shared path-fold confirm. trialDecryptEvents
// itself is untouched (its Map-fed acceptance is the recovery-tooling shape).
//
// Pure core + thin fetch shell, mirroring the balance.ts pattern: everything
// above the SelfScanIo seam is synchronous and PRNG-free, so the headless suite
// (test/selfscan.test.ts) drives recorded feeds through the whole engine.

import { hexToBytes } from "viem";
import {
  commitment,
  nullifier,
  poseidonDecrypt,
  ecdhSharedSecret,
} from "@bongtu/core/note";
import { consumerViewTag, openConsumerOutput, CONSUMER_CT_LEN } from "@bongtu/core/consumer";
import { foldToRoot } from "@bongtu/core/imt";
import { unpackPubkey } from "@bongtu/core/pubkey";
import {
  type EventKind,
  type FeedEvent,
  type Head,
  type HistoryItem,
  type KemTransport,
  type OwnerNote,
  type PathResult,
} from "@bongtu/client/indexerClient";
import type { ConsumerWalletIdentity, WalletIdentity } from "@bongtu/client/derive";

/** The event kinds the consumer pipeline scans (viewTags + kem transport). */
export const CONSUMER_EVENT_KINDS: ReadonlySet<EventKind> = new Set<EventKind>([
  "depositPriv",
  "transferPriv",
  "transfer10x2Priv",
  "withdrawPriv",
  "disbursePriv",
]);

/** Whether a derived identity carries the consumer view identity (viewPriv +
 *  kemDk) the §3.6 pipeline decrypts with. The signature derivation always
 *  produces it; enterprise-only identities (e.g. the sweeper's synthetic
 *  portal identity) do not, and cannot self-scan. */
export function isConsumerIdentity(id: WalletIdentity): id is ConsumerWalletIdentity {
  return id.viewKeypair !== undefined && id.kemKeypair !== undefined;
}

/** One note the scan discovered — a balance.ts DiscoveredNote plus where in the
 *  feed it came from (`seq`/`kind` key the activity derivation) and which
 *  scanner found it. */
export interface ScanNote {
  value: string;
  salt: string;
  leafIndex: number;
  commitment: string;
  nullifier: string;
  txHash: string;
  spent: boolean;
  seq: number;
  kind: EventKind;
  /** "consumer" = the §3.6 pipeline; "enterprise" = the spend-key trial-decrypt twin. */
  family: "consumer" | "enterprise";
}

/** A decrypted single-append note awaiting the external leaf confirmation (the
 *  feed carries its leafIndex but not the leaf value). Everything but `spent`. */
export type ScanCandidate = Omit<ScanNote, "spent">;

/** A feed entry that may hold this wallet's notes but cannot be scanned yet —
 *  surfaced as "discovery pending", never as silently empty. The shell re-reads
 *  these seqs each scan until they resolve. */
export interface PendingDiscovery {
  seq: number;
  txHash: string;
  batchId: number | null;
  /** the kem transport state (OPMOD §5); "disclosure-incomplete" when the
   *  §4.1 commitment run itself has not been served; "enterprise-batch-gated"
   *  when the wallet decrypted an enterprise DISBURSE-batch interior whose
   *  /path is 422-gated in public mode by design — this wallet may hold notes
   *  only an arbiter indexer can open. */
  status: KemTransport["status"] | "disclosure-incomplete" | "enterprise-batch-gated";
}

/** Filter-effectiveness counters: `decapsulations` counts the expensive work,
 *  and MUST equal `tagMatches` — a slice that fails the viewTag prefilter is
 *  never decapsulated or decrypted (a headless gate holds the two equal). */
export interface ScanStats {
  consumerSlices: number;
  tagMatches: number;
  decapsulations: number;
  enterpriseDecrypts: number;
}

/** One pure pass over a window of feed events. */
export interface ScanPass {
  /** batch notes, leaf-matched inline against the published commitment run. */
  accepted: ScanCandidate[];
  /** single-append decrypts awaiting the shell's path-fold confirmation. */
  candidates: ScanCandidate[];
  pending: PendingDiscovery[];
  stats: ScanStats;
  /** the highest seq in the window (-1 for an empty window). */
  cursor: number;
}

const draftOf = (
  ev: FeedEvent,
  family: ScanNote["family"],
  leafIndex: number,
  value: bigint,
  salt: bigint,
  c: bigint,
  nf: bigint,
): ScanCandidate => ({
  value: value.toString(),
  salt: salt.toString(),
  leafIndex,
  commitment: c.toString(),
  nullifier: nf.toString(),
  txHash: ev.txHash,
  seq: ev.seq,
  kind: ev.kind,
  family,
});

/**
 * The pure §3.6 pass: viewTag prefilter → Decaps + open at nonce+i →
 * leaf-match (inline for batches, deferred for single appends), plus the
 * enterprise trial-decrypt twin for events without consumer view material.
 * PRNG-free and synchronous — the whole discovery decision surface gates
 * headlessly on recorded feeds.
 */
export function scanEventsPass(events: FeedEvent[], identity: ConsumerWalletIdentity): ScanPass {
  const accepted: ScanCandidate[] = [];
  const candidates: ScanCandidate[] = [];
  const pending: PendingDiscovery[] = [];
  const stats: ScanStats = { consumerSlices: 0, tagMatches: 0, decapsulations: 0, enterpriseDecrypts: 0 };
  const viewPriv = identity.viewKeypair.formattedPrivateKey;
  const kemDk = identity.kemKeypair.dk;
  const spendPub = identity.keypair.publicKey;
  const spendPriv = identity.keypair.formattedPrivateKey;

  for (const ev of events) {
    // The real indexer serves a consumer disburse whose §4.1 disclosure run is
    // not yet full WITHOUT viewTags/outputCommitments (ingest adds the consumer
    // fields only when the run is complete) — a shape that matches NEITHER scan
    // branch below, so without this gate it would be silently skipped and its
    // notes permanently lost once the cursor passes. Surface it as pending
    // (§3.6: a batch that MIGHT hold this wallet's notes is PendingDiscovery,
    // never silently empty); the shell re-reads the seq each scan until the
    // full run arrives.
    if (
      ev.kind === "disbursePriv" &&
      ev.batchId != null &&
      (ev.viewTags === undefined || ev.outputCommitments === undefined || ev.slices.length === 0)
    ) {
      pending.push({ seq: ev.seq, txHash: ev.txHash, batchId: ev.batchId, status: "disclosure-incomplete" });
      continue;
    }
    if (!ev.ecdhPublicKey || ev.encryptionNonce == null) continue; // no receiver key material
    const eph: [bigint, bigint] = [BigInt(ev.ecdhPublicKey[0]), BigInt(ev.ecdhPublicKey[1])];
    const nonce = BigInt(ev.encryptionNonce);

    if (CONSUMER_EVENT_KINDS.has(ev.kind) && ev.viewTags !== undefined) {
      // ---- the consumer §3.6 pipeline -------------------------------------
      // One ECDH per event: S_i differs per RECIPIENT, and this wallet's view
      // key is fixed, so its shared point (and tag) is the same for every slice.
      const shared = ecdhSharedSecret(viewPriv, eph);
      const myTag = consumerViewTag(shared);
      const tags = ev.viewTags;

      // Transport gates for a batch (OPMOD §5): without the full disclosure run
      // there are no slices/tags/commitments to scan; without assembled kem cts
      // the hybrid key cannot be derived. Either way the batch MIGHT hold this
      // wallet's notes — surface it as pending. When the tags ARE available,
      // a batch with no matching tag is provably (up to 2^-8) not ours, so it
      // is skipped rather than held pending forever.
      const kemCts = ((): string[] | null => {
        if (ev.kind !== "disbursePriv") return ev.kemCiphertexts ?? null;
        if (ev.outputCommitments === undefined || ev.slices.length === 0) {
          pending.push({ seq: ev.seq, txHash: ev.txHash, batchId: ev.batchId ?? null, status: "disclosure-incomplete" });
          return null;
        }
        if (ev.kem === undefined || ev.kem.status !== "complete" || ev.kem.kemCiphertexts === undefined) {
          if (tags.some((t) => BigInt(t) === myTag)) {
            pending.push({ seq: ev.seq, txHash: ev.txHash, batchId: ev.batchId ?? null, status: ev.kem?.status ?? "pending" });
          }
          return null;
        }
        return ev.kem.kemCiphertexts;
      })();
      if (kemCts === null) continue;

      for (const slice of ev.slices) {
        if (slice.leafIndex == null || slice.elts !== CONSUMER_CT_LEN) continue;
        const outIndex = slice.offset / CONSUMER_CT_LEN; // slice order == output order (ingest)
        const tag = tags[outIndex];
        stats.consumerSlices += 1;
        // The prefilter: a tag miss ends this slice's work here — no Decaps,
        // no sponge decrypt (OPMOD §3.2; decapsulations === tagMatches).
        if (tag === undefined || BigInt(tag) !== myTag) continue;
        stats.tagMatches += 1;
        const kemHex = kemCts[outIndex];
        if (kemHex === undefined) continue; // malformed transport: nothing to Decaps
        stats.decapsulations += 1;
        const opened = openConsumerOutput({
          cipherText: ev.ciphertext.slice(slice.offset, slice.offset + slice.elts).map(BigInt),
          ecdhPublicKey: eph,
          viewPriv,
          kemDk,
          kemCiphertext: hexToBytes(kemHex as `0x${string}`),
          encryptionNonce: nonce,
          index: outIndex, // the §3.5 nonce + i rule, uniform across all five
        });
        const c = commitment(opened.value, opened.salt, spendPub);
        const nf = nullifier(opened.value, opened.salt, spendPriv);
        const draft = draftOf(ev, "consumer", slice.leafIndex, opened.value, opened.salt, c, nf);
        if (ev.kind === "disbursePriv") {
          // Batch leaf-match, inline: the feed's commitment run IS the on-chain
          // leaf set (the indexer only fills/serves a run that folds to the
          // SubtreeAppended subtreeRoot, §4.4), and slice.leafIndex ==
          // batchId + outIndex maps the note to its leaf.
          const leaf = ev.outputCommitments?.[outIndex];
          if (leaf !== undefined && BigInt(leaf) === c) accepted.push(draft);
          // mismatch = a 2^-8 tag false positive or garbage — dropped, exactly
          // the trialDecryptEvents acceptance rule.
        } else {
          candidates.push(draft); // leaf value not in the feed: confirm via /path
        }
      }
    } else if (!CONSUMER_EVENT_KINDS.has(ev.kind)) {
      // ---- enterprise coexistence: the deferred-acceptance twin of
      // ---- balance.ts trialDecryptEvents ---------------------------------
      const shared = ecdhSharedSecret(spendPriv, eph);
      for (const slice of ev.slices) {
        if (slice.leafIndex == null || slice.elts !== 4) continue; // only per-recipient leaf envelopes
        const sliceLeaf = slice.leafIndex;
        const ct = ev.ciphertext.slice(slice.offset, slice.offset + slice.elts).map(BigInt);
        if (ct.length !== 4) continue;
        const ctIndex = BigInt(slice.offset / 4);
        // Two nonces, same as trialDecryptEvents: the event nonce (pre-U-X3
        // history + disburse) and nonce + ctIndex (the per-output offset). The
        // leaf-match confirm rejects every wrong-nonce garbage decrypt.
        const nonces = ctIndex === 0n ? [nonce] : [nonce, nonce + ctIndex];
        for (const tryNonce of nonces) {
          const decrypted = ((): [bigint, bigint] | null => {
            try {
              const [value, salt] = poseidonDecrypt(ct, shared, tryNonce, 2);
              return [value, salt];
            } catch {
              return null;
            }
          })();
          if (decrypted === null) continue;
          stats.enterpriseDecrypts += 1;
          const [value, salt] = decrypted;
          const c = commitment(value, salt, spendPub);
          const nf = nullifier(value, salt, spendPriv);
          candidates.push(draftOf(ev, "enterprise", sliceLeaf, value, salt, c, nf));
        }
      }
    }
    // A consumer-kind event WITHOUT viewTags is not scannable (pre-consumer
    // indexer build) — nothing to do.
  }

  const cursor = events.reduce((m, e) => Math.max(m, e.seq), -1);
  return { accepted, candidates, pending, stats, cursor };
}

/** The single-append leaf-match, against a served merkle path: folding the
 *  candidate commitment up the path's siblings must reproduce the path's root
 *  (foldToRoot's documented convention — pathIndices[j] IS bit j of leafIndex).
 *  Fold equality is leaf equality by collision resistance, so this IS the
 *  trialDecryptEvents acceptance, fed from the auth-free public /path. */
export function pathConfirmsLeaf(
  commitmentDec: string,
  path: Pick<PathResult, "siblings" | "root">,
  leafIndex: number,
): boolean {
  return foldToRoot(BigInt(commitmentDec), path.siblings.map(BigInt), leafIndex) === BigInt(path.root);
}

/** Merge newly discovered notes into the held set, dedup by commitment (a
 *  pending batch re-scan or an overlapping window re-discovers notes the state
 *  already holds — same note, same commitment). Spent flags are recomputed by
 *  the caller against the full nullifier set. */
export function mergeNotes(prev: ScanNote[], found: ScanCandidate[]): ScanNote[] {
  const seen = new Set(prev.map((n) => n.commitment));
  const fresh = found
    .filter((n) => {
      if (seen.has(n.commitment)) return false;
      seen.add(n.commitment);
      return true;
    })
    .map((n) => ({ ...n, spent: false }));
  return [...prev, ...fresh];
}

/** Recompute spent flags against the current public nullifier set. */
export function applySpent(notes: ScanNote[], spentNullifiers: ReadonlySet<string>): ScanNote[] {
  return notes.map((n) => ({ ...n, spent: spentNullifiers.has(n.nullifier) }));
}

// --- the resumable scan state (the cursor persistence contract) --------------

/** The persisted scan state. The CONTRACT (what the app layer stores, e.g. in
 *  localStorage keyed by the owner pubkey — wiring lives there, not here):
 *
 *    v                     codec version — any other value decodes to null
 *                          (a full rescan from the feed start, which is safe:
 *                          the feed is the source of truth);
 *    cursor                the last fully processed feed seq — the next scan
 *                          reads /events from here (seq > cursor);
 *    scannedNextLeafIndex  the /head.nextLeafIndex at scan time — the sync
 *                          indicator's freshness reference;
 *    notes                 every note discovered so far (resume must not lose
 *                          pre-cursor notes; spent flags refresh every scan);
 *    pending               unresolved batches, re-read each scan.
 *
 *  Resumability invariant (gated headlessly): scan(A..B) then scan(B..C)
 *  yields the same state as scan(A..C). NOTE the stored notes carry
 *  (value, salt) plaintexts — view-side material only (spending needs the bjj
 *  key, which NEVER persists), but a local reader of the store learns amounts. */
export interface SelfScanState {
  v: 1;
  cursor: number;
  scannedNextLeafIndex: number;
  notes: ScanNote[];
  pending: PendingDiscovery[];
}

export const EMPTY_SCAN_STATE: SelfScanState = {
  v: 1,
  cursor: -1,
  scannedNextLeafIndex: 0,
  notes: [],
  pending: [],
};

/** Serialize a scan state for the app layer's store. */
export function encodeScanState(state: SelfScanState): string {
  return JSON.stringify(state);
}

/** Defensive inverse: anything that is not a well-formed v1 state decodes to
 *  null (the caller starts a full rescan — always safe, the feed is total). */
export function decodeScanState(raw: string | null): SelfScanState | null {
  if (raw === null) return null;
  const parsed = ((): unknown => {
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  })();
  if (typeof parsed !== "object" || parsed === null) return null;
  const s = parsed as Record<string, unknown>;
  if (s.v !== 1 || typeof s.cursor !== "number" || typeof s.scannedNextLeafIndex !== "number") return null;
  if (!Array.isArray(s.notes) || !Array.isArray(s.pending)) return null;
  return {
    v: 1,
    cursor: s.cursor,
    scannedNextLeafIndex: s.scannedNextLeafIndex,
    notes: s.notes as ScanNote[],
    pending: s.pending as PendingDiscovery[],
  };
}

// --- the fetch shell ---------------------------------------------------------

/** The four public reads one scan needs — injectable so the whole shell gates
 *  headlessly on recorded data (the balance.ts pure-core + injected-IO pattern).
 *  The real IO is an `IndexerClient` (indexerClient.ts), which satisfies this
 *  STRUCTURALLY — no hand-built binding to drift; the interface stays for the
 *  headless suite's recorded fakes. */
export interface SelfScanIo {
  events(cursor: number, limit?: number): Promise<FeedEvent[]>;
  nullifiers(): Promise<string[]>;
  head(): Promise<Head>;
  path(leafIndex: number): Promise<PathResult>;
}

const dedupePending = (entries: PendingDiscovery[]): PendingDiscovery[] => {
  const seen = new Set<number>();
  return entries.filter((p) => {
    if (seen.has(p.seq)) return false;
    seen.add(p.seq);
    return true;
  });
};

/** Bounds for one runSelfScan. */
export interface SelfScanRunOptions {
  /** feed pages one run may drain before stamping only what it covered
   *  (default 40 — ~200k events at the server's 5000-entry page). */
  maxPages?: number;
}

/**
 * ONE incremental scan: read /head (the freshness reference), re-read every
 * pending seq, DRAIN the feed past the cursor — one /events page is capped
 * (~5000), so an initial sync loops pages until the cursor stops advancing,
 * bounded by `maxPages` — run the pure pass, confirm single-append candidates
 * via the auth-free /path fold, refresh spent flags from /nullifiers, and fold
 * everything into the next resumable state.
 *
 * The freshness stamp is honest about coverage: a run that exhausted the feed
 * stamps the /head read at scan start (everything it reported is scanned); a
 * run that hit the page cap stamps only the highest leaf its window actually
 * covered — NEVER the head, or the sync dot would read "synced" while the
 * balance is understated by every unread page.
 *
 * A pending seq whose re-read fails (or comes back empty) keeps its previous
 * pending entry — a transient feed hiccup must not silently retire a batch the
 * wallet has not scanned. A candidate whose /path read fails is DROPPED for
 * this scan, not accepted: unconfirmed is not discovered (it reappears only if
 * a later window re-serves the event — which pending re-reads do for batches;
 * single-append ops always land in one window, so a drop here surfaces on the
 * next full rescan). The one exception is the enterprise DISBURSE-batch
 * interior, whose /path is 422-gated in public mode BY DESIGN (only the
 * arbiter opens batch slots): that candidate surfaces as an
 * "enterprise-batch-gated" pending entry — this wallet may hold notes only an
 * arbiter indexer can open — never a silent drop.
 */
export async function runSelfScan(
  io: SelfScanIo,
  identity: ConsumerWalletIdentity,
  prev: SelfScanState = EMPTY_SCAN_STATE,
  opts: SelfScanRunOptions = {},
): Promise<SelfScanState> {
  const maxPages = opts.maxPages ?? 40;
  const head = await io.head();
  const drained = await (async (): Promise<{ events: FeedEvent[]; exhausted: boolean }> => {
    const acc: FeedEvent[] = [];
    const at = { cursor: prev.cursor };
    for (const _page of Array(maxPages).keys()) {
      const page = (await io.events(at.cursor)).filter((e) => e.seq > at.cursor);
      const next = page.reduce((m, e) => Math.max(m, e.seq), at.cursor);
      if (next === at.cursor) return { events: acc, exhausted: true }; // cursor stalled: nothing left
      acc.push(...page);
      at.cursor = next;
    }
    return { events: acc, exhausted: false }; // capped mid-feed
  })();
  const reread = await Promise.all(
    prev.pending.map(async (p): Promise<FeedEvent | null> => {
      try {
        return (await io.events(p.seq - 1, 1)).find((e) => e.seq === p.seq) ?? null;
      } catch {
        return null;
      }
    }),
  );
  const kept = prev.pending.filter((_, i) => reread[i] === null);
  const window = [...reread.filter((e): e is FeedEvent => e !== null), ...drained.events];

  const pass = scanEventsPass(window, identity);

  const pathCache = new Map<number, PathResult | null>();
  const confirmed: ScanCandidate[] = [];
  const gated: PendingDiscovery[] = [];
  for (const cand of pass.candidates) {
    const cached = pathCache.get(cand.leafIndex);
    const path = cached !== undefined ? cached : await io.path(cand.leafIndex).catch(() => null);
    pathCache.set(cand.leafIndex, path);
    if (path !== null && pathConfirmsLeaf(cand.commitment, path, cand.leafIndex)) {
      confirmed.push(cand);
    } else if (path === null && cand.family === "enterprise" && cand.kind === "disburse") {
      gated.push({ seq: cand.seq, txHash: cand.txHash, batchId: null, status: "enterprise-batch-gated" });
    }
  }

  // The coverage stamp (doc comment above): the /head taken at scan start when
  // the drain exhausted the feed; the scanned window's own highest appended
  // leaf when capped. Monotonic either way — a rescan never un-covers.
  const covered = drained.exhausted
    ? Math.max(prev.scannedNextLeafIndex, head.nextLeafIndex)
    : drained.events.reduce(
        (m, e) => e.slices.reduce((mm, sl) => (sl.leafIndex == null ? mm : Math.max(mm, sl.leafIndex + 1)), m),
        prev.scannedNextLeafIndex,
      );

  const spent = new Set(await io.nullifiers());
  return {
    v: 1,
    cursor: Math.max(prev.cursor, pass.cursor),
    scannedNextLeafIndex: covered,
    notes: applySpent(mergeNotes(prev.notes, [...pass.accepted, ...confirmed]), spent),
    pending: dedupePending([...kept, ...pass.pending, ...gated]),
  };
}

// --- balance + activity derivation ------------------------------------------

/** What one op event means for THIS wallet in the activity feed. From the
 *  public feed alone the wallet can attest exactly what it decrypted: notes it
 *  received. A depositPriv holding its note is a mint to it ("deposit"); a
 *  withdrawPriv holding its note means the wallet itself withdrew (only the
 *  spender's view key gets the change ct) — rendered "withdraw" with the
 *  CHANGE value, the one amount discovery can see; everything else is
 *  "received" (a transfer's change note also reads "received" — the honest
 *  no-auditor view: the feed does not say which spend was ours). */
const ACTIVITY_KIND: Partial<Record<EventKind, HistoryItem["kind"]>> = {
  depositPriv: "deposit",
  withdrawPriv: "withdraw",
};

/** Activity items from the op events the discovered notes came from: one row
 *  per feed event holding this wallet's notes, amount = the sum of those
 *  notes' values, newest-first (seq desc). `blockTimestamp` is ABSENT — the
 *  public feed carries block numbers, not timestamps; the display edge
 *  suppresses the time element rather than render an epoch date. */
export function deriveScanActivity(notes: ScanNote[]): HistoryItem[] {
  const bySeq = new Map<number, { kind: HistoryItem["kind"]; amount: bigint; txHash: string }>();
  for (const n of notes) {
    const row = bySeq.get(n.seq) ?? {
      kind: ACTIVITY_KIND[n.kind] ?? "received",
      amount: 0n,
      txHash: n.txHash,
    };
    row.amount += BigInt(n.value);
    bySeq.set(n.seq, row);
  }
  return [...bySeq.entries()]
    .sort(([a], [b]) => b - a)
    .map(([seq, row]) => ({
      kind: row.kind,
      counterparty: null,
      amount: row.amount.toString(),
      txHash: row.txHash,
      seq,
    }));
}

/** The self-scan read in the arbiter snapshot's shape ({notes, history,
 *  historyNextBefore}) so the app's whole snapshot plumbing — sumUnspent,
 *  snapshotChanged, applySnapshot — is byte-shared between the two discovery
 *  modes. The feed is not paged (`historyNextBefore: null` is the truth: the
 *  scan holds the whole history it can ever derive). */
export function selfScanSnapshot(
  state: SelfScanState,
  ownerCompressed: string,
): { notes: OwnerNote[]; history: HistoryItem[]; historyNextBefore: null } {
  const owner = unpackPubkey(ownerCompressed);
  const ownerDec: [string, string] = [owner[0].toString(), owner[1].toString()];
  return {
    notes: state.notes.map((n) => ({
      owner: ownerDec,
      value: n.value,
      salt: n.salt,
      leafIndex: n.leafIndex,
      commitment: n.commitment,
      txHash: n.txHash,
      spent: n.spent,
    })),
    history: deriveScanActivity(state.notes),
    historyNextBefore: null,
  };
}

/** The calm strip a scan with unresolved batches shows: funds may exist that
 *  cannot be decrypted yet (kem chunks in flight) — pending, not empty. */
export const SELF_SCAN_PENDING_NOTICE =
  "Some incoming payments are still being delivered. They'll appear once delivery completes.";

/** Shown when the wallet is locked: scanning needs the view keys, so the data
 *  on screen is the last completed scan. */
export const SELF_SCAN_LOCKED_NOTICE =
  "Wallet locked. Showing your last scan. Unlock to check for new payments.";
