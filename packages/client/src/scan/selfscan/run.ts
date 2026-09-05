// scan/selfscan/run.ts — the resumable scan state codec, the SelfScanIo seam and the
// runSelfScan shell + snapshot/activity derivations (split from selfscan.ts).
import { unpackPubkey } from "@bongtu/core/pubkey";
import {
  type EventKind,
  type FeedEvent,
  type Head,
  type HistoryItem,
  type OwnerNote,
  type PathResult,
} from "@bongtu/core/indexerApi";
import type { ConsumerWalletIdentity } from "@bongtu/client/derive";
import {
  applySpent,
  mergeNotes,
  pathConfirmsLeaf,
  scanEventsPass,
  type PendingDiscovery,
  type ScanCandidate,
  type ScanNote,
} from "./engine.js";
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
 *  The real IO is an `IndexerClient` (@bongtu/core/indexerApi), which satisfies this
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
