// Institution-served disclosure blobs (SOLR §3.3.2). On the Solana rail the
// enterprise disburse persists only the BINDING on-chain (the DisburseBatch
// disclosureHash); the 2054-element blob is served from institution storage.
// This registry is the indexer's view of that contract:
//   - every ingested disburse records its anchor tuple here;
//   - blobs arrive from the operator's DISCLOSURE_DIR ({start}.json, one
//     array of 32-byte hex/decimal elements per batch) — checked at ingest
//     and re-checked at every boot (the per-batch boot invariant:
//     served-blob-refolds-to-DisburseBatch.disclosureHash);
//   - GET /disclosure/{start} serves the held blob so ANY party can refold
//     it against chain state — verification needs no key and no trust, only
//     availability;
//   - the alarm mapping is the existing disclosure class: a served blob that
//     fails the refold is "mismatch" (canonical-form aliases rejected BEFORE
//     folding — verifyServedDisclosure); a blob the institution has not
//     served past the grace window is "withheld". Within grace, absence is
//     an operational state, not an alarm (nothing chain-provable was
//     violated yet).
//
// The registry lives on EVERY Indexer (EVM included) but only the Solana
// backend records batches into it — on EVM the disburse bytes are consensus-
// published and the existing verifyDisclosure path owns them, so the registry
// stays empty and the routes it feeds serve identical bytes across backends.

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { verifyServedDisclosure, type DisclosureResult } from "../disclosure.js";
import { emitAlarm, emitDisclosureAlarm } from "../alarms.js";
import type { FeedEntry } from "../store.js";

/** THE grace-window comparison (one predicate, both consumers: statusOf and
 *  alarms): a batch whose blob has been unserved for MORE than graceSeconds
 *  is past grace — an institutional-SLA breach; at exactly graceSeconds it is
 *  still operational, so the two projections share one boundary. */
export function pastGrace(recordedAt: number, nowSeconds: number, graceSeconds: number): boolean {
  return nowSeconds - recordedAt > graceSeconds;
}

/** The chain-committed per-batch tuple (DisburseBatch PDA == the disburse
 *  self-CPI event, SOLR §3.3.1). */
export interface DisburseBatchAnchor {
  startLeafIndex: number;
  txHash: string;
  disclosureHash: bigint;
  kemBinding: bigint;
  epoch: number;
  /** unix seconds of the batch's ledger blockTime — the withheld grace clock. */
  recordedAt: number;
}

interface BatchState {
  anchor: DisburseBatchAnchor;
  elements: bigint[] | null;
  result: DisclosureResult | null;
  /** true only while the batch's persisted feed-entry verdict AGREES with the
   *  registry's own recompute — the store's alarm channel owns it then, and
   *  alarms() must not double-report it. A boot recompute that disagrees
   *  (blob swapped after ingest) clears this so the registry owns the alarm. */
  baked: boolean;
}

export class DisclosureRegistry {
  private readonly batches = new Map<number, BatchState>();
  /** Mutable like Indexer.kemGraceSeconds: the conformance suite flips it to
   *  project the same unserved batch as withheld deterministically. */
  graceSeconds: number;

  constructor(
    private readonly dir: string | null,
    graceSeconds: number,
  ) {
    this.graceSeconds = graceSeconds;
  }

  /**
   * Record one ingested batch and immediately attempt the dir-served blob.
   * Returns the verdict when a blob was held (the caller bakes it into the
   * feed entry, whose store path owns the alarm), null when no blob is held
   * yet (the registry then owns the withheld clock and any late verdict).
   * Idempotent on startLeafIndex — a replayed range re-records nothing.
   *
   * The boot path passes `persistedStatus` (the verdict the feed entry was
   * persisted with, if any): when the refold AGREES the store's replayed
   * entry stays the alarm owner (`baked`); when it DISAGREES — a blob swapped
   * AFTER the persisted verdict was computed — the registry owns the alarm
   * (baked stays false so alarms() reports the fresh verdict, statusOf()
   * projects it onto /events, and GET /disclosure refuses a clean 200).
   */
  recordBatch(
    anchor: DisburseBatchAnchor,
    batchSize: number,
    opts: { boot?: { persistedStatus: DisclosureResult["status"] | undefined } } = {},
  ): DisclosureResult | null {
    const existing = this.batches.get(anchor.startLeafIndex);
    if (existing) return null;
    const state: BatchState = { anchor, elements: null, result: null, baked: false };
    this.batches.set(anchor.startLeafIndex, state);
    const elements = this.readDirBlob(anchor.startLeafIndex);
    if (elements === null) return null;
    const result = this.verify(state, elements, batchSize);
    if (opts.boot === undefined) {
      // Fresh ingest: the caller bakes the verdict into the feed entry.
      state.baked = true;
      return result;
    }
    if (opts.boot.persistedStatus === result.status) {
      state.baked = true;
    } else if (opts.boot.persistedStatus !== undefined) {
      emitAlarm(
        "verdict-conflict",
        `disclosure verdict CONFLICT: batch ${anchor.startLeafIndex} persisted "${opts.boot.persistedStatus}" but the held blob now refolds to "${result.status}" — the served bytes changed after ingest`,
      );
    }
    return null;
  }

  /** Hand the registry a blob directly (a late-served batch, or a test). The
   *  verdict stays registry-owned — it reaches /alarms via alarms(). */
  loadBlob(startLeafIndex: number, elements: bigint[], batchSize: number): DisclosureResult | null {
    const state = this.batches.get(startLeafIndex);
    if (!state || state.result !== null) return state?.result ?? null;
    return this.verify(state, elements, batchSize);
  }

  /** Re-attempt the dir for every blob-less batch — the boot half of the
   *  per-batch invariant (an institution dropping the file later must still
   *  surface a verdict, favorable or not). */
  checkDir(batchSize: number): void {
    for (const [start, state] of this.batches) {
      if (state.result !== null) continue;
      const elements = this.readDirBlob(start);
      if (elements !== null) this.verify(state, elements, batchSize);
    }
  }

  /** The chain-committed anchor for a recorded batch — what GET /disclosure
   *  echoes so a client can refold the served bytes without a second query. */
  anchorOf(startLeafIndex: number): DisburseBatchAnchor | undefined {
    return this.batches.get(startLeafIndex)?.anchor;
  }

  /** The held blob as 32-byte 0x-hex elements (the canonical refold wire), or
   *  null when the institution store has nothing for this batch. */
  blobOf(startLeafIndex: number): string[] | null {
    const state = this.batches.get(startLeafIndex);
    if (!state || state.elements === null) return null;
    return state.elements.map((x) => "0x" + x.toString(16).padStart(64, "0"));
  }

  /** The serve-time verdict projection for a batch's feed entry: a computed
   *  verdict wins; an unserved batch reads "withheld" only past grace. */
  statusOf(startLeafIndex: number, nowSeconds: number): DisclosureResult["status"] | undefined {
    const state = this.batches.get(startLeafIndex);
    if (!state) return undefined;
    if (state.result) return state.result.status;
    return pastGrace(state.anchor.recordedAt, nowSeconds, this.graceSeconds) ? "withheld" : undefined;
  }

  /**
   * The verdict-precedence rule, owned here: for an enterprise disburse feed
   * entry the registry's CURRENT verdict overrides the baked-at-ingest fact —
   * the baked verdict describes the bytes held at ingest, the registry's the
   * bytes held NOW, and after a post-ingest blob swap only the latter is
   * truthful. Registry silent (batch unknown to it — every EVM disburse — or
   * unserved within grace) => the baked verdict stands. Non-disburse kinds
   * never consult the registry: a consumer disbursePriv carries a batchId
   * too, but its bytes are consensus-published and only ever baked.
   */
  currentStatus(
    entry: { kind: FeedEntry["kind"]; batchId?: number; disclosure?: { status: DisclosureResult["status"] } },
    nowSeconds: number,
  ): DisclosureResult["status"] | undefined {
    const baked = entry.disclosure?.status;
    if (entry.kind !== "disburse" || entry.batchId === undefined) return baked;
    return this.statusOf(entry.batchId, nowSeconds) ?? baked;
  }

  /**
   * The registry's contribution to GET /alarms: every non-passing verdict the
   * store does NOT already carry (late-loaded blobs), plus a synthesized
   * "withheld" for every batch unserved past the grace window. Withheld here
   * is an institutional-SLA breach visible to anyone who asks and gets no
   * valid bytes (SOLR §3.3.2) — detectable and attributable, not preventable.
   */
  alarms(nowSeconds: number): DisclosureResult[] {
    const out: DisclosureResult[] = [];
    for (const state of this.batches.values()) {
      if (state.result !== null) {
        if (state.result.status !== "verified" && !state.baked) out.push(state.result);
        continue;
      }
      if (pastGrace(state.anchor.recordedAt, nowSeconds, this.graceSeconds)) {
        out.push({
          status: "withheld",
          txHash: state.anchor.txHash,
          startLeafIndex: state.anchor.startLeafIndex,
          emittedCount: 0,
          receiverCount: 0,
          recomputed: "0",
          expected: state.anchor.disclosureHash.toString(),
        });
      }
    }
    return out;
  }

  private verify(state: BatchState, elements: bigint[], batchSize: number): DisclosureResult {
    const result = verifyServedDisclosure(
      elements,
      state.anchor.disclosureHash,
      batchSize,
      state.anchor.txHash,
      state.anchor.startLeafIndex,
    );
    state.elements = elements;
    state.result = result;
    if (result.status !== "verified") emitDisclosureAlarm(result, "served blob");
    return result;
  }

  private readDirBlob(startLeafIndex: number): bigint[] | null {
    if (this.dir === null) return null;
    const raw = ((): string | null => {
      try {
        return readFileSync(join(this.dir, `${startLeafIndex}.json`), "utf8");
      } catch {
        return null; // not served (yet) — the grace clock governs
      }
    })();
    if (raw === null) return null;
    const parsed = ((): unknown => {
      try {
        return JSON.parse(raw);
      } catch {
        return null;
      }
    })();
    if (!Array.isArray(parsed) || parsed.some((x) => typeof x !== "string")) {
      // A malformed file is an operator error, not chain evidence — warn and
      // treat as unserved rather than minting a tamper verdict from garbage.
      console.warn(`disclosure blob ${startLeafIndex}.json is not a JSON string array — treating as unserved`);
      return null;
    }
    return (parsed as string[]).map(BigInt);
  }
}
