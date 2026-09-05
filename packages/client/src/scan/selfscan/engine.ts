// scan/selfscan/engine.ts — the pure, PRNG-free event-scan pass: viewTag prefilter,
// decaps + open, leaf-match, spent flags (split from selfscan.ts; the subpath
// @bongtu/client/selfscan re-exports everything).
import { kemHexToBytes } from "@bongtu/core/kem";
import {
  commitment,
  nullifier,
  poseidonDecrypt,
  ecdhSharedSecret,
} from "@bongtu/core/note";
import { consumerViewTag, openConsumerOutput, CONSUMER_CT_LEN } from "@bongtu/core/consumer";
import { foldToRoot } from "@bongtu/core/imt";
import {
  type EventKind,
  type FeedEvent,
  type KemTransport,
  type PathResult,
} from "@bongtu/core/indexerApi";
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
          kemCiphertext: kemHexToBytes(kemHex),
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
