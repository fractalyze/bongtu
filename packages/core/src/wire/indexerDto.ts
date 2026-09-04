// wire/indexerDto.ts — the wire shapes every indexer endpoint serves (split from
// indexerApi.ts; the subpath @bongtu/core/indexerApi re-exports everything).

// The view-token signing contract (challenge width + validity, host binding) lives
// with the signature primitives in eddsa.ts, because the SERVER needs it too and
// must not import a fetch client to get it. Re-exported here so every existing
// `@bongtu/core/indexerApi` import of these keeps working.
export { assertValidChallenge, viewTokenHostBinding, CHALLENGE_BYTES } from "@bongtu/core/eddsa";

// --- wire shapes (what the indexer serves; what the apps consume) ---------------

/** Kind of note-bearing pool operation a feed entry came from. Same vocabulary
 *  as the envelope codec's `OpKind`, which is what an envelope alarm is keyed
 *  by — `transfer10` and `transfer10x2` are the two 10-input transfer circuits
 *  (10 outputs, or payment + change). */
export type EventKind =
  | "deposit"
  | "transfer"
  | "transfer10"
  | "transfer10x2"
  | "withdraw"
  | "disburse"
  | "depositPriv"
  | "transferPriv"
  | "transfer10x2Priv"
  | "withdrawPriv"
  | "disbursePriv";

/** GET /events disclosure verdict vocabulary (full detail lives on /alarms): a
 *  passing disclosureHash chain, a proven tamper, or the two publication gaps
 *  (receiver-only emission / nothing published) the auditor must judge. */
export type DisclosureStatus = "verified" | "mismatch" | "unverifiable" | "withheld";

/** A contiguous ciphertext run inside a feed entry (leafIndex null = the
 *  authority-envelope tail, which is not a tree leaf). */
export interface FeedSlice {
  offset: number;
  elts: number;
  leafIndex: number | null;
}

/** The kem-ct chunk transport state of a consumer disburse batch (OPMOD §5).
 *  Every non-"complete" status is OPERATIONAL — nothing on-chain-provable was
 *  violated (undelivered chunks are the sender-self-sabotage class), so they
 *  ride the feed here, never /alarms. "pending"/"withheld" mean chunks are
 *  still MISSING on-chain (inside / past the grace window);
 *  "accepted-unassembled" means every chunk was accepted (keccak-enforced) —
 *  nothing was withheld — but some chunk's bytes could not be decoded from its
 *  submit-tx calldata (a wrapped submission, or a failed fetch). The bytes are
 *  on-chain; the indexer re-attempts the fetch+decode at every boot. */
export interface KemTransport {
  status: "complete" | "pending" | "withheld" | "accepted-unassembled";
  chunkCount: number;
  acceptedCount: number;
  /** per-output 1088-byte ML-KEM cts as 0x-hex, leaf order — present once
   *  every chunk's bytes are assembled (what Decaps consumes). */
  kemCiphertexts?: string[];
}

/** One `GET /events` entry — the SPEC §6b ciphertext feed a wallet trial-decrypts. */
export interface FeedEvent {
  seq: number;
  txHash: string;
  blockNumber: number;
  kind: EventKind;
  epoch: number | null;
  ecdhPublicKey: [string, string] | null;
  encryptionNonce: string | null;
  slices: FeedSlice[];
  ciphertext: string[];
  disclosure?: DisclosureStatus; // present for `disburse` / `disbursePriv`
  /** present for `withdraw`/`withdrawPriv` since the stealth upgrade (see
   *  WithdrawAnnouncementRecord). */
  announcement?: { recipient: string; ephemeralPub: string; viewTag: number };
  /** consumer ops (OPMOD §3.2): one canonical [0,256) view tag per output
   *  slice, decimal, slice order — the S3.6 pre-filter. */
  viewTags?: string[];
  /** consumer SMALL ops (§3.4): per-output 1088-byte ML-KEM cts, 0x-hex,
   *  output order. A consumer disburse's arrive via `kem` instead. */
  kemCiphertexts?: string[];
  /** consumer disburse: the batch start (== the chunk-transport batchId). */
  batchId?: number;
  /** consumer disburse (§4.1): the published commitment run, decimal, leaf
   *  order — what lets ANY consumer re-fold the batch to its subtreeRoot. */
  outputCommitments?: string[];
  /** consumer disburse: the chunk transport state + assembled kem cts. */
  kem?: KemTransport;
}

/** One `GET /announcements` entry — the stealth-withdraw discovery feed a
 *  wallet scans with its view key (`@bongtu/core/stealth` scanStealthAnnouncement).
 *  `ephemeralPub`/`viewTag` are zero when the withdraw announced nothing. */
export interface WithdrawAnnouncementRecord {
  seq: number;
  txHash: string;
  blockNumber: number;
  /** "0x" + 20-byte hex — the proof-bound payout address. */
  recipient: string;
  /** "0x" + 32-byte hex — the packed bjj ephemeral pubkey R. */
  ephemeralPub: string;
  viewTag: number;
}

/** One owner note as the arbiter-mode `GET /notes` serves it (no private key, ever). */
export interface OwnerNote {
  owner: [string, string]; // decimal bjj pubkey
  value: string;
  salt: string;
  leafIndex: number;
  commitment: string;
  txHash: string;
  spent: boolean;
}

/** The kind of a `GET /history` activity item (arbiter-mode per-owner feed). */
export type HistoryKind = "received" | "sent" | "withdraw" | "deposit";

/** One `GET /history` activity item as the arbiter mode serves it: the owner's
 *  view of an op the ledger decrypted. `counterparty` is a COMPRESSED bjj pubkey
 *  hex (the other party — sender for "received", payee for "sent") or null for
 *  a "deposit"/"withdraw" and for a disburse's aggregated payer-side "sent"
 *  (a 255-payee batch has no single other party). A pure self-send (every
 *  nonzero output back to the owner) is a "sent" + "received" pair whose
 *  counterparty is the owner's own key. `amount` is what moved for the owner
 *  (decimal). */
export interface HistoryItem {
  kind: HistoryKind;
  counterparty: string | null; // compressed bjj pubkey hex, or null
  amount: string;
  txHash: string;
  /** unix seconds. ABSENT when the item's source has no timestamps — the
   *  selfscan public-feed derivation; the arbiter /history always stamps it,
   *  and the display edge suppresses the time element when it is missing. */
  blockTimestamp?: number;
  seq: number; // newest-first: the feed is sorted by seq desc
}

/** ONE page of `GET /history` (served whenever the request carries `limit` or
 *  `before`; a request carrying NEITHER still gets the legacy bare array).
 *  `nextBefore` is the cursor for the page after this one — pass it back as
 *  `before` — and null when the feed is exhausted, which is the caller's ONLY
 *  end-of-feed signal. */
export interface HistoryPage {
  items: HistoryItem[];
  nextBefore: number | null;
}

/** Where a page starts (`before`, exclusive on seq — omit for the newest) and how
 *  big it is (`limit`, server-capped at 200). */
export interface HistoryPageQuery {
  limit?: number;
  before?: number;
}

/** The page size the wallet asks for; the indexer route defaults to the same. */
export const HISTORY_PAGE_LIMIT = 50;

/** `GET /head` — the ingested mirror state. */
export interface Head {
  root: string;
  nextLeafIndex: number;
}

/** `GET /health` — the indexer's honest liveness signal (SPEC §6b). `ok` folds
 *  "mirror exists AND the tail poll is not persistently failing"; the raw poll
 *  state (lastBlock / lastError / consecutiveFailures) is surfaced so a caller
 *  can render "wedged since when". `alarms` is the total disclosure+envelope
 *  alarm count. Public and arbiter mode both serve it (key-free). */
export interface Health {
  ok: boolean;
  lastBlock: number;
  nextLeafIndex: number;
  batchSize: number;
  alarms: number;
  lastSuccessAt?: number | null;
  lastError?: string | null;
  lastErrorAt?: number | null;
  consecutiveFailures: number;
}

/** `GET /path/:leafIndex` — merkle path against the current root. */
export interface PathResult {
  leafIndex: number;
  siblings: string[];
  pathIndices: number[];
  root: string;
}

/** A non-passing disclosureHash check (public data; see DisclosureStatus). */
export interface DisclosureAlarm {
  type: "disclosure";
  status: DisclosureStatus;
  txHash: string;
  startLeafIndex: number;
  emittedCount: number;
  receiverCount: number;
  recomputed: string; // decimal
  expected: string; // decimal
}

/** An arbiter-mode envelope cross-check failure: the decrypted authority envelope
 *  does not reproduce the on-chain commitments (SPEC §6b first-class ALARM). */
export interface EnvelopeAlarm {
  type: "envelope";
  kind: EventKind;
  txHash: string;
  detail: string;
  recomputed: string; // decimal
  expected: string; // decimal
}

/** The single discriminated `GET /alarms` feed. Public mode has no ledger, so it
 *  only ever carries "disclosure" entries; arbiter mode appends "envelope" ones. */
export type Alarm = DisclosureAlarm | EnvelopeAlarm;
