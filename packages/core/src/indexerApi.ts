// The ONE owner of the spec-normative indexer read-API (SPEC §6b): the wire
// shapes every endpoint serves plus a thin typed fetch client.
//
// Adapter pattern (the same seam discipline §6 locks for ProvingRequest in
// proving.ts): the indexer's routes type their RESPONSE BODIES against these
// shapes (server adapter), and payroll-web / wallet-web import the client instead
// of hand-copied types (consumer adapters). Adding a field to /events is a
// one-type change here that tsc propagates to the route and both apps; silent
// wire drift becomes a type error instead of a runtime surprise.
//
// Wire conventions: JSON, every field element as a DECIMAL string (bigints do
// not survive JSON), leaf indices as numbers, tx hashes as 0x-hex.
//
// `buildNotesUrl` is the client half of the /notes signed-query protocol
// (param names, unix-seconds ts, the 300s replay window on the server side,
// EdDSA-Poseidon sig over Poseidon(ownerPub.x, ownerPub.y, ts)). It is written
// ONCE here and tested headlessly against the sdk's own `verifyNotesAuth` — the
// exact function the indexer route checks with — closing the auth loop inside
// one repo (test/indexerApi.test.ts).

import {
  signNotesAuth,
  notesAuthMessage,
  viewTokenAuthMessage,
  packSignature,
  assertValidChallenge,
  viewTokenHostBinding,
} from "@bongtu/core/eddsa";
import { unpackPubkey } from "@bongtu/core/pubkey";
import type { FieldInput, Point } from "@bongtu/core/babyjub";

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

// --- thin typed client ----------------------------------------------------------

async function getJson<T>(url: string, fetchFn: typeof fetch = fetch, signal?: AbortSignal): Promise<T> {
  const res = await fetchFn(url, signal === undefined ? undefined : { signal });
  const text = await res.text();
  if (!res.ok) throw new Error(`${url} -> ${res.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text) as T;
}

/** getJson for a JSON POST — same transport and the same thrown-message shape
 *  (`<url> -> <status>: <body-slice>`), which errors.ts classifyIndexerRead
 *  parses for the status code, so POSTs classify identically to reads. */
async function postJson<T>(url: string, body: unknown, fetchFn: typeof fetch = fetch): Promise<T> {
  const res = await fetchFn(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${url} -> ${res.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text) as T;
}

/** getJson, except a 404 resolves to null — for lookups where absence is an
 *  answer, not a failure. Every other error keeps getJson's message shape. */
async function getJsonOr404<T>(url: string, fetchFn: typeof fetch = fetch): Promise<T | null> {
  const res = await fetchFn(url);
  if (res.status === 404) return null;
  const text = await res.text();
  if (!res.ok) throw new Error(`${url} -> ${res.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text) as T;
}

const trim = (u: string): string => u.replace(/\/$/, "");

/** Per-call transport options for the reads that predate fetch injection: the
 *  test seam (`fetchFn`) plus cancellation (`signal`) for polling consumers —
 *  a trailing optional bag, so every existing call keeps its exact shape. */
export interface IndexerFetchOpts {
  fetchFn?: typeof fetch;
  signal?: AbortSignal;
}

export function getHead(indexerUrl: string, opts: IndexerFetchOpts = {}): Promise<Head> {
  return getJson<Head>(`${trim(indexerUrl)}/head`, opts.fetchFn, opts.signal);
}

/** The indexer's `GET /health` liveness signal (key-free; served in both modes). */
export function fetchHealth(indexerUrl: string, opts: IndexerFetchOpts = {}): Promise<Health> {
  return getJson<Health>(`${trim(indexerUrl)}/health`, opts.fetchFn, opts.signal);
}

/** Merkle path of a leaf against the current root. A within-batch (disburse) leaf
 *  is a 422 in public mode — the caller surfaces that (SPEC §11-7). */
export function getPath(indexerUrl: string, leafIndex: number, opts: IndexerFetchOpts = {}): Promise<PathResult> {
  return getJson<PathResult>(`${trim(indexerUrl)}/path/${leafIndex}`, opts.fetchFn, opts.signal);
}

/** Merkle path with the signed read-auth attached (same `owner/ts/sig` triple as
 *  /notes). Required to open a WITHIN-BATCH leaf on an arbiter indexer — the
 *  server checks the sig AND that the ledger holds `leafIndex` under this owner
 *  (401/403 otherwise); auth is ignored for single-append leaves, so a wallet can
 *  sign every membership fetch uniformly. */
export function getSignedPath(
  indexerUrl: string,
  leafIndex: number,
  ownerCompressed: string,
  ownerPrivateKey: FieldInput,
  opts: IndexerFetchOpts = {},
): Promise<PathResult> {
  return getJson<PathResult>(
    `${trim(indexerUrl)}/path/${leafIndex}?${signedAuthQuery(ownerCompressed, ownerPrivateKey)}`,
    opts.fetchFn,
    opts.signal,
  );
}

export function getEvents(indexerUrl: string, limit = 5000, opts: IndexerFetchOpts = {}): Promise<FeedEvent[]> {
  return getJson<FeedEvent[]>(`${trim(indexerUrl)}/events?limit=${limit}`, opts.fetchFn, opts.signal);
}

/** Cursor-paged `GET /events` (seq > cursor, chain order) — the incremental
 *  read the OPMOD §3.6 self-scan resumes on. `cursor = -1` reads from the
 *  start; the caller's next cursor is the highest `seq` it processed. */
export function getEventsFrom(
  indexerUrl: string,
  cursor: number,
  limit = 5000,
  opts: IndexerFetchOpts = {},
): Promise<FeedEvent[]> {
  return getJson<FeedEvent[]>(`${trim(indexerUrl)}/events?cursor=${cursor}&limit=${limit}`, opts.fetchFn, opts.signal);
}

/** The spent nullifier set (PUBLIC, key-free), as decimal strings. */
export function getNullifiers(indexerUrl: string, opts: IndexerFetchOpts = {}): Promise<string[]> {
  return getJson<string[]>(`${trim(indexerUrl)}/nullifiers`, opts.fetchFn, opts.signal);
}

export function getAlarms(indexerUrl: string, opts: IndexerFetchOpts = {}): Promise<Alarm[]> {
  return getJson<Alarm[]>(`${trim(indexerUrl)}/alarms`, opts.fetchFn, opts.signal);
}

/** The two arbiter-mode owner feeds. They share one read-auth (api/readAuth.ts on
 *  the server), so they share one URL builder here — only the path differs. */
export type OwnerReadRoute = "notes" | "history" | "announcements";

/**
 * Build the signed read URL for an owner feed (SPEC §6b v2 read-auth) — the ONE
 * client-side implementation of the protocol. The signature is over
 * Poseidon(ownerPub.x, ownerPub.y, ts) and must verify against the queried
 * compressed pubkey, so the caller must hold that owner's private scalar
 * (`ownerPrivateKey` — the same formatted bjj scalar the notes are owned by).
 */
export function signedReadUrl(
  indexerUrl: string,
  route: OwnerReadRoute,
  ownerCompressed: string,
  ownerPrivateKey: FieldInput,
): string {
  return `${trim(indexerUrl)}/${route}?${signedAuthQuery(ownerCompressed, ownerPrivateKey)}`;
}

/**
 * The ONE "draw ts, build message, sign, pack" step behind every owner-signed
 * proof this client emits — the query-shaped reads (signedAuthQuery) and the
 * payload-bound name registration (buildNameRegistration) differ ONLY in the
 * message the owner signs, so `messageOf` is the whole difference. Mirrors the
 * server's readAuth split (authorizeOwner / authorizeSignedPayload) primitive
 * for primitive, and keeps the wire bytes what they always were: same trim,
 * same unpack-validation, same unix-seconds ts, same packSignature encoding.
 */
function signedOwnerProof(
  ownerCompressed: string,
  ownerPrivateKey: FieldInput,
  messageOf: (ownerPub: Point, ts: number) => bigint,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): { owner: string; ts: number; sig: string } {
  const owner = ownerCompressed.trim();
  const pub = unpackPubkey(owner); // validates the compressed pubkey
  const ts = nowSeconds; // unix seconds; server allows |now-ts| <= 300
  const sig = signNotesAuth(ownerPrivateKey, messageOf(pub, ts));
  return { owner, ts, sig: packSignature(sig) };
}

/** The `owner=&ts=&sig=` auth triple every signed read carries (SPEC §6b v2) —
 *  one implementation, shared by the owner feeds and the gated /path read. */
function signedAuthQuery(ownerCompressed: string, ownerPrivateKey: FieldInput): string {
  const { owner, ts, sig } = signedOwnerProof(ownerCompressed, ownerPrivateKey, notesAuthMessage);
  return `owner=${encodeURIComponent(owner)}&ts=${ts}&sig=${sig}`;
}

/** The signed `GET /notes` URL — the owner's decrypted note list. */
export function buildNotesUrl(indexerUrl: string, ownerCompressed: string, ownerPrivateKey: FieldInput): string {
  return signedReadUrl(indexerUrl, "notes", ownerCompressed, ownerPrivateKey);
}

/** Fetch a signed /notes URL (from `buildNotesUrl`) into the owner's note list. */
export function fetchNotes(url: string, opts: IndexerFetchOpts = {}): Promise<OwnerNote[]> {
  return getJson<OwnerNote[]>(url, opts.fetchFn, opts.signal);
}

/** The signed `GET /history` URL — the owner's arbiter-mode activity feed. */
export function buildHistoryUrl(indexerUrl: string, ownerCompressed: string, ownerPrivateKey: FieldInput): string {
  return signedReadUrl(indexerUrl, "history", ownerCompressed, ownerPrivateKey);
}

/** Fetch a signed /history URL (from `buildHistoryUrl`) into the owner's feed.
 *  Unpaged: a URL with no `limit`/`before` gets the WHOLE feed as a bare array.
 *  Still the right call for the one-shot key-signed read (a tokenless session has
 *  nothing to page a second request with); token sessions use fetchHistoryPage. */
export function fetchHistory(url: string, opts: IndexerFetchOpts = {}): Promise<HistoryItem[]> {
  return getJson<HistoryItem[]>(url, opts.fetchFn, opts.signal);
}

// --- view tokens (arbiter-mode /auth) --------------------------------------------
//
// The persistence half of the read-auth protocol: prove key ownership ONCE over a
// server-drawn challenge, get back an opaque expiring token, and read /notes +
// /history with `?token=` afterwards — no private key needed for later reads. The
// server half (challenge store, HMAC token mint/verify) lives in the indexer's
// api/viewtoken.ts; this is the ONE client-side implementation, tested against the
// indexer's own service in apps/indexer/test/viewtoken.test.ts.

/** What POST /auth returns: the opaque token + its unix-seconds expiry. */
export interface ViewToken {
  token: string;
  exp: number;
}

/** What GET /auth/challenge returns. `hostBindings` are the origin digests the
 *  SERVER will accept (its PUBLIC_URL list — a wallet can be served from more than
 *  one domain, e.g. the custom domain plus preview deploys). Advisory here: the
 *  client still signs the binding it computes itself, and only uses the list to
 *  turn a PUBLIC_URL misconfiguration into a readable error instead of a bare 401
 *  at redemption. */
export interface ViewChallenge {
  challenge: string;
  expiresAt: number;
  hostBindings: string[];
}

/**
 * Run the /auth handshake for an owner: GET a challenge, sign it with the SAME
 * EdDSA-Poseidon primitive the signed queries use but over the DOMAIN-SEPARATED,
 * HOST-BOUND tuple (viewTokenAuthMessage: Poseidon(ownerPub.x, ownerPub.y,
 * challenge, hostBinding, VIEWTOKEN_DOMAIN_TAG)), POST the signature back, return
 * the issued token. The private key is used transiently here and never leaves the
 * call.
 *
 * `hostBinding` is computed from `indexerUrl` — the origin THIS client dialled —
 * never from the server's advertised list, so a hostile indexer relaying a real
 * server's challenge collects a signature the real server rejects. The advertised
 * list is only checked for membership, to fail loudly (and before signing) on a
 * server whose PUBLIC_URL does not match how clients reach it.
 */
export async function obtainViewToken(
  indexerUrl: string,
  ownerCompressed: string,
  ownerPrivateKey: FieldInput,
  fetchFn: typeof fetch = fetch,
): Promise<ViewToken> {
  const owner = ownerCompressed.trim();
  const pub = unpackPubkey(owner); // validates the compressed pubkey
  const base = trim(indexerUrl);
  const chRes = await fetchFn(`${base}/auth/challenge?owner=${encodeURIComponent(owner)}`);
  const chText = await chRes.text();
  if (!chRes.ok) throw new Error(`${base}/auth/challenge -> ${chRes.status}: ${chText.slice(0, 300)}`);
  const advertised = JSON.parse(chText) as Partial<ViewChallenge>;
  const challengeValue = assertValidChallenge(advertised.challenge);
  const challenge = challengeValue.toString();
  const hostBinding = viewTokenHostBinding(indexerUrl);
  const accepted = Array.isArray(advertised.hostBindings) ? advertised.hostBindings : [];
  if (!accepted.includes(hostBinding)) {
    throw new Error(
      `${base}/auth/challenge does not accept the origin this wallet reaches it on — ` +
        `set the indexer's PUBLIC_URL to it (need ${hostBinding}, server accepts ${JSON.stringify(accepted)})`,
    );
  }
  const sig = packSignature(signNotesAuth(ownerPrivateKey, viewTokenAuthMessage(pub, challengeValue, hostBinding)));
  const res = await fetchFn(`${base}/auth`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ owner, challenge, sig }),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${base}/auth -> ${res.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text) as ViewToken;
}

/** The token-authenticated read URL for an owner feed — no key material involved,
 *  which is the whole point of the token path. */
export function tokenReadUrl(
  indexerUrl: string,
  route: OwnerReadRoute,
  ownerCompressed: string,
  token: string,
): string {
  const owner = ownerCompressed.trim();
  unpackPubkey(owner); // validates the compressed pubkey
  return `${trim(indexerUrl)}/${route}?owner=${encodeURIComponent(owner)}&token=${encodeURIComponent(token)}`;
}

export function buildNotesTokenUrl(indexerUrl: string, ownerCompressed: string, token: string): string {
  return tokenReadUrl(indexerUrl, "notes", ownerCompressed, token);
}

export function buildHistoryTokenUrl(indexerUrl: string, ownerCompressed: string, token: string): string {
  return tokenReadUrl(indexerUrl, "history", ownerCompressed, token);
}

/** Append the paging params to an owner-feed URL. String concatenation, not `new
 *  URL`: `indexerUrl` is RELATIVE in the deployed wallet ("/indexer"), which `new
 *  URL` cannot parse without a base. Every builder above already emitted `?owner=`,
 *  so the separator is always `&`. */
function withPageParams(url: string, page: HistoryPageQuery): string {
  const q: string[] = [];
  if (page.limit !== undefined) q.push(`limit=${page.limit}`);
  if (page.before !== undefined) q.push(`before=${page.before}`);
  return q.length === 0 ? url : `${url}&${q.join("&")}`;
}

/** The token-authed URL for ONE page of an owner's `/history`. */
export function buildHistoryPageUrl(
  indexerUrl: string,
  ownerCompressed: string,
  token: string,
  page: HistoryPageQuery = {},
): string {
  // `limit` is sent ALWAYS, even for the first page: it is what selects the
  // { items, nextBefore } envelope over the legacy bare array, so a page request
  // that omitted it would parse as `items: undefined`.
  return withPageParams(buildHistoryTokenUrl(indexerUrl, ownerCompressed, token), {
    limit: page.limit ?? HISTORY_PAGE_LIMIT,
    before: page.before,
  });
}

/**
 * Fetch one page of an owner's activity feed with a view token — the paging client
 * the wallet's Activity screen drives. The token is reused per page: paging costs
 * no new signature, because `before` is a cursor into an already-authorised feed
 * and the auth is re-checked per request from the token alone.
 */
export function fetchHistoryPage(
  indexerUrl: string,
  ownerCompressed: string,
  token: string,
  page: HistoryPageQuery = {},
  fetchFn: typeof fetch = fetch,
): Promise<HistoryPage> {
  return getJson<HistoryPage>(buildHistoryPageUrl(indexerUrl, ownerCompressed, token, page), fetchFn);
}

// --- name directory (public /names endpoints) ------------------------------------
//
// The stealth/payment directory: a human name resolving to the owner's bjj
// pubkey (the in-pool receive identity) and stealth meta-address (the pool-edge
// one). Server half: apps/indexer src/names.ts + api/routes/names.ts.

import {
  nameAuthMessage,
  nameBindingField,
  nameAuthMessageV2,
  nameBindingFieldV2,
  NOTE_VIEW_PUB_ZERO,
  KEM_EK_ZERO,
} from "@bongtu/core/eddsa";
import type { StealthMetaAddress } from "@bongtu/core/stealth";

// The v2 zero-sentinels, re-exported so a client clearing its consumer pair
// keeps one import path with the fetch builders below.
export { NOTE_VIEW_PUB_ZERO, KEM_EK_ZERO } from "@bongtu/core/eddsa";

// Lowercase label, 3–32 chars, alnum with interior hyphens — a deliberately
// DNS-label-shaped grammar so a name can later become an ENS/CCIP subname
// without a migration. The grammar lives HERE, beside the wire shapes, so the
// server's registry and the wallet's pay-by-name form judge input with the ONE
// function — a form that accepted what the registry rejects (or vice versa)
// would be wire drift by another name.
const NAME_PATTERN = /^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$/;

/** Canonical form of a requested name, or null when no canonical form exists. */
export function normalizeName(raw: string): string | null {
  const name = raw.trim().toLowerCase();
  return NAME_PATTERN.test(name) ? name : null;
}

/** One directory record, as served by GET /names/:name. */
export interface NameRecord {
  name: string;
  /** compressed bjj pubkey — the owner's in-pool receive address. */
  owner: string;
  /** compressed bjj stealth VIEW pubkey (see stealth.ts). */
  viewPub: string;
  /** compressed secp256k1 stealth SPEND pubkey (see stealth.ts). */
  spendPub: string;
  /** compressed bjj NOTE-LAYER view pubkey (consumer triple, OPMOD §6.1) —
   *  absent on records registered before the consumer extension. */
  noteViewPub?: string;
  /** ML-KEM-768 encapsulation key, 0x + 1184-byte hex (consumer triple) —
   *  required together with `noteViewPub`, absent on legacy records. */
  kemEk?: string;
  /** unix seconds of the last accepted registration (server clock). */
  updatedAt: number;
}

/** The signed POST /names body. OPMOD §6.4 form selection is by payload shape:
 *  `noteViewPub`/`kemEk` present (required together) selects the v2 signature
 *  form exclusively; neither present selects v1 exclusively — no dual-try. */
export interface NameRegistration {
  name: string;
  owner: string;
  viewPub: string;
  spendPub: string;
  noteViewPub?: string;
  kemEk?: string;
  ts: number;
  sig: string;
}

/**
 * Build a registration the indexer will accept: the owner key signs the
 * payload-binding tuple (eddsa.ts nameAuthMessage), so the signature authorises
 * exactly this (name -> meta) mapping and nothing else. `nowSeconds` is
 * injectable for deterministic tests; the server allows |now - ts| <= 300s.
 */
export function buildNameRegistration(
  name: string,
  ownerCompressed: string,
  ownerPrivateKey: FieldInput,
  meta: StealthMetaAddress,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): NameRegistration {
  const { owner, ts, sig } = signedOwnerProof(
    ownerCompressed,
    ownerPrivateKey,
    (pub, at) => nameAuthMessage(pub, nameBindingField(name, meta.viewPub, meta.spendPub), at),
    nowSeconds,
  );
  return { name, owner, viewPub: meta.viewPub, spendPub: meta.spendPub, ts, sig };
}

/** The note-layer consumer identity a v2 registration binds beside the stealth
 *  meta (OPMOD §6.1): the bjj note-view pubkey + the ML-KEM-768 encapsulation
 *  key — an unusable half-identity alone, so always required together. */
export interface ConsumerNameIdentity {
  noteViewPub: string; // compressed bjj pubkey, 0x + 32-byte hex
  kemEk: string; // 0x + 1184-byte hex
}

/**
 * Build a v2 registration carrying (or clearing) the consumer triple. The owner
 * signs the FIVE-segment v2 binding under the v2 domain tag (OPMOD §6.4): pass
 * the identity to set/rotate it, or `"clear"` to sign the zero-sentinels —
 * clearing is a signed statement, never an omission. Legacy v1 payloads keep
 * using `buildNameRegistration` unchanged.
 */
export function buildNameRegistrationV2(
  name: string,
  ownerCompressed: string,
  ownerPrivateKey: FieldInput,
  meta: StealthMetaAddress,
  consumer: ConsumerNameIdentity | "clear",
  nowSeconds: number = Math.floor(Date.now() / 1000),
): NameRegistration {
  const pair = consumer === "clear" ? { noteViewPub: NOTE_VIEW_PUB_ZERO, kemEk: KEM_EK_ZERO } : consumer;
  const { owner, ts, sig } = signedOwnerProof(
    ownerCompressed,
    ownerPrivateKey,
    (pub, at) =>
      nameAuthMessageV2(
        pub,
        nameBindingFieldV2(name, meta.viewPub, meta.spendPub, pair.noteViewPub, pair.kemEk),
        at,
      ),
    nowSeconds,
  );
  return {
    name,
    owner,
    viewPub: meta.viewPub,
    spendPub: meta.spendPub,
    noteViewPub: pair.noteViewPub,
    kemEk: pair.kemEk,
    ts,
    sig,
  };
}

/** POST a registration; resolves to the accepted record, throws on any error
 *  status (the server's error body text is included). */
export function registerName(
  indexerUrl: string,
  reg: NameRegistration,
  fetchFn: typeof fetch = fetch,
): Promise<NameRecord> {
  return postJson<NameRecord>(`${trim(indexerUrl)}/names`, reg, fetchFn);
}

/** Resolve a name to its directory record; null when it is not registered. */
export function resolveName(
  indexerUrl: string,
  name: string,
  fetchFn: typeof fetch = fetch,
): Promise<NameRecord | null> {
  return getJsonOr404<NameRecord>(`${trim(indexerUrl)}/names/${encodeURIComponent(name)}`, fetchFn);
}

/** The public announcement feed (seq > cursor, capped). The trustless scan-all
 *  path — pair each record with scanStealthAnnouncement to find your own. */
export function getAnnouncements(
  indexerUrl: string,
  cursor = -1,
  limit = 5000,
  fetchFn: typeof fetch = fetch,
): Promise<WithdrawAnnouncementRecord[]> {
  return getJson<WithdrawAnnouncementRecord[]>(
    `${trim(indexerUrl)}/announcements?cursor=${cursor}&limit=${limit}`,
    fetchFn,
  );
}

/** The signed arbiter-mode `GET /announcements?owner=` URL — only the caller's
 *  own announcements, no scanning (same read-auth as /notes). */
export function buildAnnouncementsUrl(
  indexerUrl: string,
  ownerCompressed: string,
  ownerPrivateKey: FieldInput,
): string {
  return signedReadUrl(indexerUrl, "announcements", ownerCompressed, ownerPrivateKey);
}

/** Fetch a signed /announcements URL (from `buildAnnouncementsUrl`). */
export function fetchAnnouncements(url: string, opts: IndexerFetchOpts = {}): Promise<WithdrawAnnouncementRecord[]> {
  return getJson<WithdrawAnnouncementRecord[]>(url, opts.fetchFn, opts.signal);
}

// --- portal deposits (public /pay + /portal endpoints) ----------------------------
//
// The Curvy-style stealth front door (Slice ⑤): POST /pay/{name} makes the
// INDEXER derive a fresh stealth address for the name's meta-address and record
// the announcement at issuance time (a CEX sender can never announce), returning
// the CREATE2 sweeper `destination` the payer funds with a plain transfer.
// Server half: apps/indexer src/portal.ts + api/routes/portal.ts.

/** What POST /pay/{name} returns: everything the payer (and a paranoid
 *  recipient re-deriving it) needs. `destination` is the CREATE2 sweeper
 *  address to fund; `stealthAddr` is the underlying DKSAP one-time EOA whose
 *  bytes32 left-pad is the CREATE2 salt (stealth.ts portalSalt — the one rule);
 *  `factory` names the PortalFactory the wrap was computed against. */
export interface PortalIssuance {
  /** the CREATE2 sweeper address the payer actually funds (EIP-55). */
  destination: string;
  /** "0x" + 32-byte hex — the packed bjj ephemeral pubkey R (the announcement). */
  ephemeralPub: string;
  viewTag: number;
  /** "0x" + 20-byte hex — the DKSAP-derived one-time EOA (the CREATE2 salt's address). */
  stealthAddr: string;
  /** the PortalFactory address the destination was derived against. */
  factory: string;
}

/** One issuance-time portal announcement, as served by /portal/announcements and
 *  /portal/unswept. All fields are PUBLIC data: the announcement half mirrors
 *  WithdrawAnnouncementRecord (ephemeralPub, viewTag, seq cursor), and the
 *  attribution half is the resolved name record (name, owner) — public because
 *  the name directory itself is. `swept` flips when the factory's Swept event
 *  lands, carrying the sweep tx + amount. */
export interface PortalRecord {
  kind: "portal";
  /** issuance-order cursor key (the portal feed's own seq space, NOT the
   *  chain-event feed's — issuance has no tx to sequence by). */
  seq: number;
  name: string;
  /** compressed bjj pubkey of the name's owner (the recipient's in-pool identity). */
  owner: string;
  ephemeralPub: string;
  viewTag: number;
  stealthAddr: string;
  destination: string;
  /** unix seconds of issuance (server clock). */
  createdAt: number;
  swept: boolean;
  sweptTxHash: string | null;
  /** decimal; the swept deposit amount (the proof's public amount). */
  sweptAmount: string | null;
}

/** Resolve `name` into a fresh portal destination (the pay-by-name front door).
 *  Every call mints a NEW record server-side — call once per intended payment.
 *  404: unknown name, or portal deposits not configured on this indexer. */
export function payPortal(
  indexerUrl: string,
  name: string,
  fetchFn: typeof fetch = fetch,
): Promise<PortalIssuance> {
  return postJson<PortalIssuance>(`${trim(indexerUrl)}/pay/${encodeURIComponent(name)}`, {}, fetchFn);
}

/** The sweeper bot's work feed: unswept portal records (seq > cursor, capped). */
export function fetchUnswept(
  indexerUrl: string,
  cursor = -1,
  limit = 5000,
  fetchFn: typeof fetch = fetch,
): Promise<PortalRecord[]> {
  return getJson<PortalRecord[]>(
    `${trim(indexerUrl)}/portal/unswept?cursor=${cursor}&limit=${limit}`,
    fetchFn,
  );
}

/** The full portal announcement feed (swept and not) — the recipient's scan-all
 *  path: pair each record with scanStealthAnnouncement, then map the matched
 *  address through portalSalt/create2Address to confirm `destination`. */
export function getPortalAnnouncements(
  indexerUrl: string,
  cursor = -1,
  limit = 5000,
  fetchFn: typeof fetch = fetch,
): Promise<PortalRecord[]> {
  return getJson<PortalRecord[]>(
    `${trim(indexerUrl)}/portal/announcements?cursor=${cursor}&limit=${limit}`,
    fetchFn,
  );
}

// --- the bound client (issue #15 C1) ----------------------------------------------
//
// One IndexerClient binds the base URL (and the injected fetchFn) ONCE, so the
// ~25 call sites stop re-threading `indexerUrl` through every read. The class is
// a pure delegation layer: every method body is a one-line call into the free
// functions above — they REMAIN the exported primitive/protocol layer (raw
// builder use, `typeof`-typed dependency seams, the headless auth-loop tests),
// and delegation is what makes URL/auth/error drift between the two impossible.
// Methods are readonly ARROW properties so a tear-off (handing `indexer.unswept`
// to a deps bag) keeps its instance — the ToastQueue precedent.

/** Constructor options: `fetchFn` is the ONE test seam — every read and POST a
 *  client instance performs goes through it. */
export interface IndexerClientOptions {
  fetchFn?: typeof fetch;
}

/** The trailing option of the polling-consumed reads (head/health/events/path):
 *  cancellation for consumers that unmount or supersede a scan mid-flight. */
export interface ReadAbort {
  signal?: AbortSignal;
}

/** What a session holding only a VIEW TOKEN can read. Paged /history is
 *  token-only: paging spans requests, and only the token survives between them. */
export interface OwnerTokenReads {
  notes(): Promise<OwnerNote[]>;
  /** ONE page; `limit` is always sent (it selects the { items, nextBefore }
   *  envelope over the legacy bare array). */
  historyPage(page?: HistoryPageQuery): Promise<HistoryPage>;
}

/** What the owner's PRIVATE KEY can read: the signed one-shot feeds plus the
 *  signed /path a within-batch leaf needs. Unpaged /history on purpose — a
 *  key-mode binding is transient, so there is nothing to page a second request
 *  with. */
export interface OwnerKeyReads {
  notes(): Promise<OwnerNote[]>;
  history(): Promise<HistoryItem[]>;
  announcements(): Promise<WithdrawAnnouncementRecord[]>;
  signedPath(leafIndex: number): Promise<PathResult>;
}

/** The key a key-mode binding signs with — a value, or a thunk so every read
 *  pulls the key through the caller's lock at call time instead of capturing it. */
export type OwnerKeySource = FieldInput | (() => FieldInput);

/** asOwner's overload pair — the server's real capability matrix as a type:
 *  token ⇒ { notes, paged history }, key ⇒ { notes, unpaged history,
 *  announcements, signed path }. The illegal combination (a token asking for a
 *  signed /path, a transient key paging) is a compile error, not a 401. */
export interface AsOwner {
  (owner: string, auth: { token: string }): OwnerTokenReads;
  (owner: string, auth: { key: OwnerKeySource }): OwnerKeyReads;
}

export class IndexerClient {
  private readonly base: string;
  private readonly fetchFn: typeof fetch;

  constructor(indexerUrl: string, opts: IndexerClientOptions = {}) {
    // Trimmed ONCE here; the delegated free functions re-trim idempotently. The
    // base stays a plain string prefix — the deployed wallet's base is RELATIVE
    // ("/indexer"), which `new URL` cannot parse, so no URL object ever exists.
    this.base = indexerUrl.replace(/\/$/, "");
    this.fetchFn = opts.fetchFn ?? fetch;
  }

  readonly head = (opts: ReadAbort = {}): Promise<Head> =>
    getHead(this.base, { fetchFn: this.fetchFn, signal: opts.signal });

  readonly health = (opts: ReadAbort = {}): Promise<Health> =>
    fetchHealth(this.base, { fetchFn: this.fetchFn, signal: opts.signal });

  readonly path = (leafIndex: number, opts: ReadAbort = {}): Promise<PathResult> =>
    getPath(this.base, leafIndex, { fetchFn: this.fetchFn, signal: opts.signal });

  /** Cursor-paged `GET /events` (getEventsFrom) — the incremental read the
   *  self-scan resumes on, so this (not the legacy limit-only read) is the
   *  method shape. */
  readonly events = (cursor: number, limit?: number, opts: ReadAbort = {}): Promise<FeedEvent[]> =>
    getEventsFrom(this.base, cursor, limit, { fetchFn: this.fetchFn, signal: opts.signal });

  readonly nullifiers = (): Promise<string[]> => getNullifiers(this.base, { fetchFn: this.fetchFn });

  readonly alarms = (): Promise<Alarm[]> => getAlarms(this.base, { fetchFn: this.fetchFn });

  readonly announcements = (cursor?: number, limit?: number): Promise<WithdrawAnnouncementRecord[]> =>
    getAnnouncements(this.base, cursor, limit, this.fetchFn);

  readonly resolveName = (name: string): Promise<NameRecord | null> => resolveName(this.base, name, this.fetchFn);

  readonly registerName = (reg: NameRegistration): Promise<NameRecord> => registerName(this.base, reg, this.fetchFn);

  readonly payPortal = (name: string): Promise<PortalIssuance> => payPortal(this.base, name, this.fetchFn);

  readonly unswept = (cursor?: number, limit?: number): Promise<PortalRecord[]> =>
    fetchUnswept(this.base, cursor, limit, this.fetchFn);

  readonly portalAnnouncements = (cursor?: number, limit?: number): Promise<PortalRecord[]> =>
    getPortalAnnouncements(this.base, cursor, limit, this.fetchFn);

  readonly obtainViewToken = (ownerCompressed: string, ownerPrivateKey: FieldInput): Promise<ViewToken> =>
    obtainViewToken(this.base, ownerCompressed, ownerPrivateKey, this.fetchFn);

  /**
   * Bind an owner for the authed reads. CUSTODY INVARIANT: a TOKEN-mode binding
   * may live for a session (the token is the auth, no key material is held); a
   * KEY-mode binding must be constructed TRANSIENTLY inside a read — the
   * caller's key cache stays the one cross-call key holder — and the key may be
   * a thunk so each read pulls through the lock at call time. Either way every
   * signed URL is built FRESH per call (a signed URL embeds its ts, and a cached
   * one would expire out of the server's replay window mid-session).
   */
  readonly asOwner: AsOwner = ((owner: string, auth: { token: string } | { key: OwnerKeySource }) =>
    // The cast is the standard overload-implementation widening a function
    // DECLARATION would get for free; an arrow property has to say it.
    "token" in auth ? this.tokenReads(owner, auth.token) : this.keyReads(owner, auth.key)) as AsOwner;

  private readonly tokenReads = (owner: string, token: string): OwnerTokenReads => ({
    notes: () => fetchNotes(buildNotesTokenUrl(this.base, owner, token), { fetchFn: this.fetchFn }),
    historyPage: (page: HistoryPageQuery = {}) => fetchHistoryPage(this.base, owner, token, page, this.fetchFn),
  });

  private readonly keyReads = (owner: string, key: OwnerKeySource): OwnerKeyReads => {
    // Normalized to a thunk so every read below re-draws the key — nothing here
    // outlives the call when the caller handed a lock-backed thunk.
    const keyOf = typeof key === "function" ? key : (): FieldInput => key;
    return {
      notes: () => fetchNotes(buildNotesUrl(this.base, owner, keyOf()), { fetchFn: this.fetchFn }),
      history: () => fetchHistory(buildHistoryUrl(this.base, owner, keyOf()), { fetchFn: this.fetchFn }),
      announcements: () =>
        fetchAnnouncements(buildAnnouncementsUrl(this.base, owner, keyOf()), { fetchFn: this.fetchFn }),
      signedPath: (leafIndex: number) =>
        getSignedPath(this.base, leafIndex, owner, keyOf(), { fetchFn: this.fetchFn }),
    };
  };
}
