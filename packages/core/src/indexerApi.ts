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
} from "./eddsa.js";
import { unpackPubkey } from "./pubkey.js";
import type { FieldInput } from "./babyjub.js";

// The view-token signing contract (challenge width + validity, host binding) lives
// with the signature primitives in eddsa.ts, because the SERVER needs it too and
// must not import a fetch client to get it. Re-exported here so every existing
// `@bongtu/core/indexerApi` import of these keeps working.
export { assertValidChallenge, viewTokenHostBinding, CHALLENGE_BYTES } from "./eddsa.js";

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
  | "disburse";

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
  disclosure?: DisclosureStatus; // present for `disburse`
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
  blockTimestamp: number; // unix seconds
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

async function getJson<T>(url: string, fetchFn: typeof fetch = fetch): Promise<T> {
  const res = await fetchFn(url);
  const text = await res.text();
  if (!res.ok) throw new Error(`${url} -> ${res.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text) as T;
}

const trim = (u: string): string => u.replace(/\/$/, "");

export function getHead(indexerUrl: string): Promise<Head> {
  return getJson<Head>(`${trim(indexerUrl)}/head`);
}

/** The indexer's `GET /health` liveness signal (key-free; served in both modes). */
export function fetchHealth(indexerUrl: string): Promise<Health> {
  return getJson<Health>(`${trim(indexerUrl)}/health`);
}

/** Merkle path of a leaf against the current root. A within-batch (disburse) leaf
 *  is a 422 in public mode — the caller surfaces that (SPEC §11-7). */
export function getPath(indexerUrl: string, leafIndex: number): Promise<PathResult> {
  return getJson<PathResult>(`${trim(indexerUrl)}/path/${leafIndex}`);
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
): Promise<PathResult> {
  return getJson<PathResult>(`${trim(indexerUrl)}/path/${leafIndex}?${signedAuthQuery(ownerCompressed, ownerPrivateKey)}`);
}

export function getEvents(indexerUrl: string, limit = 5000): Promise<FeedEvent[]> {
  return getJson<FeedEvent[]>(`${trim(indexerUrl)}/events?limit=${limit}`);
}

/** The spent nullifier set (PUBLIC, key-free), as decimal strings. */
export function getNullifiers(indexerUrl: string): Promise<string[]> {
  return getJson<string[]>(`${trim(indexerUrl)}/nullifiers`);
}

export function getAlarms(indexerUrl: string): Promise<Alarm[]> {
  return getJson<Alarm[]>(`${trim(indexerUrl)}/alarms`);
}

/** The two arbiter-mode owner feeds. They share one read-auth (api/readAuth.ts on
 *  the server), so they share one URL builder here — only the path differs. */
export type OwnerReadRoute = "notes" | "history";

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

/** The `owner=&ts=&sig=` auth triple every signed read carries (SPEC §6b v2) —
 *  one implementation, shared by the owner feeds and the gated /path read. */
function signedAuthQuery(ownerCompressed: string, ownerPrivateKey: FieldInput): string {
  const owner = ownerCompressed.trim();
  const pub = unpackPubkey(owner); // validates the compressed pubkey
  const ts = Math.floor(Date.now() / 1000); // unix seconds; server allows |now-ts| <= 300
  const msg = notesAuthMessage(pub, ts);
  const sig = signNotesAuth(ownerPrivateKey, msg);
  return `owner=${encodeURIComponent(owner)}&ts=${ts}&sig=${packSignature(sig)}`;
}

/** The signed `GET /notes` URL — the owner's decrypted note list. */
export function buildNotesUrl(indexerUrl: string, ownerCompressed: string, ownerPrivateKey: FieldInput): string {
  return signedReadUrl(indexerUrl, "notes", ownerCompressed, ownerPrivateKey);
}

/** Fetch a signed /notes URL (from `buildNotesUrl`) into the owner's note list. */
export function fetchNotes(url: string): Promise<OwnerNote[]> {
  return getJson<OwnerNote[]>(url);
}

/** The signed `GET /history` URL — the owner's arbiter-mode activity feed. */
export function buildHistoryUrl(indexerUrl: string, ownerCompressed: string, ownerPrivateKey: FieldInput): string {
  return signedReadUrl(indexerUrl, "history", ownerCompressed, ownerPrivateKey);
}

/** Fetch a signed /history URL (from `buildHistoryUrl`) into the owner's feed.
 *  Unpaged: a URL with no `limit`/`before` gets the WHOLE feed as a bare array.
 *  Still the right call for the one-shot key-signed read (a tokenless session has
 *  nothing to page a second request with); token sessions use fetchHistoryPage. */
export function fetchHistory(url: string): Promise<HistoryItem[]> {
  return getJson<HistoryItem[]>(url);
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

import { nameAuthMessage, nameBindingField } from "./eddsa.js";
import type { StealthMetaAddress } from "./stealth.js";

/** One directory record, as served by GET /names/:name. */
export interface NameRecord {
  name: string;
  /** compressed bjj pubkey — the owner's in-pool receive address. */
  owner: string;
  /** compressed bjj stealth VIEW pubkey (see stealth.ts). */
  viewPub: string;
  /** compressed secp256k1 stealth SPEND pubkey (see stealth.ts). */
  spendPub: string;
  /** unix seconds of the last accepted registration (server clock). */
  updatedAt: number;
}

/** The signed POST /names body. */
export interface NameRegistration {
  name: string;
  owner: string;
  viewPub: string;
  spendPub: string;
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
  const owner = ownerCompressed.trim();
  const pub = unpackPubkey(owner); // validates the compressed pubkey
  const msg = nameAuthMessage(pub, nameBindingField(name, meta.viewPub, meta.spendPub), nowSeconds);
  return {
    name,
    owner,
    viewPub: meta.viewPub,
    spendPub: meta.spendPub,
    ts: nowSeconds,
    sig: packSignature(signNotesAuth(ownerPrivateKey, msg)),
  };
}

/** POST a registration; resolves to the accepted record, throws on any error
 *  status (the server's error body text is included). */
export async function registerName(indexerUrl: string, reg: NameRegistration): Promise<NameRecord> {
  const res = await fetch(`${indexerUrl.replace(/\/$/, "")}/names`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(reg),
  });
  const body = await res.text();
  if (!res.ok) throw new Error(`registerName: HTTP ${res.status}: ${body}`);
  return JSON.parse(body) as NameRecord;
}

/** Resolve a name to its directory record; null when it is not registered. */
export async function resolveName(indexerUrl: string, name: string): Promise<NameRecord | null> {
  const res = await fetch(`${indexerUrl.replace(/\/$/, "")}/names/${encodeURIComponent(name)}`);
  if (res.status === 404) return null;
  const body = await res.text();
  if (!res.ok) throw new Error(`resolveName: HTTP ${res.status}: ${body}`);
  return JSON.parse(body) as NameRecord;
}
