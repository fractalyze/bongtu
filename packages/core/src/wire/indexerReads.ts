// wire/indexerReads.ts — the public reads, the owner-signed reads and the
// view-token protocol (split from indexerApi.ts).
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
import { getJson, trim, type IndexerFetchOpts } from "./indexerHttp.js";
import {
  HISTORY_PAGE_LIMIT,
  type Alarm,
  type FeedEvent,
  type Head,
  type Health,
  type HistoryItem,
  type HistoryPage,
  type HistoryPageQuery,
  type OwnerNote,
  type PathResult,
} from "./indexerDto.js";
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
export function signedOwnerProof(
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
