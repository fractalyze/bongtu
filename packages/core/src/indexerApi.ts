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

import { sha256 } from "@noble/hashes/sha2.js";
import { signNotesAuth, notesAuthMessage, viewTokenAuthMessage, packSignature } from "./eddsa.js";
import { unpackPubkey } from "./pubkey.js";
import type { FieldInput } from "./babyjub.js";

// --- wire shapes (what the indexer serves; what the apps consume) ---------------

/** Kind of note-bearing pool operation a feed entry came from. */
export type EventKind = "deposit" | "transfer" | "withdraw" | "disburse";

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

/** The kind of a `GET /history` activity item (arbiter-mode per-owner feed).
 *  "self" is only ever read: rows stored before a pure self-send became a
 *  sent+received pair still carry it, so clients must keep rendering it. */
export type HistoryKind = "received" | "sent" | "withdraw" | "deposit" | "self";

/** One `GET /history` activity item as the arbiter mode serves it: the owner's
 *  view of an op the ledger decrypted. `counterparty` is a COMPRESSED bjj pubkey
 *  hex (the other party — sender for "received", payee for "sent") or null for
 *  a "deposit"/"withdraw"/"self". A pure self-send (every nonzero output back to
 *  the owner) is a "sent" + "received" pair whose counterparty is the owner's own
 *  key. `amount` is what moved for the owner (decimal). */
export interface HistoryItem {
  kind: HistoryKind;
  counterparty: string | null; // compressed bjj pubkey hex, or null
  amount: string;
  txHash: string;
  blockTimestamp: number; // unix seconds
  seq: number; // newest-first: the feed is sorted by seq desc
}

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

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
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

/**
 * Build the signed `GET /notes` URL for an owner (SPEC §6b v2 read-auth) — the
 * ONE client-side implementation of the protocol. The signature is over
 * Poseidon(ownerPub.x, ownerPub.y, ts) and must verify against the queried
 * compressed pubkey, so the caller must hold that owner's private scalar
 * (`ownerPrivateKey` — the same formatted bjj scalar the notes are owned by).
 */
export function buildNotesUrl(
  indexerUrl: string,
  ownerCompressed: string,
  ownerPrivateKey: FieldInput,
): string {
  const owner = ownerCompressed.trim();
  const pub = unpackPubkey(owner); // validates the compressed pubkey
  const ts = Math.floor(Date.now() / 1000); // unix seconds; server allows |now-ts| <= 300
  const msg = notesAuthMessage(pub, ts);
  const sig = signNotesAuth(ownerPrivateKey, msg);
  return `${trim(indexerUrl)}/notes?owner=${encodeURIComponent(owner)}&ts=${ts}&sig=${packSignature(sig)}`;
}

/** Fetch a signed /notes URL (from `buildNotesUrl`) into the owner's note list. */
export function fetchNotes(url: string): Promise<OwnerNote[]> {
  return getJson<OwnerNote[]>(url);
}

/**
 * Build the signed `GET /history` URL for an owner — the arbiter-mode activity
 * feed. Mirrors `buildNotesUrl` EXACTLY (same owner/ts/sig params, same
 * Poseidon(ownerPub.x, ownerPub.y, ts) message the route verifies); only the
 * path differs (`/history`). The caller must hold the owner's private scalar.
 */
export function buildHistoryUrl(
  indexerUrl: string,
  ownerCompressed: string,
  ownerPrivateKey: FieldInput,
): string {
  const owner = ownerCompressed.trim();
  const pub = unpackPubkey(owner); // validates the compressed pubkey
  const ts = Math.floor(Date.now() / 1000); // unix seconds; server allows |now-ts| <= 300
  const msg = notesAuthMessage(pub, ts);
  const sig = signNotesAuth(ownerPrivateKey, msg);
  return `${trim(indexerUrl)}/history?owner=${encodeURIComponent(owner)}&ts=${ts}&sig=${packSignature(sig)}`;
}

/** Fetch a signed /history URL (from `buildHistoryUrl`) into the owner's feed. */
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

/** The challenge is 31 random bytes rendered as a decimal (viewtoken.ts), i.e.
 *  1 <= challenge < 2^248 — comfortably below the field prime. */
const CHALLENGE_BYTES = 31;
const CHALLENGE_MAX_EXCLUSIVE = 1n << BigInt(8 * CHALLENGE_BYTES);

/**
 * Refuse to sign anything that is not a well-formed challenge. A signature is a
 * blank cheque over whatever preimage the server chose, so the client checks the
 * shape ITSELF rather than trusting the server: decimal digits only, no leading
 * zero, nonzero, and inside the 31-byte range the issuer draws from. A server
 * that hands back an out-of-range or non-decimal "challenge" is malfunctioning or
 * hostile — either way we stop before the key is used.
 */
export function assertValidChallenge(challenge: unknown): bigint {
  if (typeof challenge !== "string" || !/^[1-9][0-9]{0,77}$/.test(challenge)) {
    throw new Error(`indexer returned a malformed challenge (expected a positive decimal): ${JSON.stringify(challenge)}`);
  }
  const v = BigInt(challenge);
  if (v >= CHALLENGE_MAX_EXCLUSIVE) {
    throw new Error(`indexer returned an out-of-range challenge (expected < 2^${8 * CHALLENGE_BYTES})`);
  }
  return v;
}

/**
 * The field element that pins a view-token signature to ONE indexer origin:
 * the first 31 bytes of sha256(origin), as a decimal string.
 *
 * `origin` is scheme + host + port of the URL the caller is actually talking to
 * (path, query and trailing slash dropped, lowercased) — so `http://host:8600`
 * and `http://host:8600/notes` bind identically, while a different host or scheme
 * never can. Both halves compute this from the URL THEY see: the wallet from the
 * indexer base it dials, the indexer from PUBLIC_URL. That asymmetry is the
 * anti-relay property (see viewTokenAuthMessage).
 *
 * A RELATIVE base (the wallet's default `/indexer`, a same-origin reverse proxy)
 * resolves against the page origin — which is genuinely the origin the browser
 * talks to, and therefore what the indexer's PUBLIC_URL must name in a proxied
 * deployment. Outside a browser there is no page, so it resolves against
 * localhost.
 */
export function viewTokenHostBinding(url: string): string {
  const pageOrigin = (globalThis as { location?: { origin?: string } }).location?.origin;
  const u = new URL(trim(url), pageOrigin ?? "http://localhost");
  const digest = sha256(new TextEncoder().encode(u.origin.toLowerCase()));
  let x = 0n;
  for (const b of digest.slice(0, CHALLENGE_BYTES)) x = (x << 8n) | BigInt(b);
  return x.toString();
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

/** The token-authenticated `GET /notes` URL (no key material involved). */
export function buildNotesTokenUrl(indexerUrl: string, ownerCompressed: string, token: string): string {
  const owner = ownerCompressed.trim();
  unpackPubkey(owner); // validates the compressed pubkey
  return `${trim(indexerUrl)}/notes?owner=${encodeURIComponent(owner)}&token=${encodeURIComponent(token)}`;
}

/** The token-authenticated `GET /history` URL — mirrors buildNotesTokenUrl. */
export function buildHistoryTokenUrl(indexerUrl: string, ownerCompressed: string, token: string): string {
  const owner = ownerCompressed.trim();
  unpackPubkey(owner); // validates the compressed pubkey
  return `${trim(indexerUrl)}/history?owner=${encodeURIComponent(owner)}&token=${encodeURIComponent(token)}`;
}
