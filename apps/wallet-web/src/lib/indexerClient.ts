// Thin fetch wrappers over the indexer read API (SPEC §6b) the wallet needs:
//   - signed `GET /notes` (arbiter mode) for the primary balance path,
//   - `GET /events` + `GET /nullifiers` for the key-only trial-decrypt fallback,
//   - `GET /head` + `GET /path/{leafIndex}` to build a spend's membership witness.
//
// The /notes auth URL is built with the sdk EdDSA-Poseidon signer (byte-identical to
// the indexer's verifier) — the wallet proves control of its OWN key, so only it can
// read its own notes even though the arbiter indexer holds everyone's (SPEC §6b v2).

import { signNotesAuth, notesAuthMessage, packSignature } from "@bongtu/sdk/eddsa";
import { unpackPubkey } from "@bongtu/sdk/pubkey";

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  const text = await res.text();
  if (!res.ok) throw new Error(`${url} -> ${res.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text) as T;
}

const trim = (u: string): string => u.replace(/\/$/, "");

/** One owner note as the arbiter indexer's `GET /notes` returns it (apps/indexer/src/ledger.ts). */
export interface OwnerNote {
  owner: [string, string];
  value: string;
  salt: string;
  leafIndex: number;
  commitment: string;
  txHash: string;
  spent: boolean;
}

/** One `GET /events` entry (the subset the wallet trial-decrypts). */
export interface FeedEvent {
  seq: number;
  txHash: string;
  blockNumber: number;
  kind: "deposit" | "transfer" | "withdraw" | "disburse";
  epoch: number | null;
  ecdhPublicKey: [string, string] | null;
  encryptionNonce: string | null;
  slices: { offset: number; elts: number; leafIndex: number | null }[];
  ciphertext: string[];
  disclosure?: string;
}

export interface Head {
  root: string;
  nextLeafIndex: number;
}
export interface PathResult {
  leafIndex: number;
  siblings: string[];
  pathIndices: number[];
  root: string;
}

export function getHead(indexerUrl: string): Promise<Head> {
  return getJson<Head>(`${trim(indexerUrl)}/head`);
}

/** Merkle path of a leaf against the current root. A within-batch (disburse) leaf is
 *  a 422 in public mode — the caller surfaces that (spend needs the arbiter indexer). */
export function getPath(indexerUrl: string, leafIndex: number): Promise<PathResult> {
  return getJson<PathResult>(`${trim(indexerUrl)}/path/${leafIndex}`);
}

export function getEvents(indexerUrl: string, limit = 5000): Promise<FeedEvent[]> {
  return getJson<FeedEvent[]>(`${trim(indexerUrl)}/events?limit=${limit}`);
}

export function getNullifiers(indexerUrl: string): Promise<string[]> {
  return getJson<string[]>(`${trim(indexerUrl)}/nullifiers`);
}

/**
 * Build the signed `GET /notes` URL for an owner (SPEC §6b v2 read-auth). The
 * signature is over Poseidon(ownerPub.x, ownerPub.y, ts) and must verify against the
 * queried compressed pubkey, so the caller must hold that owner's private scalar —
 * the wallet signs with the key it just derived.
 */
export function buildNotesUrl(
  indexerUrl: string,
  ownerCompressed: string,
  ownerPrivateKey: bigint,
): string {
  const pub = unpackPubkey(ownerCompressed.trim()); // validates the compressed pubkey
  const ts = Math.floor(Date.now() / 1000);
  const msg = notesAuthMessage(pub, ts);
  const sig = signNotesAuth(ownerPrivateKey, msg);
  return `${trim(indexerUrl)}/notes?owner=${encodeURIComponent(ownerCompressed.trim())}&ts=${ts}&sig=${packSignature(sig)}`;
}

export function fetchNotes(url: string): Promise<OwnerNote[]> {
  return getJson<OwnerNote[]>(url);
}
