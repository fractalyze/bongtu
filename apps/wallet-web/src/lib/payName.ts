// The wallet's "my payment name" lookup seam + the one-time deposit address
// client, behind the Receive panel's portal surface.
//
// The wallet has NO registry of its own name — names are registered against the
// indexer's public /names directory (possibly by the institution, possibly by
// the user through another tool), and the issuance route (POST /pay/{name}) is
// name-keyed. So the seam here is a LOOKUP, not a registry: the user claims a
// name once, `verifyOwnName` checks the claim against the directory (the
// record's owner must be the session's own bjj pubkey — a foreign name never
// passes), and the accepted claim is remembered per owner in localStorage.
// Every later session re-checks the remembered claim before trusting it, so a
// name whose directory record stopped pointing at this owner silently un-links
// instead of issuing addresses that pay someone else's meta keys.
//
// Storage discipline follows lockIntro.ts: not key material (a payment name is
// public directory data), best-effort writes, unreadable storage == no claim.

import type { StorageLike } from "@bongtu/client/session";
import { normalizeName, payPortal, resolveName } from "@bongtu/client/indexerClient";

export const PAY_NAME_KEY = "bongtu.payName.v1";

function defaultStorage(): StorageLike | null {
  try {
    return (globalThis as { localStorage?: StorageLike }).localStorage ?? null;
  } catch {
    return null; // storage blocked (private mode / hard privacy settings)
  }
}

/** The remembered claim for THIS owner, or null. A record left by a different
 *  session owner is not an answer — the claim is per-pubkey, never per-device. */
export function recallPayName(
  ownerCompressed: string,
  storage: StorageLike | null = defaultStorage(),
): string | null {
  try {
    const raw = storage?.getItem(PAY_NAME_KEY);
    if (!raw) return null;
    const rec = JSON.parse(raw) as { owner?: unknown; name?: unknown };
    return typeof rec.owner === "string" &&
      typeof rec.name === "string" &&
      rec.owner.toLowerCase() === ownerCompressed.toLowerCase()
      ? rec.name
      : null;
  } catch {
    return null;
  }
}

/** Remember an accepted claim (best-effort — a blocked storage just means the
 *  next session asks again). */
export function rememberPayName(
  ownerCompressed: string,
  name: string,
  storage: StorageLike | null = defaultStorage(),
): void {
  try {
    storage?.setItem(PAY_NAME_KEY, JSON.stringify({ owner: ownerCompressed, name }));
  } catch {
    // quota/privacy-mode write failure — the claim is a convenience only.
  }
}

/**
 * Check a claimed name against the directory: it must normalize, resolve, and
 * — the load-bearing check — belong to THIS session's owner key. Returns the
 * canonical (normalized) name, or null for "not yours / not registered".
 * Network failures propagate: "the indexer is down" must not read as "you have
 * no name".
 */
export async function verifyOwnName(
  indexerUrl: string,
  name: string,
  ownerCompressed: string,
  resolve: typeof resolveName = resolveName,
): Promise<string | null> {
  const canonical = normalizeName(name);
  if (!canonical) return null;
  const record = await resolve(indexerUrl, canonical);
  if (!record) return null;
  return record.owner.toLowerCase() === ownerCompressed.toLowerCase() ? canonical : null;
}

/** The session-open detection path: re-check the remembered claim (if any).
 *  A claim that no longer resolves to this owner yields null — the surface
 *  disables rather than issuing against a stale mapping. */
export async function detectPayName(
  indexerUrl: string,
  ownerCompressed: string,
  deps: { resolve?: typeof resolveName; storage?: StorageLike | null } = {},
): Promise<string | null> {
  const storage = deps.storage === undefined ? defaultStorage() : deps.storage;
  const remembered = recallPayName(ownerCompressed, storage);
  if (!remembered) return null;
  return verifyOwnName(indexerUrl, remembered, ownerCompressed, deps.resolve ?? resolveName);
}

/** The distinct copy for the factory-unconfigured 404 — a deployment state,
 *  not a user mistake, so it must not read like one. */
export const PORTAL_UNCONFIGURED_MESSAGE =
  "One-time deposit addresses aren't set up on this indexer yet.";

export type IssueOutcome =
  | { ok: true; destination: string }
  | { ok: false; unconfigured: boolean; message: string };

/**
 * Issue one fresh portal destination for `name`. The server mints a NEW record
 * per call (single-use-fresh per payer), so callers invoke this once per
 * intended payment. The unconfigured-factory 404 (the server names
 * PORTAL_FACTORY in its body) maps to its own message; every other failure
 * surfaces the thrown text as-is (the SpendScreen resolve-error posture).
 */
export async function issueOneTimeAddress(
  indexerUrl: string,
  name: string,
  pay: typeof payPortal = payPortal,
): Promise<IssueOutcome> {
  try {
    const issued = await pay(indexerUrl, name);
    return { ok: true, destination: issued.destination };
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    const unconfigured = message.includes("404") && message.includes("not configured");
    return { ok: false, unconfigured, message: unconfigured ? PORTAL_UNCONFIGURED_MESSAGE : message };
  }
}
