// The portal-deposit endpoints (PUBLIC — registered in both modes; every datum
// here is public: the announcement half is what a withdraw announcement already
// publishes on-chain, and the attribution half is the public name directory):
//
//   POST /pay/{name}              -> PortalIssuance | 404 unknown name | 400
//                                    non-canonical | 404 factory unconfigured
//   GET  /portal/announcements?cursor=&limit=  -> PortalRecord[] (full feed)
//   GET  /portal/unswept?cursor=&limit=        -> PortalRecord[] (bot work feed)
//
// POST /pay is the resolve-time issuance the Slice ⑤ design demands: a CEX
// sender can never announce, so the ISSUER records the announcement when it
// hands out the address. The ephemeral scalar is drawn server-side and
// DISCARDED after derivation — the resolver keeps nothing beyond what the
// announcement itself publishes, so it can only derive the public destination,
// never spend from it (spending needs the recipient's secp spend key, which
// never exists here). The destination is fetched by eth_call
// `factory.addressOf(portalSalt(stealthAddr))` through the indexer's chain
// client rather than recomputed locally: the chain is the one owner of the
// initcode-hash fact.
//
// RECORDED BOUNDARY (PoC spam surface, deliberate): issuance is unauthenticated
// — anyone who can resolve a name can mint issuance rows, so /portal/unswept is
// floodable with never-funded records. The bot must treat rows as HINTS (sweep
// only funded addresses); rate limiting / proof-of-payment gating is future
// work, stated here rather than hidden.
//
// Portal records live on their OWN cursor feed (not inside /announcements):
// issuance has no chain tx, so its seq space is the registry's issuance order,
// not the event feed's — mixing the two spaces in one cursor-paged route would
// break paging. The wallet scans both feeds with the same view key
// (scanStealthAnnouncement), then maps a portal match through
// portalSalt/create2Address (@bongtu/core/stealth) to confirm `destination`.

import type { Route, RouteContext, RouteResult } from "../router.js";
import type { PortalIssuance, PortalRecord } from "@bongtu/core/indexerApi";
import { deriveStealthAddress, portalSalt, randomEphemeralScalar } from "@bongtu/core/stealth";
import { normalizeName } from "../../names.js";

const DEFAULT_LIMIT = 5000;

const unconfigured = (): RouteResult => ({
  status: 404,
  body: { error: "portal deposits are not configured on this indexer (PORTAL_FACTORY unset)" },
});

/**
 * The issuance handler with injectable randomness + clock so the derived
 * destination is deterministic under test (the handleNameRegister seam pattern).
 * The route always defaults both.
 */
export async function handlePayPortal(
  { ix, params }: RouteContext,
  drawScalar: () => bigint = randomEphemeralScalar,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): Promise<RouteResult> {
  const factory = ix.cfg.portalFactory ?? null;
  // portalAddressOf is the EVM-only host capability (src/host.ts): absent on
  // the Solana engine, where a configured factory address has no chain to
  // resolve against — same 404 as an unset PORTAL_FACTORY.
  if (!factory || !ix.portalAddressOf) return unconfigured();
  const name = normalizeName(params[0]);
  if (!name) {
    return { status: 400, body: { error: "invalid name: 3-32 chars, lowercase a-z 0-9, interior hyphens" } };
  }
  const record = ix.names.resolve(name);
  if (!record) return { status: 404, body: { error: "name not registered", name } };

  // Derive, then let the scalar go out of scope: only the PUBLIC derivation
  // (ephemeralPub, viewTag, stealthAddr) survives this call — see the module
  // header for why the resolver must hold nothing more.
  const derived = deriveStealthAddress(
    { viewPub: record.viewPub, spendPub: record.spendPub },
    drawScalar(),
  );
  const destination = await ix.portalAddressOf(portalSalt(derived.address));
  const issued = await ix.portal.issue(
    {
      name,
      owner: record.owner,
      ephemeralPub: derived.ephemeralPub,
      viewTag: derived.viewTag,
      stealthAddr: derived.address,
      destination,
    },
    nowSeconds,
  );
  const body: PortalIssuance = {
    destination: issued.destination,
    ephemeralPub: issued.ephemeralPub,
    viewTag: issued.viewTag,
    stealthAddr: issued.stealthAddr,
    factory,
  };
  return { status: 200, body };
}

export const payPortal: Route = {
  method: "POST",
  pattern: /^\/pay\/([A-Za-z0-9-]{1,64})$/,
  handle: (ctx) => handlePayPortal(ctx),
};

/** Shared tail of the two feed reads: param validation + the registry read. */
function serveFeed(
  ctx: RouteContext,
  read: (cursor: number, limit: number) => PortalRecord[],
): RouteResult {
  if (!ctx.ix.cfg.portalFactory) return unconfigured();
  const cursor = Number(ctx.query.get("cursor") ?? -1);
  const limit = Number(ctx.query.get("limit") ?? DEFAULT_LIMIT);
  if (!Number.isInteger(cursor) || !Number.isInteger(limit) || limit <= 0) {
    return { status: 400, body: { error: "cursor/limit must be integers (limit > 0)" } };
  }
  return { status: 200, body: read(cursor, limit) };
}

export const portalAnnouncements: Route = {
  method: "GET",
  pattern: "/portal/announcements",
  handle: (ctx) => serveFeed(ctx, (c, l) => ctx.ix.portal.list(c, l)),
};

export const portalUnswept: Route = {
  method: "GET",
  pattern: "/portal/unswept",
  handle: (ctx) => serveFeed(ctx, (c, l) => ctx.ix.portal.unswept(c, l)),
};
