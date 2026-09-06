// The portal/receive endpoints:
//
//   POST /pay/{name}              -> PortalIssuance | 404 unknown name | 400
//                                    non-canonical | 404 factory unconfigured
//                                    (PUBLIC — server-side issuance, portal pair)
//   POST /portal/announce         -> PortalPublicRecord | 404 unknown label or
//                                    RECEIVE_FACTORY unconfigured | 400 bad
//                                    shape | 409 stealth address already
//                                    recorded (PUBLIC — pay-page issuance)
//   GET  /portal/announcements?cursor=&limit= -> PortalPublicRecord[] (PUBLIC:
//                                    the ATTRIBUTION-FREE projection — no name,
//                                    no owner; the recipient scan path)
//   GET  /portal/unswept?cursor=&limit=       -> PortalRecord[] (OPERATOR: the
//                                    attributed bot work feed; 401 without the
//                                    x-operator-token header once
//                                    PORTAL_OPERATOR_TOKEN is set)
//
// POST /pay is the resolve-time issuance the Slice ⑤ design demands: a CEX
// sender can never announce, so the ISSUER records the announcement when it
// hands out the address (server-drawn scalar, DISCARDED after derivation).
// POST /portal/announce is the receive-product twin with the derivation moved
// into the VISITOR'S BROWSER: the page derives from the record's public keys,
// announces BEFORE displaying the address, and the server (1) recomputes the
// destination itself via the receive factory's addressOf — it never trusts a
// client destination — and (2) rejects a stealth address already recorded, so
// first write wins: a hijacker re-announcing an observed destination under its
// own label always loses the race to the honest record.
//
// RECORDED BOUNDARY (PoC spam surface, deliberate): both write routes are
// unauthenticated — anyone can mint rows, so the work feed is floodable with
// never-funded records. The bot must treat rows as HINTS (sweep only funded
// addresses); rate limiting is ops, stated here rather than hidden.
//
// ATTRIBUTION SPLIT (spec R4): the public feed serves records through
// `toPublic` — no name/owner field at all. The attributed rows the sweep bot
// needs stay behind the operator token. The recipient never needs attribution:
// its view key re-derives which records are its own.
//
// Portal records live on their OWN cursor feed (not inside /announcements):
// issuance has no chain tx, so its seq space is the registry's issuance order,
// not the event feed's — mixing the two spaces in one cursor-paged route would
// break paging. The wallet scans both feeds with the same view key
// (scanStealthAnnouncement), then maps a portal match through
// portalSalt/create2Address (@bongtu/core/stealth) to confirm `destination`.

import type { Route, RouteContext, RouteResult } from "../router.js";
import type { PortalIssuance, PortalPublicRecord, PortalRecord } from "@bongtu/core/indexerApi";
import {
  deriveStealthAddress,
  isStealthAnnouncement,
  portalSalt,
  randomEphemeralScalar,
} from "@bongtu/core/stealth";
import { normalizeName } from "../../names.js";
import { toPublic } from "../../portal.js";

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
      factory,
      rail: "evm",
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

/** The POST /portal/announce body, shape-checked field by field (unknown JSON
 *  in, so every field is validated before use). */
function parseAnnounceBody(body: unknown): { label: string; ephemeralPub: string; viewTag: number; stealthAddr: string } | null {
  if (typeof body !== "object" || body === null) return null;
  const b = body as Record<string, unknown>;
  if (typeof b.label !== "string" || typeof b.ephemeralPub !== "string" || typeof b.stealthAddr !== "string") return null;
  if (typeof b.viewTag !== "number" || !Number.isInteger(b.viewTag) || b.viewTag < 0 || b.viewTag > 255) return null;
  if (b.rail !== undefined && b.rail !== "evm") return null; // the one shipped flavor
  if (!isStealthAnnouncement(b.ephemeralPub)) return null;
  if (!/^0x[0-9a-fA-F]{40}$/.test(b.stealthAddr)) return null;
  return { label: b.label, ephemeralPub: b.ephemeralPub, viewTag: b.viewTag, stealthAddr: b.stealthAddr };
}

/** The pay-page announce handler (clock injectable, the handlePayPortal seam). */
export async function handlePortalAnnounce(
  { ix, body }: RouteContext,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): Promise<RouteResult> {
  const factory = ix.cfg.receiveFactory ?? null;
  if (!factory || !ix.receiveAddressOf) {
    return { status: 404, body: { error: "receive deposits are not configured on this indexer (RECEIVE_FACTORY unset)" } };
  }
  const parsed = parseAnnounceBody(body);
  if (!parsed) {
    return { status: 400, body: { error: "bad announce body: need { label, ephemeralPub (32-byte hex, nonzero), viewTag (0-255), stealthAddr (20-byte hex) }" } };
  }
  const name = normalizeName(parsed.label);
  if (!name) {
    return { status: 400, body: { error: "invalid label: 3-32 chars, lowercase a-z 0-9, interior hyphens" } };
  }
  const record = ix.names.resolve(name);
  if (!record) return { status: 404, body: { error: "label not registered", name } };
  // First write wins (spec C4): the page announces BEFORE displaying, so the
  // honest record always exists before anyone could observe the destination.
  if (ix.portal.hasStealth(parsed.stealthAddr)) {
    return { status: 409, body: { error: "stealth address already recorded", stealthAddr: parsed.stealthAddr.toLowerCase() } };
  }
  // The server recomputes the destination — a client-sent destination would
  // let an announcer redirect the display address away from the salt it
  // announces, so no such field is even accepted.
  const destination = await ix.receiveAddressOf(portalSalt(parsed.stealthAddr));
  const issued = await ix.portal.issue(
    {
      name,
      owner: record.owner,
      ephemeralPub: parsed.ephemeralPub,
      viewTag: parsed.viewTag,
      stealthAddr: parsed.stealthAddr,
      destination,
      factory,
      rail: "evm",
    },
    nowSeconds,
  );
  return { status: 200, body: toPublic(issued) };
}

export const portalAnnounce: Route = {
  method: "POST",
  pattern: "/portal/announce",
  handle: (ctx) => handlePortalAnnounce(ctx),
};

/** Shared tail of the two feed reads: param validation + the registry read.
 *  Feeds answer when EITHER factory is configured (each row names its own). */
function serveFeed<T extends PortalPublicRecord>(
  ctx: RouteContext,
  read: (cursor: number, limit: number) => T[],
): RouteResult {
  if (!ctx.ix.cfg.portalFactory && !ctx.ix.cfg.receiveFactory) return unconfigured();
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
  handle: (ctx) => serveFeed(ctx, (c, l) => ctx.ix.portal.listPublic(c, l)),
};

/** The operator gate (spec C3): PORTAL_OPERATOR_TOKEN set => the attributed
 *  work feed requires the same value in x-operator-token; unset => open (the
 *  depositor-facing local flows keep working). A plain shared secret, compared
 *  here and never echoed. */
export const portalUnswept: Route = {
  method: "GET",
  pattern: "/portal/unswept",
  handle: (ctx): RouteResult => {
    const want = ctx.ix.cfg.portalOperatorToken ?? null;
    if (want !== null && ctx.headers?.["x-operator-token"] !== want) {
      return { status: 401, body: { error: "operator token required (x-operator-token header)" } };
    }
    return serveFeed<PortalRecord>(ctx, (c, l) => ctx.ix.portal.unswept(c, l));
  },
};
