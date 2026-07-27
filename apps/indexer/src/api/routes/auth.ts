// View-token auth endpoints (ARBITER MODE ONLY — registered with /notes and
// /history, the routes the token unlocks; public mode 404s them):
//
//   GET  /auth/challenge?owner=<compressed>  -> { challenge, expiresAt, hostBindings }
//   POST /auth  { owner, challenge, sig }    -> { token, exp }
//
// The signature is the SAME bjj EdDSA-Poseidon primitive the signed /notes query
// uses, over the domain-separated, host-bound tuple Poseidon(ownerPub.x,
// ownerPub.y, challenge, hostBinding, VIEWTOKEN_DOMAIN_TAG) — proving control of
// the queried key once; the returned token then authorises /notes + /history reads
// until it expires (~24h). Nothing else in the system accepts the token.
// Redemption failures are one undifferentiated 401 so a probe cannot learn which
// check (challenge liveness, owner binding, signature) failed.

import type { Route, RouteResult } from "../router.js";

const bad = (body: unknown): RouteResult => ({ status: 400, body });

// Both routes are registered only in arbiter mode, which always builds a token
// service — so a null one means the server was assembled wrong, not that the
// caller did anything. Say so instead of throwing a 500 from a null deref.
const noService = (): RouteResult => ({
  status: 503,
  body: { error: "view tokens are not available on this indexer" },
});

export const authChallenge: Route = {
  method: "GET",
  pattern: "/auth/challenge",
  handle({ tokens, query }) {
    if (!tokens) return noService();
    const owner = query.get("owner");
    if (!owner) {
      return bad({ error: "owner query param required: a compressed bjj pubkey (32-byte hex)" });
    }
    try {
      return { status: 200, body: tokens.issueChallenge(owner) };
    } catch (e) {
      return bad({ error: `malformed compressed owner pubkey: ${(e as Error).message}`, owner });
    }
  },
};

export const authRedeem: Route = {
  method: "POST",
  pattern: "/auth",
  handle({ tokens, body }) {
    if (!tokens) return noService();
    const b = body as { owner?: unknown; challenge?: unknown; sig?: unknown } | undefined;
    if (
      !b ||
      typeof b.owner !== "string" ||
      typeof b.challenge !== "string" ||
      typeof b.sig !== "string"
    ) {
      return bad({ error: "JSON body required: { owner, challenge, sig } (all strings)" });
    }
    const issued = tokens.redeemChallenge(b.owner, b.challenge, b.sig);
    if (!issued) {
      return { status: 401, body: { error: "challenge redemption failed (unknown/expired challenge, or signature does not verify)" } };
    }
    return { status: 200, body: issued };
  },
};
