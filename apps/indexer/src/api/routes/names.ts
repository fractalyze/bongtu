// The name-directory endpoints (PUBLIC — registered in both modes; a name maps
// to public identity material only: the payment name, the owner's compressed
// bjj pubkey, and the stealth meta-address):
//
//   GET  /names/:name  -> NameRecord | 404
//   POST /names { name, owner, viewPub, spendPub, ts, sig } -> NameRecord
//
// Registration auth is the payload-bound half of the ONE owner-signed protocol
// (api/readAuth.ts authorizeSignedPayload): the owner signs
// Poseidon(ownerPub.x, ownerPub.y, binding, ts, NAME_AUTH tag) where `binding`
// digests the full (name, viewPub, spendPub) payload — so a signature authorises
// exactly ONE mapping (a relay cannot splice a different stealth meta under a
// captured signature), the domain tag keeps it unredeemable as any other
// signature in the system, and readAuth's shared replay window bounds replay.
// Within that window a replay is a no-op: it re-asserts the identical record.
// This route owns only what is genuinely its own: body shape, name grammar,
// stealth-meta validation, and the ownership-transition rule.
//
// Ownership rule (names.ts): first-come per name; same-owner update allowed;
// different owner -> 409 with no detail beyond the taken name.

import type { Route, RouteContext, RouteResult } from "../router.js";
import { authorizeSignedPayload } from "../readAuth.js";
import { nameAuthMessage, nameBindingField } from "@bongtu/core/eddsa";
import { validateStealthMetaAddress } from "@bongtu/core/stealth";
import { normalizeName } from "../../names.js";

const bad = (body: unknown): RouteResult => ({ status: 400, body });

export const nameResolve: Route = {
  method: "GET",
  pattern: /^\/names\/([A-Za-z0-9-]{1,64})$/,
  handle({ ix, params }) {
    const name = normalizeName(params[0]);
    if (!name) {
      return bad({ error: "invalid name: 3-32 chars, lowercase a-z 0-9, interior hyphens" });
    }
    const record = ix.names.resolve(name);
    if (!record) return { status: 404, body: { error: "name not registered", name } };
    return { status: 200, body: record };
  },
};

/**
 * The registration handler with an injectable clock — `nowSeconds` reaches both
 * the auth's replay window and the record's `updatedAt`, so the window BOUNDARY
 * is deterministically testable (names.test.ts); the route always defaults it.
 */
export async function handleNameRegister(
  { ix, body }: RouteContext,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): Promise<RouteResult> {
  const b = body as
    | { name?: unknown; owner?: unknown; viewPub?: unknown; spendPub?: unknown; ts?: unknown; sig?: unknown }
    | undefined;
  if (
    !b ||
    typeof b.name !== "string" ||
    typeof b.owner !== "string" ||
    typeof b.viewPub !== "string" ||
    typeof b.spendPub !== "string" ||
    typeof b.ts !== "number" ||
    typeof b.sig !== "string"
  ) {
    return bad({
      error: "JSON body required: { name, owner, viewPub, spendPub (strings), ts (number), sig (string) }",
    });
  }
  const name = normalizeName(b.name);
  if (!name) {
    return bad({ error: "invalid name: 3-32 chars, lowercase a-z 0-9, interior hyphens" });
  }
  const { viewPub, spendPub } = b;
  try {
    validateStealthMetaAddress({ viewPub, spendPub });
  } catch (e) {
    return bad({ error: `malformed stealth meta-address: ${(e as Error).message}` });
  }
  // Auth: readAuth's payload-bound ladder over the name-binding message. The
  // binding closes over the ALREADY-VALIDATED name/meta fields, so what the
  // signature is checked against is exactly what the registry will store.
  const auth = authorizeSignedPayload(
    { owner: b.owner, ts: b.ts, sig: b.sig },
    (ownerPub, ts) => nameAuthMessage(ownerPub, nameBindingField(name, viewPub, spendPub), ts),
    nowSeconds,
  );
  if (!auth.ok) return auth.denied;

  const outcome = await ix.names.register({ name, owner: b.owner, viewPub, spendPub }, nowSeconds);
  if (!outcome.ok) {
    return { status: 409, body: { error: "name is registered to another owner", name } };
  }
  return { status: 200, body: outcome.record };
}

export const nameRegister: Route = {
  method: "POST",
  pattern: "/names",
  handle: (ctx) => handleNameRegister(ctx),
};
