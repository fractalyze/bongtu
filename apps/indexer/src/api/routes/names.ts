// The name-directory endpoints (PUBLIC — registered in both modes; a name maps
// to public identity material only: the payment name, the owner's compressed
// bjj pubkey, and the stealth meta-address):
//
//   GET  /names/:name  -> NameRecord | 404
//   POST /names { name, owner, viewPub, spendPub, ts, sig } -> NameRecord
//
// Registration auth mirrors the signed /notes read: the owner signs
// Poseidon(ownerPub.x, ownerPub.y, binding, ts, NAME_AUTH tag) where `binding`
// digests the full (name, viewPub, spendPub) payload — so a signature authorises
// exactly ONE mapping (a relay cannot splice a different stealth meta under a
// captured signature), the domain tag keeps it unredeemable as any other
// signature in the system, and |now - ts| <= 300s bounds replay. Within that
// window a replay is a no-op: it re-asserts the identical record.
//
// Ownership rule (names.ts): first-come per name; same-owner update allowed;
// different owner -> 409 with no detail beyond the taken name.

import type { Route, RouteResult } from "../router.js";
import { unpackPubkey } from "@bongtu/core/pubkey";
import {
  nameAuthMessage,
  nameBindingField,
  parseSignature,
  verifyNotesAuth,
} from "@bongtu/core/eddsa";
import { validateStealthMetaAddress } from "@bongtu/core/stealth";
import { normalizeName } from "../../names.js";

const WINDOW_SECONDS = 300; // same replay bound as the signed /notes query

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

export const nameRegister: Route = {
  method: "POST",
  pattern: "/names",
  async handle({ ix, body }) {
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
    let ownerPub;
    try {
      ownerPub = unpackPubkey(b.owner);
    } catch (e) {
      return bad({ error: `malformed compressed owner pubkey: ${(e as Error).message}` });
    }
    try {
      validateStealthMetaAddress({ viewPub: b.viewPub, spendPub: b.spendPub });
    } catch (e) {
      return bad({ error: `malformed stealth meta-address: ${(e as Error).message}` });
    }
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isInteger(b.ts) || Math.abs(now - b.ts) > WINDOW_SECONDS) {
      return { status: 401, body: { error: `stale ts (|now - ts| must be <= ${WINDOW_SECONDS}s)` } };
    }
    let sigOk = false;
    try {
      const msg = nameAuthMessage(ownerPub, nameBindingField(name, b.viewPub, b.spendPub), b.ts);
      sigOk = verifyNotesAuth(ownerPub, msg, parseSignature(b.sig));
    } catch {
      sigOk = false; // malformed signature encoding fails like a wrong one
    }
    if (!sigOk) {
      return { status: 401, body: { error: "signature does not verify for this registration" } };
    }
    const outcome = await ix.names.register(
      { name, owner: b.owner, viewPub: b.viewPub, spendPub: b.spendPub },
      now,
    );
    if (!outcome.ok) {
      return { status: 409, body: { error: "name is registered to another owner", name } };
    }
    return { status: 200, body: outcome.record };
  },
};
