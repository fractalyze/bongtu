// The name-directory endpoints (PUBLIC — registered in both modes; a name maps
// to public identity material only: the payment name, the owner's compressed
// bjj pubkey, the stealth meta-address, and — post-op-module — the consumer
// triple's note-layer viewPub + ML-KEM ek):
//
//   GET  /names/:name  -> NameRecord | 404
//   POST /names { name, owner, viewPub, spendPub, [noteViewPub, kemEk,] ts, sig }
//                      -> NameRecord
//
// Registration auth is the payload-bound half of the ONE owner-signed protocol
// (api/readAuth.ts authorizeSignedPayload): the owner signs
// Poseidon(ownerPub.x, ownerPub.y, binding, ts, TAG) where `binding` digests
// the full payload — so a signature authorises exactly ONE mapping (a relay
// cannot splice a different stealth meta or consumer triple under a captured
// signature), the domain tag keeps it unredeemable as any other signature in
// the system, and readAuth's shared replay window bounds replay.
//
// TWO signature forms, selected DETERMINISTICALLY by payload shape (OPMOD
// §6.4 — no dual-try fallback):
//   v1  payload carries NEITHER new key: 3-segment binding under
//       bongtu/name-auth-v1. A v1 write can NEVER set, change or clear the
//       consumer columns — the registry preserves them, so a replayed legacy
//       registration re-asserts only what it already bound.
//   v2  payload carries BOTH new keys (one without the other is a 400 — an
//       unusable half-identity): 5-segment binding under bongtu/name-auth-v2.
//       Signing the full-width zero-sentinels for both is the explicit CLEAR.
//
// Ownership rule (names.ts): first-come per name; same-owner update allowed;
// different owner -> 409 with no detail beyond the taken name.

import type { Route, RouteContext, RouteResult } from "../router.js";
import { authorizeSignedPayload } from "../readAuth.js";
import {
  nameAuthMessage,
  nameBindingField,
  nameAuthMessageV2,
  nameBindingFieldV2,
  NOTE_VIEW_PUB_ZERO,
  KEM_EK_ZERO,
} from "@bongtu/core/eddsa";
import { validateStealthMetaAddress } from "@bongtu/core/stealth";
import { unpackPubkey } from "@bongtu/core/pubkey";
import { kemHexToBytes, ml_kem768, KEM_PUBLIC_KEY_BYTES } from "@bongtu/core/kem";
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
    | {
        name?: unknown; owner?: unknown; viewPub?: unknown; spendPub?: unknown;
        noteViewPub?: unknown; kemEk?: unknown; ts?: unknown; sig?: unknown;
      }
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
      error: "JSON body required: { name, owner, viewPub, spendPub (strings), [noteViewPub, kemEk (strings, together)], ts (number), sig (string) }",
    });
  }
  // OPMOD §6.1: the consumer pair is required-together — a viewPub without an
  // ek (or vice versa) is an unusable half-identity, refused before any auth.
  const hasNote = b.noteViewPub !== undefined;
  const hasKem = b.kemEk !== undefined;
  if (hasNote !== hasKem) {
    return bad({ error: "noteViewPub and kemEk are required together (a lone half is an unusable identity)" });
  }
  const v2 = hasNote && hasKem;
  if (v2 && (typeof b.noteViewPub !== "string" || typeof b.kemEk !== "string")) {
    return bad({ error: "noteViewPub and kemEk must be strings" });
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

  // v2 payload validation: either BOTH values are the full-width zero-sentinels
  // (the explicit signed CLEAR) or both are well-formed key material — a
  // sentinel paired with a real key is the half-identity again.
  const noteViewPub = v2 ? (b.noteViewPub as string).trim() : null;
  const kemEk = v2 ? (b.kemEk as string).trim() : null;
  const clearing = v2 && noteViewPub!.toLowerCase() === NOTE_VIEW_PUB_ZERO && kemEk!.toLowerCase() === KEM_EK_ZERO;
  if (v2 && !clearing) {
    if (noteViewPub!.toLowerCase() === NOTE_VIEW_PUB_ZERO || kemEk!.toLowerCase() === KEM_EK_ZERO) {
      return bad({ error: "clearing the consumer pair requires BOTH zero-sentinels (a lone sentinel is a half-identity)" });
    }
    try {
      unpackPubkey(noteViewPub!);
    } catch (e) {
      return bad({ error: `malformed noteViewPub: ${(e as Error).message}` });
    }
    const ekErr = ((): string | null => {
      try {
        const bytes = kemHexToBytes(kemEk!);
        if (bytes.length !== KEM_PUBLIC_KEY_BYTES) {
          return `expected ${KEM_PUBLIC_KEY_BYTES} bytes, got ${bytes.length}`;
        }
        // noble's encapsulation performs the FIPS 203 input validation
        // (module-lattice range check) — cheap, and it stops a payer from
        // burning a note against garbage (OPMOD §6.2).
        ml_kem768.encapsulate(bytes);
        return null;
      } catch (e) {
        return (e as Error).message;
      }
    })();
    if (ekErr !== null) return bad({ error: `malformed kemEk: ${ekErr}` });
  }

  // Auth: readAuth's payload-bound ladder over the form-selected binding. The
  // binding closes over the ALREADY-VALIDATED fields, so what the signature is
  // checked against is exactly what the registry will store. A payload of the
  // other form's shape never reaches the other form's tag (no dual-try).
  const auth = authorizeSignedPayload(
    { owner: b.owner, ts: b.ts, sig: b.sig },
    (ownerPub, ts) =>
      v2
        ? nameAuthMessageV2(ownerPub, nameBindingFieldV2(name, viewPub, spendPub, noteViewPub!, kemEk!), ts)
        : nameAuthMessage(ownerPub, nameBindingField(name, viewPub, spendPub), ts),
    nowSeconds,
  );
  if (!auth.ok) return auth.denied;

  const outcome = await ix.names.register(
    { name, owner: b.owner, viewPub, spendPub },
    nowSeconds,
    v2 ? (clearing ? { noteViewPub: null, kemEk: null } : { noteViewPub: noteViewPub!, kemEk: kemEk! }) : undefined,
  );
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
