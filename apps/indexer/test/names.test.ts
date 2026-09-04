// Headless gate for the name directory (/names routes + NameRegistry). No
// Postgres: the registry runs pool-less (the write-through is the only part not
// covered here; the conformance gate exercises it against real Postgres).
// What's under test: the registration auth (payload-bound signature, replay
// window), the ownership-transition rule, and the client/server loop — the
// body posted is built by the ONE client implementation in
// @bongtu/core/indexerApi, the same closing-the-loop pattern the view-token
// suite uses.

import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveKeypair } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import {
  buildNameRegistration,
  buildNameRegistrationV2,
  NOTE_VIEW_PUB_ZERO,
  KEM_EK_ZERO,
} from "@bongtu/core/indexerApi";
import { ml_kem768 } from "@bongtu/core/kem";
import { stealthKeysFromScalars } from "@bongtu/core/stealth";
import { NameRegistry, normalizeName } from "../src/names.js";
import { handleNameRegister, nameRegister, nameResolve } from "../src/api/routes/names.js";
import type { Indexer } from "../src/ingest.js";
import type { RouteContext, RouteResult } from "../src/api/router.js";

const OWNER = deriveKeypair(123456789123456789n);
const OTHER = deriveKeypair(987654321987654321n);
const ownerCompressed = packPubkey(OWNER.publicKey);
const otherCompressed = packPubkey(OTHER.publicKey);
const META = stealthKeysFromScalars(1111n, 2222n).meta;
const META2 = stealthKeysFromScalars(3333n, 4444n).meta;

// The routes only touch ix.names; a stub Indexer around a REAL registry.
function freshIx(): { ix: Indexer; registry: NameRegistry } {
  const registry = new NameRegistry(null);
  return { ix: { names: registry } as unknown as Indexer, registry };
}

async function call(
  route: { handle: (ctx: RouteContext) => RouteResult | Promise<RouteResult> },
  ix: Indexer,
  body?: unknown,
  params: string[] = [],
): Promise<RouteResult> {
  return route.handle({ ix, tokens: null, params, query: new URLSearchParams(), body });
}

test("normalizeName: canonicalizes case/whitespace, rejects bad shapes", () => {
  assert.equal(normalizeName("  Alice-01 "), "alice-01");
  for (const badName of ["ab", "-abc", "abc-", "a".repeat(33), "al ice", "al_ice", ""]) {
    assert.equal(normalizeName(badName), null, `accepted: ${JSON.stringify(badName)}`);
  }
});

test("register -> resolve round-trip via the core client body", async () => {
  const { ix } = freshIx();
  const reg = buildNameRegistration("alice", ownerCompressed, OWNER.formattedPrivateKey, META);
  const posted = await call(nameRegister, ix, reg);
  assert.equal(posted.status, 200, JSON.stringify(posted.body));

  const got = await call(nameResolve, ix, undefined, ["alice"]);
  assert.equal(got.status, 200);
  const rec = got.body as { name: string; owner: string; viewPub: string; spendPub: string };
  assert.equal(rec.name, "alice");
  assert.equal(rec.owner, ownerCompressed);
  assert.equal(rec.viewPub, META.viewPub);
  assert.equal(rec.spendPub, META.spendPub);
});

test("same owner may update the record (stealth-meta rotation)", async () => {
  const { ix } = freshIx();
  await call(nameRegister, ix, buildNameRegistration("alice", ownerCompressed, OWNER.formattedPrivateKey, META));
  const updated = await call(
    nameRegister, ix,
    buildNameRegistration("alice", ownerCompressed, OWNER.formattedPrivateKey, META2),
  );
  assert.equal(updated.status, 200);
  const got = await call(nameResolve, ix, undefined, ["alice"]);
  assert.equal((got.body as { spendPub: string }).spendPub, META2.spendPub);
});

test("a different owner cannot take or overwrite a registered name", async () => {
  const { ix } = freshIx();
  await call(nameRegister, ix, buildNameRegistration("alice", ownerCompressed, OWNER.formattedPrivateKey, META));
  const stolen = await call(
    nameRegister, ix,
    buildNameRegistration("alice", otherCompressed, OTHER.formattedPrivateKey, META2),
  );
  assert.equal(stolen.status, 409);
  const got = await call(nameResolve, ix, undefined, ["alice"]);
  assert.equal((got.body as { owner: string }).owner, ownerCompressed); // unchanged
});

test("the signature binds the exact payload: any spliced field is a 401", async () => {
  const { ix } = freshIx();
  const reg = buildNameRegistration("alice", ownerCompressed, OWNER.formattedPrivateKey, META);
  for (const tamper of [
    { ...reg, name: "mallory" },
    { ...reg, viewPub: META2.viewPub },
    { ...reg, spendPub: META2.spendPub },
    { ...reg, ts: reg.ts + 1 },
    { ...reg, owner: otherCompressed },
  ]) {
    const r = await call(nameRegister, ix, tamper);
    assert.equal(r.status, 401, `accepted tampered ${JSON.stringify(Object.keys(tamper))}`);
  }
  // A signature by the WRONG key over the right payload also fails.
  const forged = { ...buildNameRegistration("alice", ownerCompressed, OTHER.formattedPrivateKey, META) };
  assert.equal((await call(nameRegister, ix, forged)).status, 401);
});

test("ts outside the replay window is rejected either direction", async () => {
  const { ix } = freshIx();
  const now = Math.floor(Date.now() / 1000);
  for (const ts of [now - 400, now + 400]) {
    const reg = buildNameRegistration("alice", ownerCompressed, OWNER.formattedPrivateKey, META, ts);
    assert.equal((await call(nameRegister, ix, reg)).status, 401);
  }
});

test("replay-window boundary is exact under an injected clock: now-300 in, now-301 out", async () => {
  // The wall-clock window test above can only probe far outside the window (a
  // slow runner drifts seconds between build and check); the injectable
  // nowSeconds pins the clock so the EXACT boundary second is assertable.
  const { ix } = freshIx();
  const now = 1_700_000_000;
  const post = (ts: number) =>
    handleNameRegister(
      {
        ix,
        tokens: null,
        params: [],
        query: new URLSearchParams(),
        body: buildNameRegistration("alice", ownerCompressed, OWNER.formattedPrivateKey, META, ts),
      },
      now,
    );
  assert.equal((await post(now - 300)).status, 200, "the boundary second in the past must pass");
  assert.equal((await post(now + 300)).status, 200, "the boundary second in the future must pass");
  assert.equal((await post(now - 301)).status, 401, "one second beyond the window must fail");
  assert.equal((await post(now + 301)).status, 401, "one second beyond the window must fail (future)");
});

test("malformed inputs are the caller's 400, not a 500", async () => {
  const { ix } = freshIx();
  const reg = buildNameRegistration("alice", ownerCompressed, OWNER.formattedPrivateKey, META);
  assert.equal((await call(nameRegister, ix, undefined)).status, 400);
  assert.equal((await call(nameRegister, ix, { ...reg, ts: "12" })).status, 400);
  assert.equal((await call(nameRegister, ix, { ...reg, name: "ab" })).status, 400);
  assert.equal((await call(nameRegister, ix, { ...reg, owner: "0x1234" })).status, 400);
  assert.equal((await call(nameRegister, ix, { ...reg, viewPub: "0xzz" })).status, 400);
  assert.equal((await call(nameRegister, ix, { ...reg, spendPub: "0x00" })).status, 400);
  // Malformed signature ENCODING fails closed as auth, not as a crash.
  assert.equal((await call(nameRegister, ix, { ...reg, sig: "0x01" })).status, 401);
});

// ---- the consumer registry triple (OPMOD §6.1/§6.4) ------------------------

const NOTE_VIEW = packPubkey(deriveKeypair(555000111222n).publicKey);
const KEM_EK_HEX = "0x" + Buffer.from(ml_kem768.keygen(new Uint8Array(64).fill(5)).publicKey).toString("hex");
const CONSUMER = { noteViewPub: NOTE_VIEW, kemEk: KEM_EK_HEX };

test("v2 register -> resolve carries the consumer triple", async () => {
  const { ix } = freshIx();
  const reg = buildNameRegistrationV2("alice", ownerCompressed, OWNER.formattedPrivateKey, META, CONSUMER);
  const posted = await call(nameRegister, ix, reg);
  assert.equal(posted.status, 200, JSON.stringify(posted.body));
  const got = await call(nameResolve, ix, undefined, ["alice"]);
  const rec = got.body as { noteViewPub?: string; kemEk?: string };
  assert.equal(rec.noteViewPub, NOTE_VIEW);
  assert.equal(rec.kemEk, KEM_EK_HEX);
});

test("v1 writes are read-only for the consumer pair (replay containment)", async () => {
  const { ix } = freshIx();
  await call(nameRegister, ix, buildNameRegistrationV2("alice", ownerCompressed, OWNER.formattedPrivateKey, META, CONSUMER));
  // A LEGACY (v1-signed) same-owner update — e.g. a captured registration
  // replayed inside the window — updates the stealth meta but must not touch
  // the consumer columns.
  const v1 = buildNameRegistration("alice", ownerCompressed, OWNER.formattedPrivateKey, META2);
  assert.equal((await call(nameRegister, ix, v1)).status, 200);
  const rec = (await call(nameResolve, ix, undefined, ["alice"])).body as {
    spendPub: string; noteViewPub?: string; kemEk?: string;
  };
  assert.equal(rec.spendPub, META2.spendPub, "legacy fields updated");
  assert.equal(rec.noteViewPub, NOTE_VIEW, "consumer pair PRESERVED across the v1 write");
  assert.equal(rec.kemEk, KEM_EK_HEX);
});

test("v2 clear: signing the zero-sentinels removes the pair", async () => {
  const { ix } = freshIx();
  await call(nameRegister, ix, buildNameRegistrationV2("alice", ownerCompressed, OWNER.formattedPrivateKey, META, CONSUMER));
  const cleared = await call(
    nameRegister, ix,
    buildNameRegistrationV2("alice", ownerCompressed, OWNER.formattedPrivateKey, META, "clear"),
  );
  assert.equal(cleared.status, 200, JSON.stringify(cleared.body));
  const rec = (await call(nameResolve, ix, undefined, ["alice"])).body as { noteViewPub?: string; kemEk?: string };
  assert.equal(rec.noteViewPub, undefined);
  assert.equal(rec.kemEk, undefined);
});

test("required-together + validation: half pairs and malformed material are 400s", async () => {
  const { ix } = freshIx();
  const reg = buildNameRegistrationV2("alice", ownerCompressed, OWNER.formattedPrivateKey, META, CONSUMER);
  const dropKem: Record<string, unknown> = { ...reg };
  delete dropKem.kemEk;
  assert.equal((await call(nameRegister, ix, dropKem)).status, 400, "noteViewPub without kemEk");
  const dropView: Record<string, unknown> = { ...reg };
  delete dropView.noteViewPub;
  assert.equal((await call(nameRegister, ix, dropView)).status, 400, "kemEk without noteViewPub");
  // A lone sentinel is the half-identity again.
  assert.equal((await call(nameRegister, ix, { ...reg, kemEk: KEM_EK_ZERO })).status, 400, "lone kemEk sentinel");
  assert.equal((await call(nameRegister, ix, { ...reg, noteViewPub: NOTE_VIEW_PUB_ZERO })).status, 400, "lone noteViewPub sentinel");
  // Malformed material dies before auth.
  assert.equal((await call(nameRegister, ix, { ...reg, noteViewPub: "0xzz" })).status, 400, "unparseable noteViewPub");
  assert.equal((await call(nameRegister, ix, { ...reg, kemEk: "0x" + "ab".repeat(10) })).status, 400, "wrong-length kemEk");
});

test("form selection is deterministic: cross-form payloads are 401s, splices too", async () => {
  const { ix } = freshIx();
  // A v1 signature with the consumer fields spliced on: the payload SHAPE
  // selects v2, whose message the v1 signature cannot satisfy.
  const v1 = buildNameRegistration("alice", ownerCompressed, OWNER.formattedPrivateKey, META);
  assert.equal((await call(nameRegister, ix, { ...v1, ...CONSUMER })).status, 401, "v1 sig on a v2-shaped payload");
  // A v2 signature with the fields stripped: shape selects v1 — rejected too.
  const v2 = buildNameRegistrationV2("alice", ownerCompressed, OWNER.formattedPrivateKey, META, CONSUMER);
  const stripped: Record<string, unknown> = { ...v2 };
  delete stripped.noteViewPub;
  delete stripped.kemEk;
  assert.equal((await call(nameRegister, ix, stripped)).status, 401, "v2 sig on a v1-shaped payload");
  // Splicing a different noteViewPub under a captured v2 signature.
  const otherView = packPubkey(deriveKeypair(999888777n).publicKey);
  assert.equal((await call(nameRegister, ix, { ...v2, noteViewPub: otherView })).status, 401, "spliced noteViewPub");
});

test("unknown and non-canonical GET names", async () => {
  const { ix } = freshIx();
  assert.equal((await call(nameResolve, ix, undefined, ["nosuch"])).status, 404);
  assert.equal((await call(nameResolve, ix, undefined, ["-bad"])).status, 400);
  // Uppercase in the path canonicalizes to the registered name.
  await call(nameRegister, ix, buildNameRegistration("alice", ownerCompressed, OWNER.formattedPrivateKey, META));
  assert.equal((await call(nameResolve, ix, undefined, ["Alice"])).status, 200);
});
