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
import { buildNameRegistration } from "@bongtu/core/indexerApi";
import { stealthKeysFromScalars } from "@bongtu/core/stealth";
import { NameRegistry, normalizeName } from "../src/names.js";
import { nameRegister, nameResolve } from "../src/api/routes/names.js";
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

test("unknown and non-canonical GET names", async () => {
  const { ix } = freshIx();
  assert.equal((await call(nameResolve, ix, undefined, ["nosuch"])).status, 404);
  assert.equal((await call(nameResolve, ix, undefined, ["-bad"])).status, 400);
  // Uppercase in the path canonicalizes to the registered name.
  await call(nameRegister, ix, buildNameRegistration("alice", ownerCompressed, OWNER.formattedPrivateKey, META));
  assert.equal((await call(nameResolve, ix, undefined, ["Alice"])).status, 200);
});
