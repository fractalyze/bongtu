// Headless gate for the portal-deposit surface (Slice ⑤ U-P2), at its three
// seams:
//
//   1. ISSUANCE ROUTE — POST /pay/{name} via handlePayPortal with the two
//      injected seams (fixed ephemeral scalar, fixed clock) and a fake
//      portalAddressOf standing in for the factory eth_call: deterministic
//      destination, the recorded announcement, and the 400/404 fences.
//   2. SWEPT MARKING — a synthetic Swept ParsedLog through the REAL
//      Indexer.applyLogs (the ingest.test.ts convention: constructor reads the
//      Foundry ABI, the dummy RPC is never contacted) flips the matching
//      record; unknown salts and replays no-op.
//   3. FEEDS — /portal/unswept + /portal/announcements cursor/limit behavior
//      and the unconfigured-factory 404.
//
//   node --import tsx --test test/portal.test.ts   # (== npm run test:portal)

import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveKeypair } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import {
  create2Address,
  deriveStealthAddress,
  portalSalt,
  stealthKeysFromScalars,
} from "@bongtu/core/stealth";
import type { PortalIssuance, PortalRecord } from "@bongtu/core/indexerApi";

import { NameRegistry } from "../src/names.js";
import { PortalRegistry } from "../src/portal.js";
import { Indexer, type ParsedLog } from "../src/ingest.js";
import { handlePayPortal, payPortal, portalAnnouncements, portalUnswept } from "../src/api/routes/portal.js";
import type { RouteContext, RouteResult } from "../src/api/router.js";

const OWNER = deriveKeypair(123456789123456789n);
const ownerCompressed = packPubkey(OWNER.publicKey);
const META = stealthKeysFromScalars(1111n, 2222n).meta;

const FACTORY = "0x" + "c0".repeat(20);
const INITCODE_HASH = "0x" + "ab".repeat(32);
const EPHEMERAL = 424242424242424242424242n;
const NOW = 1_700_000_000;

// The fake chain edge: answers addressOf(salt) with the same EIP-1014 math the
// real factory implements (core create2Address is parity-pinned against it in
// packages/core/test/stealth.test.ts), so the "chain" stays internally
// consistent without an RPC.
const fakeAddressOf = async (salt: string): Promise<string> => create2Address(FACTORY, salt, INITCODE_HASH);

async function seededIx(opts: { factory?: string | null } = {}): Promise<{ ix: Indexer; portal: PortalRegistry }> {
  const registry = new NameRegistry(null);
  await registry.register({ name: "alice", owner: ownerCompressed, viewPub: META.viewPub, spendPub: META.spendPub }, NOW);
  const portal = new PortalRegistry(null);
  const ix = {
    cfg: { portalFactory: opts.factory === undefined ? FACTORY : opts.factory },
    names: registry,
    portal,
    portalAddressOf: fakeAddressOf,
  } as unknown as Indexer;
  return { ix, portal };
}

function ctx(ix: Indexer, params: string[] = [], query = ""): RouteContext {
  return { ix, tokens: null, params, query: new URLSearchParams(query) };
}

// ============================ (1) ISSUANCE ROUTE =============================

test("issuance happy path: fixed randomness -> deterministic destination, record persisted unswept", async () => {
  const { ix, portal } = await seededIx();
  const r = await handlePayPortal(ctx(ix, ["alice"]), () => EPHEMERAL, NOW);
  assert.equal(r.status, 200, JSON.stringify(r.body));

  // Expected values recomputed with the same core primitives — a drift in the
  // route's derivation (wrong meta half, a local re-pad instead of portalSalt)
  // breaks here deterministically.
  const derived = deriveStealthAddress(META, EPHEMERAL);
  const expectedDestination = create2Address(FACTORY, portalSalt(derived.address), INITCODE_HASH);
  const body = r.body as PortalIssuance;
  assert.deepEqual(body, {
    destination: expectedDestination,
    ephemeralPub: derived.ephemeralPub,
    viewTag: derived.viewTag,
    stealthAddr: derived.address,
    factory: FACTORY,
  });

  // The registry now holds the announcement with the name-owner attribution.
  const records = portal.list();
  assert.equal(records.length, 1);
  assert.deepEqual(records[0], {
    kind: "portal",
    seq: 0,
    name: "alice",
    owner: ownerCompressed,
    ephemeralPub: derived.ephemeralPub,
    viewTag: derived.viewTag,
    stealthAddr: derived.address,
    destination: expectedDestination,
    createdAt: NOW,
    swept: false,
    sweptTxHash: null,
    sweptAmount: null,
  } satisfies PortalRecord);
});

test("each issuance draws fresh randomness: two calls for one name differ", async () => {
  const { ix, portal } = await seededIx();
  await handlePayPortal(ctx(ix, ["alice"]), () => EPHEMERAL, NOW);
  await handlePayPortal(ctx(ix, ["alice"]), () => EPHEMERAL + 1n, NOW);
  const [a, b] = portal.list();
  assert.notEqual(a.stealthAddr, b.stealthAddr);
  assert.notEqual(a.destination, b.destination);
  assert.deepEqual([a.seq, b.seq], [0, 1]);
});

test("unknown name is 404, non-canonical name is 400 (the names route conventions)", async () => {
  const { ix } = await seededIx();
  const unknown = await handlePayPortal(ctx(ix, ["nosuch"]), () => EPHEMERAL, NOW);
  assert.equal(unknown.status, 404);
  assert.equal((unknown.body as { name: string }).name, "nosuch");
  const bad = await handlePayPortal(ctx(ix, ["-bad"]), () => EPHEMERAL, NOW);
  assert.equal(bad.status, 400);
  // Uppercase canonicalizes to the registered name, like GET /names.
  assert.equal((await handlePayPortal(ctx(ix, ["Alice"]), () => EPHEMERAL, NOW)).status, 200);
});

test("unconfigured factory: /pay and both /portal feeds 404 with a clear body", async () => {
  const { ix } = await seededIx({ factory: null });
  for (const r of [
    await payPortal.handle(ctx(ix, ["alice"])),
    await portalUnswept.handle(ctx(ix)),
    await portalAnnouncements.handle(ctx(ix)),
  ]) {
    assert.equal(r.status, 404);
    assert.match((r.body as { error: string }).error, /PORTAL_FACTORY/);
  }
});

// ============================ (2) SWEPT MARKING ==============================

// A real Indexer (the ingest.test.ts recipe: the ABI loads from chains/evm/out,
// the dummy RPC is never contacted), its registry seeded through issue().
const DUMMY_RPC = "http://127.0.0.1:1";
const DUMMY_POOL = "0x" + "12".repeat(20);

function sweptLog(salt: string, txHash: string, amount: bigint, logIndex = 0): ParsedLog {
  return {
    name: "Swept",
    blockNumber: 7,
    logIndex,
    txHash,
    // The dispatch gate admits Swept only from the factory (address-gated
    // ingest) — stamp the emitter the way scanRange does.
    address: FACTORY.toLowerCase(),
    blockTimestamp: NOW,
    args: { salt, sweeper: "0x" + "ee".repeat(20), amount },
  };
}

async function sweepFixture(): Promise<{ ix: Indexer; record: PortalRecord }> {
  const ix = new Indexer({ rpc: DUMMY_RPC, pool: DUMMY_POOL, startBlock: 0, authorityKey: null, portalFactory: FACTORY });
  const derived = deriveStealthAddress(META, EPHEMERAL);
  const record = await ix.portal.issue(
    {
      name: "alice",
      owner: ownerCompressed,
      ephemeralPub: derived.ephemeralPub,
      viewTag: derived.viewTag,
      stealthAddr: derived.address,
      destination: create2Address(FACTORY, portalSalt(derived.address), INITCODE_HASH),
    },
    NOW,
  );
  return { ix, record };
}

test("Swept log through applyLogs flips the matching record (salt = portalSalt(stealthAddr))", async () => {
  const { ix, record } = await sweepFixture();
  ix.applyLogs([sweptLog(portalSalt(record.stealthAddr), "0xsweep", 123n)]);
  assert.equal(record.swept, true);
  assert.equal(record.sweptTxHash, "0xsweep");
  assert.equal(record.sweptAmount, "123");
  // …and the feeds reflect it immediately (the read model is live).
  assert.equal(ix.portal.unswept().length, 0);
  assert.equal(ix.portal.list().length, 1);
});

test("an unknown salt is a no-op (issuance rows are indexer-local, like names)", async () => {
  const { ix, record } = await sweepFixture();
  ix.applyLogs([sweptLog("0x" + "00".repeat(12) + "99".repeat(20), "0xsweep", 5n)]);
  assert.equal(record.swept, false);
});

test("a replayed Swept range converges: the first mark wins, no re-mark", async () => {
  const { ix, record } = await sweepFixture();
  const log = sweptLog(portalSalt(record.stealthAddr), "0xsweep", 123n);
  ix.applyLogs([log]);
  // The retry-after-throw path re-delivers the same range; a later foreign tx
  // with the same salt must not overwrite the recorded sweep either.
  ix.applyLogs([log, sweptLog(portalSalt(record.stealthAddr), "0xother", 999n, 1)]);
  assert.equal(record.sweptTxHash, "0xsweep");
  assert.equal(record.sweptAmount, "123");
});

// ============================ (3) FEEDS ======================================

async function threeRecords(): Promise<{ ix: Indexer; portal: PortalRegistry }> {
  const { ix, portal } = await seededIx();
  for (const i of Array(3).keys()) {
    await handlePayPortal(ctx(ix, ["alice"]), () => EPHEMERAL + BigInt(i), NOW + i);
  }
  return { ix, portal };
}

test("/portal/unswept pages by seq cursor, caps by limit, drops swept records", async () => {
  const { ix, portal } = await threeRecords();
  const all = (await portalUnswept.handle(ctx(ix))).body as PortalRecord[];
  assert.deepEqual(all.map((r) => r.seq), [0, 1, 2]);

  const paged = (await portalUnswept.handle(ctx(ix, [], `cursor=${all[0].seq}&limit=1`))).body as PortalRecord[];
  assert.deepEqual(paged.map((r) => r.seq), [1]);

  // A swept record leaves the work feed but stays on the announcements feed
  // (the recipient scan needs swept history too).
  portal.markSwept(portalSalt(all[1].stealthAddr), "0xsweep", 7n);
  const after = (await portalUnswept.handle(ctx(ix))).body as PortalRecord[];
  assert.deepEqual(after.map((r) => r.seq), [0, 2]);
  const announce = (await portalAnnouncements.handle(ctx(ix))).body as PortalRecord[];
  assert.deepEqual(announce.map((r) => r.seq), [0, 1, 2]);
  assert.equal(announce[1].swept, true);
});

test("/portal/announcements pages by seq cursor and caps by limit", async () => {
  const { ix } = await threeRecords();
  const all = (await portalAnnouncements.handle(ctx(ix))).body as PortalRecord[];
  const paged = (await portalAnnouncements.handle(ctx(ix, [], `cursor=${all[0].seq}&limit=1`))).body as PortalRecord[];
  assert.deepEqual(paged.map((r) => r.seq), [1]);
  assert.deepEqual((await portalAnnouncements.handle(ctx(ix, [], `cursor=${all[2].seq}`))).body, []);
});

test("malformed cursor/limit is the caller's 400", async () => {
  const { ix } = await seededIx();
  for (const route of [portalUnswept, portalAnnouncements]) {
    assert.equal((await route.handle(ctx(ix, [], "cursor=abc"))).status as number, 400);
    assert.equal((await route.handle(ctx(ix, [], "limit=0"))).status as number, 400);
  }
});
