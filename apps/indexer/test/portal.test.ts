// Headless gate for the portal/receive surface, at its seams:
//
//   1. ISSUANCE ROUTE — POST /pay/{name} via handlePayPortal with the two
//      injected seams (fixed ephemeral scalar, fixed clock) and a fake
//      portalAddressOf standing in for the factory eth_call: deterministic
//      destination, the recorded announcement, and the 400/404 fences.
//   2. ANNOUNCE ROUTE — POST /portal/announce via handlePortalAnnounce: the
//      server-side destination recompute, the first-write-wins 409, the shape
//      fences, and the unconfigured-receive 404.
//   3. SWEPT MARKING + ANNOUNCED BACKFILL — synthetic ParsedLogs through the
//      REAL Indexer.applyLogs (the ingest.test.ts convention: constructor
//      reads the Foundry ABI, the dummy RPC is never contacted): Swept flips
//      the matching record (either factory); a receive-factory Announced
//      backfills an unknown salt from chain data and no-ops a known one.
//   4. FEEDS — the ATTRIBUTION SPLIT (public projection carries no name/owner
//      field at all; unswept stays attributed behind the operator token),
//      cursor/limit behavior, and the unconfigured-factory 404.
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
import type { PortalIssuance, PortalPublicRecord, PortalRecord } from "@bongtu/core/indexerApi";

import { NameRegistry } from "../src/names.js";
import { PortalRegistry } from "../src/portal.js";
import { Indexer, type ParsedLog } from "../src/ingest.js";
import {
  handlePayPortal,
  handlePortalAnnounce,
  payPortal,
  portalAnnounce,
  portalAnnouncements,
  portalUnswept,
} from "../src/api/routes/portal.js";
import type { RouteContext, RouteResult } from "../src/api/router.js";

const OWNER = deriveKeypair(123456789123456789n);
const ownerCompressed = packPubkey(OWNER.publicKey);
const META = stealthKeysFromScalars(1111n, 2222n).meta;

const FACTORY = "0x" + "c0".repeat(20);
const RECEIVE_FACTORY = "0x" + "c1".repeat(20);
const INITCODE_HASH = "0x" + "ab".repeat(32);
const RECEIVE_INITCODE_HASH = "0x" + "cd".repeat(32);
const EPHEMERAL = 424242424242424242424242n;
const NOW = 1_700_000_000;

// The fake chain edge: answers addressOf(salt) with the same EIP-1014 math the
// real factories implement (core create2Address is parity-pinned against it in
// packages/core/test/stealth.test.ts), so the "chain" stays internally
// consistent without an RPC. One per factory — their initcode hashes differ.
const fakeAddressOf = async (salt: string): Promise<string> => create2Address(FACTORY, salt, INITCODE_HASH);
const fakeReceiveAddressOf = async (salt: string): Promise<string> =>
  create2Address(RECEIVE_FACTORY, salt, RECEIVE_INITCODE_HASH);

// The registered consumer pair (v2): what makes "alice" payable by the
// receive product — announce refuses a record without it.
const CONSUMER_PAIR = { noteViewPub: "0x" + "22".repeat(32), kemEk: "0x" + "33".repeat(1184) };

async function seededIx(
  opts: {
    factory?: string | null;
    receiveFactory?: string | null;
    operatorToken?: string | null;
    receiveAddressOf?: (salt: string) => Promise<string>;
    v1Only?: boolean;
  } = {},
): Promise<{ ix: Indexer; portal: PortalRegistry }> {
  const registry = new NameRegistry(null);
  await registry.register(
    { name: "alice", owner: ownerCompressed, viewPub: META.viewPub, spendPub: META.spendPub },
    NOW,
    opts.v1Only ? undefined : CONSUMER_PAIR,
  );
  const portal = new PortalRegistry(null);
  const ix = {
    cfg: {
      portalFactory: opts.factory === undefined ? FACTORY : opts.factory,
      receiveFactory: opts.receiveFactory === undefined ? RECEIVE_FACTORY : opts.receiveFactory,
      portalOperatorToken: opts.operatorToken ?? null,
    },
    names: registry,
    portal,
    portalAddressOf: fakeAddressOf,
    receiveAddressOf: opts.receiveAddressOf ?? fakeReceiveAddressOf,
  } as unknown as Indexer;
  return { ix, portal };
}

function ctx(ix: Indexer, params: string[] = [], query = "", body?: unknown, headers?: Record<string, string>): RouteContext {
  return { ix, tokens: null, params, query: new URLSearchParams(query), body, headers };
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
    rail: "evm",
    factory: FACTORY,
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

test("unconfigured factories: /pay and both /portal feeds 404 with a clear body", async () => {
  const { ix } = await seededIx({ factory: null, receiveFactory: null });
  for (const r of [
    await payPortal.handle(ctx(ix, ["alice"])),
    await portalUnswept.handle(ctx(ix)),
    await portalAnnouncements.handle(ctx(ix)),
  ]) {
    assert.equal(r.status, 404);
    assert.match((r.body as { error: string }).error, /PORTAL_FACTORY/);
  }
});

test("feeds stay live with only the receive factory configured (rows name their own factory)", async () => {
  const { ix } = await seededIx({ factory: null });
  assert.equal((await portalAnnouncements.handle(ctx(ix))).status, 200);
  assert.equal((await portalUnswept.handle(ctx(ix))).status, 200);
  // …but the portal-pair issuance route stays down.
  assert.equal((await payPortal.handle(ctx(ix, ["alice"]))).status, 404);
});

// ============================ (2) ANNOUNCE ROUTE =============================

// A browser-shaped derivation: the pay page derives with the record's public
// keys and a locally drawn scalar — reproduced here with the core primitive.
function browserDerivation(scalar: bigint = EPHEMERAL) {
  const d = deriveStealthAddress(META, scalar);
  return { label: "alice", ephemeralPub: d.ephemeralPub, viewTag: d.viewTag, stealthAddr: d.address };
}

test("announce happy path: server recomputes the destination against the RECEIVE factory", async () => {
  const { ix, portal } = await seededIx();
  const req = browserDerivation();
  const r = await handlePortalAnnounce(ctx(ix, [], "", req), NOW);
  assert.equal(r.status, 200, JSON.stringify(r.body));

  const body = r.body as PortalPublicRecord;
  // The destination is the SERVER's recompute (receive factory + its initcode
  // hash) — nothing client-sent, and not the portal pair's address.
  assert.equal(body.destination, create2Address(RECEIVE_FACTORY, portalSalt(req.stealthAddr), RECEIVE_INITCODE_HASH));
  assert.equal(body.factory, RECEIVE_FACTORY);
  assert.equal(body.rail, "evm");
  assert.equal(body.swept, false);
  // The response is the PUBLIC projection: no attribution fields at all.
  assert.equal("name" in (body as object), false);
  assert.equal("owner" in (body as object), false);
  // …but the stored row carries it for the operator feed (the sweep bot's need).
  assert.equal(portal.list()[0].name, "alice");
  assert.equal(portal.list()[0].owner, ownerCompressed);
});

test("announce dedupes on stealth address: first write wins with a 409", async () => {
  const { ix } = await seededIx();
  const req = browserDerivation();
  assert.equal((await handlePortalAnnounce(ctx(ix, [], "", req), NOW)).status, 200);
  // The same address under a different (also registered) label still refuses.
  const hijack = { ...req, label: "alice" };
  const r = await handlePortalAnnounce(ctx(ix, [], "", hijack), NOW + 1);
  assert.equal(r.status, 409);
  assert.match((r.body as { error: string }).error, /already recorded/);
});

test("announce fences: unknown label 404, malformed shapes 400", async () => {
  const { ix } = await seededIx();
  const good = browserDerivation();
  assert.equal((await handlePortalAnnounce(ctx(ix, [], "", { ...good, label: "nosuch" }), NOW)).status, 404);
  for (const bad of [
    undefined,
    { ...good, ephemeralPub: "0x" + "00".repeat(32) },          // the zero sentinel is not an announcement
    { ...good, ephemeralPub: "0x1234" },                         // not 32 bytes
    { ...good, viewTag: 256 },                                   // out of the u8 range
    { ...good, viewTag: 1.5 },                                   // not an integer
    { ...good, stealthAddr: "0x1234" },                          // not 20 bytes
    { ...good, rail: "tron" },                                   // no shipped flavor but evm
    { label: good.label },                                       // missing fields
  ]) {
    assert.equal((await handlePortalAnnounce(ctx(ix, [], "", bad), NOW)).status, 400, JSON.stringify(bad));
  }
});

test("announce 404s when RECEIVE_FACTORY is unset (portal pair alone does not enable it)", async () => {
  const { ix } = await seededIx({ receiveFactory: null });
  const r = await portalAnnounce.handle(ctx(ix, [], "", browserDerivation()));
  assert.equal(r.status, 404);
  assert.match((r.body as { error: string }).error, /RECEIVE_FACTORY/);
});

test("announce refuses a v1-only label (no consumer pair -> the sweep could never build)", async () => {
  const { ix, portal } = await seededIx({ v1Only: true });
  const r = await handlePortalAnnounce(ctx(ix, [], "", browserDerivation()), NOW);
  assert.equal(r.status, 400);
  assert.match((r.body as { error: string }).error, /consumer identity/);
  assert.equal(portal.list().length, 0, "nothing recorded for an unpayable label");
});

test("CONCURRENT double-announce: exactly one 200, one 409, one recorded row", async () => {
  // The destination recompute awaits mid-handler — the exact window the
  // reviewer's race lives in. A deferred fake holds BOTH handlers inside it,
  // past the fast-path probe, before releasing them together.
  const gate: { open: () => void } = { open: () => undefined };
  const held = new Promise<void>((resolve) => { gate.open = resolve; });
  const { ix, portal } = await seededIx({
    receiveAddressOf: async (salt: string) => {
      await held;
      return fakeReceiveAddressOf(salt);
    },
  });
  const req = browserDerivation();
  const race = Promise.all([
    handlePortalAnnounce(ctx(ix, [], "", req), NOW),
    handlePortalAnnounce(ctx(ix, [], "", { ...req }), NOW),
  ]);
  gate.open();
  const results = await race;
  assert.deepEqual(results.map((r) => r.status).sort(), [200, 409], JSON.stringify(results));
  assert.equal(portal.list().length, 1, "first write wins: exactly one row");
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
  const ix = new Indexer({
    rpc: DUMMY_RPC, pool: DUMMY_POOL, startBlock: 0, authorityKey: null,
    portalFactory: FACTORY, receiveFactory: RECEIVE_FACTORY,
  });
  const derived = deriveStealthAddress(META, EPHEMERAL);
  const record = await ix.portal.issue(
    {
      name: "alice",
      owner: ownerCompressed,
      ephemeralPub: derived.ephemeralPub,
      viewTag: derived.viewTag,
      stealthAddr: derived.address,
      destination: create2Address(FACTORY, portalSalt(derived.address), INITCODE_HASH),
      factory: FACTORY,
      rail: "evm",
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

// The receive factory's sweep tx: Swept then Announced, both from RECEIVE_FACTORY.
function receiveSweepLogs(salt: string, ephemeralPub: string, viewTag: number, txHash: string, amount: bigint): ParsedLog[] {
  const base = { blockNumber: 9, txHash, address: RECEIVE_FACTORY.toLowerCase(), blockTimestamp: NOW + 50 };
  return [
    { ...base, name: "Swept", logIndex: 0, args: { salt, sweeper: "0x" + "df".repeat(20), amount } },
    { ...base, name: "Announced", logIndex: 1, args: { salt, ephemeralPub, viewTag } },
  ];
}

test("receive-factory Swept flips a record issued through the announce path", async () => {
  const { ix } = await sweepFixture();
  const d = deriveStealthAddress(META, EPHEMERAL + 7n);
  const announced = await ix.portal.issue(
    {
      name: "alice", owner: ownerCompressed, ephemeralPub: d.ephemeralPub, viewTag: d.viewTag,
      stealthAddr: d.address, destination: create2Address(RECEIVE_FACTORY, portalSalt(d.address), RECEIVE_INITCODE_HASH),
      factory: RECEIVE_FACTORY, rail: "evm",
    },
    NOW,
  );
  ix.applyLogs(receiveSweepLogs(portalSalt(announced.stealthAddr), d.ephemeralPub, d.viewTag, "0xrsweep", 55n));
  assert.equal(announced.swept, true);
  assert.equal(announced.sweptTxHash, "0xrsweep");
  // The same-tx Announced found its record already indexed: no duplicate row.
  assert.equal(ix.portal.list().filter((r) => r.stealthAddr === announced.stealthAddr).length, 1);
});

test("Announced with an UNKNOWN salt backfills a swept row from chain data alone", async () => {
  const { ix } = await sweepFixture();
  const d = deriveStealthAddress(META, EPHEMERAL + 9n);
  const before = ix.portal.list().length;
  ix.applyLogs(receiveSweepLogs(portalSalt(d.address), d.ephemeralPub, d.viewTag, "0xlost", 77n));

  const rows = ix.portal.list();
  assert.equal(rows.length, before + 1);
  const row = rows[rows.length - 1];
  // Chain data carries no attribution — the row is honest about that…
  assert.equal(row.name, "");
  assert.equal(row.owner, "");
  // …but the recovery tuple is complete: the recipient's scan can find it.
  assert.equal(row.stealthAddr, d.address.toLowerCase());
  assert.equal(row.ephemeralPub, d.ephemeralPub);
  assert.equal(row.viewTag, d.viewTag);
  assert.equal(row.destination, "0x" + "df".repeat(20));
  assert.equal(row.factory, RECEIVE_FACTORY);
  assert.equal(row.swept, true);
  assert.equal(row.sweptTxHash, "0xlost");
  assert.equal(row.sweptAmount, "77");
  // Already swept, so it never enters the bot's work feed.
  assert.equal(ix.portal.unswept().some((r) => r.stealthAddr === row.stealthAddr), false);
  // Replay converges: the same range again adds nothing.
  ix.applyLogs(receiveSweepLogs(portalSalt(d.address), d.ephemeralPub, d.viewTag, "0xlost", 77n));
  assert.equal(ix.portal.list().length, before + 1);
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

// ==================== (5) ATTRIBUTION SPLIT + OPERATOR GATE ==================

test("the public announcement feed carries NO attribution field at all (spec R4)", async () => {
  const { ix } = await threeRecords();
  const rows = (await portalAnnouncements.handle(ctx(ix))).body as PortalPublicRecord[];
  assert.equal(rows.length, 3);
  for (const row of rows) {
    assert.equal("name" in (row as object), false, "public row leaks name");
    assert.equal("owner" in (row as object), false, "public row leaks owner");
    // The recipient scan still has everything it needs.
    for (const field of ["seq", "rail", "factory", "ephemeralPub", "viewTag", "stealthAddr", "destination", "swept"]) {
      assert.equal(field in (row as object), true, `public row lacks ${field}`);
    }
  }
  // Belt over the field checks: the serialized body never mentions the values.
  assert.equal(JSON.stringify(rows).includes(ownerCompressed), false);
  assert.equal(JSON.stringify(rows).includes("alice"), false);
});

test("PORTAL_OPERATOR_TOKEN set: /portal/unswept 401s without the header, serves attributed rows with it", async () => {
  const { ix } = await seededIx({ operatorToken: "sekrit" });
  await handlePayPortal(ctx(ix, ["alice"]), () => EPHEMERAL, NOW);

  const naked = await portalUnswept.handle(ctx(ix));
  assert.equal(naked.status, 401);
  const wrong = await portalUnswept.handle(ctx(ix, [], "", undefined, { "x-operator-token": "nope" }));
  assert.equal(wrong.status, 401);

  const authed = await portalUnswept.handle(ctx(ix, [], "", undefined, { "x-operator-token": "sekrit" }));
  assert.equal(authed.status, 200);
  const rows = authed.body as PortalRecord[];
  assert.equal(rows[0].name, "alice");
  assert.equal(rows[0].owner, ownerCompressed);
  // The token gates ONLY the attributed feed — the public projection stays open.
  assert.equal((await portalAnnouncements.handle(ctx(ix))).status, 200);
});

test("PORTAL_OPERATOR_TOKEN unset: the work feed stays open (local depositor-facing flows)", async () => {
  const { ix } = await seededIx();
  await handlePayPortal(ctx(ix, ["alice"]), () => EPHEMERAL, NOW);
  const open = await portalUnswept.handle(ctx(ix));
  assert.equal(open.status, 200);
  assert.equal((open.body as PortalRecord[])[0].name, "alice");
});
