// Headless gate for the CCIP-Read name gateway (SPEC: payment-name R1-R5,
// R13), at its seams:
//
//   1. HAPPY PATH — a resolve(addr(bytes32)) lookup answers a SIGNED response
//      whose result is the priv-factory destination, and the announcement row
//      exists BEFORE the response could reach a wallet (it is written by the
//      time the handler returns).
//   2. FRESHNESS — the same label twice derives two destinations, two rows.
//   3. COINTYPE ROUTING (R13) — the served chain answers; any other coinType
//      404s and mints NOTHING.
//   4. FENCES — foreign sender, node mismatch, v1-only label, unknown label,
//      unconfigured gateway: all fail closed, none mint a row, and no
//      response ever carries the signing key.
//
//   node --import tsx --test test/ensGateway.test.ts   # (== npm run test:ensgateway)

import { test } from "node:test";
import assert from "node:assert/strict";

import { decodeAbiParameters, encodeAbiParameters } from "viem";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { deriveKeypair } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import {
  coinTypeForChain,
  dnsEncodeName,
  gatewaySignatureHash,
  namehash,
  recoverGatewaySigner,
  signGatewayResponse,
} from "@bongtu/core/ens";
import { create2Address, deriveStealthAddress, portalSalt, stealthKeysFromScalars } from "@bongtu/core/stealth";

import { NameRegistry } from "../src/names.js";
import { PortalRegistry } from "../src/portal.js";
import type { Indexer } from "../src/ingest.js";
import { handleEnsResolve } from "../src/api/routes/ensGateway.js";
import type { RouteContext } from "../src/api/router.js";

const OWNER = deriveKeypair(987654321987654321n);
const ownerCompressed = packPubkey(OWNER.publicKey);
const META = stealthKeysFromScalars(3333n, 4444n).meta;
const CONSUMER_PAIR = { noteViewPub: "0x" + "44".repeat(32), kemEk: "0x" + "55".repeat(1184) };

const RESOLVER = "0x" + "aa".repeat(20);
const PRIV_FACTORY = "0x" + "c1".repeat(20);
const PRIV_INITCODE_HASH = "0x" + "cd".repeat(32);
const GATEWAY_KEY = hexToBytes("11".repeat(32));
const CHAIN_ID = 31337;
const EPHEMERAL = 777777777777777777777n;
const NOW = 1_700_000_000;

const fakePrivAddressOf = async (salt: string): Promise<string> =>
  create2Address(PRIV_FACTORY, salt, PRIV_INITCODE_HASH);

async function seededIx(
  opts: { ens?: { resolver: string; gatewayKey: Uint8Array; chainId: number } | null; v1Only?: boolean } = {},
): Promise<{ ix: Indexer; portal: PortalRegistry }> {
  const registry = new NameRegistry(null);
  await registry.register(
    { name: "jun", owner: ownerCompressed, viewPub: META.viewPub, spendPub: META.spendPub },
    NOW,
    opts.v1Only ? undefined : CONSUMER_PAIR,
  );
  const portal = new PortalRegistry(null);
  const ix = {
    cfg: {
      portalPrivFactory: PRIV_FACTORY,
      ens: opts.ens === undefined ? { resolver: RESOLVER, gatewayKey: GATEWAY_KEY, chainId: CHAIN_ID } : opts.ens,
    },
    names: registry,
    portal,
    portalPrivAddressOf: fakePrivAddressOf,
  } as unknown as Indexer;
  return { ix, portal };
}

const ctx = (ix: Indexer): RouteContext => ({
  ix,
  tokens: null,
  params: [],
  query: new URLSearchParams(),
});

/** Build resolve(dnsName, inner) calldata the way the resolver's
 *  OffchainLookup hands it to the gateway. */
function resolveCalldata(name: string, inner: `0x${string}`): string {
  const args = encodeAbiParameters(
    [{ type: "bytes" }, { type: "bytes" }],
    [("0x" + bytesToHex(dnsEncodeName(name))) as `0x${string}`, inner],
  );
  return "0x9061b923" + args.slice(2);
}

const addrCall = (name: string): string =>
  resolveCalldata(name, ("0x3b3b57de" + namehash(name).slice(2)) as `0x${string}`);

const addrCoinTypeCall = (name: string, coinType: bigint): string =>
  resolveCalldata(
    name,
    ("0xf1cb7e06" +
      encodeAbiParameters([{ type: "bytes32" }, { type: "uint256" }], [namehash(name) as `0x${string}`, coinType]).slice(2)) as `0x${string}`,
  );

test("happy path: signed answer carries the priv destination, row minted first", async () => {
  const { ix, portal } = await seededIx();
  const data = addrCall("jun.demo.eth");
  const r = await handleEnsResolve(ctx(ix), RESOLVER, data, () => EPHEMERAL, NOW);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.headers?.["cache-control"], "no-store");

  const derived = deriveStealthAddress(META, EPHEMERAL);
  const expectedDestination = create2Address(PRIV_FACTORY, portalSalt(derived.address), PRIV_INITCODE_HASH);

  const { data: responseData } = r.body as { data: `0x${string}` };
  const [result, expires, sig] = decodeAbiParameters(
    [{ type: "bytes" }, { type: "uint64" }, { type: "bytes" }],
    responseData,
  ) as readonly [`0x${string}`, bigint, `0x${string}`];
  const [answered] = decodeAbiParameters([{ type: "address" }], result);
  assert.equal((answered as string).toLowerCase(), expectedDestination.toLowerCase());
  assert.equal(expires, BigInt(NOW) + 300n, "expiry pinned to the 300 s bound");

  // The verifier-equivalent check: the signature recovers to the gateway
  // key's address over the SAME preimage PortalPrivResolver re-derives.
  const digest = gatewaySignatureHash(RESOLVER, expires, hexToBytes(data.slice(2)), hexToBytes(result.slice(2)));
  const signerAddr = recoverGatewaySigner(digest, hexToBytes(sig.slice(2)));
  const expectedSigner = recoverGatewaySigner(digest, signGatewayResponse(GATEWAY_KEY, digest));
  assert.equal(signerAddr, expectedSigner);

  // Announce-before-return: the row is already there, attributed, priv-family.
  const rows = portal.list();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].name, "jun");
  assert.equal(rows[0].factory, PRIV_FACTORY);
  assert.equal(rows[0].destination.toLowerCase(), expectedDestination.toLowerCase());
  assert.equal(rows[0].ephemeralPub, derived.ephemeralPub);
});

test("freshness: the same label twice derives two destinations, two rows", async () => {
  const { ix, portal } = await seededIx();
  const scalars = [1001n, 1002n];
  const draws = { at: 0 };
  const draw = (): bigint => scalars[draws.at++];
  const r1 = await handleEnsResolve(ctx(ix), RESOLVER, addrCall("jun.demo.eth"), draw, NOW);
  const r2 = await handleEnsResolve(ctx(ix), RESOLVER, addrCall("jun.demo.eth"), draw, NOW + 1);
  assert.equal(r1.status, 200);
  assert.equal(r2.status, 200);
  const dest = (r: typeof r1): string => {
    const [result] = decodeAbiParameters(
      [{ type: "bytes" }, { type: "uint64" }, { type: "bytes" }],
      (r.body as { data: `0x${string}` }).data,
    );
    const [a] = decodeAbiParameters([{ type: "address" }], result as `0x${string}`);
    return (a as string).toLowerCase();
  };
  assert.notEqual(dest(r1), dest(r2), "per-resolution freshness");
  assert.equal(portal.list().length, 2);
});

test("coinType routing (R13): the served chain answers as bytes, others mint nothing", async () => {
  const { ix, portal } = await seededIx();
  const served = await handleEnsResolve(
    ctx(ix),
    RESOLVER,
    addrCoinTypeCall("jun.demo.eth", coinTypeForChain(CHAIN_ID)),
    () => EPHEMERAL,
    NOW,
  );
  assert.equal(served.status, 200, JSON.stringify(served.body));
  const [result] = decodeAbiParameters(
    [{ type: "bytes" }, { type: "uint64" }, { type: "bytes" }],
    (served.body as { data: `0x${string}` }).data,
  );
  const [answeredBytes] = decodeAbiParameters([{ type: "bytes" }], result as `0x${string}`);
  const derived = deriveStealthAddress(META, EPHEMERAL);
  const expected = create2Address(PRIV_FACTORY, portalSalt(derived.address), PRIV_INITCODE_HASH);
  assert.equal((answeredBytes as string).toLowerCase(), expected.toLowerCase(), "ENSIP-9 bytes answer");

  const foreign = await handleEnsResolve(
    ctx(ix),
    RESOLVER,
    addrCoinTypeCall("jun.demo.eth", coinTypeForChain(8453)),
    () => EPHEMERAL,
    NOW,
  );
  assert.equal(foreign.status, 404);
  const solana = await handleEnsResolve(ctx(ix), RESOLVER, addrCoinTypeCall("jun.demo.eth", 501n), () => EPHEMERAL, NOW);
  assert.equal(solana.status, 404);
  assert.equal(portal.list().length, 1, "unserved coinTypes minted nothing");
});

test("fences fail closed and mint nothing", async () => {
  const { ix, portal } = await seededIx();
  const data = addrCall("jun.demo.eth");

  const foreignSender = await handleEnsResolve(ctx(ix), "0x" + "bb".repeat(20), data, () => EPHEMERAL, NOW);
  assert.equal(foreignSender.status, 404);

  const wrongNode = await handleEnsResolve(
    ctx(ix),
    RESOLVER,
    resolveCalldata("jun.demo.eth", ("0x3b3b57de" + namehash("other.demo.eth").slice(2)) as `0x${string}`),
    () => EPHEMERAL,
    NOW,
  );
  assert.equal(wrongNode.status, 400);

  const unknown = await handleEnsResolve(ctx(ix), RESOLVER, addrCall("ghost.demo.eth"), () => EPHEMERAL, NOW);
  assert.equal(unknown.status, 404);

  const garbage = await handleEnsResolve(ctx(ix), RESOLVER, "0xdeadbeef", () => EPHEMERAL, NOW);
  assert.equal(garbage.status, 400);

  assert.equal(portal.list().length, 0, "no fence minted a row");

  const { ix: v1Ix, portal: v1Portal } = await seededIx({ v1Only: true });
  const v1 = await handleEnsResolve(ctx(v1Ix), RESOLVER, data, () => EPHEMERAL, NOW);
  assert.equal(v1.status, 404, "v1-only label cannot receive");
  assert.equal(v1Portal.list().length, 0);

  const { ix: offIx } = await seededIx({ ens: null });
  const off = await handleEnsResolve(ctx(offIx), RESOLVER, data, () => EPHEMERAL, NOW);
  assert.equal(off.status, 404, "unconfigured gateway 404s");
});

test("no response or error ever carries the signing key", async () => {
  const { ix } = await seededIx();
  const keyHex = bytesToHex(GATEWAY_KEY);
  for (const [sender, data] of [
    [RESOLVER, addrCall("jun.demo.eth")],
    [RESOLVER, "0xdeadbeef"],
    ["0x" + "bb".repeat(20), addrCall("jun.demo.eth")],
  ] as const) {
    const r = await handleEnsResolve(ctx(ix), sender, data, () => EPHEMERAL, NOW);
    assert.ok(!JSON.stringify(r).includes(keyHex), "gateway key must never appear in a response");
  }
});
