// The CCIP-Read gateway for the payment name (SPEC: payment-name R1-R5, R13).
//
// Wallets never call this directly by choice: PortalPrivResolver reverts
// OffchainLookup at them and they fetch `/ens/{sender}/{data}.json` (GET) or
// POST /ens per the ERC-3668 transport. Each served lookup IS an issuance:
// the gateway derives a fresh stealth destination against the PRIV factory,
// RECORDS its announcement first (portal.issue, first-write-wins — the same
// row a pay-page issuance writes, because a MetaMask sender will never
// announce), and only then signs and returns the answer. Anything that
// cannot be served — unknown or non-consumer label, foreign sender, a
// coinType this deployment does not fund — fails CLOSED with a 4xx and
// MINTS NOTHING (spec R13: an unserved coinType must not leave a row).
//
// Freshness is a gateway obligation, not a protocol one (the spec's R2): the
// scalar is drawn per request and discarded after derivation (the
// handlePayPortal discipline), responses carry expiry <= 300 s and
// Cache-Control: no-store, and the wallet-side 60 s cache is the sender's
// own UI session, not ours.

import { decodeAbiParameters, encodeAbiParameters } from "viem";

import type { Route, RouteContext, RouteResult } from "../router.js";
import { KEM_EK_ZERO, NOTE_VIEW_PUB_ZERO } from "@bongtu/core/eddsa";
import {
  chainForCoinType,
  directoryLabel,
  dnsDecodeName,
  gatewaySignatureHash,
  namehash,
  signGatewayResponse,
} from "@bongtu/core/ens";
import { deriveStealthAddress, portalSalt, randomEphemeralScalar } from "@bongtu/core/stealth";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";

/** Selectors of the three calls the gateway understands (ENSIP-10 resolve
 *  wrapping ENSIP-1 addr or ENSIP-9/11 addr-with-coinType). */
const RESOLVE_SELECTOR = "0x9061b923";
const ADDR_SELECTOR = "0x3b3b57de";
const ADDR_COINTYPE_SELECTOR = "0xf1cb7e06";

/** Answers are valid this long (spec R4: <= 300 s, no-store). */
const EXPIRY_SECONDS = 300n;

const unconfigured = (): RouteResult => ({
  status: 404,
  body: { error: "the name gateway is not configured on this indexer (ENS_RESOLVER unset)" },
});

interface DecodedLookup {
  /** dot-separated queried name (dns-decoded) */
  name: string;
  /** the inner addr() node argument, 0x-hex */
  node: string;
  /** requested coinType (60 for the legacy addr(bytes32) form) */
  coinType: bigint;
  /** whether the answer encodes as `address` (legacy) or `bytes` (ENSIP-9) */
  legacyAddr: boolean;
}

/** Decode resolve(dnsName, addrCall) calldata. Returns null on any shape the
 *  gateway does not serve (fail closed, mint nothing). */
function decodeLookup(dataHex: string): DecodedLookup | null {
  if (!/^0x[0-9a-fA-F]{8,}$/.test(dataHex)) return null;
  if (dataHex.slice(0, 10).toLowerCase() !== RESOLVE_SELECTOR) return null;
  const decoded = ((): readonly [`0x${string}`, `0x${string}`] | null => {
    try {
      return decodeAbiParameters(
        [{ type: "bytes" }, { type: "bytes" }],
        ("0x" + dataHex.slice(10)) as `0x${string}`,
      ) as readonly [`0x${string}`, `0x${string}`];
    } catch {
      return null;
    }
  })();
  if (!decoded) return null;
  const [nameWire, inner] = decoded;
  const name = ((): string | null => {
    try {
      return dnsDecodeName(hexToBytes(nameWire.slice(2)));
    } catch {
      return null;
    }
  })();
  if (!name) return null;
  const innerSelector = inner.slice(0, 10).toLowerCase();
  try {
    if (innerSelector === ADDR_SELECTOR) {
      const [node] = decodeAbiParameters([{ type: "bytes32" }], ("0x" + inner.slice(10)) as `0x${string}`);
      return { name, node: node as string, coinType: 60n, legacyAddr: true };
    }
    if (innerSelector === ADDR_COINTYPE_SELECTOR) {
      const [node, coinType] = decodeAbiParameters(
        [{ type: "bytes32" }, { type: "uint256" }],
        ("0x" + inner.slice(10)) as `0x${string}`,
      );
      return { name, node: node as string, coinType: coinType as bigint, legacyAddr: false };
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * The lookup handler with injectable randomness + clock (the handlePayPortal
 * seam pattern). `sender` and `data` arrive from either transport.
 */
export async function handleEnsResolve(
  ctx: RouteContext,
  sender: string,
  data: string,
  drawScalar: () => bigint = randomEphemeralScalar,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): Promise<RouteResult> {
  const { ix } = ctx;
  const ens = ix.cfg.ens ?? null;
  const privFactory = ix.cfg.portalPrivFactory ?? null;
  if (!ens || !privFactory || !ix.portalPrivAddressOf) return unconfigured();
  if (sender.toLowerCase() !== ens.resolver.toLowerCase()) {
    return { status: 404, body: { error: "unknown resolver", sender } };
  }
  const lookup = decodeLookup(data);
  if (!lookup) return { status: 400, body: { error: "unsupported lookup calldata" } };
  if (namehash(lookup.name) !== lookup.node.toLowerCase()) {
    return { status: 400, body: { error: "node does not match the queried name" } };
  }

  // R13 routing. The LEGACY addr(bytes32) form carries no coinType: it is
  // what a wallet on an ENS-NATIVE chain (mainnet, Sepolia) asks its own
  // registry, so it means "this deployment's chain" and is always served.
  // The ENSIP-11 form names an explicit chain: serve only the one funds
  // chain this deployment derives for; anything else answers empty-handed
  // and mints nothing.
  if (!lookup.legacyAddr) {
    const chain = chainForCoinType(lookup.coinType);
    if (chain === null || chain !== ens.chainId) {
      return { status: 404, body: { error: "coinType not served", coinType: lookup.coinType.toString() } };
    }
  }

  const label = directoryLabel(lookup.name.split(".")[0] ?? "");
  if (!label) return { status: 404, body: { error: "label not resolvable" } };
  const record = ix.names.resolve(label);
  if (!record) return { status: 404, body: { error: "name not registered" } };
  if (!record.viewPub || !record.spendPub) {
    return { status: 404, body: { error: "label has no stealth identity registered" } };
  }
  // The sweep mints consumer notes, so a label without the consumer pair can
  // never RECEIVE through this family — fail before deriving anything (the
  // handlePortalAnnounce gate).
  if (
    !record.noteViewPub || !record.kemEk ||
    record.noteViewPub === NOTE_VIEW_PUB_ZERO || record.kemEk === KEM_EK_ZERO
  ) {
    return { status: 404, body: { error: "label has no consumer identity registered" } };
  }

  // Derive, then let the scalar go out of scope (the resolver holds nothing
  // more than the public tuple — the handlePayPortal discipline).
  const derived = deriveStealthAddress({ viewPub: record.viewPub, spendPub: record.spendPub }, drawScalar());
  const destination = await ix.portalPrivAddressOf(portalSalt(derived.address));
  await ix.portal.issue(
    {
      name: label,
      owner: record.owner,
      ephemeralPub: derived.ephemeralPub,
      viewTag: derived.viewTag,
      stealthAddr: derived.address,
      destination,
      factory: privFactory,
      rail: "evm",
    },
    nowSeconds,
  );

  const result = lookup.legacyAddr
    ? encodeAbiParameters([{ type: "address" }], [destination as `0x${string}`])
    : encodeAbiParameters([{ type: "bytes" }], [destination as `0x${string}`]);
  const expires = BigInt(nowSeconds) + EXPIRY_SECONDS;
  const digest = gatewaySignatureHash(ens.resolver, expires, hexToBytes(data.slice(2)), hexToBytes(result.slice(2)));
  const sig = signGatewayResponse(ens.gatewayKey, digest);
  const responseData = encodeAbiParameters(
    [{ type: "bytes" }, { type: "uint64" }, { type: "bytes" }],
    [result, expires, ("0x" + bytesToHex(sig)) as `0x${string}`],
  );
  return {
    status: 200,
    body: { data: responseData },
    headers: { "cache-control": "no-store" },
  };
}

export const ensResolveGet: Route = {
  method: "GET",
  pattern: /^\/ens\/(0x[0-9a-fA-F]{40})\/(0x[0-9a-fA-F]+)\.json$/,
  handle: (ctx) => handleEnsResolve(ctx, ctx.params[0], ctx.params[1]),
};

/** ERC-3668's POST transport: { sender, data } in the JSON body. */
export const ensResolvePost: Route = {
  method: "POST",
  pattern: "/ens",
  handle: (ctx) => {
    const b = (typeof ctx.body === "object" && ctx.body !== null ? ctx.body : {}) as Record<string, unknown>;
    if (typeof b.sender !== "string" || typeof b.data !== "string") {
      return { status: 400, body: { error: "expected { sender, data }" } };
    }
    return handleEnsResolve(ctx, b.sender, b.data);
  },
};
