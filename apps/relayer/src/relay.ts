// The relay decision: validate a proven withdraw, simulate it, submit it with the
// relayer's own funded key. Pure of node:http — the server (server.ts) maps these
// results onto the wire, and the viem clients enter through the RelayerChain deps
// seam so the whole decision table gates headlessly over fakes (test/relay.test.ts).
//
// WHY THIS IS SAFE TO OFFER TO ANYONE: the withdraw circuit binds the payout
// address into the proof itself (pub[26], milestone-stealth slice C), and the
// contract pays THAT address — never msg.sender. So whoever submits the tx —
// the owner's wallet or this relayer — cannot redirect a single wei; the worst a
// hostile relayer can do is decline to spend its own gas. That proof-bound
// recipient is the entire reason this service can exist.
//
// WITHDRAW-ONLY BY DESIGN: transfers and deposits have no recipient bound into
// their public inputs — relaying them would let the relayer redirect nothing
// either, but it would also buy the user nothing except the relayer paying gas
// for someone else's account bookkeeping, with no proof-bound guarantee to
// anchor the service on. The pool's withdraw is the one op whose calldata
// carries its own destination, so it is the one op relayed.

import { parseAbi, type Abi, type Address } from "viem";

import { POOL_ABI_FRAGMENTS } from "@bongtu/core/network";
import { KEM_CIPHERTEXT_BYTES } from "@bongtu/core/kem";
import { ZERO_EPHEMERAL } from "@bongtu/core/stealth";
import type { Calldata } from "@bongtu/core/proving";

// Only the one function this service submits: withdraw pays the proof-bound
// pub[26] recipient (never msg.sender), which is what makes it relayable at all.
export const WITHDRAW_ABI: Abi = parseAbi([POOL_ABI_FRAGMENTS.withdraw]);

/** The withdraw circuit's public-vector length (SPEC: 27 signals). */
export const WITHDRAW_PUB_LEN = 27;
/** Index of the proof-bound payout address in the withdraw public vector. */
export const RECIPIENT_PUB_INDEX = 26;

/** What POST /relay accepts (wire shape, decimal-string field elements). */
export interface RelayBody {
  calldata: Calldata;
  kemCiphertext: string;
  /** stealth announcement half; absent == the plain-withdraw sentinel
   *  (ZERO_EPHEMERAL / viewTag 0), exactly like a wallet-submitted plain withdraw. */
  ephemeralPub?: string;
  viewTag?: number;
}

/** How the relay reaches the chain — the viem clients behind a seam, so unit
 *  tests drive the whole handler with fakes (no RPC, no key). index.ts builds
 *  the real pair from RPC + SUBMITTER_KEY. */
export interface RelayerChain {
  /** the submitter EOA address (derived from SUBMITTER_KEY — the ONLY public
   *  trace of the key). */
  submitter: string;
  /** the pool address every relay targets. */
  pool: string;
  publicClient: {
    simulateContract(params: unknown): Promise<unknown>;
    getGasPrice(): Promise<bigint>;
    waitForTransactionReceipt(params: { hash: `0x${string}` }): Promise<unknown>;
    getBalance(params: { address: Address }): Promise<bigint>;
  };
  walletClient: {
    writeContract(params: unknown): Promise<`0x${string}`>;
  };
}

/** A route-shaped result: HTTP status + JSON body (server.ts owns the wire). */
export interface RelayResult {
  status: number;
  body: unknown;
}

const bad = (error: string): RelayResult => ({ status: 400, body: { error } });

const isDec = (s: unknown): s is string => typeof s === "string" && /^[0-9]+$/.test(s);
const isPair = (x: unknown): x is [string, string] =>
  Array.isArray(x) && x.length === 2 && x.every(isDec);

// Same check as packages/client connection.ts assertKemCiphertext (no shared
// home for the string-form assert yet — the byte length itself is the sdk's
// KEM_CIPHERTEXT_BYTES). The contract re-checks (WrongKemCiphertextLength);
// pre-checking turns that revert into a 400 the caller can read.
function kemCiphertextError(kemCiphertext: unknown): string | null {
  if (typeof kemCiphertext !== "string") return "kemCiphertext must be a 0x-hex string";
  if (!/^0x[0-9a-fA-F]+$/.test(kemCiphertext) || (kemCiphertext.length - 2) / 2 !== KEM_CIPHERTEXT_BYTES) {
    return `kemCiphertext must be ${KEM_CIPHERTEXT_BYTES} bytes of 0x-hex (got ${kemCiphertext.length} chars)`;
  }
  return null;
}

/**
 * Structural validation of the POST /relay body. Returns the parsed body, or a
 * 400 RelayResult naming what is wrong. The recipient check is the one semantic
 * gate: pub[26] must be a nonzero address-range value, because a zero or
 * out-of-range recipient is a proof that could never have come from the wallet
 * and would only waste the submitter's simulation budget.
 */
export function parseRelayBody(raw: unknown): { ok: RelayBody } | { err: RelayResult } {
  if (typeof raw !== "object" || raw === null) return { err: bad("body must be a JSON object") };
  const b = raw as Record<string, unknown>;
  const cd = b.calldata as Record<string, unknown> | undefined;
  if (typeof cd !== "object" || cd === null) return { err: bad("calldata must be an object {a,b,c,pub}") };
  if (!isPair(cd.a)) return { err: bad("calldata.a must be [dec, dec]") };
  if (!Array.isArray(cd.b) || cd.b.length !== 2 || !cd.b.every(isPair)) {
    return { err: bad("calldata.b must be [[dec, dec], [dec, dec]]") };
  }
  if (!isPair(cd.c)) return { err: bad("calldata.c must be [dec, dec]") };
  if (!Array.isArray(cd.pub) || !cd.pub.every(isDec)) return { err: bad("calldata.pub must be decimal strings") };
  if (cd.pub.length !== WITHDRAW_PUB_LEN) {
    return { err: bad(`calldata.pub must have ${WITHDRAW_PUB_LEN} elements (withdraw circuit), got ${cd.pub.length}`) };
  }
  const recipient = BigInt(cd.pub[RECIPIENT_PUB_INDEX] as string);
  if (recipient === 0n) return { err: bad("pub[26] (the proof-bound recipient) is zero") };
  if (recipient >= 1n << 160n) return { err: bad("pub[26] (the proof-bound recipient) exceeds the address range") };
  const kemErr = kemCiphertextError(b.kemCiphertext);
  if (kemErr) return { err: bad(kemErr) };
  const ephemeralPub = b.ephemeralPub ?? ZERO_EPHEMERAL;
  if (typeof ephemeralPub !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(ephemeralPub)) {
    return { err: bad("ephemeralPub must be 32 bytes of 0x-hex") };
  }
  const viewTag = b.viewTag ?? 0;
  if (typeof viewTag !== "number" || !Number.isInteger(viewTag) || viewTag < 0 || viewTag > 255) {
    return { err: bad("viewTag must be an integer in [0, 255]") };
  }
  return {
    ok: {
      calldata: cd as unknown as Calldata,
      kemCiphertext: b.kemCiphertext as string,
      ephemeralPub,
      viewTag,
    },
  };
}

/** The EXACT argument tuple packages/client connection.ts submit() builds for a
 *  withdraw — [a, b, c, pub, kemCiphertext, ephemeralPub, viewTag] with the
 *  proof coordinates as bigints. Kept as its own function so the test can pin
 *  deep-equality against that shape: the relayer must be indistinguishable from
 *  a wallet submit at the ABI encoder. */
export function withdrawArgs(body: RelayBody): unknown[] {
  return [
    body.calldata.a.map(BigInt) as [bigint, bigint],
    body.calldata.b.map((r) => r.map(BigInt)) as [[bigint, bigint], [bigint, bigint]],
    body.calldata.c.map(BigInt) as [bigint, bigint],
    body.calldata.pub.map(BigInt),
    body.kemCiphertext as `0x${string}`,
    (body.ephemeralPub ?? ZERO_EPHEMERAL) as `0x${string}`,
    body.viewTag ?? 0,
  ];
}

/** Best human-readable line out of a viem revert/failure: walk the cause chain
 *  for the most specific field a layer offers (revert reason > shortMessage >
 *  message). Mirrors the digging discipline of @bongtu/core/errors causeChain. */
export function revertReason(e: unknown): string {
  const seen: string[] = [];
  const walk = (cur: unknown, depth: number): void => {
    if (cur === null || typeof cur !== "object" || depth >= 8) return;
    const o = cur as Record<string, unknown>;
    for (const k of ["reason", "shortMessage", "message"]) {
      if (typeof o[k] === "string" && (o[k] as string).length > 0) seen.push(o[k] as string);
    }
    walk(o.cause, depth + 1);
  };
  walk(e, 0);
  // The DEEPEST reason is the revert itself; fall back outward.
  const reason = seen.reverse().find((s) => s.length > 0);
  return reason ?? String(e);
}

/**
 * POST /relay: validate → simulate → submit → receipt. One tx at a time by
 * construction (the caller awaits); PoC scope — no fee model, no rate limiting,
 * no queue (see index.ts header). Status mapping:
 *   400 malformed shape, 422 simulation revert (with the revert reason text),
 *   502 submit/receipt failure (the tx may or may not have landed — the caller
 *   retries or checks the chain), 200 { txHash }.
 */
export async function handleRelay(chain: RelayerChain, raw: unknown): Promise<RelayResult> {
  const parsed = parseRelayBody(raw);
  if ("err" in parsed) return parsed.err;
  const body = parsed.ok;
  const args = withdrawArgs(body);
  const target = {
    address: chain.pool as Address,
    abi: WITHDRAW_ABI,
    functionName: "withdraw",
    args,
  } as const;

  // Simulate BEFORE spending gas: a proof the contract would reject (stale root,
  // spent nullifier, InvalidProof) costs the submitter nothing and the caller
  // gets the revert reason instead of a burned relayer balance.
  try {
    await chain.publicClient.simulateContract({ ...target, account: chain.submitter as Address });
  } catch (e) {
    return { status: 422, body: { error: `simulation reverted: ${revertReason(e)}` } };
  }

  try {
    const hash = await chain.walletClient.writeContract({
      ...target,
      account: chain.submitter as Address,
      // 3x headroom over the node's quote — the packages/client chainGasPrice
      // rationale: eth_gasPrice IS the current floor, and a tx priced exactly at
      // it goes pending the moment the floor drifts up a block later.
      gasPrice: (await chain.publicClient.getGasPrice()) * 3n,
    });
    await chain.publicClient.waitForTransactionReceipt({ hash });
    return { status: 200, body: { txHash: hash } };
  } catch (e) {
    return { status: 502, body: { error: `submit failed: ${revertReason(e)}` } };
  }
}

/**
 * GET /health: { ok, submitter, balanceWei }. ok=false when the balance is 0 —
 * an unfunded relayer must be visible BEFORE a user waits on a /relay that can
 * only fail at submit. The submitter ADDRESS is public by nature (it signs
 * on-chain txs); the key never appears anywhere.
 */
export async function handleHealth(chain: RelayerChain): Promise<RelayResult> {
  const balance = await chain.publicClient.getBalance({ address: chain.submitter as Address });
  return {
    status: 200,
    body: { ok: balance > 0n, submitter: chain.submitter, balanceWei: balance.toString() },
  };
}
