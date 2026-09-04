// Headless gates for the relay decision (relay.ts) and its HTTP surface
// (server.ts), driven entirely by FAKE viem clients — no chain, no RPC, no real
// key. What is gated:
//
//   (1) SHAPE — the 400 table: pub.length must be 27 (the withdraw circuit),
//       pub[26] (the proof-bound recipient) nonzero and inside the 160-bit
//       address range, kemCiphertext exactly 1088 bytes of 0x-hex, and the
//       optional announcement pair well-formed.
//   (2) 422 — a simulation revert answers 422 carrying the revert reason text,
//       and never reaches writeContract (no gas spent on a doomed proof).
//   (3) HAPPY PATH — writeContract receives the EXACT
//       [a, b, c, pub, kemCiphertext, ephemeralPub, viewTag] tuple that
//       packages/client connection.ts submit() builds for a withdraw (bigint
//       proof coords, sentinel announcement when none) — the relayer must be
//       indistinguishable from a wallet submit at the ABI encoder — priced at
//       the chain quote x3 and resolved only after the receipt.
//   (4) 502 — a submit/receipt failure is the relayer's own fault class, not
//       the caller's.
//   (5) HEALTH — ok=false when the submitter balance is 0 (an unfunded relayer
//       must be visible before a user waits on it), and no response ever
//       carries key material.

import { test } from "node:test";
import assert from "node:assert/strict";

import { ZERO_EPHEMERAL } from "@bongtu/core/stealth";

import {
  handleHealth,
  handleRelay,
  parseRelayBody,
  withdrawArgs,
  WITHDRAW_PUB_LEN,
  type RelayerChain,
  type RelayBody,
} from "../src/relay.js";
import { startApi } from "../src/server.js";

const SUBMITTER = "0x00000000000000000000000000000000000000e1";
const POOL = "0x0000000000000000000000000000000000000b0b";
const TX_HASH = ("0x" + "ab".repeat(32)) as `0x${string}`;
const KEM_CT = "0x" + "cd".repeat(1088);
const RECIPIENT = "0x00000000000000000000000000000000000d0001";

/** A valid relay body: a 27-signal withdraw whose pub[26] is RECIPIENT. */
function validBody(over: Partial<RelayBody> = {}): RelayBody {
  const pub = Array.from({ length: WITHDRAW_PUB_LEN }, (_, i) => String(i + 1));
  pub[26] = BigInt(RECIPIENT).toString();
  return {
    calldata: { a: ["1", "2"], b: [["3", "4"], ["5", "6"]], c: ["7", "8"], pub },
    kemCiphertext: KEM_CT,
    ...over,
  };
}

/** A fake chain: records every call, and lets a test script failures. */
function fakeChain(over: {
  simulate?: () => Promise<unknown>;
  write?: () => Promise<`0x${string}`>;
  balance?: bigint;
} = {}) {
  const calls: { name: string; params: unknown }[] = [];
  const chain: RelayerChain = {
    submitter: SUBMITTER,
    pool: POOL,
    publicClient: {
      simulateContract: async (params) => {
        calls.push({ name: "simulateContract", params });
        return over.simulate ? over.simulate() : {};
      },
      getGasPrice: async () => {
        calls.push({ name: "getGasPrice", params: undefined });
        return 1_000_000n;
      },
      waitForTransactionReceipt: async (params) => {
        calls.push({ name: "waitForTransactionReceipt", params });
        return { status: "success" };
      },
      getBalance: async (params) => {
        calls.push({ name: "getBalance", params });
        return over.balance ?? 10n ** 18n;
      },
    },
    walletClient: {
      writeContract: async (params) => {
        calls.push({ name: "writeContract", params });
        return over.write ? over.write() : TX_HASH;
      },
    },
  };
  return { chain, calls };
}

// ============================== (1) SHAPE ====================================

test("400 table: every malformed body is named, and none reaches the chain", async () => {
  const { chain, calls } = fakeChain();
  const cases: [unknown, RegExp][] = [
    [null, /JSON object/],
    [{}, /calldata/],
    [{ ...validBody(), calldata: { ...validBody().calldata, a: ["1"] } }, /calldata\.a/],
    [{ ...validBody(), calldata: { ...validBody().calldata, b: [["1", "2"]] } }, /calldata\.b/],
    [{ ...validBody(), calldata: { ...validBody().calldata, c: ["x", "y"] } }, /calldata\.c/],
    // the load-bearing arity: 27 public signals or it is not a withdraw proof
    [{ ...validBody(), calldata: { ...validBody().calldata, pub: ["1", "2", "3"] } }, /27/],
    // a zero recipient is a proof no wallet could have built
    [
      (() => {
        const b = validBody();
        b.calldata.pub[26] = "0";
        return b;
      })(),
      /recipient.*zero/,
    ],
    // out of the 160-bit address range
    [
      (() => {
        const b = validBody();
        b.calldata.pub[26] = (1n << 160n).toString();
        return b;
      })(),
      /address range/,
    ],
    // the same kemCiphertext check as packages/client connection.ts
    [validBody({ kemCiphertext: "0x" + "cd".repeat(1087) }), /1088 bytes/],
    [validBody({ kemCiphertext: "cd".repeat(1088) }), /1088 bytes/],
    [validBody({ ephemeralPub: "0x1234" }), /ephemeralPub/],
    [validBody({ viewTag: 256 }), /viewTag/],
    [validBody({ viewTag: -1 }), /viewTag/],
  ];
  for (const [body, want] of cases) {
    const res = await handleRelay(chain, body);
    assert.equal(res.status, 400, `expected 400 for ${JSON.stringify(body).slice(0, 80)}`);
    assert.match((res.body as { error: string }).error, want);
  }
  assert.deepEqual(calls, [], "a malformed body must never touch the chain");
});

// ============================== (2) 422 ======================================

test("a simulation revert answers 422 with the revert reason, and nothing is submitted", async () => {
  const revert = Object.assign(new Error("Execution reverted"), {
    cause: { shortMessage: "InvalidProof()", cause: { reason: "InvalidProof" } },
  });
  const { chain, calls } = fakeChain({
    simulate: async () => {
      throw revert;
    },
  });
  const res = await handleRelay(chain, validBody());
  assert.equal(res.status, 422);
  assert.match((res.body as { error: string }).error, /simulation reverted: .*InvalidProof/);
  assert.ok(!calls.some((c) => c.name === "writeContract"), "no gas is spent on a doomed proof");
});

// ============================ (3) HAPPY PATH =================================

test("a valid relay submits the EXACT withdraw tuple connection.ts submit() builds, at quote x3, after the receipt", async () => {
  const { chain, calls } = fakeChain();
  const body = validBody();
  const res = await handleRelay(chain, body);
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { txHash: TX_HASH });

  const write = calls.find((c) => c.name === "writeContract");
  assert.ok(write, "writeContract was called");
  const p = write.params as { address: string; functionName: string; args: unknown[]; gasPrice: bigint; account: string };
  assert.equal(p.address, POOL);
  assert.equal(p.functionName, "withdraw");
  assert.equal(p.account, SUBMITTER);
  // THE tuple: [a, b, c, pub, kemCiphertext, ephemeralPub, viewTag] exactly as
  // packages/client/src/wallet/poolWrites.ts submit() assembles it for fn === "withdraw"
  // (asProofArgs bigints + the ZERO_EPHEMERAL/0 sentinel when no stealth
  // derivation rides along). Deep-equality — not shape-checking — because any
  // drift here is a different transaction than the wallet would have sent.
  assert.deepEqual(p.args, [
    [1n, 2n],
    [[3n, 4n], [5n, 6n]],
    [7n, 8n],
    body.calldata.pub.map(BigInt),
    KEM_CT,
    ZERO_EPHEMERAL,
    0,
  ]);
  assert.equal(p.gasPrice, 3_000_000n, "chain quote x3 (packages/client chainGasPrice rationale)");
  // simulate before write, receipt after — in that order.
  assert.deepEqual(
    calls.map((c) => c.name),
    ["simulateContract", "getGasPrice", "writeContract", "waitForTransactionReceipt"],
  );
});

test("a stealth announcement pair rides through verbatim (a relayed stealth withdraw announces like a wallet one)", async () => {
  const { chain, calls } = fakeChain();
  const eph = ("0x" + "5a".repeat(32));
  const res = await handleRelay(chain, validBody({ ephemeralPub: eph, viewTag: 129 }));
  assert.equal(res.status, 200);
  const p = calls.find((c) => c.name === "writeContract")!.params as { args: unknown[] };
  assert.equal(p.args[5], eph);
  assert.equal(p.args[6], 129);
});

test("withdrawArgs defaults the announcement to the plain sentinel", () => {
  const args = withdrawArgs(validBody());
  assert.equal(args[5], ZERO_EPHEMERAL);
  assert.equal(args[6], 0);
  // and the parse fills the same defaults, so wire-absent == plain withdraw
  const parsed = parseRelayBody(validBody());
  assert.ok("ok" in parsed);
  assert.equal(parsed.ok.ephemeralPub, ZERO_EPHEMERAL);
  assert.equal(parsed.ok.viewTag, 0);
});

// ============================== (4) 502 ======================================

test("a submit failure is 502 — the relayer's fault class, not the caller's", async () => {
  const { chain } = fakeChain({
    write: async () => {
      throw new Error("nonce too low");
    },
  });
  const res = await handleRelay(chain, validBody());
  assert.equal(res.status, 502);
  assert.match((res.body as { error: string }).error, /submit failed: .*nonce too low/);
});

// ============================= (5) HEALTH ====================================

test("health reports the submitter and balance, and an unfunded relayer is ok=false", async () => {
  const funded = await handleHealth(fakeChain({ balance: 5n }).chain);
  assert.deepEqual(funded.body, { ok: true, submitter: SUBMITTER, balanceWei: "5" });
  const broke = await handleHealth(fakeChain({ balance: 0n }).chain);
  assert.deepEqual(broke.body, { ok: false, submitter: SUBMITTER, balanceWei: "0" });
});

// ============================ HTTP SURFACE ===================================

test("the wire: POST /relay and GET /health over real HTTP, 404 elsewhere, malformed JSON is a 400", async () => {
  const { chain } = fakeChain();
  const api = await startApi(chain, 0);
  const base = `http://127.0.0.1:${api.port}`;
  try {
    const health = await fetch(`${base}/health`);
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { ok: true, submitter: SUBMITTER, balanceWei: (10n ** 18n).toString() });

    const relay = await fetch(`${base}/relay`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(validBody()),
    });
    assert.equal(relay.status, 200);
    assert.deepEqual(await relay.json(), { txHash: TX_HASH });

    const badJson = await fetch(`${base}/relay`, { method: "POST", body: "{not json" });
    assert.equal(badJson.status, 400);

    const missing = await fetch(`${base}/nope`);
    assert.equal(missing.status, 404);

    // /relay is POST-only: relaying is a state change, never a GET.
    const wrongMethod = await fetch(`${base}/relay`);
    assert.equal(wrongMethod.status, 404);
  } finally {
    await api.stop();
  }
});
