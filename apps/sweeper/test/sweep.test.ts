// Headless gates for the sweep decision (sweep.ts) and its HTTP surface
// (server.ts), driven entirely by FAKE deps — no chain, no indexer, no snarkjs,
// no real key (the relayer relay.test.ts discipline). What is gated:
//
//   (1) HAPPY PATH — a funded record produces ONE PortalFactory.sweep carrying
//       the EXACT [salt, pool, a, b, c, pub, kemCiphertext] tuple (salt from
//       the ONE portalSalt padding rule, proof coords BigInt-mapped), priced at
//       the chain quote x3 and resolved only after the receipt; the deposit
//       input's TWO output owners are the record owner's unpacked pubkey and
//       the output values sum to the read balance ([balance, 0]).
//   (2) ZERO-BALANCE SKIP — an unfunded record (spam-surface hint) costs
//       nothing: no prove, no tx.
//   (3) ONE IN FLIGHT — records are processed strictly sequentially: the second
//       record's balance read happens only after the first's receipt.
//   (4) NO LOCAL MARKING — after a successful sweep the bot holds no "done"
//       state: the same record served again next round is re-examined (the
//       indexer's Swept-event ingest is the only swept flip).
//   (5) RE-READ PIN — the balance is re-read between prove and send, and a
//       re-read BELOW the proof-bound pub[0] skips the send (the
//       SweepExceedsBalance guard's free client-side twin).
//   (6) HEALTH — { ok, sweeper, balanceWei, lastSweepAt, unswept }, ok=false at
//       zero gas balance.

import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveKeypair } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import { portalSalt } from "@bongtu/core/stealth";
import type { Calldata, DepositInput, ProvingRequest } from "@bongtu/core/proving";
import type { PortalRecord } from "@bongtu/core/indexerApi";

import {
  DEPOSIT_PUB_LEN,
  handleHealth,
  initialState,
  runOnce,
  sweepArgs,
  type SweeperChain,
  type SweeperDeps,
  type SweeperState,
} from "../src/sweep.js";
import { startApi } from "../src/server.js";

const SWEEPER = "0x00000000000000000000000000000000000000e1";
const FACTORY = "0x00000000000000000000000000000000000fac70";
const POOL = "0x0000000000000000000000000000000000000b0b";
const TOKEN = "0x000000000000000000000000000000000000700c";
const TX_HASH = ("0x" + "ab".repeat(32)) as `0x${string}`;
const KEM_CT = "0x" + "cd".repeat(1088);

// The announced recipient: a real bjj keypair so unpackPubkey round-trips.
const OWNER_KEYPAIR = deriveKeypair(7n);
const OWNER_COMPRESSED = packPubkey(OWNER_KEYPAIR.publicKey);

function record(over: Partial<PortalRecord> = {}): PortalRecord {
  return {
    kind: "portal",
    seq: 0,
    name: "alice",
    owner: OWNER_COMPRESSED,
    ephemeralPub: "0x" + "11".repeat(32),
    viewTag: 42,
    stealthAddr: "0x00000000000000000000000000000000000d0001",
    destination: "0x00000000000000000000000000000000000de571",
    createdAt: 1_700_000_000,
    swept: false,
    sweptTxHash: null,
    sweptAmount: null,
    ...over,
  };
}

/** Deterministic randomness: distinct nonzero field draws per call. */
function countingRand(): () => string {
  const state = { n: 0 };
  return () => String(++state.n);
}

/** Deterministic KEM draw — the freshDepositCrypto seam's test double. */
const fakeKem = () => ({ kemSs: ["101", "102"] as [string, string], kemCiphertext: KEM_CT });

/** A fake prover that echoes the request's proof-bound amount into pub[0] the
 *  way the real circuit does (pub[0] == V), so the amount check downstream is
 *  exercised against the request actually built. */
function fakeProver(captured: ProvingRequest[]) {
  return async (request: ProvingRequest): Promise<Calldata> => {
    captured.push(request);
    const V = BigInt((request.input as DepositInput).outputValues[0] as string);
    const pub = Array.from({ length: DEPOSIT_PUB_LEN }, (_, i) => "0x" + BigInt(i + 1).toString(16));
    pub[0] = "0x" + V.toString(16);
    return { a: ["0x1", "0x2"], b: [["0x3", "0x4"], ["0x5", "0x6"]], c: ["0x7", "0x8"], pub };
  };
}

/** A fake chain: records every call (tagged with the queried address so
 *  per-record ordering is visible), and lets a test script balances. */
function fakeChain(over: {
  /** balanceOf results per destination, consumed in order (last repeats). */
  balances?: Record<string, bigint[]>;
  gasBalance?: bigint;
} = {}) {
  const calls: { name: string; params: unknown }[] = [];
  const consumed: Record<string, number> = {};
  const chain: SweeperChain = {
    sweeper: SWEEPER,
    factory: FACTORY,
    pool: POOL,
    token: TOKEN,
    publicClient: {
      readContract: async (params) => {
        const p = params as { functionName: string; args: [string] };
        calls.push({ name: `balanceOf:${p.args[0]}`, params });
        const seq = over.balances?.[p.args[0]] ?? [1000n];
        const i = consumed[p.args[0]] ?? 0;
        consumed[p.args[0]] = i + 1;
        return seq[Math.min(i, seq.length - 1)];
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
        return over.gasBalance ?? 10n ** 18n;
      },
    },
    walletClient: {
      writeContract: async (params) => {
        calls.push({ name: "writeContract", params });
        return TX_HASH;
      },
    },
  };
  return { chain, calls };
}

function makeDeps(
  chain: SweeperChain,
  records: PortalRecord[][],
  captured: ProvingRequest[],
  proveCalls: { name: string }[],
): SweeperDeps {
  const feed = { round: 0 };
  return {
    chain,
    fetchUnswept: async () => {
      const page = records[Math.min(feed.round, records.length - 1)];
      feed.round += 1;
      return page;
    },
    prove: async (request) => {
      proveCalls.push({ name: "prove" });
      return fakeProver(captured)(request);
    },
    rand: countingRand(),
    drawKem: fakeKem,
  };
}

// ============================ (1) HAPPY PATH =================================

test("a funded record sweeps with the EXACT factory tuple, owners = the record owner, sum == balance", async () => {
  const rec = record();
  const balance = 777n;
  const { chain, calls } = fakeChain({ balances: { [rec.destination]: [balance] } });
  const captured: ProvingRequest[] = [];
  const state = initialState();
  await runOnce(makeDeps(chain, [[rec]], captured, []), state);

  // The deposit input: outputs [note(balance), note(0)] BOTH owned by the
  // announced recipient's bjj pubkey — deep-equality against the unpacked
  // owner, in the wire form buildDepositRequest emits (decimal strings).
  assert.equal(captured.length, 1, "exactly one proof");
  const input = captured[0].input as DepositInput;
  const owner = [OWNER_KEYPAIR.publicKey[0].toString(), OWNER_KEYPAIR.publicKey[1].toString()];
  assert.deepEqual(input.outputOwnerPublicKeys, [owner, owner], "both outputs owned by the record owner");
  assert.deepEqual(input.outputValues, [balance.toString(), "0"], "values [balance, 0] — sum == balance");

  const write = calls.find((c) => c.name === "writeContract");
  assert.ok(write, "writeContract was called");
  const p = write.params as {
    address: string; functionName: string; args: unknown[]; gasPrice: bigint; account: string;
  };
  assert.equal(p.address, FACTORY, "the sweep goes through the factory, not the pool");
  assert.equal(p.functionName, "sweep");
  assert.equal(p.account, SWEEPER);
  // THE tuple: [salt, pool, a, b, c, pub, kemCiphertext] — salt from the ONE
  // portalSalt padding rule, proof coords as bigints (relayer withdrawArgs
  // discipline). Deep-equality, not shape-checking: any drift here is a
  // different transaction than the factory verifies.
  const expectedPub = Array.from({ length: DEPOSIT_PUB_LEN }, (_, i) => BigInt(i + 1));
  expectedPub[0] = balance;
  assert.deepEqual(p.args, [
    portalSalt(rec.stealthAddr),
    POOL,
    [1n, 2n],
    [[3n, 4n], [5n, 6n]],
    [7n, 8n],
    expectedPub,
    KEM_CT,
  ]);
  assert.equal(p.gasPrice, 3_000_000n, "chain quote x3 (packages/client chainGasPrice rationale)");
  assert.ok(state.lastSweepAt !== null, "a landed sweep stamps lastSweepAt");
  assert.equal(state.unswept, 1);
});

// ========================= (2) ZERO-BALANCE SKIP =============================

test("an unfunded record costs nothing: no prove, no tx (unswept rows are hints)", async () => {
  const rec = record();
  const { chain, calls } = fakeChain({ balances: { [rec.destination]: [0n] } });
  const captured: ProvingRequest[] = [];
  const proveCalls: { name: string }[] = [];
  const state = initialState();
  await runOnce(makeDeps(chain, [[rec]], captured, proveCalls), state);
  assert.equal(proveCalls.length, 0, "no proof for a zero balance");
  assert.ok(!calls.some((c) => c.name === "writeContract"), "no tx for a zero balance");
  assert.equal(state.lastSweepAt, null);
  assert.equal(state.unswept, 1, "the record still counts as unswept work");
});

// =========================== (3) ONE IN FLIGHT ===============================

test("records are strictly sequential: the second's balance read follows the first's receipt", async () => {
  const r1 = record({ seq: 1, destination: "0x00000000000000000000000000000000000de571" });
  const r2 = record({ seq: 2, destination: "0x00000000000000000000000000000000000de572", stealthAddr: "0x00000000000000000000000000000000000d0002" });
  const { chain, calls } = fakeChain({
    balances: { [r1.destination]: [5n], [r2.destination]: [7n] },
  });
  await runOnce(makeDeps(chain, [[r1, r2]], [], []), initialState());
  const order = calls.map((c) => c.name);
  const r2FirstRead = order.indexOf(`balanceOf:${r2.destination}`);
  const r1Receipt = order.indexOf("waitForTransactionReceipt");
  assert.ok(r1Receipt !== -1 && r2FirstRead !== -1);
  assert.ok(r2FirstRead > r1Receipt, `record 2 must not start before record 1's receipt (order: ${order.join(", ")})`);
  assert.equal(order.filter((n) => n === "writeContract").length, 2, "both records swept");
});

// ========================== (4) NO LOCAL MARKING =============================

test("a swept record is NOT locally marked: served again next round, it is re-examined", async () => {
  const rec = record();
  // Round 1: funded (5) — swept. Round 2: the indexer has not ingested Swept
  // yet, so the SAME record comes back; its balance is now 0 — skipped, not
  // filtered by any local "done" set.
  const { chain, calls } = fakeChain({ balances: { [rec.destination]: [5n, 5n, 0n] } });
  const deps = makeDeps(chain, [[rec]], [], []);
  const state = initialState();
  await runOnce(deps, state);
  await runOnce(deps, state);
  const reads = calls.filter((c) => c.name === `balanceOf:${rec.destination}`).length;
  assert.equal(reads, 3, "round 2 re-reads the record's balance (2 reads in round 1, 1 in round 2)");
  assert.equal(calls.filter((c) => c.name === "writeContract").length, 1, "only round 1 sweeps");
  assert.equal(state.unswept, 1, "the feed, not the bot, owns the swept flip");
});

// ============================ (5) RE-READ PIN ================================

test("the balance is re-read between prove and send; a shrunk re-read skips the send", async () => {
  const rec = record();
  // Ordering pin: read(10) -> prove -> re-read(10) -> write.
  const first = fakeChain({ balances: { [rec.destination]: [10n, 10n] } });
  const proveCalls: { name: string }[] = [];
  const trace: string[] = [];
  const deps = makeDeps(first.chain, [[rec]], [], proveCalls);
  const tracedDeps: SweeperDeps = {
    ...deps,
    prove: async (request) => {
      trace.push("prove");
      return deps.prove(request);
    },
  };
  await runOnce(tracedDeps, initialState());
  const order = first.calls.map((c) => c.name).filter((n) => n.startsWith("balanceOf") || n === "writeContract");
  assert.deepEqual(
    order,
    [`balanceOf:${rec.destination}`, `balanceOf:${rec.destination}`, "writeContract"],
    "two balance reads bracket the proof, and only then the send",
  );
  assert.equal(trace.length, 1);

  // A re-read BELOW pub[0] (a concurrent pull) skips the send entirely — the
  // client-side twin of the factory's SweepExceedsBalance guard.
  const shrunk = fakeChain({ balances: { [rec.destination]: [10n, 3n] } });
  await runOnce(makeDeps(shrunk.chain, [[rec]], [], []), initialState());
  assert.ok(!shrunk.calls.some((c) => c.name === "writeContract"), "no tx when the balance shrank below the proof amount");
});

// ============================= (6) HEALTH ====================================

test("health reports sweeper/balance/lastSweepAt/unswept, and an unfunded sweeper is ok=false", async () => {
  const state: SweeperState = { lastSweepAt: 1_700_000_123, unswept: 4 };
  const funded = await handleHealth(fakeChain({ gasBalance: 5n }).chain, state);
  assert.deepEqual(funded.body, {
    ok: true,
    sweeper: SWEEPER,
    balanceWei: "5",
    lastSweepAt: 1_700_000_123,
    unswept: 4,
  });
  const broke = await handleHealth(fakeChain({ gasBalance: 0n }).chain, initialState());
  assert.deepEqual(broke.body, { ok: false, sweeper: SWEEPER, balanceWei: "0", lastSweepAt: null, unswept: 0 });
});

// ============================ HTTP SURFACE ===================================

test("the wire: GET /health over real HTTP, 404 elsewhere", async () => {
  const { chain } = fakeChain({ gasBalance: 9n });
  const api = await startApi(chain, initialState(), 0);
  const base = `http://127.0.0.1:${api.port}`;
  try {
    const health = await fetch(`${base}/health`);
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), {
      ok: true,
      sweeper: SWEEPER,
      balanceWei: "9",
      lastSweepAt: null,
      unswept: 0,
    });
    const missing = await fetch(`${base}/nope`);
    assert.equal(missing.status, 404);
  } finally {
    await api.stop();
  }
});

// ============================ ARG GUARDS =====================================

test("sweepArgs refuses a non-deposit-arity public vector", () => {
  const cd: Calldata = { a: ["0x1", "0x2"], b: [["0x3", "0x4"], ["0x5", "0x6"]], c: ["0x7", "0x8"], pub: ["0x1", "0x2"] };
  assert.throws(() => sweepArgs(record().stealthAddr, POOL, cd, KEM_CT), /19/);
});
