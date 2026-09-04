// Headless gates for the relayed withdraw submit (src/relayerClient.ts), driven
// by a fake fetchFn — no relayer process, no network. What is gated:
//
//   (1) HAPPY PATH — POST {calldata, kemCiphertext} to <relayerUrl>/relay and
//       map { txHash } into the same SubmitResult shape submitWithdraw returns
//       (explorer link included), so spendFlow cannot tell the paths apart. A
//       stealth derivation's announcement half rides in the body; a plain run
//       sends NEITHER field (the relayer's own default is the sentinel).
//   (2) FAILURE SURFACES, NO SILENT FALLBACK — a 422 (simulation revert) and a
//       network failure both THROW readable messages and never retry or touch a
//       wallet: silently self-submitting would pay gas from the very account
//       the relayer promised to spare.

import { test } from "node:test";
import assert from "node:assert/strict";

import type { Calldata } from "@bongtu/core/proving";
import type { StealthDerivation } from "@bongtu/core/stealth";

import { submitWithdrawRelayed } from "@bongtu/client/relayerClient";

const CALLDATA: Calldata = {
  a: ["1", "2"],
  b: [["3", "4"], ["5", "6"]],
  c: ["7", "8"],
  pub: Array.from({ length: 27 }, (_, i) => String(i + 1)),
};
const KEM = "0x" + "ab".repeat(1088);
const TX = "0x" + "cd".repeat(32);
const EXPLORER = "https://scan.example";

interface RecordedCall {
  url: string;
  method?: string;
  body: unknown;
}

/** A fake fetch: records the request, answers a scripted status/body. */
function fakeFetch(status: number, body: unknown) {
  const calls: RecordedCall[] = [];
  const fetchFn = (async (url: unknown, init?: { method?: string; body?: string }) => {
    calls.push({ url: String(url), method: init?.method, body: JSON.parse(init?.body ?? "null") });
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
    };
  }) as unknown as typeof fetch;
  return { calls, fetchFn };
}

test("a relayed withdraw POSTs the calldata and maps {txHash} into the SubmitResult shape", async () => {
  const { calls, fetchFn } = fakeFetch(200, { txHash: TX });
  // trailing slash on the configured URL must not double up
  const res = await submitWithdrawRelayed("http://relayer:8700/", CALLDATA, KEM, EXPLORER, undefined, fetchFn);
  assert.deepEqual(res, { txHash: TX, explorerUrl: `${EXPLORER}/tx/${TX}` });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://relayer:8700/relay");
  assert.equal(calls[0].method, "POST");
  // a PLAIN withdraw sends neither announcement field — the relayer's own
  // default is the sentinel, so absence == plain, same as a wallet submit.
  assert.deepEqual(calls[0].body, { calldata: CALLDATA, kemCiphertext: KEM });
});

test("a stealth run's announcement half rides in the relay body", async () => {
  const { calls, fetchFn } = fakeFetch(200, { txHash: TX });
  const stealth: StealthDerivation = {
    ephemeralPub: "0x" + "5a".repeat(32),
    viewTag: 129,
    address: "0x00000000000000000000000000000000000d0001",
  };
  await submitWithdrawRelayed("http://relayer:8700", CALLDATA, KEM, EXPLORER, stealth, fetchFn);
  assert.deepEqual(calls[0].body, {
    calldata: CALLDATA,
    kemCiphertext: KEM,
    ephemeralPub: stealth.ephemeralPub,
    viewTag: stealth.viewTag,
  });
});

test("a 422 surfaces the relayer's revert reason and never falls back", async () => {
  const { calls, fetchFn } = fakeFetch(422, { error: "simulation reverted: InvalidProof" });
  await assert.rejects(
    submitWithdrawRelayed("http://relayer:8700", CALLDATA, KEM, EXPLORER, undefined, fetchFn),
    /rejected the withdrawal: simulation reverted: InvalidProof/,
  );
  assert.equal(calls.length, 1, "one POST, no retry, no fallback submit");
});

test("an unreachable relayer throws a readable failure saying nothing was sent", async () => {
  const fetchFn = (async () => {
    throw new Error("ECONNREFUSED");
  }) as unknown as typeof fetch;
  await assert.rejects(
    submitWithdrawRelayed("http://relayer:8700", CALLDATA, KEM, EXPLORER, undefined, fetchFn),
    (e: unknown) => {
      const msg = (e as Error).message;
      assert.match(msg, /could not be reached/);
      assert.match(msg, /ECONNREFUSED/);
      assert.match(msg, /was not sent/);
      return true;
    },
  );
});

test("a 200 without a real txHash is a relayer bug, not a success", async () => {
  for (const body of [{}, { txHash: "0x123" }, { txHash: 42 }]) {
    const { fetchFn } = fakeFetch(200, body);
    await assert.rejects(
      submitWithdrawRelayed("http://relayer:8700", CALLDATA, KEM, EXPLORER, undefined, fetchFn),
      /without a transaction hash/,
    );
  }
});
