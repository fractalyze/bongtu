// Gate for the prover-service adapter (lib/proverClient.ts) and the base-URL
// default (config.ts proverUrlFromEnv): every payroll proof goes through this
// one POST, so its per-circuit pub-length pins — the SERVICE registry's vkey
// truth, NOT the old local-CPU 10 — and the backend rewrite are load-bearing.

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

import type { ProvingRequest } from "@bongtu/core/proving";
import { SERVICE_PUB_LEN, proveViaService } from "../src/lib/proverClient.js";
import { proverUrlFromEnv } from "../src/config.js";

const WORD = "0x" + "0".repeat(64);
const calldataWith = (pubLen: number) => ({
  a: [WORD, WORD],
  b: [[WORD, WORD], [WORD, WORD]],
  c: [WORD, WORD],
  pub: Array.from({ length: pubLen }, () => WORD),
});

/** A fetch double capturing the one POST the adapter makes. */
function fakeFetch(status: number, body: unknown) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fn = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
    };
  }) as unknown as typeof fetch;
  return { calls, fn };
}

function withFetch<T>(f: typeof fetch, run: () => Promise<T>): Promise<T> {
  const real = globalThis.fetch;
  globalThis.fetch = f;
  return run().finally(() => {
    globalThis.fetch = real;
  });
}

const request = (circuit: string): ProvingRequest =>
  ({ circuit, input: {}, backend: "cpu" }) as unknown as ProvingRequest;

// ---------------------------- pub-length pins -------------------------------------

test("the per-circuit pub lengths are the service registry's vkey truth", () => {
  // disburse is 11 — the old payroll client pinned 10 (the pre-service local-CPU
  // calldata), which would reject every real service proof.
  assert.deepEqual(SERVICE_PUB_LEN, { disburse: 11, transfer10x2: 68, deposit: 19 });
});

test("the pins match the built vkeys where they exist locally", () => {
  // circuits/out is a gitignored build product; where it exists the pin must
  // equal the ground truth (same skip-rule as the service's own registry test).
  const artifacts: [string, string][] = [
    ["disburse", "disburse256"],
    ["transfer10x2", "transfer10x2"],
    ["deposit", "deposit"],
  ];
  for (const [tag, stem] of artifacts) {
    const vkey = new URL(`../../../circuits/out/${stem}.vkey.json`, import.meta.url).pathname;
    if (!existsSync(vkey)) continue;
    assert.equal(
      SERVICE_PUB_LEN[tag],
      (JSON.parse(readFileSync(vkey, "utf8")) as { nPublic: number }).nPublic,
      `${tag} pin != ${stem}.vkey.json nPublic`,
    );
  }
});

// ---------------------------- the adapter -----------------------------------------

test("proveViaService posts {base}/prove with backend rewritten to gpu", async () => {
  const { calls, fn } = fakeFetch(200, calldataWith(11));
  const cd = await withFetch(fn, () => proveViaService("http://127.0.0.1:8700/", request("disburse")));
  assert.equal(cd.pub.length, 11);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://127.0.0.1:8700/prove");
  const body = JSON.parse(calls[0].init.body as string) as { backend: string; circuit: string };
  // The client builders tag "cpu" (in-browser snarkjs); on the service that tag
  // means "refuse" — the one adapter rewrites it for everything it posts.
  assert.equal(body.backend, "gpu");
  assert.equal(body.circuit, "disburse");
});

test("each circuit's calldata is checked against ITS pub length", async () => {
  for (const [circuit, expected] of Object.entries(SERVICE_PUB_LEN)) {
    const ok = await withFetch(fakeFetch(200, calldataWith(expected)).fn, () =>
      proveViaService("/prover", request(circuit)),
    );
    assert.equal(ok.pub.length, expected, circuit);
    await assert.rejects(
      withFetch(fakeFetch(200, calldataWith(expected + 1)).fn, () =>
        proveViaService("/prover", request(circuit)),
      ),
      new RegExp(`${expected} public signals`),
      `${circuit} must reject a wrong-length pub vector`,
    );
  }
});

test("a circuit the service does not serve is refused before any fetch", async () => {
  const { calls, fn } = fakeFetch(200, calldataWith(11));
  await assert.rejects(
    withFetch(fn, () => proveViaService("/prover", request("withdraw"))),
    /does not serve/,
  );
  assert.equal(calls.length, 0);
});

test("service errors surface with their status and body", async () => {
  await assert.rejects(
    withFetch(fakeFetch(403, { detail: "Origin not allowed" }).fn, () =>
      proveViaService("/prover", request("disburse")),
    ),
    /prover service 403/,
  );
  await assert.rejects(
    withFetch(fakeFetch(200, "<html>gateway</html>").fn, () =>
      proveViaService("/prover", request("disburse")),
    ),
    /non-JSON/,
  );
});

// ---------------------------- base-URL default ------------------------------------

test("the base URL is VITE_PROVER_URL, else /prover in prod and loopback in dev", () => {
  assert.equal(proverUrlFromEnv(undefined, false), "/prover");
  assert.equal(proverUrlFromEnv(undefined, true), "http://127.0.0.1:8700");
  assert.equal(proverUrlFromEnv("", true), "http://127.0.0.1:8700");
  assert.equal(proverUrlFromEnv("https://gpu.example/prover/", false), "https://gpu.example/prover");
  assert.equal(proverUrlFromEnv("https://gpu.example", true), "https://gpu.example");
});

test("an old deployment's full ENDPOINT is accepted as the base it used to be", () => {
  // Migration hazard: VITE_PROVER_URL once carried "…/prove" and the adapter now
  // appends /prove itself — an unstripped value posts to /prove/prove and 404s at
  // pay time, on a machine nobody is looking at until payroll day.
  assert.equal(proverUrlFromEnv("http://x:8700/prove", true), "http://x:8700");
  assert.equal(proverUrlFromEnv("https://gpu.example/prove/", false), "https://gpu.example");
  // …and a path that merely STARTS like it is left alone.
  assert.equal(proverUrlFromEnv("https://gpu.example/prover", false), "https://gpu.example/prover");
  assert.equal(proverUrlFromEnv("https://gpu.example/prove/v2", false), "https://gpu.example/prove/v2");
});
