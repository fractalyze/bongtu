// Gate for the service session (lib/serviceAuth.ts): the Basic value the login
// builds, the sign-in probe against GET /auth/check, and the holder App's render
// gate subscribes to. Credentials in this file are throwaway pairs minted here —
// the real pair lives only in the prover's env (PROVER_AUTH_SHA256), never in
// the repo.

import { test, afterEach } from "node:test";
import assert from "node:assert/strict";

import {
  basicAuthValue,
  serviceAuth,
  signInToProver,
} from "../src/lib/serviceAuth.js";

afterEach(() => serviceAuth.drop()); // module-level holder — never leak across tests

function withFetch<T>(f: typeof fetch, run: () => Promise<T>): Promise<T> {
  const real = globalThis.fetch;
  globalThis.fetch = f;
  return run().finally(() => {
    globalThis.fetch = real;
  });
}

function fakeCheck(status: number) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fn = (async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return { ok: status >= 200 && status < 300, status } as Response;
  }) as unknown as typeof fetch;
  return { calls, fn };
}

// ---------------------------- the Basic value -------------------------------------

test("basicAuthValue is exactly HTTP Basic over utf8(id:password)", () => {
  // base64("throw-id:away-pw") — what the prover decodes and sha256-compares.
  assert.equal(basicAuthValue("throw-id", "away-pw"), "Basic dGhyb3ctaWQ6YXdheS1wdw==");
});

// ---------------------------- the holder ------------------------------------------

test("the holder round-trips and notifies its subscribers on set and drop", () => {
  const seen: (string | null)[] = [];
  const unsubscribe = serviceAuth.subscribe(() => seen.push(serviceAuth.header()));
  assert.equal(serviceAuth.header(), null);
  serviceAuth.set("Basic dGhyb3ctaWQ6YXdheS1wdw==");
  assert.equal(serviceAuth.header(), "Basic dGhyb3ctaWQ6YXdheS1wdw==");
  serviceAuth.drop();
  assert.equal(serviceAuth.header(), null);
  unsubscribe();
  assert.deepEqual(seen, ["Basic dGhyb3ctaWQ6YXdheS1wdw==", null]);
});

// ---------------------------- the sign-in probe -----------------------------------

test("a 200 from /auth/check starts the service session with the probed value", async () => {
  const { calls, fn } = fakeCheck(200);
  const result = await withFetch(fn, () => signInToProver("http://127.0.0.1:8700/", "throw-id", "away-pw"));
  assert.deepEqual(result, { ok: true });
  assert.equal(calls[0].url, "http://127.0.0.1:8700/auth/check");
  const header = (calls[0].init?.headers as Record<string, string>).authorization;
  assert.equal(header, basicAuthValue("throw-id", "away-pw"));
  assert.equal(serviceAuth.header(), header, "the validated value IS the session");
});

test("a 401 is the inline wrong-credentials error, and no session starts", async () => {
  const result = await withFetch(fakeCheck(401).fn, () => signInToProver("/prover", "throw-id", "nope"));
  assert.deepEqual(result, { ok: false, error: "Wrong ID or password." });
  assert.equal(serviceAuth.header(), null);
});

test("a non-401 failure names the status instead of blaming the credentials", async () => {
  const result = await withFetch(fakeCheck(503).fn, () => signInToProver("/prover", "throw-id", "away-pw"));
  assert.equal(result.ok, false);
  assert.match(result.ok ? "" : result.error, /503/);
  assert.equal(serviceAuth.header(), null);
});
