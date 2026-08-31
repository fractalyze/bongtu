// POST a ProvingRequest to the bongtu prover service (top-level prover/ — FastAPI
// over rabbitsnark on the employer's GPU box) and get back Groth16 calldata.
// payroll-web does NO in-browser proving: every proof of the pay run — the
// transfer10x2 merge legs, the terminal 1×256 disburse, and the funding deposit —
// goes through here (SPEC §6 "we prove in the demo"). The base URL comes from
// config (VITE_PROVER_URL, else /prover in prod and the loopback bind in dev);
// the work endpoint is POST {base}/prove (prover/README.md).

import type { Calldata, ProvingRequest } from "@bongtu/core/proving";

import { serviceAuth } from "./serviceAuth.js";

/**
 * The public-signal count each served circuit's calldata must carry — the
 * service registry's per-circuit vkey truth (prover_service/config.py CIRCUITS
 * num_public, itself pinned to circuits/out/<name>.vkey.json nPublic; the
 * payroll test cross-checks the vkeys where they exist locally). A pub vector of
 * any other length would revert on-chain as a malformed verifier call, so it is
 * rejected here with the counts named instead of burning gas to find out.
 */
export const SERVICE_PUB_LEN: Record<string, number> = {
  disburse: 11,
  transfer10x2: 68,
  deposit: 19,
};

/**
 * Prove `request` on the service at `baseUrl`. The @bongtu/client builders tag
 * their requests `backend: "cpu"` (they were written for in-browser snarkjs);
 * on the service that tag means "refuse — this box is GPU-only", so the ONE
 * service adapter rewrites it to "gpu" for every request it posts.
 */
export async function proveViaService(baseUrl: string, request: ProvingRequest): Promise<Calldata> {
  const expected = SERVICE_PUB_LEN[request.circuit];
  if (expected === undefined) {
    throw new Error(`the prover service does not serve '${request.circuit}'`);
  }
  // The service session rides on every prover request (the prover's
  // PROVER_AUTH_SHA256 gate); absent — local dev against an open service, or
  // the node e2e driver — the request goes out bare, unchanged behavior.
  const headers: Record<string, string> = { "content-type": "application/json" };
  const auth = serviceAuth.header();
  if (auth !== null) headers.authorization = auth;
  const res = await fetch(`${baseUrl.replace(/\/$/, "")}/prove`, {
    method: "POST",
    headers,
    body: JSON.stringify({ ...request, backend: "gpu" }),
  });
  const text = await res.text();
  if (res.status === 401) {
    // The prover no longer honors this credential (rotated, or never valid):
    // the service session is over — dropping it sends App back to the login
    // page, which beats every later request failing the same way.
    serviceAuth.drop();
    throw new Error("The prover service rejected this sign-in. Sign in again.");
  }
  if (!res.ok) throw new Error(`prover service ${res.status}: ${text.slice(0, 400)}`);
  const cd: Calldata = (() => {
    try {
      return JSON.parse(text) as Calldata;
    } catch {
      throw new Error(`prover service returned non-JSON: ${text.slice(0, 200)}`);
    }
  })();
  if (!cd.a || !cd.b || !cd.c || !cd.pub) throw new Error("prover service response missing a/b/c/pub");
  if (cd.pub.length !== expected) {
    throw new Error(`${request.circuit} calldata must have ${expected} public signals, got ${cd.pub.length}`);
  }
  return cd;
}
