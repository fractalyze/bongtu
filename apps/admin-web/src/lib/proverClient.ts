// POST a ProvingRequest to the bongtu prover service (top-level prover/ — a Python
// FastAPI service over rabbitsnark, run on the employer's GPU box) and get back
// Groth16 calldata. Browser GPU proving is infeasible (1.24GB zkey + rabbitsnark),
// so the honest PoC path is: assemble in the browser -> prove on the service ->
// submit from the browser (SPEC §6 "we prove in the demo").
//
// The service URL is env-configurable at build time (VITE_PROVER_URL) with the
// config.ts default; the running page can still edit it in the employer view.

import type { Calldata, ProvingRequest } from "@bongtu/sdk/proving";

export async function proveViaService(proverUrl: string, request: ProvingRequest): Promise<Calldata> {
  const res = await fetch(proverUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`prover service ${res.status}: ${text.slice(0, 400)}`);
  let cd: Calldata;
  try {
    cd = JSON.parse(text) as Calldata;
  } catch {
    throw new Error(`prover service returned non-JSON: ${text.slice(0, 200)}`);
  }
  if (!cd.a || !cd.b || !cd.c || !cd.pub) throw new Error("prover service response missing a/b/c/pub");
  if (cd.pub.length !== 10) throw new Error(`disburse calldata must have 10 public signals, got ${cd.pub.length}`);
  return cd;
}
