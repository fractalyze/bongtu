// POST a ProvingRequest to the local prover-cli helper (apps/admin-web/prover-helper.ts)
// running on the employer's GPU box, and get back Groth16 calldata. Browser GPU
// proving is infeasible (1.24GB zkey + rabbitsnark binary), so the honest PoC path
// is: assemble in the browser -> prove on the local helper -> submit from the browser
// (SPEC §6 "we prove in the demo").

import type { Calldata, ProvingRequest } from "@bongtu/prover-cli/types";

export async function proveViaHelper(proverUrl: string, request: ProvingRequest): Promise<Calldata> {
  const res = await fetch(proverUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`prover helper ${res.status}: ${text.slice(0, 400)}`);
  let cd: Calldata;
  try {
    cd = JSON.parse(text) as Calldata;
  } catch {
    throw new Error(`prover helper returned non-JSON: ${text.slice(0, 200)}`);
  }
  if (!cd.a || !cd.b || !cd.c || !cd.pub) throw new Error("prover helper response missing a/b/c/pub");
  if (cd.pub.length !== 10) throw new Error(`disburse calldata must have 10 public signals, got ${cd.pub.length}`);
  return cd;
}
