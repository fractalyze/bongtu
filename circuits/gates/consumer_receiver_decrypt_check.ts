// OPMOD §2.1 consumer gate #1 — receiver-decrypt parity.
//
// Runs the OPMOD §3.6 discovery pipeline against every CPU consumer circuit's
// REAL proved artifacts (prove -> viewTag filter -> Decaps -> decrypt ->
// leaf-match), for funded AND pad outputs, pinning the circuit and TS
// derivations equal: the recipient's view identity (viewPriv + kemDk — neither
// can spend) must decrypt exactly the [value, salt] the circuit encrypted, and
// the rebuilt commitment must equal the published output commitment (the
// leaf-match MAC substitute).
//
// Layouts are asserted INDEX-EXACT per OPMOD §2 (a drifted public vector fails
// here before it can ship in a module). For the four small ops the ciphertexts
// and viewTags are public signals and are consumed directly from
// out/<fixture>.public.json; for disbursePriv they are NOT public (they ride
// the `disclosure` calldata) — the TS reseal is first tied to the circuit via
// the extended fold (disclosureHash equality), then decrypted, so the parity
// chain still starts from a proof-bound value.
//
// The per-output ML-KEM encapsulations are re-derived from the SHARED
// deterministic plan (fixtures/consumer_lib.ts) — the same bytes the sender
// would put in the module's kemCiphertexts calldata — and are opened with a
// GENUINE ML-KEM.Decaps against each recipient's secret key.
//
// Requires a built out/ (bash build/prove_all.sh, the consumer legs).
//
//   npx tsx circuits/gates/consumer_receiver_decrypt_check.ts   # exits 0 iff parity holds

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { commitment, ecdhSharedSecret } from "@bongtu/core/note";
import { consumerDisclosureHash, consumerViewTag, openConsumerOutput } from "@bongtu/core/consumer";

import { ENCRYPTION_NONCE } from "../fixtures/fixture_lib.js";
import {
  depositPrivPlan,
  disbursePrivPlan,
  sealPlan,
  transfer10x2PrivPlan,
  transferPrivPlan,
  withdrawPrivPlan,
} from "../fixtures/consumer_lib.js";
import type { OutputPlan, SealedPlanOutput } from "../fixtures/consumer_lib.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "..", "out");

const failures = { count: 0 };
const fail = (msg: string): void => {
  console.error(`FAIL: ${msg}`);
  failures.count++;
};

function publics(fixture: string): bigint[] | undefined {
  const p = join(OUT, `${fixture}.public.json`);
  if (!existsSync(p)) return undefined;
  return (JSON.parse(readFileSync(p, "utf8")) as string[]).map(BigInt);
}

/** Index-exact OPMOD §2 layout of one small-op public vector. */
interface SmallOpLayout {
  fixture: string;
  len: number;
  ecdhAt: number;
  ctsAt: number;
  tagsAt: number;
  outCommitsAt: number;
  nonceAt: number;
  plan: OutputPlan[];
}

const SMALL_OPS: SmallOpLayout[] = [
  { fixture: "depositPriv", len: 16, ecdhAt: 1, ctsAt: 3, tagsAt: 11, outCommitsAt: 13, nonceAt: 15, plan: depositPrivPlan() },
  { fixture: "transferPriv", len: 20, ecdhAt: 0, ctsAt: 2, tagsAt: 10, outCommitsAt: 17, nonceAt: 19, plan: transferPrivPlan() },
  { fixture: "transfer10x2Priv", len: 36, ecdhAt: 0, ctsAt: 2, tagsAt: 10, outCommitsAt: 33, nonceAt: 35, plan: transfer10x2PrivPlan() },
  { fixture: "withdrawPriv", len: 16, ecdhAt: 1, ctsAt: 3, tagsAt: 7, outCommitsAt: 13, nonceAt: 14, plan: withdrawPrivPlan() },
];

/** The §3.6 pipeline for one output: filter -> Decaps+decrypt -> leaf-match. */
function checkOutput(
  fixture: string,
  i: number,
  sealed: SealedPlanOutput,
  ecdhPub: [bigint, bigint],
  cipherText: bigint[],
  publicTag: bigint | undefined,
  publicCommitment: bigint,
): void {
  const id = sealed.plan.id;
  const kind = sealed.plan.value === 0n ? "pad" : "funded";

  // (1) viewTag pre-filter — recomputed from viewPriv · ecdhPublicKey alone
  // (no Decaps), as a viewPriv-only scanner would.
  const filterTag = consumerViewTag(ecdhSharedSecret(id.view.formattedPrivateKey, ecdhPub));
  if (publicTag !== undefined && filterTag !== publicTag) {
    fail(`${fixture}[${i}] (${kind}): scanner viewTag ${filterTag} != published ${publicTag}`);
    return;
  }

  // (2) Decaps with the recipient's kemDk + hybrid decrypt at nonce+i.
  const opened = openConsumerOutput({
    cipherText,
    ecdhPublicKey: ecdhPub,
    viewPriv: id.view.formattedPrivateKey,
    kemDk: id.kem.secretKey,
    kemCiphertext: sealed.seal.kemCiphertext,
    encryptionNonce: ENCRYPTION_NONCE,
    index: i,
  });

  // (3) leaf-match acceptance: the rebuilt commitment equals the published one.
  const leaf = commitment(opened.value, opened.salt, id.spend.publicKey);
  if (leaf !== publicCommitment) {
    fail(`${fixture}[${i}] (${kind}): leaf-match REJECT (rebuilt ${leaf} != published ${publicCommitment})`);
    return;
  }
  if (opened.value !== sealed.plan.value || opened.salt !== sealed.plan.salt) {
    fail(`${fixture}[${i}] (${kind}): decrypted (${opened.value}, ${opened.salt}) != planned (${sealed.plan.value}, ${sealed.plan.salt})`);
    return;
  }
  console.log(`OK: ${fixture}[${i}] (${kind}) viewTag=${filterTag} -> Decaps -> decrypt -> leaf-match ACCEPT`);
}

// --- the four small ops: cts + tags are public signals ----------------------

for (const op of SMALL_OPS) {
  const pub = publics(op.fixture);
  if (!pub) {
    fail(`${op.fixture}: out/${op.fixture}.public.json missing — run bash build/prove_all.sh ${op.fixture}`);
    continue;
  }
  if (pub.length !== op.len) {
    fail(`${op.fixture}: public vector is ${pub.length} signals, OPMOD §2 says ${op.len}`);
    continue;
  }
  if (pub[op.nonceAt] !== ENCRYPTION_NONCE) {
    fail(`${op.fixture}: encryptionNonce public (pub[${op.nonceAt}]) != fixture nonce`);
    continue;
  }
  const ecdhPub: [bigint, bigint] = [pub[op.ecdhAt], pub[op.ecdhAt + 1]];
  const sealed = sealPlan(op.fixture, op.plan);
  for (const [i, s] of sealed.entries()) {
    checkOutput(
      op.fixture,
      i,
      s,
      ecdhPub,
      pub.slice(op.ctsAt + 4 * i, op.ctsAt + 4 * i + 4),
      pub[op.tagsAt + i],
      pub[op.outCommitsAt + i],
    );
  }
}

// --- disbursePriv: cts + tags ride the disclosure, bound by the fold --------

const disbursePub = publics("disbursePriv");
if (!disbursePub) {
  fail("disbursePriv: out/disbursePriv.public.json missing — run bash build/prove_all.sh disbursePriv");
} else if (disbursePub.length !== 8) {
  fail(`disbursePriv: public vector is ${disbursePub.length} signals, OPMOD §2 says 8`);
} else if (disbursePub[7] !== ENCRYPTION_NONCE) {
  fail("disbursePriv: encryptionNonce public (pub[7]) != fixture nonce");
} else {
  const sealed = sealPlan("disbursePriv", disbursePrivPlan());
  const cts = sealed.map((s) => s.seal.cipherText);
  const tags = sealed.map((s) => s.seal.viewTag);
  const commitments = sealed.map((s) => s.commitment);
  // Tie the TS reseal to the circuit's (non-public) ciphertexts: the extended
  // fold over the TS artifacts must equal the proof-bound disclosureHash.
  const dh = consumerDisclosureHash(cts, tags, commitments);
  if (dh !== disbursePub[2]) {
    fail(`disbursePriv: TS reseal fold ${dh} != proof disclosureHash ${disbursePub[2]} — circuit/TS ct drift`);
  } else {
    console.log("OK: disbursePriv TS reseal folds to the proof-bound disclosureHash (circuit cts == TS cts)");
    const ecdhPub: [bigint, bigint] = [disbursePub[0], disbursePub[1]];
    for (const [i, s] of sealed.entries()) {
      checkOutput("disbursePriv", i, s, ecdhPub, cts[i], tags[i], commitments[i]);
    }
  }
}

if (failures.count) {
  console.error(`\nRECEIVER-DECRYPT PARITY GATE: FAIL (${failures.count})`);
  process.exit(1);
}
console.log(
  "\nRECEIVER-DECRYPT PARITY GATE: PASS — TS decrypts what the circuits encrypted (funded AND pad outputs; leaf-match accepts)",
);
process.exit(0);
