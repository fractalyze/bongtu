// gen_withdraw_solana_fixture.ts — re-prove the ONE withdrawPriv fixture the
// Solana rail needs (SOLR §5.2's single exception): the committed EVM
// withdrawPriv realproof binds an EVM address in pub[15], so the op-level
// happy-path withdraw on Solana needs a proof bound to a Solana-mapped
// recipient under the OPEN-3 truncate-253 rule. Everything else about the
// fixture — inputs, seed leaves, seals, kem ct — is byte-identical to the EVM
// entry, and this script asserts that, so the two fixtures prove the SAME
// spend against two recipient encodings.
//
// OPEN-3 truncate-253 (see chains/solana/program/src/recipient_binding.rs): the
// recipient token account Pubkey is read as a BIG-ENDIAN 256-bit integer and
// the top 3 bits are cleared: recipient = addr mod 2^253 (< r, always
// canonical). The circuit input `recipient` gets that value in decimal — the
// same field the pipeline already fills (circuits/fixtures/gen_consumer_inputs.ts).
//
// CPU-provable via the existing pipeline artifacts (withdrawPriv wasm + zkey,
// circuits/build/prove_all.sh outputs). Run from the repo root:
//   node_modules/.bin/tsx chains/solana/scripts/gen_withdraw_solana_fixture.ts
//
// Reads  circuits/fixtures/inputs/withdrawPriv.json (the committed witness input)
//        circuits/out/withdrawPriv_js/withdrawPriv.wasm, withdrawPriv.zkey/vkey
//        chains/evm/test/fixtures/consumer_realproofs.json (the EVM twin, for belts)
// Writes chains/evm/test/fixtures/consumer_realproofs_solana.json
//        (committed beside the EVM realproofs — SOLR §5.2)

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadSnarkjs } from "@bongtu/core/extern";
import { ImtTree } from "@bongtu/core/imt";

import { sealPlan, withdrawPrivPlan } from "../../../circuits/fixtures/consumer_lib.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const OUT = join(REPO, "circuits", "out");
const FIXDIR = join(REPO, "chains", "evm", "test", "fixtures");

const snarkjs = loadSnarkjs();

const s = (x: bigint | number | string): string => "0x" + BigInt(x).toString(16).padStart(64, "0");

function assertEq(got: bigint | number | string, want: bigint | number | string, msg: string): void {
  if (BigInt(got) !== BigInt(want)) throw new Error(`${msg}: got ${got} want ${want}`);
}

// --- the fixture recipient token account ------------------------------------
// A deterministic label-derived 32-byte address (mollusk accounts need not be
// on-curve; SPL token account addresses are arbitrary). sha256 output has its
// top bits uniformly set, so this exercises the 2^253 mask for real: the bound
// value differs from the raw address bytes.
const RECIPIENT_TOKEN_ACCOUNT = new Uint8Array(
  createHash("sha256").update("bongtu/solana-fixture/recipient-token-account/v1").digest(),
);

// Stealth announcement pair (calldata-carried, NOT proof-bound — OPMOD §3.4
// class): deterministic filler with the same can-only-break-discovery role as
// the EVM WithdrawAnnouncement halves.
const STEALTH_EPHEMERAL_PUB = new Uint8Array(
  createHash("sha256").update("bongtu/solana-fixture/withdraw-stealth-ephemeral/v1").digest(),
);
const STEALTH_VIEW_TAG = 0x2a;

const hex = (b: Uint8Array): string => "0x" + Buffer.from(b).toString("hex");

/** OPEN-3 truncate-253: BE integer of the address with the top 3 bits cleared. */
function boundRecipient(addr: Uint8Array): bigint {
  const masked = Uint8Array.from(addr);
  masked[0] &= 0x1f;
  return BigInt("0x" + Buffer.from(masked).toString("hex"));
}

async function main(): Promise<void> {
  const evm = JSON.parse(readFileSync(join(FIXDIR, "consumer_realproofs.json"), "utf8"))
    .withdrawPriv as {
    pub: string[];
    seedLeaves: string[];
    rootAfter: string;
    kemCiphertexts: string[];
  };

  const input = JSON.parse(
    readFileSync(join(REPO, "circuits", "fixtures", "inputs", "withdrawPriv.json"), "utf8"),
  ) as Record<string, unknown> & { inputCommitments: string[]; recipient: string };

  const bound = boundRecipient(RECIPIENT_TOKEN_ACCOUNT);
  if (bound === 0n) throw new Error("fixture recipient bound to zero (label collision?)");
  const solInput = { ...input, recipient: bound.toString(10) };

  console.log(`proving withdrawPriv against Solana recipient (bound=${s(bound)})...`);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    solInput,
    join(OUT, "withdrawPriv_js", "withdrawPriv.wasm"),
    join(OUT, "withdrawPriv.zkey"),
  );

  const vkey = JSON.parse(readFileSync(join(OUT, "withdrawPriv.vkey.json"), "utf8"));
  if (!(await snarkjs.groth16.verify(vkey, publicSignals, proof))) {
    throw new Error("re-proven withdrawPriv proof does not verify against the committed vkey");
  }
  const cd = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
  const [a, b, c, pub] = JSON.parse("[" + cd + "]") as [string[], string[][], string[], string[]];

  // Belts: same spend as the EVM fixture — every public except the recipient
  // (pub[15]) must be identical; pub[15] must be the bound Solana value.
  if (pub.length !== 16) throw new Error(`withdrawPriv pub is ${pub.length} signals, want 16`);
  for (const i of Array(15).keys()) {
    assertEq(pub[i], evm.pub[i], `pub[${i}] diverged from the EVM withdrawPriv fixture`);
  }
  assertEq(pub[15], bound, "pub[15] != truncate-253 bound recipient");

  // Tree replay: identical seed leaves and post-op root (the recipient is not
  // part of any commitment).
  const inC = input.inputCommitments.map(BigInt);
  assertEq(inC.length, 2, "withdrawPriv input commitments");
  for (const [i, leaf] of inC.entries()) {
    assertEq(s(leaf), evm.seedLeaves[i], `seedLeaves[${i}] vs EVM fixture`);
  }
  const t = new ImtTree(32, 16);
  for (const leaf of inC) t.appendLeaf(leaf);
  assertEq(t.getRoot(), BigInt(pub[10]), "seeded tree root vs pub[10]");
  t.appendLeaf(BigInt(pub[13]));
  assertEq(s(t.getRoot()), evm.rootAfter, "post-append root vs EVM rootAfter");

  // Seals: re-derive the change-note seal from the shared plan; the ct/viewTag
  // publics and the kem ciphertext must match the EVM entry byte-for-byte.
  const sealed = sealPlan("withdrawPriv", withdrawPrivPlan());
  assertEq(sealed.length, 1, "withdrawPriv seal count");
  for (const [j, cj] of sealed[0].seal.cipherText.entries()) {
    assertEq(pub[3 + j], cj, `ctChange[${j}] public != seal`);
  }
  assertEq(pub[7], sealed[0].seal.viewTag, "viewTag public != seal");
  const kemCt = hex(sealed[0].seal.kemCiphertext);
  assertEq(BigInt(kemCt.slice(0, 10)), BigInt(evm.kemCiphertexts[0].slice(0, 10)), "kem ct prefix");
  if (kemCt !== evm.kemCiphertexts[0]) throw new Error("kem ciphertext != EVM fixture entry");

  const out = {
    comment:
      "GENERATED by chains/solana/scripts/gen_withdraw_solana_fixture.ts — the ONE re-proven " +
      "consumer fixture (SOLR §5.2): the EVM withdrawPriv spend re-proven with pub[15] " +
      "bound to a Solana token account under the OPEN-3 truncate-253 rule. All other " +
      "publics, seed leaves, and the kem ct are asserted identical to consumer_realproofs.json.",
    withdrawPriv: {
      a,
      b,
      c,
      pub,
      seedLeaves: evm.seedLeaves,
      rootAfter: evm.rootAfter,
      kemCiphertexts: evm.kemCiphertexts,
      recipientTokenAccount: hex(RECIPIENT_TOKEN_ACCOUNT),
      stealthEphemeralPub: hex(STEALTH_EPHEMERAL_PUB),
      stealthViewTag: STEALTH_VIEW_TAG,
    },
  };
  const outPath = join(FIXDIR, "consumer_realproofs_solana.json");
  writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n");
  console.log(`wrote ${outPath} (all belt-checks passed)`);
}

main()
  .then(() => process.exit(0))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
