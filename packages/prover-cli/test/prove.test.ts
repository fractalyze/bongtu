// prove.test.ts — the CPU gate.
//
// Build a valid deposit ProvingRequest (0-in / 2-out, the simplest circuit: no
// membership, no ciphertext-as-public) with the SDK, prove it via prove(), and
// assert snarkjs groth16.verify accepts the emitted calldata against the committed
// circuits/out/deposit.vkey.json. The deposit witness never touches chain state, so
// this runs standalone (no anvil, no GPU) in a few seconds.
//
// The GPU disburse path is NOT run here (1.24GB zkey + a ~116s cold compile on GPU0
// — too heavy for a unit gate). It is covered by the type system and the documented
// dry path at the bottom of this file, and is exercised for real by
// deploy/giwa_disburse256.ts, whose proveDisburse256 prove.ts copies verbatim.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

import { deriveKeypair, commitment } from "@bongtu/sdk/note";
import { prove } from "../src/prove.js";
import type { Calldata, ProvingRequest } from "../src/types.js";

const require = createRequire(import.meta.url);
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", ".."); // repo root (packages/prover-cli/test -> repo)
const NODE_MODULES =
  process.env.BONGTU_NODE_MODULES || "/home/a41/Workspace/zkx-snap/circuits/node_modules";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const snarkjs: any = require(join(NODE_MODULES, "snarkjs/build/main.cjs"));

// Reconstruct a snarkjs-native proof from exportSolidityCallData form so we can
// verify EXACTLY the proof prove() emitted. exportSolidityCallData applies a G2
// inner-swap on `b` (b = [[pi_b[0][1], pi_b[0][0]], [pi_b[1][1], pi_b[1][0]]]); undo
// it here. All calldata values are 0x-hex; groth16.verify wants decimal strings.
function proofFromCallData({ a, b, c }: Calldata): Record<string, unknown> {
  const d = (x: string): string => BigInt(x).toString();
  return {
    pi_a: [d(a[0]), d(a[1]), "1"],
    pi_b: [
      [d(b[0][1]), d(b[0][0])],
      [d(b[1][1]), d(b[1][0])],
      ["1", "0"],
    ],
    pi_c: [d(c[0]), d(c[1]), "1"],
    protocol: "groth16",
    curve: "bn128",
  };
}

test("deposit (CPU): prove() emits calldata that groth16.verify accepts", async () => {
  // Arbiter (auditor) key = the disburse256 fixture's pub[8..9] — the same key the
  // committed deposit.zkey/vkey and the live pool were generated with. It rides as a
  // PUBLIC signal, so any consistent value verifies; using the live one keeps the
  // fixture faithful.
  const fixture: string[] = JSON.parse(
    readFileSync(join(ROOT, "contracts/test/fixtures/disburse256.public.json"), "utf8"),
  );
  const arbiter: [bigint, bigint] = [BigInt(fixture[8]), BigInt(fixture[9])];

  // A fresh employer keypair + a fresh ephemeral ECDH key + nonce for THIS deposit.
  const EMPLOYER = deriveKeypair(313131313131313131313131n);
  const V = 3000n;
  const sD0 = 8000001n;
  const sD1 = 8000002n;
  const noteV = commitment(V, sD0, EMPLOYER.publicKey);
  const note0 = commitment(0n, sD1, EMPLOYER.publicKey);

  const req: ProvingRequest = {
    circuit: "deposit",
    input: {
      outputCommitments: [noteV, note0],
      outputValues: [V, 0n],
      outputSalts: [sD0, sD1],
      outputOwnerPublicKeys: [EMPLOYER.publicKey, EMPLOYER.publicKey],
      ecdhPrivateKey: 610000000000000000011n,
      encryptionNonce: 424242424242n,
      authorityPublicKey: arbiter,
    },
  };

  const calldata = await prove(req);

  // shape: deposit has 18 public signals; pub[0] is the minted value out.
  assert.equal(calldata.pub.length, 18, "deposit exposes 18 public signals");
  assert.equal(BigInt(calldata.pub[0]), V, "pub[0] == deposited V");
  assert.equal(BigInt(calldata.pub[13]), noteV, "pub[13] == output commitment 0 (note(V))");
  assert.equal(BigInt(calldata.pub[14]), note0, "pub[14] == output commitment 1 (note(0))");

  // the real gate: verify the emitted proof against the committed vkey.
  const vkey = JSON.parse(readFileSync(join(ROOT, "circuits/out/deposit.vkey.json"), "utf8"));
  const publicSignals = calldata.pub.map((x) => BigInt(x).toString());
  const verified: boolean = await snarkjs.groth16.verify(vkey, publicSignals, proofFromCallData(calldata));
  assert.ok(verified, "snarkjs groth16.verify accepts prove()'s deposit proof");
});

test("disburse two-time-pad guard: duplicate output owner pubkeys are rejected", async () => {
  // The §11-8 guard must fire BEFORE any proving work (no GPU touched). A disburse
  // request whose outputs repeat an owner pubkey is rejected synchronously.
  const RCPT = deriveKeypair(4000000019n);
  const dupOwners = [RCPT.publicKey, RCPT.publicKey]; // same owner twice -> two-time pad
  const req = {
    circuit: "disburse",
    input: {
      nullifiers: [1n],
      inputCommitments: [1n],
      inputValues: [200n],
      inputSalts: [1n],
      inputOwnerPrivateKey: 1n,
      ecdhPrivateKey: 1n,
      root: 1n,
      pathElements: [new Array(32).fill(0n)],
      leafIndices: [0n],
      enabled: [1n],
      outputCommitments: [1n, 2n],
      outputValues: [100n, 100n],
      outputSalts: [1n, 2n],
      outputOwnerPublicKeys: dupOwners,
      encryptionNonce: 1n,
      authorityPublicKey: [1n, 2n],
    },
  } as unknown as ProvingRequest;
  await assert.rejects(() => prove(req), /duplicate output owner pubkey/);
});

test("backend guard: a non-disburse circuit cannot use the GPU backend", async () => {
  const req = {
    circuit: "deposit",
    backend: "gpu",
    input: {
      outputCommitments: [1n, 2n],
      outputValues: [1n, 0n],
      outputSalts: [1n, 2n],
      outputOwnerPublicKeys: [
        [1n, 2n],
        [3n, 4n],
      ],
      ecdhPrivateKey: 1n,
      encryptionNonce: 1n,
      authorityPublicKey: [1n, 2n],
    },
  } as unknown as ProvingRequest;
  await assert.rejects(() => prove(req), /GPU backend only supports 'disburse'/);
});

// ---------------------------------------------------------------------------
// DOCUMENTED DRY PATH — disburse (GPU), intentionally not executed here.
//
// A disburse ProvingRequest is proved by the SAME prove() call; only the backend
// differs (defaults to 'gpu' for circuit 'disburse'). To run it manually (needs GPU0
// + the 1.24GB artifacts/circuit.zkey; ~116s cold compile + ~0.5s warm):
//
//   const req: ProvingRequest = {
//     circuit: "disburse",
//     input: {
//       nullifiers: [nfV], inputCommitments: [noteV], inputValues: [V], inputSalts: [sD0],
//       inputOwnerPrivateKey: EMPLOYER.formattedPrivateKey, ecdhPrivateKey: ECDH,
//       root, pathElements: [siblings], leafIndices: [BigInt(leafV)], enabled: [1n],
//       outputCommitments,          // 256 distinct commitments
//       outputValues,               // 256 amounts
//       outputSalts,                // 256 salts
//       outputOwnerPublicKeys,      // 256 DISTINCT recipient pubkeys (§11-8 guard)
//       encryptionNonce: NONCE, authorityPublicKey: ARBITER,
//     },
//   };
//   const { a, b, c, pub } = await prove(req);   // -> pool.disburseWithCiphertexts(a,b,c,pub,...)
//
// This is exactly what deploy/giwa_disburse256.ts does against the LIVE pool; its
// proveDisburse256 helper is the code prove()'s GPU backend was factored out of.
// ---------------------------------------------------------------------------
