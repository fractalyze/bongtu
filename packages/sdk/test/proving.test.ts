// proving.ts gate — the shared ProvingRequest / Calldata wire types.
//
// These types are the TS source of truth for the proving wire format; the Python
// prover service (prover/prover_service/schema.py) mirrors them. What a runtime
// test CAN pin here: (1) a request built with bigints survives decimal-stringify +
// JSON round-trip into the exact same discriminated shape a JSON consumer (the
// service, the browser prover) receives; (2) the circuit tag narrows the union
// (compile-time, exercised by construction); (3) Calldata's shape is what the
// admin/wallet chain submitters splat into (a, b, c, pub).

import { test } from "node:test";
import assert from "node:assert/strict";

import { toWire } from "../src/proving.js";
import type {
  Calldata,
  DepositInput,
  DisburseInput,
  ProvingRequest,
} from "../src/proving.js";
import { deriveKeypair, commitment } from "../src/note.js";

test("a bigint-built deposit ProvingRequest JSON round-trips to the same decimal shape", () => {
  const kp = deriveKeypair(313131313131313131313131n);
  const input: DepositInput = {
    outputCommitments: [commitment(5n, 1n, kp.publicKey), commitment(0n, 2n, kp.publicKey)],
    outputValues: [5n, 0n],
    outputSalts: [1n, 2n],
    outputOwnerPublicKeys: [kp.publicKey, kp.publicKey],
    ecdhPrivateKey: 7n,
    encryptionNonce: 42n,
    authorityPublicKey: kp.publicKey,
  };
  const req: ProvingRequest = { circuit: "deposit", input, backend: "cpu" };

  const wire = JSON.parse(JSON.stringify(toWire(req))) as ProvingRequest;
  assert.equal(wire.circuit, "deposit");
  assert.equal(wire.backend, "cpu");
  if (wire.circuit !== "deposit") throw new Error("unreachable"); // narrows the union
  assert.equal(wire.input.outputValues.length, 2);
  // decimal strings on the wire, numerically identical to the bigints we built.
  assert.equal(wire.input.outputValues[0], "5");
  assert.equal(BigInt(wire.input.outputCommitments[0] as string), input.outputCommitments[0]);
  assert.equal(wire.input.outputOwnerPublicKeys[0][0], kp.publicKey[0].toString());
});

test("a disburse ProvingRequest keeps its [1][H] membership arrays through JSON", () => {
  const H = 32;
  const input: DisburseInput = {
    nullifiers: [11n],
    inputCommitments: [22n],
    inputValues: [100n],
    inputSalts: [3n],
    inputOwnerPrivateKey: 4n,
    ecdhPrivateKey: 5n,
    root: 6n,
    pathElements: [new Array<bigint>(H).fill(0n)],
    leafIndices: [1n],
    enabled: [1n],
    outputCommitments: [7n, 8n],
    outputValues: [60n, 40n],
    outputSalts: [9n, 10n],
    outputOwnerPublicKeys: [
      [1n, 2n],
      [3n, 4n],
    ],
    encryptionNonce: 12n,
    authorityPublicKey: [13n, 14n],
  };
  const req: ProvingRequest = { circuit: "disburse", input, backend: "gpu" };
  const wire = JSON.parse(JSON.stringify(toWire(req))) as ProvingRequest;
  assert.equal(wire.circuit, "disburse");
  if (wire.circuit !== "disburse") throw new Error("unreachable");
  assert.equal(wire.input.pathElements.length, 1);
  assert.equal(wire.input.pathElements[0].length, H);
  assert.equal(wire.input.enabled[0], "1");
});

test("Calldata is the exportSolidityCallData shape the pool submitters splat", () => {
  const word = (n: bigint): string => "0x" + n.toString(16).padStart(64, "0");
  const cd: Calldata = {
    a: [word(1n), word(2n)],
    b: [
      [word(3n), word(4n)],
      [word(5n), word(6n)],
    ],
    c: [word(7n), word(8n)],
    pub: [word(9n), word(10n)],
  };
  // every element is a 32-byte 0x-hex word a uint256 calldata slot accepts.
  for (const x of [...cd.a, ...cd.b[0], ...cd.b[1], ...cd.c, ...cd.pub]) {
    assert.match(x, /^0x[0-9a-f]{64}$/);
  }
  assert.equal(BigInt(cd.pub[1]), 10n);
});
