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
  DisbursePrivInput,
  ProvingRequest,
  Transfer10Input,
  Transfer10x2Input,
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
    kemSs: [15n, 16n],
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
    kemSs: [15n, 16n],
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

test("a transfer10 ProvingRequest keeps all ten [10][H] slots and duplicate owners", () => {
  const H = 32;
  const kp = deriveKeypair(414141414141414141n);
  const ten = <T>(f: (i: number) => T): T[] => Array.from({ length: 10 }, (_, i) => f(i));
  const values = ten((i) => BigInt(10 * i));
  const salts = ten((i) => 900n + BigInt(i));
  const input: Transfer10Input = {
    nullifiers: ten((i) => (i < 4 ? 100n + BigInt(i) : 0n)), // 4 real, 6 padded
    inputCommitments: ten((i) => commitment(values[i], salts[i], kp.publicKey)),
    inputValues: values,
    inputSalts: salts,
    inputOwnerPrivateKey: 4n,
    ecdhPrivateKey: 5n,
    root: 6n,
    pathElements: ten(() => new Array<bigint>(H).fill(0n)),
    leafIndices: ten((i) => BigInt(i)),
    enabled: ten((i) => (i < 4 ? 1n : 0n)),
    outputCommitments: ten((i) => 700n + BigInt(i)),
    outputValues: ten((i) => (i === 0 ? 450n : 0n)),
    outputSalts: ten((i) => 800n + BigInt(i)),
    // every output to ONE owner: the self-merge shape the per-output nonce allows.
    outputOwnerPublicKeys: ten(() => kp.publicKey),
    kemSs: [15n, 16n],
    encryptionNonce: 12n,
    authorityPublicKey: [13n, 14n],
  };
  const req: ProvingRequest = { circuit: "transfer10", input, backend: "cpu" };
  const wire = JSON.parse(JSON.stringify(toWire(req))) as ProvingRequest;
  assert.equal(wire.circuit, "transfer10");
  if (wire.circuit !== "transfer10") throw new Error("unreachable"); // narrows the union
  assert.equal(wire.input.pathElements.length, 10);
  assert.equal(wire.input.pathElements[9].length, H);
  assert.equal(wire.input.nullifiers[9], "0");
  assert.equal(wire.input.enabled[3], "1");
  assert.equal(wire.input.enabled[4], "0");
  assert.equal(wire.input.outputOwnerPublicKeys.length, 10);
  assert.deepEqual(wire.input.outputOwnerPublicKeys[9], wire.input.outputOwnerPublicKeys[0]);
  assert.equal(BigInt(wire.input.inputCommitments[0] as string), input.inputCommitments[0]);
});

test("a transfer10x2 ProvingRequest keeps ten input slots against only two outputs", () => {
  const H = 32;
  const kp = deriveKeypair(515151515151515151n);
  const ten = <T>(f: (i: number) => T): T[] => Array.from({ length: 10 }, (_, i) => f(i));
  const values = ten((i) => BigInt(10 * i)); // 450 total
  const salts = ten((i) => 900n + BigInt(i));
  const input: Transfer10x2Input = {
    nullifiers: ten((i) => (i < 4 ? 100n + BigInt(i) : 0n)), // 4 real, 6 padded
    inputCommitments: ten((i) => commitment(values[i], salts[i], kp.publicKey)),
    inputValues: values,
    inputSalts: salts,
    inputOwnerPrivateKey: 4n,
    ecdhPrivateKey: 5n,
    root: 6n,
    pathElements: ten(() => new Array<bigint>(H).fill(0n)),
    leafIndices: ten((i) => BigInt(i)),
    enabled: ten((i) => (i < 4 ? 1n : 0n)),
    outputCommitments: [700n, 701n],
    outputValues: [450n, 0n], // merged note + zero change
    outputSalts: [800n, 801n],
    // both outputs to ONE owner: the merge shape the per-output nonce allows.
    outputOwnerPublicKeys: [kp.publicKey, kp.publicKey],
    kemSs: [15n, 16n],
    encryptionNonce: 12n,
    authorityPublicKey: [13n, 14n],
  };
  const req: ProvingRequest = { circuit: "transfer10x2", input, backend: "cpu" };
  const wire = JSON.parse(JSON.stringify(toWire(req))) as ProvingRequest;
  assert.equal(wire.circuit, "transfer10x2");
  if (wire.circuit !== "transfer10x2") throw new Error("unreachable"); // narrows the union
  // the asymmetry IS the circuit: ten membership slots, two output slots.
  assert.equal(wire.input.pathElements.length, 10);
  assert.equal(wire.input.pathElements[9].length, H);
  assert.equal(wire.input.nullifiers.length, 10);
  assert.equal(wire.input.enabled[3], "1");
  assert.equal(wire.input.enabled[4], "0");
  assert.equal(wire.input.outputCommitments.length, 2);
  assert.equal(wire.input.outputOwnerPublicKeys.length, 2);
  assert.deepEqual(wire.input.outputOwnerPublicKeys[1], wire.input.outputOwnerPublicKeys[0]);
  assert.equal(wire.input.outputValues[1], "0");
  assert.equal(BigInt(wire.input.inputCommitments[0] as string), input.inputCommitments[0]);
});

test("a disbursePriv ProvingRequest keeps per-output kemSs pairs and view-key runs through JSON", () => {
  const H = 32;
  const kp = deriveKeypair(616161616161616161n);
  const view = deriveKeypair(717171717171717171n);
  const many = <T>(f: (i: number) => T): T[] => Array.from({ length: 256 }, (_, i) => f(i));
  const input: DisbursePrivInput = {
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
    outputCommitments: many((i) => 1000n + BigInt(i)),
    outputValues: many((i) => (i < 2 ? 50n : 0n)),
    outputSalts: many((i) => 2000n + BigInt(i)),
    // duplicate owners are LEGAL in this family (per-output hybrid key +
    // nonce+i, OPMOD §3.3/§3.5) — a batch may pay one person twice.
    outputOwnerPublicKeys: many(() => kp.publicKey),
    outputViewPublicKeys: many(() => view.publicKey),
    kemSs: many((i) => [3000n + BigInt(i), 4000n + BigInt(i)]),
    encryptionNonce: 12n,
  };
  const req: ProvingRequest = { circuit: "disbursePriv", input, backend: "gpu" };
  const wire = JSON.parse(JSON.stringify(toWire(req))) as ProvingRequest;
  assert.equal(wire.circuit, "disbursePriv");
  if (wire.circuit !== "disbursePriv") throw new Error("unreachable"); // narrows the union
  // the family's shape deltas: NO authorityPublicKey, per-output kemSs limb
  // pairs, and the note-layer view-key run beside the spend-key run.
  assert.ok(!("authorityPublicKey" in wire.input));
  assert.equal(wire.input.kemSs.length, 256);
  assert.deepEqual(wire.input.kemSs[1], ["3001", "4001"]);
  assert.equal(wire.input.outputViewPublicKeys.length, 256);
  assert.equal(wire.input.pathElements.length, 1);
  assert.equal(wire.input.pathElements[0].length, H);
  assert.deepEqual(wire.input.outputOwnerPublicKeys[1], wire.input.outputOwnerPublicKeys[0]);
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
