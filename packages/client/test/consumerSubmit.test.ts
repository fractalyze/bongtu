// Headless gates for the consumer SUBMIT layer (src/consumerSubmit.ts): each
// wrapper must land on ITS module address with args the shared fragment
// (CONSUMER_MODULE_ABI_FRAGMENTS) actually encodes — the same parse the live
// module's ABI is generated from — riding the one submit discipline
// (submitPoolWrite: pending-view nonce, floor-quote x3 gas). ONE shared
// S2-assembled transferPriv request supplies the real 1088-byte kem cts every
// pin reuses; the proof calldata is shape-only (a submit never inspects proof
// values, only the encoder's arity checks do).

import { test } from "node:test";
import assert from "node:assert/strict";
import { encodeFunctionData, parseAbi } from "viem";

import { commitment } from "@bongtu/core/note";
import { CONSUMER_MODULES, CONSUMER_MODULE_ABI_FRAGMENTS, H, B } from "@bongtu/core/network";
import { ZERO_EPHEMERAL } from "@bongtu/core/stealth";
import { ImtTree } from "@bongtu/core/imt";
import type { Calldata } from "@bongtu/core/proving";

import { deriveIdentityFromSignature } from "@bongtu/client/derive";
import type { Connection } from "@bongtu/client/connection";
import {
  buildConsumerTransferRequest,
  selfConsumerRecipient,
} from "@bongtu/client/consumerBuild";
import {
  submitDepositPriv,
  submitTransferPriv,
  submitTransfer10x2Priv,
  submitWithdrawPriv,
} from "@bongtu/client/consumerSubmit";

// ---- the ONE shared assembled request (S2 builder, real per-output seals) ----

const SENDER = deriveIdentityFromSignature("0x" + "a1".repeat(32) + "b2".repeat(32) + "1c");
const PAYEE = selfConsumerRecipient(deriveIdentityFromSignature("0x" + "c3".repeat(32) + "d4".repeat(32) + "1b"));

const TREE = new ImtTree(H, B);
const SALTS = [91n, 92n];
TREE.appendLeaf(commitment(700n, SALTS[0], SENDER.keypair.publicKey));
TREE.appendLeaf(commitment(300n, SALTS[1], SENDER.keypair.publicKey));
const TRF = buildConsumerTransferRequest(
  SENDER,
  [700n, 300n].map((v, i) => ({ value: v.toString(), salt: SALTS[i].toString(), leafIndex: i })),
  [0, 1].map((i) => {
    const p = TREE.merklePath(i);
    return { root: TREE.getRoot().toString(), pathElements: p.siblings.map(String), leafIndex: i };
  }),
  PAYEE,
  "600",
  { ecdhPrivateKey: "12345", encryptionNonce: "999", payeeSalt: "1", changeSalt: "2", padSalts: [] },
);
/** two real 1088-byte ML-KEM cts, in output order — what every pin submits. */
const CTS = TRF.meta.kemCiphertexts;

// ---- a fake Connection recording what submitPoolWrite hands the wallet ------

interface CapturedWrite {
  address: string;
  abi: unknown;
  functionName: string;
  args: readonly unknown[];
  nonce: number;
  gasPrice: bigint;
}

function world(): { writes: CapturedWrite[]; connection: Connection } {
  const writes: CapturedWrite[] = [];
  const connection = {
    address: "0x00000000000000000000000000000000000000a1",
    walletClient: {
      writeContract: async (w: CapturedWrite) => {
        writes.push(w);
        return "0xfeedbeef";
      },
    },
    publicClient: {
      getTransactionCount: async () => 7,
      getGasPrice: async () => 100n,
      waitForTransactionReceipt: async () => ({}),
    },
  } as unknown as Connection;
  return { writes, connection };
}

const pubLenOf = (fragment: string): number => Number(/uint256\[(\d+)\] pub/.exec(fragment)?.[1]);
const calldata = (pubLen: number): Calldata => ({
  a: ["1", "2"],
  b: [["3", "4"], ["5", "6"]],
  c: ["7", "8"],
  pub: Array.from({ length: pubLen }, (_, i) => String(i + 1)),
});

// ============================ arg-shape pins =================================

const CASES = [
  { op: "depositPriv", cts: CTS, submit: submitDepositPriv },
  { op: "transferPriv", cts: CTS, submit: submitTransferPriv },
  { op: "transfer10x2Priv", cts: CTS, submit: submitTransfer10x2Priv },
  { op: "withdrawPriv", cts: [CTS[0]], submit: submitWithdrawPriv },
] as const;

for (const { op, cts, submit } of CASES) {
  test(`${op} submit targets ITS module with args the shared fragment encodes, on the one submit discipline`, async () => {
    const w = world();
    const fragment = CONSUMER_MODULE_ABI_FRAGMENTS[op];
    const res = await submit(w.connection, calldata(pubLenOf(fragment)), [...cts], "https://x");

    assert.equal(w.writes.length, 1);
    const write = w.writes[0];
    assert.equal(write.address, CONSUMER_MODULES[op].module, "the write lands on the op's MODULE, never the pool");
    assert.equal(write.functionName, op);
    // THE shape pin: the exact args handed to the wallet must encode under the
    // op's own fragment parse — proof tuples as bigints, the pub vector at the
    // circuit's full arity, the per-output bytes[] kem cts (+ withdraw's tail).
    assert.doesNotThrow(() =>
      encodeFunctionData({
        abi: parseAbi([fragment]),
        functionName: op,
        args: write.args as never,
      }),
    );
    assert.deepEqual(write.args[4], cts, "kem cts ride as the bytes[] calldata, in output order");
    // rides submitPoolWrite, not a private path: pending-view nonce, floor x3 gas.
    assert.equal(write.nonce, 7);
    assert.equal(write.gasPrice, 300n);
    assert.equal(res.txHash, "0xfeedbeef");
    assert.equal(res.explorerUrl, "https://x/tx/0xfeedbeef");
  });
}

test("withdrawPriv pins the no-announcement sentinel tail — consumer v1 self-submits, the slot is reserved", async () => {
  const w = world();
  await submitWithdrawPriv(w.connection, calldata(16), [CTS[0]], "https://x");
  const args = w.writes[0].args;
  assert.equal(args.length, 7, "a,b,c,pub,kemCiphertexts + the reserved (ephemeralPub, viewTag) pair");
  assert.equal(args[5], ZERO_EPHEMERAL, "zero32 = no stealth announcement");
  assert.equal(args[6], 0);
});

test("the kem-ct belt fails a wrong count or a wrong length BEFORE any wallet write", async () => {
  const w = world();
  await assert.rejects(
    submitTransferPriv(w.connection, calldata(20), [CTS[0]], "https://x"),
    /expected 2, got 1/,
  );
  await assert.rejects(
    submitWithdrawPriv(w.connection, calldata(16), ["0x" + "ab".repeat(32)], "https://x"),
    /1088 bytes/,
  );
  assert.equal(w.writes.length, 0, "a malformed ct set never reaches the wallet");
});

test("an explicit moduleAddress retargets the write (the fresh-stack gate seam); the default stays the canonical record", async () => {
  const w = world();
  const fresh = "0x00000000000000000000000000000000000000f7";
  await submitTransferPriv(w.connection, calldata(20), [...CTS], "https://x", fresh);
  assert.equal(w.writes[0].address, fresh, "the override lands the SAME encode path on the gate's own module");
  assert.equal(w.writes[0].functionName, "transferPriv");
});
