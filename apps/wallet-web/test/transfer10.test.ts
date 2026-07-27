// Headless gate for the wallet's ARITY-10 spend path (U-Z1): the circuit auto-pick,
// the transfer10 witness, and the guided self-merge that rescues a balance too
// scattered to spend at once.
//
// The wallet never asks the user which circuit to prove. It infers it from how many
// notes the payment needs, which makes that inference — and its two blocked cases —
// the thing worth gating:
//
//   (1) ROUTING — ≤2 notes stay on the cheap 2×2 transfer, 3–10 move to transfer10,
//       >10 is blocked as `needs-merge`; withdraw has no arity-10 circuit, so >2 is
//       blocked the same way. previewSpend answers the same questions without
//       throwing, because the form asks it on every keystroke.
//   (2) WITNESS — a transfer10 request whose output commitments are the sdk's, whose
//       value is conserved across all ten slots, and whose padded slots carry the
//       SAME convention the committed circuits/inputs/transfer10.json fixture does
//       (that file is what the circuit is proved against, so a drift here is a
//       witness that only fails at proving time).
//   (3) MERGE — a self-consolidation of up to ten notes into one, every output owned
//       by the sender (legal since the §11-8 v1.1 per-output nonce), and the flow
//       routing that submits it through pool.transfer10 rather than pool.transfer.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { commitment, nullifier } from "@bongtu/core/note";
import { ImtTree } from "@bongtu/core/imt";
import { packPubkey } from "@bongtu/core/pubkey";
import { deriveKeypair } from "@bongtu/core/note";
import { TRANSFER10_ARITY } from "@bongtu/core/envelope";
import type { Calldata } from "@bongtu/core/proving";

import { deriveIdentityFromSignature } from "../src/lib/derive.js";
import { KeyCache } from "../src/lib/keyCache.js";
import { runSpend, type RunSpendDeps, type SpendContext } from "../src/lib/spendFlow.js";
import type { OwnerNote } from "../src/lib/indexerClient.js";
import {
  buildTransfer10Request,
  buildTransferRequest,
  planSpendAction,
  previewMerge,
  previewSpend,
  selectInputNotes,
  selectMergeNotes,
  SpendSelectionError,
  type MembershipWitness,
  type SelectableNote,
  type SpendCrypto,
  type WalletInputNote,
} from "../src/lib/spend.js";
import { CIRCUIT_ASSET_BYTES, DEFAULTS, H, B } from "../src/config.js";

const SIG = "0x" + "a1".repeat(32) + "b2".repeat(32) + "1c";
const WALLET = deriveIdentityFromSignature(SIG);
const SELF = WALLET.keypair.publicKey;
const PAYEE = deriveKeypair(4242424242424242n).publicKey;
const PAYEE_ADDR = packPubkey(PAYEE);

// Fixed per-tx material, shaped exactly like freshSpendCrypto's — 9 input-pad salts
// (arity 10 with one real note) and 8 output-pad salts (arity 10 minus payment and
// change), all distinct so no two padded slots collide.
const CRYPTO: SpendCrypto = {
  ecdhPrivateKey: "800000000000000000003",
  encryptionNonce: "222222222222",
  authorityPubKey: DEFAULTS.arbiterPubKey,
  kemSs: ["8731609943253620952139260337378020862", "172620469314477595042522651585199579459"],
  kemCiphertext: "0x" + "ab".repeat(1088),
  changeSalt: "7000002",
  padSalts: Array.from({ length: 9 }, (_, i) => `${7100001 + i}`),
  payeeSalt: "7000001",
  outputPadSalts: Array.from({ length: 8 }, (_, i) => `${7200001 + i}`),
};

/** A live tree holding `values` as the wallet's notes, one per leaf. */
function fixture(values: bigint[]) {
  const tree = new ImtTree(H, B);
  const salts = values.map((_, i) => 500000n + BigInt(i));
  values.forEach((v, i) => tree.appendLeaf(commitment(v, salts[i], SELF)));
  const root = tree.getRoot().toString();
  const inputs: WalletInputNote[] = values.map((v, i) => ({
    value: v.toString(),
    salt: salts[i].toString(),
    leafIndex: i,
  }));
  const memberships: MembershipWitness[] = values.map((_, i) => ({
    root,
    pathElements: tree.merklePath(i).siblings.map(String),
    leafIndex: i,
  }));
  const notes: OwnerNote[] = inputs.map((n, i) => ({
    owner: [SELF[0].toString(), SELF[1].toString()],
    value: n.value,
    salt: n.salt,
    leafIndex: n.leafIndex,
    commitment: commitment(values[i], salts[i], SELF).toString(),
    txHash: "0xdep",
    spent: false,
  }));
  return { tree, root, inputs, memberships, notes, salts };
}

const selectable = (values: bigint[]): SelectableNote[] =>
  values.map((v, i) => ({ value: v.toString(), salt: `9${i}`, leafIndex: i, spent: false }));

// ============================ (1) ROUTING ====================================

test("a send picks the circuit from how many notes it needs: ≤2 transfer, 3–10 transfer10", () => {
  const notes = selectable([100n, 100n, 100n, 100n]);
  const plan1 = planSpendAction("transfer", notes, WALLET.compressedPubkey, { to: PAYEE_ADDR, amount: "100" });
  assert.equal(plan1.circuit, "transfer");
  assert.equal(plan1.inputs.length, 1);

  const plan2 = planSpendAction("transfer", notes, WALLET.compressedPubkey, { to: PAYEE_ADDR, amount: "200" });
  assert.equal(plan2.circuit, "transfer", "two notes still fit the small circuit");

  const plan3 = planSpendAction("transfer", notes, WALLET.compressedPubkey, { to: PAYEE_ADDR, amount: "250" });
  assert.equal(plan3.circuit, "transfer10", "the third note is what moves it to arity 10");
  assert.equal(plan3.inputs.length, 3);
  assert.equal(plan3.to, PAYEE_ADDR, "the payee is the typed recipient, not the wallet");
});

test("a send needing more than 10 notes is blocked as needs-merge, not as poverty", () => {
  const many = selectable(Array.from({ length: 12 }, () => 100n)); // 1200 spendable
  assert.throws(
    () => planSpendAction("transfer", many, WALLET.compressedPubkey, { amount: "1100" }),
    (e: unknown) => e instanceof SpendSelectionError && e.blocker === "needs-merge",
  );
  // …and the same wallet genuinely cannot fund more than it holds.
  assert.throws(
    () => planSpendAction("transfer", many, WALLET.compressedPubkey, { amount: "9999" }),
    (e: unknown) => e instanceof SpendSelectionError && e.blocker === "insufficient",
  );
  // exactly ten notes is the last amount that goes through
  assert.equal(
    planSpendAction("transfer", many, WALLET.compressedPubkey, { amount: "1000" }).inputs.length,
    10,
  );
});

test("withdraw stays at arity 2 — there is no withdraw10 — so >2 notes needs a merge first", () => {
  const notes = selectable([100n, 100n, 100n, 100n]);
  assert.equal(planSpendAction("withdraw", notes, WALLET.compressedPubkey, { amount: "200" }).circuit, "withdraw");
  assert.throws(
    () => planSpendAction("withdraw", notes, WALLET.compressedPubkey, { amount: "250" }),
    (e: unknown) => e instanceof SpendSelectionError && e.blocker === "needs-merge",
  );
});

test("previewSpend answers the form's question on every keystroke without throwing", () => {
  const notes = selectable([100n, 100n, 100n, 100n]);
  assert.deepEqual(previewSpend("transfer", notes, "200"), { circuit: "transfer", blocker: null });
  assert.deepEqual(previewSpend("transfer", notes, "250"), { circuit: "transfer10", blocker: null });
  assert.deepEqual(previewSpend("withdraw", notes, "250"), { circuit: "withdraw", blocker: "needs-merge" });
  assert.deepEqual(previewSpend("transfer", notes, "9999"), { circuit: "transfer", blocker: "insufficient" });
  // a half-typed amount is not a verdict: the form's own amountError owns that case
  assert.deepEqual(previewSpend("transfer", notes, "0"), { circuit: "transfer", blocker: null });
  assert.deepEqual(previewSpend("transfer", notes, ""), { circuit: "transfer", blocker: null });
});

test("selectInputNotes takes the arity as a parameter and names the limit it hit", () => {
  const notes = selectable([30n, 30n, 30n, 30n]);
  assert.equal(selectInputNotes(notes, "80", TRANSFER10_ARITY).length, 3);
  assert.throws(() => selectInputNotes(notes, "80", 2), /more than 2 notes/);
  assert.throws(() => selectInputNotes(selectable(Array(11).fill(10n)), "105", 10), /more than 10 notes/);
});

// ============================ (2) WITNESS ====================================

test("transfer10: output commitments == sdk commitment() and value is conserved over 10 slots", () => {
  const f = fixture([400n, 300n, 200n, 100n]); // total 1000
  const { request, meta } = buildTransfer10Request(WALLET, f.inputs, f.memberships, PAYEE_ADDR, "700", CRYPTO);
  const inp = request.input;

  assert.equal(request.circuit, "transfer10");
  assert.equal(request.backend, "cpu");
  for (const field of ["nullifiers", "inputCommitments", "inputValues", "inputSalts", "enabled",
    "leafIndices", "outputCommitments", "outputValues", "outputSalts", "outputOwnerPublicKeys"] as const) {
    assert.equal((inp[field] as unknown[]).length, 10, `${field} must be a length-10 vector`);
  }
  assert.equal((inp.pathElements as unknown[][]).length, 10);
  assert.equal((inp.pathElements as unknown[][])[0].length, H);

  // every output commitment recomputed independently with the sdk
  const owners = inp.outputOwnerPublicKeys as [string, string][];
  inp.outputCommitments.forEach((c, i) => {
    const owner: [bigint, bigint] = [BigInt(owners[i][0]), BigInt(owners[i][1])];
    assert.equal(c, commitment(BigInt(inp.outputValues[i]), BigInt(inp.outputSalts[i]), owner).toString());
  });

  const inSum = (inp.inputValues as string[]).reduce((a, x) => a + BigInt(x), 0n);
  const outSum = (inp.outputValues as string[]).reduce((a, x) => a + BigInt(x), 0n);
  assert.equal(inSum, 1000n);
  assert.equal(outSum, 1000n, "value conserved across all ten output slots");
  assert.equal(inp.outputValues[0], "700"); // payment
  assert.equal(inp.outputValues[1], "300"); // change
  assert.deepEqual((inp.outputValues as string[]).slice(2), Array(8).fill("0"));
  assert.equal(meta.realInputCount, 4);
  assert.equal(meta.membershipOk, true);

  // the real inputs are the wallet's own notes, byte-identical to the sdk
  assert.equal(inp.inputCommitments[0], commitment(400n, f.salts[0], SELF).toString());
  assert.equal(inp.nullifiers[0], nullifier(400n, f.salts[0], WALLET.keypair.formattedPrivateKey).toString());
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(request)), "no bigints leak to the wire");
});

/**
 * The padding convention, read off a transfer10 witness: which slots are padded, and
 * what a padded slot must carry. Applied below to BOTH the committed fixture and the
 * wallet's own output, so the two cannot drift apart.
 */
function paddingProfile(w: {
  nullifiers: string[];
  inputValues: string[];
  inputSalts: string[];
  inputCommitments: string[];
  enabled: string[];
  leafIndices: string[];
  pathElements: string[][];
}): { real: number; padded: number } {
  const padded: number[] = [];
  w.enabled.forEach((e, i) => {
    if (e === "0") padded.push(i);
  });
  for (const i of padded) {
    assert.equal(w.nullifiers[i], "0", `padded slot ${i} must carry a zero nullifier`);
    assert.equal(w.inputValues[i], "0", `padded slot ${i} must carry value 0 (§5.2 value belt)`);
    assert.equal(w.leafIndices[i], "0", `padded slot ${i} must carry leafIndex 0`);
    assert.ok(w.pathElements[i].every((x) => x === "0"), `padded slot ${i} must carry a zeros path`);
    assert.notEqual(w.inputCommitments[i], "0", `padded slot ${i} must still be a real value-0 note`);
  }
  // distinct pad salts -> distinct pad commitments
  const padCommitments = padded.map((i) => w.inputCommitments[i]);
  assert.equal(new Set(padCommitments).size, padCommitments.length, "no two pads share a commitment");
  // and every ENABLED slot is a real spend
  w.enabled.forEach((e, i) => {
    if (e !== "0") {
      assert.equal(e, "1", "enabled is a 0/1 flag");
      assert.notEqual(w.nullifiers[i], "0", `enabled slot ${i} must nullify a real note`);
    }
  });
  return { real: 10 - padded.length, padded: padded.length };
}

test("transfer10 padding follows the committed circuits/inputs/transfer10.json convention", () => {
  const fixturePath = new URL("../../../circuits/inputs/transfer10.json", import.meta.url).pathname;
  const committed = JSON.parse(readFileSync(fixturePath, "utf8"));
  const fromFixture = paddingProfile(committed);
  assert.deepEqual(fromFixture, { real: 4, padded: 6 }, "the fixture is the 4-real/6-pad shape");

  // the wallet, given the same 4-of-10 shape, pads the same way
  const f = fixture([400n, 300n, 200n, 100n]);
  const { request } = buildTransfer10Request(WALLET, f.inputs, f.memberships, PAYEE_ADDR, "700", CRYPTO);
  assert.deepEqual(paddingProfile(request.input as never), { real: 4, padded: 6 });

  // the fixture's own output tail is what the builder produces: 2 funded slots then
  // value-0 notes back to the sender, one salt each.
  assert.deepEqual((committed.outputValues as string[]).slice(2), Array(8).fill("0"));
  assert.equal(new Set(committed.outputSalts as string[]).size, 10, "every output slot has its own salt");
});

test("transfer10 with a single note pads nine slots, and the sums still balance", () => {
  const f = fixture([1000n]);
  const { request, meta } = buildTransfer10Request(WALLET, f.inputs, f.memberships, PAYEE_ADDR, "250", CRYPTO);
  const inp = request.input;
  assert.deepEqual(inp.enabled, ["1", ...Array(9).fill("0")]);
  assert.deepEqual(paddingProfile(inp as never), { real: 1, padded: 9 });
  assert.equal(meta.changeValue, "750");
  const outSum = (inp.outputValues as string[]).reduce((a, x) => a + BigInt(x), 0n);
  assert.equal(outSum, 1000n);
});

test("transfer10 rejects what it cannot represent: >10 inputs, over-spend, missing salts", () => {
  const f = fixture(Array.from({ length: 11 }, () => 100n));
  assert.throws(
    () => buildTransfer10Request(WALLET, f.inputs, f.memberships, PAYEE_ADDR, "1100", CRYPTO),
    /1 to 10 input notes/,
  );
  const small = fixture([100n]);
  assert.throws(
    () => buildTransfer10Request(WALLET, small.inputs, small.memberships, PAYEE_ADDR, "500", CRYPTO),
    /exceeds/,
  );
  assert.throws(
    () => buildTransfer10Request(WALLET, small.inputs, small.memberships, PAYEE_ADDR, "50", { ...CRYPTO, padSalts: ["1"] }),
    /pad salts/,
  );
  assert.throws(
    () => buildTransfer10Request(WALLET, small.inputs, small.memberships, PAYEE_ADDR, "50", { ...CRYPTO, outputPadSalts: [] }),
    /outputPadSalts/,
  );
});

// ============================= (3) MERGE =====================================

test("a merge folds the ten largest notes into one, every output the sender's own", () => {
  const values = Array.from({ length: 12 }, (_, i) => BigInt(100 * (i + 1))); // 100…1200
  const f = fixture(values);
  const plan = planSpendAction("merge", f.notes, WALLET.compressedPubkey, { amount: "ignored" });

  assert.equal(plan.circuit, "transfer10");
  assert.equal(plan.inputs.length, 10, "one merge takes at most the circuit's arity");
  assert.equal(plan.to, WALLET.compressedPubkey, "a merge pays the wallet itself");
  // largest-first: the two smallest notes (100, 200) are the ones left behind
  assert.deepEqual(plan.inputs.map((n) => n.value), ["1200", "1100", "1000", "900", "800", "700", "600", "500", "400", "300"]);
  assert.equal(plan.amount, "7500", "the merged amount is the total of what it consumes");

  const memberships = plan.inputs.map((n) => f.memberships[n.leafIndex]);
  const { request, meta } = buildTransfer10Request(
    WALLET, plan.inputs, memberships, plan.to, plan.amount, CRYPTO,
  );
  const inp = request.input;
  // every output owner is the wallet — safe since §11-8 v1.1 gives output i its own
  // nonce, which is exactly what the shared-nonce disburse path forbids.
  for (const owner of inp.outputOwnerPublicKeys as [string, string][]) {
    assert.deepEqual(owner, [SELF[0].toString(), SELF[1].toString()]);
  }
  assert.equal(new Set(inp.outputCommitments as string[]).size, 10, "distinct salts -> distinct notes");
  assert.equal(inp.outputValues[0], "7500", "the whole balance lands in ONE note");
  assert.deepEqual((inp.outputValues as string[]).slice(1), Array(9).fill("0"));
  assert.deepEqual(inp.enabled, Array(10).fill("1"), "a full-arity merge pads nothing");
  assert.equal(meta.membershipOk, true);
});

test("merging needs something to merge, and previewMerge says so without throwing", () => {
  const one = selectable([500n]);
  assert.throws(() => selectMergeNotes(one), /at least 2 unspent notes/);
  assert.equal(previewMerge(one), null);
  assert.equal(previewMerge([]), null);
  assert.deepEqual(previewMerge(selectable([100n, 200n, 300n])), { count: 3, total: "600" });
  // spent notes are not merge material
  const withSpent: SelectableNote[] = [...selectable([100n, 200n])];
  withSpent[0] = { ...withSpent[0], spent: true };
  assert.equal(previewMerge(withSpent), null);
});

// The flow's own routing: the SAME machine the screens run, with every I/O edge
// faked, so what is asserted is which circuit gets proved and which pool entry point
// gets called — the two decisions a wrong route would only reveal on-chain.
function flowDeps(f: ReturnType<typeof fixture>, trace: { circuit: string | null; submitted: string[] }): Partial<RunSpendDeps> {
  const dummy: Calldata = { a: ["0", "0"], b: [["0", "0"], ["0", "0"]], c: ["0", "0"], pub: [] };
  return {
    ensureChain: async () => {},
    assertPoolKemEpoch: async () => {},
    keyCache: new KeyCache({
      derive: async () => deriveIdentityFromSignature(SIG),
      currentAccount: async () => "0x1",
      arm: () => () => {},
    }),
    getHead: async () => ({ root: f.root, nextLeafIndex: f.inputs.length }),
    getPath: async (_url: string, leafIndex: number) => ({
      leafIndex,
      siblings: f.memberships[leafIndex].pathElements,
      pathIndices: Array.from({ length: H }, () => 0),
      root: f.root,
    }),
    proveInBrowser: async (request) => {
      trace.circuit = request.circuit;
      return dummy;
    },
    submitTransfer: async () => {
      trace.submitted.push("transfer");
      return { txHash: "0xt", explorerUrl: "https://x/tx/0xt" };
    },
    submitTransfer10: async () => {
      trace.submitted.push("transfer10");
      return { txHash: "0xt10", explorerUrl: "https://x/tx/0xt10" };
    },
    submitWithdraw: async () => {
      trace.submitted.push("withdraw");
      return { txHash: "0xw", explorerUrl: "https://x/tx/0xw" };
    },
  };
}

test("runSpend routes by arity: a 4-note send proves transfer10 and submits to transfer10", async () => {
  const f = fixture([400n, 300n, 200n, 100n]);
  const ctx: SpendContext = {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    connection: { address: "0x1", provider: {}, signer: {} } as any,
    indexerUrl: "http://indexer",
    notes: f.notes,
    sessionPubkey: WALLET.compressedPubkey,
  };
  const stages: string[] = [];

  // 800 needs three notes (400+300+200); 700 would have fit in two.
  const wide = { circuit: null as string | null, submitted: [] as string[] };
  const out = await runSpend("transfer", ctx, { to: PAYEE_ADDR, amount: "800" }, (s) => stages.push(s), flowDeps(f, wide));
  assert.equal(wide.circuit, "transfer10");
  assert.deepEqual(wide.submitted, ["transfer10"]);
  assert.equal(out.txHash, "0xt10");
  assert.deepEqual(stages, ["unlock", "assemble", "prove", "submit"]);

  // the same wallet, an amount one note covers: back on the small circuit
  const small = { circuit: null as string | null, submitted: [] as string[] };
  await runSpend("transfer", ctx, { to: PAYEE_ADDR, amount: "400" }, () => {}, flowDeps(f, small));
  assert.equal(small.circuit, "transfer");
  assert.deepEqual(small.submitted, ["transfer"]);
});

test("runSpend('merge') consolidates to the wallet's own key through transfer10", async () => {
  const f = fixture([400n, 300n, 200n, 100n]);
  const ctx: SpendContext = {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    connection: { address: "0x1", provider: {}, signer: {} } as any,
    indexerUrl: "http://indexer",
    notes: f.notes,
    sessionPubkey: WALLET.compressedPubkey,
  };
  const trace = { circuit: null as string | null, submitted: [] as string[] };
  // The amount argument is the form's, and a merge ignores it entirely — it spends
  // what the wallet holds, to the wallet.
  const out = await runSpend("merge", ctx, { amount: "0" }, () => {}, flowDeps(f, trace));
  assert.equal(trace.circuit, "transfer10");
  assert.deepEqual(trace.submitted, ["transfer10"]);
  assert.equal(out.explorerUrl, "https://x/tx/0xt10");
});

// ============================ (4) ASSETS =====================================

test("the arity-10 proving assets are pinned, and are the ones worth not prefetching", () => {
  const t10 = CIRCUIT_ASSET_BYTES.transfer10;
  assert.equal(t10.wasm, 4717238);
  assert.equal(t10.zkey, 114422848);
  // The whole reason the auto-pick defers this download: it dwarfs the 2×2 key, so
  // opening Send must not pull it. If these ever converge, revisit the lazy fetch.
  assert.ok(t10.zkey > 3 * CIRCUIT_ASSET_BYTES.transfer.zkey, "transfer10's key is the heavy one");
});
