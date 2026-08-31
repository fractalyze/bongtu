// Headless gate for the wallet's ARITY-10 spend path on transfer10x2 (U-Z3): the
// circuit auto-pick, the 10-in/2-out witness, and the ten-into-one fold a spend
// chain's merge leg proves.
//
// transfer10 (10-in / 10-OUT) is DEPRECATED — user decision 2026-07-28: it stays
// deployed on chain, but the wallet stops using it entirely. Every >2-input spend
// AND every merge leg now proves transfer10x2, whose two outputs are the two a
// spend needs (payment-or-merged-note + change; zero change is legal). This file
// is the gate that keeps it that way:
//
//   (1) ROUTING — ≤2 notes stay on the cheap 2×2 transfer, 3–10 move to
//       transfer10x2; past that one transaction cannot pay at all (`needs-merge`),
//       and withdraw, which has no arity-10 circuit, hits that at 3. Plus the
//       DEPRECATION PIN: nothing routes to "transfer10" anymore — these asserts
//       FAIL the moment any plan or merge leg selects it again.
//   (2) WITNESS — a transfer10x2 request whose output commitments are the sdk's,
//       whose value is conserved across the 10-in/2-out shape, and whose padded
//       slots carry the SAME convention the committed
//       circuits/fixtures/inputs/transfer10x2{,_merge}.json fixtures do (those files are
//       what the circuit is proved against, so a drift here is a witness that
//       only fails at proving time).
//   (3) MERGE LEG — the witness a chain's fold proves: up to ten notes into ONE
//       note plus a zero-value change note, both the sender's own (legal since
//       the §11-8 v1.1 per-output nonce). How chains are PLANNED and run is
//       test/spendChain.test.ts.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { commitment, nullifier } from "@bongtu/core/note";
import { ImtTree } from "@bongtu/core/imt";
import { packPubkey } from "@bongtu/core/pubkey";
import { deriveKeypair } from "@bongtu/core/note";
import { TRANSFER10_ARITY } from "@bongtu/core/envelope";
import type { Calldata } from "@bongtu/core/proving";

import { deriveIdentityFromSignature } from "@bongtu/client/derive";
import { KeyCache } from "@bongtu/client/keyCache";
import { runSpendChain, type SpendIo, type SpendContext } from "@bongtu/client/spendFlow";
import type { OwnerNote } from "@bongtu/client/indexerClient";
import {
  buildTransfer10x2Request,
  legCircuit,
  planSpendAction,
  planSpendChain,
  previewSpend,
  selectInputNotes,
  SpendSelectionError,
  type MembershipWitness,
  type SelectableNote,
  type SpendCrypto,
  type WalletInputNote,
} from "@bongtu/client/spend";
import { CIRCUIT_ASSET_BYTES, DEFAULTS, H, B } from "../src/config.js";

const SIG = "0x" + "a1".repeat(32) + "b2".repeat(32) + "1c";
const WALLET = deriveIdentityFromSignature(SIG);
const SELF = WALLET.keypair.publicKey;
const PAYEE = deriveKeypair(4242424242424242n).publicKey;
const PAYEE_ADDR = packPubkey(PAYEE);

// Fixed per-tx material, shaped exactly like freshSpendCrypto's — 9 input-pad salts
// (arity 10 with one real note), all distinct so no two padded slots collide.
// outputPadSalts exist only for the deprecated transfer10 builder; transfer10x2
// never touches them (its two outputs are payeeSalt + changeSalt).
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

test("a send picks the circuit from how many notes it needs: ≤2 transfer, 3–10 transfer10x2", () => {
  const notes = selectable([100n, 100n, 100n, 100n]);
  const plan1 = planSpendAction("transfer", notes, { to: PAYEE_ADDR, amount: "100" });
  assert.equal(plan1.circuit, "transfer");
  assert.equal(plan1.inputs.length, 1);

  const plan2 = planSpendAction("transfer", notes, { to: PAYEE_ADDR, amount: "200" });
  assert.equal(plan2.circuit, "transfer", "two notes still fit the small circuit");

  const plan3 = planSpendAction("transfer", notes, { to: PAYEE_ADDR, amount: "250" });
  assert.equal(plan3.circuit, "transfer10x2", "the third note is what moves it to arity 10");
  assert.equal(plan3.inputs.length, 3);
  assert.equal(plan3.to, PAYEE_ADDR, "the payee is the typed recipient, not the wallet");
});

test("DEPRECATION PIN: no route, plan or merge leg answers transfer10 anymore", () => {
  // The type system already forbids it (SpendCircuit has no "transfer10" member);
  // this is the runtime tripwire in case the union is ever widened back.
  const notes = selectable([100n, 100n, 100n, 100n]);
  assert.notEqual(
    planSpendAction("transfer", notes, { to: PAYEE_ADDR, amount: "250" }).circuit as string,
    "transfer10",
  );
  const merge: import("@bongtu/client/spend").SpendLeg = { leg: "merge", inputs: [], mergedValue: "0" };
  assert.equal(legCircuit(merge), "transfer10x2", "a merge leg proves transfer10x2");
  const wide = selectable(Array(25).fill(100n));
  for (const leg of planSpendChain("transfer", wide, "2500")) {
    assert.notEqual(legCircuit(leg) as string, "transfer10", "deprecated circuit resurfaced");
  }
  assert.equal(previewSpend("transfer", notes, "250").circuit, "transfer10x2");
});

test("one transaction cannot spend more than 10 notes — needs-merge, not poverty", () => {
  const many = selectable(Array.from({ length: 12 }, () => 100n)); // 1200 spendable
  assert.throws(
    () => planSpendAction("transfer", many, { amount: "1100" }),
    (e: unknown) => e instanceof SpendSelectionError && e.blocker === "needs-merge",
  );
  // …and the same wallet genuinely cannot fund more than it holds.
  assert.throws(
    () => planSpendAction("transfer", many, { amount: "9999" }),
    (e: unknown) => e instanceof SpendSelectionError && e.blocker === "insufficient",
  );
  // exactly ten notes is the last amount that goes through
  assert.equal(
    planSpendAction("transfer", many, { amount: "1000" }).inputs.length,
    10,
  );
});

test("withdraw stays at arity 2 — there is no withdraw10 — so >2 notes is over its arity", () => {
  const notes = selectable([100n, 100n, 100n, 100n]);
  assert.equal(planSpendAction("withdraw", notes, { amount: "200" }).circuit, "withdraw");
  assert.throws(
    () => planSpendAction("withdraw", notes, { amount: "250" }),
    (e: unknown) => e instanceof SpendSelectionError && e.blocker === "needs-merge",
  );
});

test("previewSpend answers the form's question on every keystroke without throwing", () => {
  const notes = selectable([100n, 100n, 100n, 100n]);
  const p = (kind: "transfer" | "withdraw", amount: string) => previewSpend(kind, notes, amount);
  assert.deepEqual(p("transfer", "200"), { circuit: "transfer", blocker: null, legCount: 1, pieces: 4 });
  assert.deepEqual(p("transfer", "250"), { circuit: "transfer10x2", blocker: null, legCount: 1, pieces: 4 });
  // a withdraw over arity 2 is not blocked: it becomes a merge then the withdraw,
  // and the circuit named is the FIRST leg's — the merge the user waits on next.
  assert.deepEqual(p("withdraw", "250"), { circuit: "transfer10x2", blocker: null, legCount: 2, pieces: 4 });
  assert.deepEqual(p("withdraw", "200"), { circuit: "withdraw", blocker: null, legCount: 1, pieces: 4 });
  // only poverty still blocks the form
  assert.deepEqual(p("transfer", "9999"), { circuit: "transfer", blocker: "insufficient", legCount: 1, pieces: 4 });
  // a half-typed amount is not a verdict: the form's own amountError owns that case
  assert.deepEqual(p("transfer", "0"), { circuit: "transfer", blocker: null, legCount: 1, pieces: 4 });
  assert.deepEqual(p("transfer", ""), { circuit: "transfer", blocker: null, legCount: 1, pieces: 4 });
});

test("selectInputNotes takes the arity as a parameter and names the limit it hit", () => {
  const notes = selectable([30n, 30n, 30n, 30n]);
  assert.equal(selectInputNotes(notes, "80", TRANSFER10_ARITY).length, 3);
  assert.throws(() => selectInputNotes(notes, "80", 2), /more than 2 notes/);
  assert.throws(() => selectInputNotes(selectable(Array(11).fill(10n)), "105", 10), /more than 10 notes/);
});

// ============================ (2) WITNESS ====================================

test("transfer10x2: output commitments == sdk commitment() and value is conserved over 10-in/2-out", () => {
  const f = fixture([400n, 300n, 200n, 100n]); // total 1000
  const { request, meta } = buildTransfer10x2Request(WALLET, f.inputs, f.memberships, PAYEE_ADDR, "700", CRYPTO);
  const inp = request.input;

  assert.equal(request.circuit, "transfer10x2");
  assert.equal(request.backend, "cpu");
  for (const field of ["nullifiers", "inputCommitments", "inputValues", "inputSalts", "enabled",
    "leafIndices"] as const) {
    assert.equal((inp[field] as unknown[]).length, 10, `${field} must be a length-10 vector`);
  }
  assert.equal((inp.pathElements as unknown[][]).length, 10);
  assert.equal((inp.pathElements as unknown[][])[0].length, H);
  for (const field of ["outputCommitments", "outputValues", "outputSalts", "outputOwnerPublicKeys"] as const) {
    assert.equal((inp[field] as unknown[]).length, 2, `${field} must be a length-2 vector — the 2-out is the point`);
  }

  // every output commitment recomputed independently with the sdk
  const owners = inp.outputOwnerPublicKeys as [string, string][];
  inp.outputCommitments.forEach((c, i) => {
    const owner: [bigint, bigint] = [BigInt(owners[i][0]), BigInt(owners[i][1])];
    assert.equal(c, commitment(BigInt(inp.outputValues[i]), BigInt(inp.outputSalts[i]), owner).toString());
  });

  const inSum = (inp.inputValues as string[]).reduce((a, x) => a + BigInt(x), 0n);
  const outSum = (inp.outputValues as string[]).reduce((a, x) => a + BigInt(x), 0n);
  assert.equal(inSum, 1000n);
  assert.equal(outSum, 1000n, "value conserved across the two output slots");
  assert.equal(inp.outputValues[0], "700"); // payment
  assert.equal(inp.outputValues[1], "300"); // change
  assert.equal(meta.realInputCount, 4);
  assert.equal(meta.membershipOk, true);

  // the real inputs are the wallet's own notes, byte-identical to the sdk
  assert.equal(inp.inputCommitments[0], commitment(400n, f.salts[0], SELF).toString());
  assert.equal(inp.nullifiers[0], nullifier(400n, f.salts[0], WALLET.keypair.formattedPrivateKey).toString());
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(request)), "no bigints leak to the wire");
});

/**
 * The padding convention, read off a transfer10x2 witness: which input slots are
 * padded, and what a padded slot must carry. Applied below to BOTH the committed
 * fixtures and the wallet's own output, so the two cannot drift apart.
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

test("transfer10x2 padding follows the committed circuits/fixtures/inputs/transfer10x2.json convention", () => {
  const fixturePath = new URL("../../../circuits/fixtures/inputs/transfer10x2.json", import.meta.url).pathname;
  const committed = JSON.parse(readFileSync(fixturePath, "utf8"));
  const fromFixture = paddingProfile(committed);
  assert.deepEqual(fromFixture, { real: 4, padded: 6 }, "the fixture is the 4-real/6-pad shape");
  assert.equal((committed.outputValues as string[]).length, 2, "the fixture is 2-out");

  // the wallet, given the same 4-of-10 payment shape, pads the same way and lands
  // on the fixture's [payment, change] output split.
  const f = fixture([400n, 300n, 200n, 100n]);
  const { request } = buildTransfer10x2Request(WALLET, f.inputs, f.memberships, PAYEE_ADDR, "700", CRYPTO);
  assert.deepEqual(paddingProfile(request.input as never), { real: 4, padded: 6 });
  assert.deepEqual(request.input.outputValues, committed.outputValues, "[700 payment, 300 change]");
});

test("transfer10x2 with a single note pads nine slots, and the sums still balance", () => {
  const f = fixture([1000n]);
  const { request, meta } = buildTransfer10x2Request(WALLET, f.inputs, f.memberships, PAYEE_ADDR, "250", CRYPTO);
  const inp = request.input;
  assert.deepEqual(inp.enabled, ["1", ...Array(9).fill("0")]);
  assert.deepEqual(paddingProfile(inp as never), { real: 1, padded: 9 });
  assert.equal(meta.changeValue, "750");
  const outSum = (inp.outputValues as string[]).reduce((a, x) => a + BigInt(x), 0n);
  assert.equal(outSum, 1000n);
});

test("transfer10x2 rejects what it cannot represent: >10 inputs, over-spend, missing salts", () => {
  const f = fixture(Array.from({ length: 11 }, () => 100n));
  assert.throws(
    () => buildTransfer10x2Request(WALLET, f.inputs, f.memberships, PAYEE_ADDR, "1100", CRYPTO),
    /1 to 10 input notes/,
  );
  const small = fixture([100n]);
  assert.throws(
    () => buildTransfer10x2Request(WALLET, small.inputs, small.memberships, PAYEE_ADDR, "500", CRYPTO),
    /exceeds/,
  );
  assert.throws(
    () => buildTransfer10x2Request(WALLET, small.inputs, small.memberships, PAYEE_ADDR, "50", { ...CRYPTO, padSalts: ["1"] }),
    /pad salts/,
  );
  assert.throws(
    () => buildTransfer10x2Request(WALLET, small.inputs, small.memberships, PAYEE_ADDR, "50", { ...CRYPTO, payeeSalt: undefined }),
    /payeeSalt/,
  );
});

// ============================= (3) MERGE LEG =================================
// A merge is a leg planSpendChain inserts (test/spendChain.test.ts owns the
// planning). What belongs HERE is the witness that leg proves: a full-arity
// transfer10x2 folding up to ten notes into ONE merged note plus a ZERO-value
// change note, both the sender's own.

test("a merge leg folds the ten largest notes into one note + a zero change note, matching the committed merge fixture", () => {
  const values = Array.from({ length: 12 }, (_, i) => BigInt(100 * (i + 1))); // 100…1200
  const f = fixture(values);
  // 7600 is past what any ten of these notes cover (the largest ten total 7500), so
  // the chain has to fold before it can pay.
  const [first] = planSpendChain("transfer", f.notes, "7600");
  assert.equal(first.leg, "merge");
  if (first.leg !== "merge") return;
  assert.equal(legCircuit(first), "transfer10x2");
  assert.equal(first.inputs.length, 10, "one merge takes at most the circuit's arity");
  // largest-first: the two smallest notes (100, 200) are the ones left behind
  assert.deepEqual(first.inputs.map((n) => n.value), ["1200", "1100", "1000", "900", "800", "700", "600", "500", "400", "300"]);
  assert.equal(first.mergedValue, "7500", "the merged note is worth everything it consumes");

  const memberships = first.inputs.map((n) => f.memberships[n.leafIndex]);
  const { request, meta } = buildTransfer10x2Request(
    WALLET, first.inputs, memberships, WALLET.compressedPubkey, first.mergedValue, CRYPTO,
  );
  const inp = request.input;
  // every output owner is the wallet — safe since §11-8 v1.1 gives output i its own
  // nonce, which is exactly what the shared-nonce disburse path forbids.
  for (const owner of inp.outputOwnerPublicKeys as [string, string][]) {
    assert.deepEqual(owner, [SELF[0].toString(), SELF[1].toString()]);
  }
  assert.equal(inp.outputValues[0], "7500", "the whole fold lands in ONE note");
  assert.equal(inp.outputValues[1], "0", "the change note is zero — legal, and still a real note");
  assert.notEqual(inp.outputCommitments[1], "0", "a zero-value note still commits nonzero");
  assert.notEqual(inp.outputCommitments[0], inp.outputCommitments[1], "distinct salts -> distinct notes");
  assert.deepEqual(inp.enabled, Array(10).fill("1"), "a full-arity merge pads nothing");
  assert.equal(meta.membershipOk, true);

  // the committed merge fixture carries this exact shape: all-enabled inputs,
  // [full total, 0] outputs, one owner for both.
  const fixturePath = new URL("../../../circuits/fixtures/inputs/transfer10x2_merge.json", import.meta.url).pathname;
  const committed = JSON.parse(readFileSync(fixturePath, "utf8"));
  assert.deepEqual(committed.enabled, Array(10).fill("1"));
  assert.equal(committed.outputValues[1], "0");
  assert.deepEqual(committed.outputOwnerPublicKeys[0], committed.outputOwnerPublicKeys[1]);
});

// The flow's own routing: the SAME machine the screens run, with every I/O edge
// faked, so what is asserted is which circuit gets proved and which pool entry point
// gets called — the two decisions a wrong route would only reveal on-chain.
function flowDeps(f: ReturnType<typeof fixture>, trace: { circuit: string | null; submitted: string[] }): SpendIo {
  const dummy: Calldata = { a: ["0", "0"], b: [["0", "0"], ["0", "0"]], c: ["0", "0"], pub: [] };
  return {
    ensureChain: async () => {},
    assertPoolKemEpoch: async () => {},
    keyCache: new KeyCache({
      derive: async () => deriveIdentityFromSignature(SIG),
      // Routing, not stealth, is under test; the seam must stay unreached.
      deriveStealth: async () => {
        throw new Error("stealth derive must not be reached here");
      },
      currentAccount: async () => "0x1",
      arm: () => () => {},
    }),
    getHead: async () => ({ root: f.root, nextLeafIndex: f.inputs.length }),
    getSignedPath: async (_url: string, leafIndex: number) => ({
      leafIndex,
      siblings: f.memberships[leafIndex].pathElements,
      pathIndices: Array.from({ length: H }, () => 0),
      root: f.root,
    }),
    prove: async (request) => {
      trace.circuit = request.circuit;
      return dummy;
    },
    submitTransfer: async () => {
      trace.submitted.push("transfer");
      return { txHash: "0xt", explorerUrl: "https://x/tx/0xt" };
    },
    submitTransfer10x2: async () => {
      trace.submitted.push("transfer10x2");
      return { txHash: "0xt10x2", explorerUrl: "https://x/tx/0xt10x2" };
    },
    submitWithdraw: async () => {
      trace.submitted.push("withdraw");
      return { txHash: "0xw", explorerUrl: "https://x/tx/0xw" };
    },
  };
}

function flowCtx(f: ReturnType<typeof fixture>): SpendContext {
  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    connection: { address: "0x1", provider: {}, signer: {} } as any,
    indexerUrl: "http://indexer",
    pool: "0x0000000000000000000000000000000000000b0b",
    explorer: "https://x",
    notes: f.notes,
    sessionPubkey: WALLET.compressedPubkey,
    reloadNotes: async () => f.notes,
  };
}

test("runSpendChain routes by arity: a 4-note send proves transfer10x2 and submits to transfer10x2", async () => {
  const f = fixture([400n, 300n, 200n, 100n]);
  const ctx = flowCtx(f);
  const stages: string[] = [];

  // 800 needs three notes (400+300+200); 700 would have fit in two.
  const wide = { circuit: null as string | null, submitted: [] as string[] };
  const out = await runSpendChain("transfer", ctx, { to: PAYEE_ADDR, amount: "800" }, (s) => stages.push(s), flowDeps(f, wide));
  assert.equal(wide.circuit, "transfer10x2");
  assert.deepEqual(wide.submitted, ["transfer10x2"], "never the deprecated transfer10 entrypoint");
  assert.equal(out.txHash, "0xt10x2");
  assert.deepEqual(stages, ["unlock", "assemble", "prove", "submit"]);

  // the same wallet, an amount one note covers: back on the small circuit
  const small = { circuit: null as string | null, submitted: [] as string[] };
  await runSpendChain("transfer", ctx, { to: PAYEE_ADDR, amount: "400" }, () => {}, flowDeps(f, small));
  assert.equal(small.circuit, "transfer");
  assert.deepEqual(small.submitted, ["transfer"]);
});

// ============================ (4) ASSETS =====================================

test("the arity-10 proving assets are transfer10x2's; transfer10 left the download set", () => {
  const t10x2 = CIRCUIT_ASSET_BYTES.transfer10x2;
  assert.equal(t10x2.wasm, 4520070);
  assert.equal(t10x2.zkey, 95008180);
  // The whole reason the auto-pick defers this download: it dwarfs the 2×2 key, so
  // opening Send must not pull it. If these ever converge, revisit the lazy fetch.
  assert.ok(t10x2.zkey > 3 * CIRCUIT_ASSET_BYTES.transfer.zkey, "transfer10x2's key is the heavy one");
  // DEPRECATION PIN (2026-07-28): the wallet must not serve, size or prefetch the
  // 10-out circuit's assets anymore.
  assert.ok(!("transfer10" in CIRCUIT_ASSET_BYTES), "deprecated transfer10 must stay out of the download set");
});

test("the pinned transfer10x2 sizes match the build the blob store serves (circuits/out)", () => {
  // Same skip-if-absent posture as assets.test.ts: the build outputs are
  // gitignored, so only the dev/deploy box checks the byte identity.
  const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  const files = {
    wasm: join(root, "circuits", "out", "transfer10x2_js", "transfer10x2.wasm"),
    zkey: join(root, "circuits", "out", "transfer10x2.zkey"),
  } as const;
  for (const kind of ["wasm", "zkey"] as const) {
    if (!existsSync(files[kind])) continue;
    assert.equal(
      statSync(files[kind]).size,
      CIRCUIT_ASSET_BYTES.transfer10x2[kind],
      `transfer10x2.${kind} size drifted from CIRCUIT_ASSET_BYTES — re-pin alongside CIRCUITS_VERSION`,
    );
  }
});
