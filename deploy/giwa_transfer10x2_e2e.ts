// LIVE GIWA transfer10x2 e2e — the U-Z3 DoD gate, modeled line-for-line on
// deploy/giwa_transfer10_e2e.ts (the driver of the now-DEPRECATED V4 entrypoint;
// user decision 2026-07-28: the wallet routes every >2-input spend and every
// merge leg to transfer10x2, 10-in / 2-out).
//
// Two transactions, exercising BOTH output shapes of the circuit:
//
//   1. MERGE — the exact leg a wallet spend chain inserts: the wallet's own
//      SpendLeg/legCircuit says a merge proves transfer10x2, and
//      buildTransfer10x2Request folds A's three SMALLEST notes into ONE note
//      (output 0 = the merged note, output 1 = a ZERO-value change note — zero
//      change is legal, the fixture circuits/inputs/transfer10x2_merge.json shape).
//   2. PAYMENT — a >2-input spend planned by the wallet's own planSpendChain:
//      an amount only 3+ notes cover, proving output 0 = payment to B and
//      output 1 = a NONZERO change note back to A.
//
// Both go through the WALLET'S OWN production path (selection, planning, witness
// assembly), so what this proves is the code users run, not a parallel
// re-implementation. Proof is CPU snarkjs against circuits/out; submit pins
// gasPrice to the GIWA floor (ethers' auto-estimate once overpaid ~1500x), and
// per-tx gasUsed is printed for the gas table.
//
//   GIWA_RPC (default: the sdk network RPC_URL) + DEPLOYER_KEY (env) required.
//   Run:       npx tsx deploy/giwa_transfer10x2_e2e.ts
//   Dry check: npx tsx deploy/giwa_transfer10x2_e2e.ts --dry
//     --dry touches NO network and needs NO keys: it runs the same wallet path
//     against an in-memory tree, proves both transfer10x2 witnesses on CPU and
//     snarkjs-verifies them against circuits/out/transfer10x2.vkey.json.

// The wallet sources read import.meta.env (a Vite inject); pull the wallet's own
// ambient declaration into this program so the root tsc pass sees the same types.
/// <reference path="../apps/wallet-web/src/vite-env.d.ts" />
import { commitment } from "@bongtu/core/note";
import { ImtTree } from "@bongtu/core/imt";
import { loadSnarkjs } from "@bongtu/core/extern";
import { RPC_URL, H, explorerTxUrl } from "@bongtu/core/network";
import { maxUint256, parseAbi, zeroAddress } from "viem";
import { artifact, prove, ok, step, failureCount } from "./lib/proof_toolbox.js";
// The viem rig centralizes the GIWA gas-price pin (auto-estimate once overpaid ~1500x).
import { giwaChain, GIWA_GAS_PRICE, makeRig, proofArgs } from "./lib/viem_client.js";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// The wallet's production spend path, imported as-is (tsx resolves the NodeNext
// ".js" specifiers to the .ts sources exactly as the wallet's own tests do).
import {
  planSpendChain,
  legCircuit,
  buildTransfer10x2Request,
  freshSpendCrypto,
  randField,
  type SelectableNote,
  type SpendLeg,
  type MembershipWitness,
  type WalletInputNote,
} from "../apps/wallet-web/src/lib/spend.js";
import { deriveIdentityFromSignature } from "../apps/wallet-web/src/lib/derive.js";
import { toWire } from "@bongtu/core/proving";

const HERE = dirname(fileURLToPath(import.meta.url));
const ADDR = JSON.parse(readFileSync(join(HERE, "addresses.91342.json"), "utf8"));
const DRY = process.argv.includes("--dry");

// Deterministic throwaway e2e identities (funds are testnet kKRW; the bjj keys
// derive from fixed stand-in signatures the way the wallet derives from a real one).
const SIG_A = "0x" + "7a".repeat(64) + "1b";
const SIG_B = "0x" + "8b".repeat(64) + "1c";

const KKRW = 10n ** 18n;
// Five deposits: the three smallest fold in the merge; the payment then needs the
// merged note plus BOTH remaining notes (3 inputs -> the wallet plans transfer10x2).
const VALUES = [100n, 200n, 300n, 400n, 500n].map((v) => v * KKRW);

const A = deriveIdentityFromSignature(SIG_A);
const B = deriveIdentityFromSignature(SIG_B);

/** The transfer10x2 merge leg exactly as the wallet's chain runner shapes it:
 *  fold `notes` into ONE self-owned note worth their total (zero change). */
function mergeLeg(notes: WalletInputNote[]): { leg: SpendLeg; mergedValue: string } {
  const mergedValue = notes.reduce((s, n) => s + BigInt(n.value), 0n).toString();
  const leg: SpendLeg = { leg: "merge", inputs: notes, mergedValue };
  ok(legCircuit(leg) === "transfer10x2", "a merge leg proves transfer10x2 (transfer10 is deprecated)");
  return { leg, mergedValue };
}

/** The payment amount that FORCES a >2-input transfer10x2 spend: one unit past
 *  what the two largest notes cover (change stays nonzero for the total). */
function forcingAmount(notes: SelectableNote[]): bigint {
  const sorted = [...notes].map((n) => BigInt(n.value)).sort((a, b) => (a < b ? 1 : -1));
  return sorted[0] + sorted[1] + 1n;
}

// ---------------------------------------------------------------------------------
// --dry: the same wallet path over an in-memory tree, proof + local verify only.
// ---------------------------------------------------------------------------------

async function dryRun(): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const snarkjs: any = loadSnarkjs();
  const vkey = JSON.parse(readFileSync(join(HERE, "..", "circuits", "out", "transfer10x2.vkey.json"), "utf8"));
  const tree = new ImtTree(H, 256);
  const notes: SelectableNote[] = [];
  for (const v of VALUES) {
    const salt = randField();
    tree.appendLeaf(commitment(v, BigInt(salt), A.keypair.publicKey));
    notes.push({ value: v.toString(), salt, leafIndex: tree.getNextLeafIndex() - 1, spent: false });
  }
  const membership = (leafIndex: number): MembershipWitness => ({
    root: tree.getRoot().toString(),
    pathElements: tree.merklePath(leafIndex).siblings.map(String),
    leafIndex,
  });
  const proveAndVerify = async (tag: string, input: unknown): Promise<void> => {
    const wasm = join(HERE, "..", "circuits", "out", "transfer10x2_js", "transfer10x2.wasm");
    const zkey = join(HERE, "..", "circuits", "out", "transfer10x2.zkey");
    const t0 = Date.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(toWire(input), wasm, zkey);
    ok(await snarkjs.groth16.verify(vkey, publicSignals, proof), `${tag}: proof verifies against transfer10x2.vkey (${((Date.now() - t0) / 1000).toFixed(1)}s, ${publicSignals.length} publics)`);
    ok(publicSignals.length === 68, `${tag}: 68 public signals (the V5 entrypoint's uint[68])`);
  };

  step("DRY 1/2 — MERGE: fold the 3 smallest notes, zero change");
  const three = notes.slice(0, 3).map(({ value, salt, leafIndex }) => ({ value, salt, leafIndex }));
  const { mergedValue } = mergeLeg(three);
  const mCrypto = freshSpendCrypto(randField);
  const merge = buildTransfer10x2Request(A, three, three.map((n) => membership(n.leafIndex)), A.compressedPubkey, mergedValue, mCrypto);
  ok(merge.meta.membershipOk, "merge membership folds to the root");
  ok(merge.request.input.outputValues[1] === "0", "merge change output is ZERO (legal)");
  await proveAndVerify("merge", merge.request.input);
  // land the merge locally: the contract appends exactly the two output commitments
  for (const c of merge.request.input.outputCommitments) tree.appendLeaf(BigInt(c as string));
  const mergedNote: SelectableNote = {
    value: mergedValue,
    salt: mCrypto.payeeSalt as string,
    leafIndex: tree.getNextLeafIndex() - 2,
    spent: false,
  };

  step("DRY 2/2 — PAYMENT: planSpendChain routes a 3-note spend to transfer10x2");
  const working = [mergedNote, ...notes.slice(3)];
  const pay = forcingAmount(working);
  const plan = planSpendChain("transfer", working, pay.toString());
  ok(plan.length === 1 && plan[0].leg === "transfer10x2", `the wallet plans ONE transfer10x2 leg (got ${plan.map((l) => l.leg).join(",")})`);
  ok(plan.every((l) => legCircuit(l) !== ("transfer10" as never)), "no leg selects the deprecated transfer10");
  const picked = plan[0].inputs;
  ok(picked.length >= 3, `the payment needs ${picked.length} (>2) input notes`);
  const pCrypto = freshSpendCrypto(randField);
  const paid = buildTransfer10x2Request(A, picked, picked.map((n) => membership(n.leafIndex)), B.compressedPubkey, pay.toString(), pCrypto);
  ok(paid.meta.membershipOk, "payment membership folds to the root");
  ok(BigInt(paid.meta.changeValue) > 0n, `payment change is NONZERO (${paid.meta.changeValue})`);
  await proveAndVerify("payment", paid.request.input);
}

// ---------------------------------------------------------------------------------
// live run against GIWA
// ---------------------------------------------------------------------------------

async function main(): Promise<void> {
  if (DRY) {
    await dryRun();
    if (failureCount() > 0) {
      console.error(`\nTRANSFER10X2 DRY E2E: ${failureCount()} FAILURE(S)`);
      process.exit(1);
    }
    console.log("\nTRANSFER10X2 DRY E2E: PASS — merge (zero change) + 3-note payment (nonzero change), both proved and verified, no network touched");
    // snarkjs' curve workers keep the event loop alive after fullProve; exit explicitly.
    process.exit(0);
  }

  const rpc = process.env.GIWA_RPC || RPC_URL;
  const key = process.env.DEPLOYER_KEY;
  if (!key) throw new Error("DEPLOYER_KEY required");
  // The viem rig pins gasPrice to the GIWA floor on every write.
  const rig = makeRig({ chain: giwaChain, rpc, privateKey: key, gasPrice: GIWA_GAS_PRICE });

  step(`owners: A=${A.compressedPubkey.slice(0, 14)}… merges 3 notes then pays B=${B.compressedPubkey.slice(0, 14)}… from >2 notes`);

  const pool = rig.at(
    ADDR.pool,
    parseAbi([
      "function deposit(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[19] pub, bytes kemCiphertext)",
      "function transfer10x2(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[68] pub, bytes kemCiphertext)",
      "function root() view returns (uint256)",
      "function nextLeafIndex() view returns (uint256)",
      "function nullifierUsed(uint256) view returns (bool)",
      "function transfer10x2Verifier() view returns (address)",
    ]),
  );
  const token = rig.at(ADDR.token, artifact("MockERC20", "MockERC20").abi);

  ok((await pool.read("transfer10x2Verifier")) !== zeroAddress, "pool is V5 (transfer10x2Verifier set)");

  // ---- deposits -> spendable notes for A ---------------------------------------
  // Repeat runs reuse A's existing unspent notes (the ledger remembers them), so
  // the driver deposits only what is missing to reach five.
  const IDX = process.env.INDEXER_URL || "https://bongtu.fractalyze.io/indexer";
  const { buildNotesUrl } = await import("@bongtu/core/indexerApi");
  const existing = ((await (await fetch(buildNotesUrl(IDX, A.compressedPubkey, A.keypair.formattedPrivateKey))).json()) as Array<{
    value: string; salt: string; leafIndex: number; spent: boolean;
  }>).filter((n) => !n.spent && BigInt(n.value) > 0n);

  const notes: SelectableNote[] = existing.map((n) => ({
    value: n.value, salt: n.salt, leafIndex: n.leafIndex, spent: false,
  }));
  const missing = VALUES.slice(Math.min(notes.length, VALUES.length));
  step(`DEPOSIT x${missing.length} for A (has ${notes.length} unspent notes already)`);
  if (missing.length > 0) {
    const total = missing.reduce((a2, b2) => a2 + b2, 0n);
    await token.write("mint", [rig.address, total]);
    await token.write("approve", [ADDR.pool, maxUint256]);
  }
  for (const v of missing) {
    const crypto = freshSpendCrypto(randField);
    const salt0 = randField();
    const salt1 = randField();
    const leafBase = Number(await pool.read("nextLeafIndex"));
    const cV = commitment(v, BigInt(salt0), A.keypair.publicKey);
    const c0 = commitment(0n, BigInt(salt1), A.keypair.publicKey);
    const { a, b, c, pub } = await prove("deposit", {
      outputCommitments: [cV, c0],
      outputValues: [v, 0n],
      outputSalts: [BigInt(salt0), BigInt(salt1)],
      outputOwnerPublicKeys: [A.keypair.publicKey, A.keypair.publicKey],
      ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
      kemSs: crypto.kemSs.map(BigInt),
      encryptionNonce: BigInt(crypto.encryptionNonce),
      authorityPublicKey: crypto.authorityPubKey.map(BigInt),
    });
    const rc = await pool.write("deposit", [...proofArgs({ a, b, c, pub }), crypto.kemCiphertext]);
    ok(rc.status === "success", `deposit(${v / KKRW}) mined: ${rc.transactionHash}  gasUsed ${rc.gasUsed.toString()}`);
    notes.push({ value: v.toString(), salt: salt0, leafIndex: leafBase, spent: false });
  }

  // ---- helpers against the LIVE indexer ----------------------------------------
  const waitHead = async (wantLeaf: number): Promise<{ root: string; nextLeafIndex: number }> => {
    let head: { root: string; nextLeafIndex: number } | null = null;
    for (let i = 0; i < 30; i++) {
      head = (await (await fetch(`${IDX}/head`)).json()) as { root: string; nextLeafIndex: number };
      if (head.nextLeafIndex >= wantLeaf) break;
      await new Promise((r) => setTimeout(r, 3000));
    }
    ok(head !== null && head.nextLeafIndex >= wantLeaf, `indexer caught up (nextLeafIndex ${head?.nextLeafIndex} >= ${wantLeaf})`);
    ok(head!.root === (await pool.read("root")).toString(), "indexer /head root == pool.root");
    return head!;
  };
  const memberships = async (inputs: WalletInputNote[], root: string): Promise<MembershipWitness[]> => {
    const out: MembershipWitness[] = [];
    for (const n of inputs) {
      const p = (await (await fetch(`${IDX}/path/${n.leafIndex}`)).json()) as { siblings: string[] };
      out.push({ root, pathElements: p.siblings, leafIndex: n.leafIndex });
    }
    return out;
  };
  const submit10x2 = async (tag: string, input: unknown, kemCiphertext: string): Promise<void> => {
    const { a, b, c, pub } = await prove("transfer10x2", toWire(input));
    const before = Number(await pool.read("nextLeafIndex"));
    const rcpt = await pool.write("transfer10x2", [...proofArgs({ a, b, c, pub }), kemCiphertext]);
    ok(rcpt.status === "success", `${tag} transfer10x2 mined: ${rcpt.transactionHash}`);
    console.log(`   gasUsed ${rcpt.gasUsed.toString()}  ${explorerTxUrl(rcpt.transactionHash)}`);
    ok(Number(await pool.read("nextLeafIndex")) === before + 2, `only TWO leaves appended (${before} -> ${before + 2}) — the 2-out saving`);
  };

  step("MERGE LEG (wallet shape): fold A's 3 smallest notes into one, ZERO change");
  const head0 = await waitHead(Math.max(...notes.map((n) => n.leafIndex)) + 1);
  const smallest3 = [...notes]
    .sort((a2, b2) => (BigInt(a2.value) < BigInt(b2.value) ? -1 : 1))
    .slice(0, 3)
    .map(({ value, salt, leafIndex }) => ({ value, salt, leafIndex }));
  const { mergedValue } = mergeLeg(smallest3);
  const mCrypto = freshSpendCrypto(randField);
  const merge = buildTransfer10x2Request(
    A, smallest3, await memberships(smallest3, head0.root), A.compressedPubkey, mergedValue, mCrypto,
  );
  ok(merge.meta.membershipOk, "merge membership folds to the live root");
  ok(merge.request.input.outputValues[1] === "0", "merge change output is ZERO (legal)");
  await submit10x2("MERGE", merge.request.input, mCrypto.kemCiphertext);
  for (const [i, m] of merge.meta.nullifiers.entries()) {
    if (m !== "0") ok(await pool.read("nullifierUsed", [BigInt(m)]), `merge input nullifier ${i} marked used`);
  }

  // The merged note is output 0, on this run's payee salt — wait for the arbiter
  // ledger to surface it with its leaf index, exactly as the wallet's chain does.
  step("WAIT: the arbiter ledger surfaces the merged note");
  let merged: { value: string; salt: string; leafIndex: number } | null = null;
  const wantedC = commitment(BigInt(mergedValue), BigInt(mCrypto.payeeSalt as string), A.keypair.publicKey).toString();
  for (let i = 0; i < 30; i++) {
    const res = await fetch(buildNotesUrl(IDX, A.compressedPubkey, A.keypair.formattedPrivateKey));
    if (res.ok) {
      const ns = (await res.json()) as Array<{ value: string; salt: string; leafIndex: number; commitment: string; spent: boolean }>;
      const hit = ns.find((n) => n.commitment === wantedC && !n.spent);
      if (hit) { merged = { value: mergedValue, salt: mCrypto.payeeSalt as string, leafIndex: hit.leafIndex }; break; }
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  ok(merged !== null, `merged note (${BigInt(mergedValue) / KKRW} kKRW) indexed with a leaf`);

  step("PAYMENT LEG: planSpendChain routes a >2-note spend to transfer10x2");
  const spent3 = new Set(smallest3.map((n) => n.leafIndex));
  const working: SelectableNote[] = [
    { ...merged!, spent: false },
    ...notes.filter((n) => !spent3.has(n.leafIndex)),
  ];
  const pay = forcingAmount(working);
  const plan = planSpendChain("transfer", working, pay.toString());
  ok(plan.length === 1 && plan[0].leg === "transfer10x2", `the wallet plans ONE transfer10x2 leg (got ${plan.map((l) => l.leg).join(",")})`);
  const picked = plan[0].inputs;
  ok(picked.length >= 3, `the payment needs ${picked.length} (>2) input notes`);
  const head1 = await waitHead(merged!.leafIndex + 1);
  const pCrypto = freshSpendCrypto(randField);
  const paid = buildTransfer10x2Request(
    A, picked, await memberships(picked, head1.root), B.compressedPubkey, pay.toString(), pCrypto,
  );
  ok(paid.meta.membershipOk, "payment membership folds to the live root");
  ok(BigInt(paid.meta.changeValue) > 0n, `payment change is NONZERO (${BigInt(paid.meta.changeValue) / KKRW} kKRW back to A)`);
  await submit10x2("PAYMENT", paid.request.input, pCrypto.kemCiphertext);

  // ---- final verification: B received via the live ledger ----------------------
  step("VERIFY: B's ledger shows the unspent payment note");
  let bHolds = false;
  for (let i = 0; i < 30; i++) {
    const res = await fetch(buildNotesUrl(IDX, B.compressedPubkey, B.keypair.formattedPrivateKey));
    if (res.ok) {
      const ns = (await res.json()) as Array<{ value: string; spent: boolean }>;
      if (ns.some((n) => BigInt(n.value) === pay && !n.spent)) { bHolds = true; break; }
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  ok(bHolds, `B's ledger shows the unspent ${pay / KKRW} kKRW payment note`);

  if (failureCount() > 0) {
    console.error(`\nTRANSFER10X2 LIVE E2E: ${failureCount()} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nTRANSFER10X2 LIVE E2E: PASS — merge (zero change) + >2-note payment (nonzero change) through the wallet's own path, 2 leaves per tx, on GIWA");
  // snarkjs' curve workers keep the event loop alive after fullProve; exit explicitly.
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
