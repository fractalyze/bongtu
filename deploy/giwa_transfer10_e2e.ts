// LIVE GIWA transfer10 e2e — the U-Z1 DoD gate, repeatable this time (the
// self-send e2e was run ad hoc and left nothing in the repo; this one is the
// committed driver the proof toolbox split was made for).
//
// Three deposits give owner A three spendable notes; the spend then goes through
// the WALLET'S OWN production path — selectInputNotes at arity 10 picks all
// three, buildTransfer10Request assembles the 10-slot witness (3 real + 7
// padded inputs, payment to B + change + 8 zero pads) — so what this proves is
// the code users run, not a parallel re-implementation. Proof is CPU snarkjs
// against circuits/out; submit pins gasPrice to the GIWA floor (ethers'
// auto-estimate once overpaid ~1500x).
//
//   GIWA_RPC (default: the sdk network RPC_URL) + DEPLOYER_KEY (env) required.
//   Run: npx tsx deploy/giwa_transfer10_e2e.ts

// The wallet sources read import.meta.env (a Vite inject); pull the wallet's own
// ambient declaration into this program so the root tsc pass sees the same types.
/// <reference path="../apps/wallet-web/src/vite-env.d.ts" />
import { deriveKeypair, commitment } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import { RPC_URL, explorerTxUrl } from "@bongtu/core/network";
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
  selectInputNotes,
  buildTransfer10Request,
  freshSpendCrypto,
  type SelectableNote,
  type MembershipWitness,
} from "../apps/wallet-web/src/lib/spend.js";
import { randField } from "../apps/wallet-web/src/lib/spend.js";
import { deriveIdentityFromSignature } from "../apps/wallet-web/src/lib/derive.js";
import { toWire } from "@bongtu/core/proving";

const HERE = dirname(fileURLToPath(import.meta.url));
const ADDR = JSON.parse(readFileSync(join(HERE, "addresses.91342.json"), "utf8"));

// Deterministic throwaway e2e identities (funds are testnet kKRW; the bjj keys
// derive from fixed stand-in signatures the way the wallet derives from a real one).
const SIG_A = "0x" + "7a".repeat(64) + "1b";
const SIG_B = "0x" + "8b".repeat(64) + "1c";

const V1 = 100n * 10n ** 18n;
const V2 = 200n * 10n ** 18n;
const V3 = 300n * 10n ** 18n;
const PAY = 550n * 10n ** 18n; // > any single pair — forces the 3-note transfer10 path

async function main(): Promise<void> {
  const rpc = process.env.GIWA_RPC || RPC_URL;
  const key = process.env.DEPLOYER_KEY;
  if (!key) throw new Error("DEPLOYER_KEY required");
  // The viem rig pins gasPrice to the GIWA floor on every write.
  const rig = makeRig({ chain: giwaChain, rpc, privateKey: key, gasPrice: GIWA_GAS_PRICE });

  const A = deriveIdentityFromSignature(SIG_A);
  const B = deriveIdentityFromSignature(SIG_B);
  step(`owners: A=${A.compressedPubkey.slice(0, 14)}… pays B=${B.compressedPubkey.slice(0, 14)}… ${PAY / 10n ** 18n} kKRW from 3 notes`);

  const pool = rig.at(
    ADDR.pool,
    parseAbi([
      "function deposit(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[19] pub, bytes kemCiphertext)",
      "function transfer10(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[141] pub, bytes kemCiphertext)",
      "function root() view returns (uint256)",
      "function nextLeafIndex() view returns (uint256)",
      "function nullifierUsed(uint256) view returns (bool)",
      "function transfer10Verifier() view returns (address)",
    ]),
  );
  const token = rig.at(ADDR.token, artifact("MockERC20", "MockERC20").abi);

  ok((await pool.read("transfer10Verifier")) !== zeroAddress, "pool is V4 (transfer10Verifier set)");

  // ---- three deposits -> three spendable notes for A ---------------------------
  // Repeat runs reuse A's existing unspent notes (the ledger remembers them), so
  // the driver deposits only what is missing.
  const IDX0 = process.env.INDEXER_URL || "https://bongtu.fractalyze.io/indexer";
  const { buildNotesUrl: notesUrl0 } = await import("@bongtu/core/indexerApi");
  const existing = ((await (await fetch(notesUrl0(IDX0, A.compressedPubkey, A.keypair.formattedPrivateKey))).json()) as Array<{
    value: string; salt: string; leafIndex: number; spent: boolean;
  }>).filter((n) => !n.spent && BigInt(n.value) > 0n);

  const notes: SelectableNote[] = existing.map((n) => ({
    value: n.value, salt: n.salt, leafIndex: n.leafIndex, spent: false,
  }));
  const missing = [V1, V2, V3].slice(notes.length >= 3 ? 3 : notes.length);
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
    ok(rc.status === "success", `deposit(${v / 10n ** 18n}) mined: ${rc.transactionHash}`);
    notes.push({ value: v.toString(), salt: salt0, leafIndex: leafBase, spent: false });
  }

  // ---- membership witnesses from the LIVE indexer ------------------------------
  step("membership witnesses from the live indexer (/head + /path)");
  const IDX = process.env.INDEXER_URL || "https://bongtu.fractalyze.io/indexer";
  // the indexer tails on a poll — give it a beat to reach our last deposit
  let head: { root: string; nextLeafIndex: number } | null = null;
  const wantLeaf = notes[2].leafIndex + 2;
  for (let i = 0; i < 30; i++) {
    head = (await (await fetch(`${IDX}/head`)).json()) as { root: string; nextLeafIndex: number };
    if (head.nextLeafIndex >= wantLeaf) break;
    await new Promise((r) => setTimeout(r, 3000));
  }
  ok(head !== null && head.nextLeafIndex >= wantLeaf, `indexer caught up (nextLeafIndex ${head?.nextLeafIndex} >= ${wantLeaf})`);
  ok(head!.root === (await pool.read("root")).toString(), "indexer /head root == pool.root");

  // ---- the wallet's own selection + assembly ----------------------------------
  step("WALLET PATH: selectInputNotes(arity 10) -> buildTransfer10Request");
  const picked = selectInputNotes(notes, PAY.toString(), 10);
  ok(picked.length === 3, `selection uses all 3 notes (got ${picked.length})`);
  // Membership witnesses in SELECTION order — one per picked note, exactly as the
  // wallet's spendFlow fetches them (selection is largest-first, not deposit order).
  const memberships: MembershipWitness[] = [];
  for (const n of picked) {
    const p = (await (await fetch(`${IDX}/path/${n.leafIndex}`)).json()) as { siblings: string[] };
    memberships.push({ root: head!.root, pathElements: p.siblings, leafIndex: n.leafIndex });
  }
  const crypto = freshSpendCrypto(randField);
  const built = buildTransfer10Request(A, picked, memberships, B.compressedPubkey, PAY.toString(), crypto);
  ok(built.meta.membershipOk, "membership folds to the live root");

  step("PROVE transfer10 (CPU snarkjs) + SUBMIT to GIWA");
  const { a, b, c, pub } = await prove("transfer10", toWire(built.request.input));
  const before = Number(await pool.read("nextLeafIndex"));
  const rcpt = await pool.write("transfer10", [...proofArgs({ a, b, c, pub }), crypto.kemCiphertext]);
  ok(rcpt.status === "success", `transfer10 mined: ${rcpt.transactionHash}`);
  console.log(`   gasUsed ${rcpt.gasUsed.toString()}  ${explorerTxUrl(rcpt.transactionHash)}`);

  // ---- on-chain + indexer verification ----------------------------------------
  step("VERIFY: 10 leaves appended, 3 nullifiers spent, B received via the live ledger");
  ok(Number(await pool.read("nextLeafIndex")) === before + 10, `nextLeafIndex ${before} -> ${before + 10}`);
  for (const [i, m] of built.meta.nullifiers.entries()) {
    if (m !== "0") ok(await pool.read("nullifierUsed", [BigInt(m)]), `input nullifier ${i} marked used`);
  }
  // arbiter ledger: B holds the payment note (signed read via the wallet's URL
  // builder; /notes returns a bare array of owner notes)
  const { buildNotesUrl } = await import("@bongtu/core/indexerApi");
  let bNotes: Array<{ value: string; spent: boolean }> = [];
  for (let i = 0; i < 30; i++) {
    const res = await fetch(buildNotesUrl(IDX, B.compressedPubkey, B.keypair.formattedPrivateKey));
    if (res.ok) {
      bNotes = (await res.json()) as typeof bNotes;
      if (bNotes.some((n) => BigInt(n.value) === PAY && !n.spent)) break;
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  ok(bNotes.some((n) => BigInt(n.value) === PAY && !n.spent),
    `B's ledger shows the unspent ${PAY / 10n ** 18n} kKRW payment note`);

  if (failureCount() > 0) {
    console.error(`\nTRANSFER10 LIVE E2E: ${failureCount()} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nTRANSFER10 LIVE E2E: PASS — 3-note spend through the wallet's own path, on GIWA, ingested by the live ledger");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
