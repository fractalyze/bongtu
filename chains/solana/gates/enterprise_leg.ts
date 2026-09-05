// The Solana enterprise acceptance driver (SOLR §5.3's enterprise row, run by
// e2e_s.sh): a REAL solana-test-validator, the enterprise profile initialized
// through the real `initialize` instruction (B=256, arbiter key from the
// committed fixtures), and the FULL enterprise family settling on-chain by
// replaying the committed realproof fixtures in the recorded-ledger order —
//
//   INITIALIZE enterprise profile (all nine family flags, B=256, the
//              disburse fixture's own arbiter key injected at verify);
//   DEPOSIT    enterprise deposit funds the pool (SPL pull, 2 leaves);
//   DISBURSE   the 256-out disburse settles IN ONE TRANSACTION: the chain
//              verifies + persists only the BINDING (DisburseBatch PDA:
//              disclosureHash, kemBinding, epoch — 82 fixed bytes, no
//              per-recipient record: recipient-count hiding is structural);
//   WITHDRAW   institution exit to the truncate-253 proof-bound account;
//   TRANSFER / TRANSFER10X2 complete the family on the same tree;
//   SERVE      the indexer (Solana backend) ingests the ledger, holds the
//              institution blob (DISCLOSURE_DIR), and serves it from
//              GET /disclosure/{start} with its refold verdict;
//   REFOLD     this leg INDEPENDENTLY refolds the served 2054 elements
//              (@bongtu/core disclosureChain — the one fold implementation)
//              against the DisburseBatch account read straight from the
//              validator: chain-checkable bytes, no trust in the server.
//
// Spend membership is state-level replay (SOLR §5.2): each fixture's spend
// root is genesis-seeded as a KnownRoot marker PDA — the validator twin of
// the mollusk/recorded-ledger posture — while the tree itself GROWS from
// empty through the executed ops (the local ImtTree oracle predicts every
// post-op root, so a divergence fails the send, not the assert).

import type { ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ImtTree } from "@bongtu/core/imt";
import { disclosureChain } from "@bongtu/core/envelope";
import {
  BATCH_B_ENTERPRISE,
  DISBURSE_BATCH_LEN,
  PROGRAM_ID_BASE58,
  TAG_DISBURSE_BATCH,
  TREE_HEIGHT,
  bytesToBase58,
} from "@bongtu/core/solana";
import {
  getAccountData,
  getGenesisHash,
  getTokenBalance,
  keypairConnection,
  type SolanaConnection,
} from "@bongtu/client-solana/connection";
import {
  CU_LIMIT_HEADROOM,
  SYSTEM_PROGRAM_ADDRESS,
  TOKEN_PROGRAM_ADDRESS,
  configPda,
  disburseBatchPda,
  eventAuthorityPda,
  initializeInstruction,
  knownRootPda,
  nullifierPda,
  parseTreeState,
  treePda,
  vaultAuthorityPda,
} from "@bongtu/client-solana/txbuild";
import { AccountRole, type Address, type Instruction } from "@solana/kit";

import { failureCount, ok, step } from "../../../deploy/live/lib/proof_toolbox.js";
import {
  addressOfSecret,
  airdrop,
  mintImage,
  secretKeyOf,
  sendInstruction,
  sha,
  spawnIndexer,
  spawnValidator,
  tokenAccountImage,
  waitFor,
  waitForFinalized,
} from "./leg_common.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", "..");
const SO_PATH = join(ROOT, "chains", "solana", "target", "deploy", "bongtu_pool_solana.so");
const CONFORMANCE = join(ROOT, "chains", "solana", "conformance");

const RPC_PORT = Number(process.env.SOLANA_E2E_ENT_RPC_PORT || 8952);
const INDEXER_PORT = Number(process.env.SOLANA_E2E_ENT_INDEXER_PORT || 8654);
const RPC = `http://127.0.0.1:${RPC_PORT}`;
const INDEXER = `http://127.0.0.1:${INDEXER_PORT}`;

// --- fixtures (the committed conformance vectors, fixture-bound wire) --------

interface EntFixture {
  proof: string;
  publicsCarried: string[];
  publicsFull: string[];
  kemCiphertexts: string[];
  outputCommitments?: string[];
  nullifiers?: string[];
  nullifier?: string;
  changeCommitment?: string;
  amount?: string;
  recipientTokenAccount?: string;
  stealthEphemeralPub?: string;
  stealthViewTag?: number;
  spentRoot?: string;
  subtreeRoot?: string;
  disclosureHash?: string;
  kemBinding?: string;
  startLeafIndex?: number;
  disclosureElements?: string[];
}

const loadFixture = (name: string): EntFixture =>
  JSON.parse(readFileSync(join(CONFORMANCE, name), "utf8")) as EntFixture;

const hexBytes = (hex: string): Uint8Array => {
  const h = hex.replace(/^0x/, "");
  return Uint8Array.from({ length: h.length / 2 }, (_, i) => parseInt(h.slice(2 * i, 2 * i + 2), 16));
};

/** discriminator || proof || carried publics || kem cts || tail. */
function wire(disc: number, fx: EntFixture, tail?: Uint8Array): Uint8Array {
  const parts: Uint8Array[] = [Uint8Array.of(disc), hexBytes(fx.proof)];
  for (const p of fx.publicsCarried) parts.push(hexBytes(p));
  for (const k of fx.kemCiphertexts) parts.push(hexBytes(k));
  if (tail) parts.push(tail);
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  parts.reduce((off, p) => {
    out.set(p, off);
    return off + p.length;
  }, 0);
  return out;
}

// --- deterministic actors ----------------------------------------------------

const MINT_ADDR = bytesToBase58(sha("bongtu/solana-enterprise-gate/mint"));
const VAULT_ADDR = bytesToBase58(sha("bongtu/solana-enterprise-gate/vault"));
const PAYER_TOKEN_ADDR = bytesToBase58(sha("bongtu/solana-enterprise-gate/payer-token"));
const SK_E = secretKeyOf("bongtu/solana-enterprise-gate/institution");
const ADDR_E = addressOfSecret(SK_E);

const ro = (address: string) => ({ address: address as Address, role: AccountRole.READONLY });
const w = (address: string) => ({ address: address as Address, role: AccountRole.WRITABLE });
const ws = (address: string) => ({ address: address as Address, role: AccountRole.WRITABLE_SIGNER });

async function main(): Promise<void> {
  const scratch = mkdtempSync(join(tmpdir(), "bongtu-solana-enterprise-"));
  const budgets = JSON.parse(
    readFileSync(join(ROOT, "chains", "solana", "cu_budget.json"), "utf8"),
  ) as Record<string, number>;
  const cu = (op: string): number => {
    const budget = budgets[op];
    if (typeof budget !== "number") throw new Error(`no CU budget for ${op}`);
    return budget + CU_LIMIT_HEADROOM;
  };

  const dep = loadFixture("deposit_fixture.json");
  const dis = loadFixture("disburse256_fixture.json");
  const wd = loadFixture("withdraw_fixture.json");
  const trf = loadFixture("transfer_fixture.json");
  const t10 = loadFixture("transfer10x2_fixture.json");

  const CONFIG_ADDR = await configPda(MINT_ADDR);
  const TREE_ADDR = await treePda(CONFIG_ADDR);
  const vaultOwner = await vaultAuthorityPda(CONFIG_ADDR);
  const eventAuth = await eventAuthorityPda();
  const depAmount = BigInt(dep.amount as string);
  const wdAmount = BigInt(wd.amount as string);
  const recipientToken = bytesToBase58(hexBytes(wd.recipientTokenAccount as string));

  // The institution blob the indexer serves: written to DISCLOSURE_DIR before
  // ingest, keyed by the batch's start leaf index (served.ts contract).
  const disclosureDir = join(scratch, "disclosure");
  mkdirSync(disclosureDir);
  writeFileSync(
    join(disclosureDir, `${dis.startLeafIndex}.json`),
    JSON.stringify(dis.disclosureElements),
  );

  step("validator: program + out-of-program accounts + fixture spend-root markers");
  // Fixture spend roots are chain history the recorded proofs were made
  // against — genesis-seeded as program-owned KnownRoot markers (SOLR §5.2
  // state-level replay), exactly what mollusk and the recorded ledger seed.
  const markers = await Promise.all(
    [wd, trf, t10, dis].map(async (fx, i): Promise<[string, string, string, Uint8Array]> => [
      `spent-root-${i}`,
      await knownRootPda(BigInt(fx.spentRoot as string)),
      PROGRAM_ID_BASE58,
      new Uint8Array(0),
    ]),
  );
  const validator: ChildProcess = spawnValidator({
    scratch,
    rpcPort: RPC_PORT,
    soPath: SO_PATH,
    programId: PROGRAM_ID_BASE58,
    accounts: [
      ["mint", MINT_ADDR, TOKEN_PROGRAM_ADDRESS, mintImage()],
      ["vault", VAULT_ADDR, TOKEN_PROGRAM_ADDRESS, tokenAccountImage(MINT_ADDR, vaultOwner, 0n)],
      [
        "payer-token",
        PAYER_TOKEN_ADDR,
        TOKEN_PROGRAM_ADDRESS,
        tokenAccountImage(MINT_ADDR, ADDR_E, depAmount * 2n),
      ],
      [
        "recipient-token",
        recipientToken,
        TOKEN_PROGRAM_ADDRESS,
        tokenAccountImage(MINT_ADDR, bytesToBase58(sha("bongtu/solana-enterprise-gate/recipient")), 0n),
      ],
      ...markers,
    ],
  });
  const children: ChildProcess[] = [validator];
  const stop = (): void => {
    for (const c of children) c.kill("SIGTERM");
  };
  process.on("exit", stop);

  await waitFor("validator rpc", async () => (await getGenesisHash(RPC)).length > 0);
  await airdrop(RPC, ADDR_E);
  const conn: SolanaConnection = await keypairConnection(RPC, SK_E);

  step("initialize: the enterprise profile (B=256, fixture arbiter key) on-chain");
  const initIx = await initializeInstruction({
    mint: MINT_ADDR,
    vault: VAULT_ADDR,
    payer: ADDR_E,
    profile: {
      familyFlags: 0x01ff,
      batchB: BATCH_B_ENTERPRISE,
      // The one committed arbiter key (realproofs.arbiterKey == the disburse
      // publics [9..10]); the config-injected key must match it or every
      // enterprise verify below fails.
      arbiterKeyX: BigInt(dis.publicsFull[9]).toString(),
      arbiterKeyY: BigInt(dis.publicsFull[10]).toString(),
    },
  });
  const initSig = await sendInstruction(conn, initIx, 150_000);
  ok(initSig.length > 0, `initialize landed: ${initSig}`);
  const configData = await getAccountData(RPC, CONFIG_ADDR);
  ok(
    configData !== null && configData[2] === 0xff && configData[3] === 0x01,
    "config records the full nine-family profile",
  );

  await waitForFinalized(RPC, CONFIG_ADDR);
  await waitForFinalized(RPC, TREE_ADDR);

  step("indexer: Solana backend + the institution disclosure store");
  const indexer = spawnIndexer(ROOT, {
    SOLANA_RPC: RPC,
    SOLANA_TREE: TREE_ADDR,
    DISCLOSURE_DIR: disclosureDir,
    PORT: String(INDEXER_PORT),
    POLL_MS: "500",
  });
  children.push(indexer);
  await waitFor("indexer /head", async () => {
    const r = await fetch(`${INDEXER}/head`);
    return r.ok && ((await r.json()) as { nextLeafIndex: number }).nextLeafIndex === 0;
  });

  // The local oracle: predicts every post-op root so each new-root PDA meta
  // is derived before the send (the program computes the same root or the
  // instruction fails PdaMismatch — prediction is itself an assertion).
  const oracle = new ImtTree(TREE_HEIGHT, BATCH_B_ENTERPRISE);

  step(`enterprise deposit: funds the pool (${depAmount})`);
  for (const oc of dep.outputCommitments as string[]) oracle.appendLeaf(BigInt(oc));
  const depRoot = oracle.getRoot();
  const depIx: Instruction = {
    programAddress: PROGRAM_ID_BASE58 as Address,
    accounts: [
      ro(CONFIG_ADDR),
      w(TREE_ADDR),
      w(await knownRootPda(depRoot)),
      ws(ADDR_E),
      ro(SYSTEM_PROGRAM_ADDRESS),
      ro(eventAuth),
      ro(PROGRAM_ID_BASE58),
      ro(TOKEN_PROGRAM_ADDRESS),
      w(PAYER_TOKEN_ADDR),
      w(VAULT_ADDR),
    ],
    data: wire(6, dep),
  };
  const depSig = await sendInstruction(conn, depIx, cu("deposit"));
  ok(depSig.length > 0, `enterprise deposit landed: ${depSig}`);
  ok((await getTokenBalance(RPC, VAULT_ADDR)) === depAmount, "vault escrowed the funding");

  step("disburse256: the 256-out batch settles in ONE transaction");
  oracle.attachSubtree(BigInt(dis.subtreeRoot as string));
  ok(
    oracle.getNextLeafIndex() === (dis.startLeafIndex as number) + 256,
    `attach closed the partial block and landed at ${dis.startLeafIndex}`,
  );
  const disRoot = oracle.getRoot();
  const batchPda = await disburseBatchPda(dis.startLeafIndex as number);
  const disIx: Instruction = {
    programAddress: PROGRAM_ID_BASE58 as Address,
    accounts: [
      ro(CONFIG_ADDR),
      w(TREE_ADDR),
      ro(await knownRootPda(BigInt(dis.spentRoot as string))),
      w(await knownRootPda(disRoot)),
      w(batchPda),
      ws(ADDR_E),
      ro(SYSTEM_PROGRAM_ADDRESS),
      ro(eventAuth),
      ro(PROGRAM_ID_BASE58),
      w(await nullifierPda(BigInt(dis.nullifier as string))),
    ],
    data: wire(8, dis),
  };
  const disSig = await sendInstruction(conn, disIx, cu("disburse256"));
  ok(disSig.length > 0, `disburse256 landed 1-tx: ${disSig}`);

  // The durable audit anchor, read straight from the chain: 82 fixed bytes
  // regardless of recipient count — the count-hiding shape.
  const batch = await getAccountData(RPC, batchPda);
  ok(batch !== null && batch.length === DISBURSE_BATCH_LEN, "DisburseBatch is the 82-byte anchor");
  ok(batch !== null && batch[0] === TAG_DISBURSE_BATCH, "anchor tag");
  const anchorHash = ((): bigint => {
    const bytes = (batch as Uint8Array).slice(10, 42);
    return bytes.reduce<bigint>((acc, b) => (acc << 8n) | BigInt(b), 0n);
  })();
  ok(anchorHash === BigInt(dis.disclosureHash as string), "anchor binds the fixture disclosureHash");
  const treeAfterDis = parseTreeState((await getAccountData(RPC, TREE_ADDR)) as Uint8Array);
  ok(treeAfterDis.nextLeafIndex === 512, "tree advanced by the fixed 256-batch");

  step("enterprise withdraw: institution exit under truncate-253");
  oracle.appendLeaf(BigInt(wd.changeCommitment as string));
  const wdRoot = oracle.getRoot();
  const wdNfs = (wd.nullifiers as string[]).map(BigInt).filter((nf) => nf !== 0n);
  const stealth = new Uint8Array(33);
  stealth.set(hexBytes(wd.stealthEphemeralPub as string), 0);
  stealth[32] = wd.stealthViewTag as number;
  const wdIx: Instruction = {
    programAddress: PROGRAM_ID_BASE58 as Address,
    accounts: [
      ro(CONFIG_ADDR),
      w(TREE_ADDR),
      ro(await knownRootPda(BigInt(wd.spentRoot as string))),
      w(await knownRootPda(wdRoot)),
      ws(ADDR_E),
      ro(SYSTEM_PROGRAM_ADDRESS),
      ro(eventAuth),
      ro(PROGRAM_ID_BASE58),
      ro(TOKEN_PROGRAM_ADDRESS),
      w(VAULT_ADDR),
      ro(vaultOwner),
      w(recipientToken),
      ...(await Promise.all(wdNfs.map((nf) => nullifierPda(nf)))).map(w),
    ],
    data: wire(7, wd, stealth),
  };
  const wdSig = await sendInstruction(conn, wdIx, cu("withdraw"));
  ok(wdSig.length > 0, `enterprise withdraw landed: ${wdSig}`);
  ok(
    (await getTokenBalance(RPC, recipientToken)) === wdAmount,
    "the proof-bound recipient token account received the exit",
  );

  step("enterprise transfer + transfer10x2 complete the family");
  for (const [disc, fx, opName] of [
    [9, trf, "transfer"],
    [10, t10, "transfer10x2"],
  ] as const) {
    for (const oc of fx.outputCommitments as string[]) oracle.appendLeaf(BigInt(oc));
    const newRoot = oracle.getRoot();
    const nfs = (fx.nullifiers as string[]).map(BigInt).filter((nf) => nf !== 0n);
    const ix: Instruction = {
      programAddress: PROGRAM_ID_BASE58 as Address,
      accounts: [
        ro(CONFIG_ADDR),
        w(TREE_ADDR),
        ro(await knownRootPda(BigInt(fx.spentRoot as string))),
        w(await knownRootPda(newRoot)),
        ws(ADDR_E),
        ro(SYSTEM_PROGRAM_ADDRESS),
        ro(eventAuth),
        ro(PROGRAM_ID_BASE58),
        ...(await Promise.all(nfs.map((nf) => nullifierPda(nf)))).map(w),
      ],
      data: wire(disc, fx),
    };
    const sig = await sendInstruction(conn, ix, cu(opName));
    ok(sig.length > 0, `enterprise ${opName} landed: ${sig}`);
  }
  const finalTree = parseTreeState((await getAccountData(RPC, TREE_ADDR)) as Uint8Array);
  ok(finalTree.nextLeafIndex === 517, "the family's five ops grew the tree to leaf 517");
  ok(finalTree.root === oracle.getRoot(), "on-chain root equals the ImtTree oracle replay");

  step("disclosure: the indexer serves the blob; ANY party refolds it against the chain");
  await waitFor("indexer ingest of the family", async () => {
    const r = await fetch(`${INDEXER}/head`);
    return r.ok && ((await r.json()) as { nextLeafIndex: number }).nextLeafIndex === 517;
  });
  const served = await fetch(`${INDEXER}/disclosure/${dis.startLeafIndex}`);
  ok(served.status === 200, "GET /disclosure serves the held blob with a clean 200");
  const body = (await served.json()) as {
    elements: string[];
    disclosureHash: string;
    verdict: string;
  };
  ok(body.verdict === "verified", `indexer refold verdict (got "${body.verdict}")`);
  ok(body.elements.length === 2054, "the blob is the full 2054-element disclosure");
  // The independent refold — no trust in the server: fold the served bytes
  // with the ONE disclosureChain implementation and compare against the
  // DisburseBatch account read straight from the validator.
  const refolded = disclosureChain(body.elements.map(BigInt));
  ok(refolded === anchorHash, "served bytes refold to the chain-committed disclosureHash");
  ok(BigInt(body.disclosureHash) === anchorHash, "the served anchor echoes the chain");

  step("done");
  stop();
}

main()
  .then(() => process.exit(failureCount()))
  .catch((e) => {
    console.error("enterprise_leg fatal:", e && (e as Error).stack ? (e as Error).stack : e);
    process.exit(1);
  });
