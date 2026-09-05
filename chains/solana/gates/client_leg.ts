// The Solana consumer-client acceptance driver (SOLR §5.3's client row, run
// by e2e_s.sh): a REAL solana-test-validator + the deployed program + a
// funded SPL mint, driven end to end through the REAL client path —
//
//   INITIALIZE runSolanaLogin's payer sends the real `initialize`
//              instruction (consumer profile: P2P flags, B=16, no arbiter
//              key) — the pool's config/tree PDAs are program-created, not
//              genesis images (the S6 deploy-profile migration);
//   LOGIN      runSolanaLogin over a keypair wallet: the OPEN-2 payload is
//              signed, the stricter first-derivation double-sign fires, the
//              binding makes the second login single-signature;
//   DEPOSIT    consumerRunDeposit -> CPU snarkjs proof -> the client-built
//              depositPriv transaction (v1 header-config budget, PDA metas,
//              pre-send v1 size assertion) accepted on-SVM;
//   SELF-SCAN  the UNCHANGED engine (runSelfScan) discovers the balance from
//              the indexer Solana backend's PUBLIC feed with only the
//              wallet's keys;
//   TRANSFER   consumerRunSpendChain pays a second wallet's consumer triple;
//              the recipient self-scans the note in;
//   WITHDRAW   the recipient exits to its token account under the
//              truncate-253 proof-bound recipient; SPL balances assert.
//
// Genesis images remain only for what a real deployment also creates outside
// the program: the SPL mint, the user token accounts, and the vault (the
// token account owned by the vault-authority PDA — spl-token CLI territory,
// deploy/solana runbook).
//
// Spawns (and trap-kills) its own validator + indexer; Postgres arrives via
// DATABASE_URL from the gate script. Exits nonzero on the first failed assert.

import type { ChildProcess } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { BATCH_B_CONSUMER, PROGRAM_ID_BASE58, bytesToBase58 } from "@bongtu/core/solana";
import type { Calldata, ProvingRequest } from "@bongtu/core/proving";
import type { ConsumerWalletIdentity, WalletIdentity } from "@bongtu/client/derive";
import { consumerRunDeposit, consumerRunSpendChain, selfConsumerRecipient } from "@bongtu/client/consumer";
import { EMPTY_SCAN_STATE, runSelfScan, type ScanNote } from "@bongtu/client/selfscan";
import { solanaKeyDerivation } from "@bongtu/client-solana/derive";
import { runSolanaLogin } from "@bongtu/client-solana/identity";
import {
  getAccountData,
  getGenesisHash,
  getTokenBalance,
  keypairConnection,
  type SolanaConnection,
} from "@bongtu/client-solana/connection";
import { boundWithdrawRecipient, type SolanaConsumerConfig } from "@bongtu/client-solana/consumer";
import { solanaConsumerIo } from "@bongtu/client-solana/ops";
import { solanaSelfScanIo } from "@bongtu/client-solana/selfscan";
import {
  TOKEN_PROGRAM_ADDRESS,
  associatedTokenAccount,
  configPda,
  initializeInstruction,
  parseTreeState,
  treePda,
  vaultAuthorityPda,
} from "@bongtu/client-solana/txbuild";

import { failureCount, ok, prove, step } from "../../../deploy/live/lib/proof_toolbox.js";
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

const RPC_PORT = Number(process.env.SOLANA_E2E_RPC_PORT || 8949);
const INDEXER_PORT = Number(process.env.SOLANA_E2E_INDEXER_PORT || 8651);
const RPC = `http://127.0.0.1:${RPC_PORT}`;
const INDEXER = `http://127.0.0.1:${INDEXER_PORT}`;
const EXPLORER = "http://localhost/explorer";

const V_DEPOSIT = 100_000n;
const V_TRANSFER = 40_000n;
const PAYER_TOKENS = 1_000_000n;

// --- deterministic actors ----------------------------------------------------

// Non-wallet accounts a deployment also creates outside the program — any
// 32-byte address works for a genesis-seeded image.
const MINT_ADDR = bytesToBase58(sha("bongtu/solana-client-gate/mint"));
const VAULT_ADDR = bytesToBase58(sha("bongtu/solana-client-gate/vault"));

const SK_A = secretKeyOf("bongtu/solana-client-gate/wallet-a");
const SK_B = secretKeyOf("bongtu/solana-client-gate/wallet-b");
const ADDR_A = addressOfSecret(SK_A);
const ADDR_B = addressOfSecret(SK_B);

/** The engine's prove seam over the repo's CPU snarkjs toolbox (the same
 *  circuits/out artifacts every other gate proves against). */
async function proveCalldata(request: ProvingRequest): Promise<Calldata> {
  const { a, b, c, pub } = await prove(request.circuit, request.input, { verbose: true });
  return { a, b, c, pub } as Calldata;
}

/** A trivial always-unlocked lock over one identity (the engine's KeyCacheLike
 *  seam; the browser lock's custody rules are out of scope for a gate). */
const lockOf = (identity: ConsumerWalletIdentity) => ({
  isUnlocked: (): boolean => true,
  unlock: async (): Promise<WalletIdentity> => identity,
});

const balanceOf = (notes: ScanNote[]): bigint =>
  notes.filter((n) => !n.spent).reduce((acc, n) => acc + BigInt(n.value), 0n);

// --- the leg -----------------------------------------------------------------

async function main(): Promise<void> {
  const scratch = mkdtempSync(join(tmpdir(), "bongtu-solana-client-"));
  const CONFIG_ADDR = await configPda(MINT_ADDR);
  const TREE_ADDR = await treePda(CONFIG_ADDR);
  const vaultOwner = await vaultAuthorityPda(CONFIG_ADDR);
  const ataA = await associatedTokenAccount(ADDR_A, MINT_ADDR);
  const ataB = await associatedTokenAccount(ADDR_B, MINT_ADDR);

  step("validator: deploy the program + genesis-seed the out-of-program accounts");
  const validator: ChildProcess = spawnValidator({
    scratch,
    rpcPort: RPC_PORT,
    soPath: SO_PATH,
    programId: PROGRAM_ID_BASE58,
    accounts: [
      ["mint", MINT_ADDR, TOKEN_PROGRAM_ADDRESS, mintImage()],
      ["vault", VAULT_ADDR, TOKEN_PROGRAM_ADDRESS, tokenAccountImage(MINT_ADDR, vaultOwner, 0n)],
      ["ata-a", ataA, TOKEN_PROGRAM_ADDRESS, tokenAccountImage(MINT_ADDR, ADDR_A, PAYER_TOKENS)],
      ["ata-b", ataB, TOKEN_PROGRAM_ADDRESS, tokenAccountImage(MINT_ADDR, ADDR_B, 0n)],
    ],
  });
  const children: ChildProcess[] = [validator];
  const stop = (): void => {
    for (const c of children) c.kill("SIGTERM");
  };
  process.on("exit", stop);

  await waitFor("validator rpc", async () => (await getGenesisHash(RPC)).length > 0);
  const genesisHash = await getGenesisHash(RPC);
  ok(genesisHash.length >= 32, `validator up, genesis ${genesisHash}`);
  await airdrop(RPC, ADDR_A);
  await airdrop(RPC, ADDR_B);

  step("initialize: the consumer profile through the real instruction");
  const initConn = await keypairConnection(RPC, SK_A);
  const initIx = await initializeInstruction({
    mint: MINT_ADDR,
    vault: VAULT_ADDR,
    payer: ADDR_A,
    profile: { familyFlags: 0x000f, batchB: BATCH_B_CONSUMER },
  });
  const initSig = await sendInstruction(initConn, initIx, 150_000);
  ok(initSig.length > 0, `initialize landed: ${initSig}`);
  const configData = await getAccountData(RPC, CONFIG_ADDR);
  ok(configData !== null && configData.length === 200, "config PDA created at the derived address");
  ok(
    configData !== null && configData[2] === 0x0f && configData[3] === 0x00,
    "config records the consumer P2P family flags",
  );
  const treeData = await getAccountData(RPC, TREE_ADDR);
  ok(treeData !== null, "tree PDA created at the derived address");
  const head0 = parseTreeState(treeData as Uint8Array);
  ok(head0.nextLeafIndex === 0, "initialized tree starts empty");

  await waitForFinalized(RPC, CONFIG_ADDR);
  await waitForFinalized(RPC, TREE_ADDR);

  step("indexer: Solana backend over the live validator");
  const indexer = spawnIndexer(ROOT, {
    SOLANA_RPC: RPC,
    SOLANA_TREE: TREE_ADDR,
    PORT: String(INDEXER_PORT),
    POLL_MS: "500",
  });
  children.push(indexer);
  const feed = solanaSelfScanIo(INDEXER);
  await waitFor("indexer /head", async () => (await feed.head()).nextLeafIndex === 0);

  step("login: OPEN-2 derivation + the stricter double-sign guard, live");
  const kdf = solanaKeyDerivation(genesisHash);
  const bindings = new Map<string, string>();
  const signCounts = { a: 0 };
  const openA = async (): Promise<SolanaConnection> => {
    const conn = await keypairConnection(RPC, SK_A);
    const sign = conn.signMessage;
    return {
      ...conn,
      signMessage: (bytes) => {
        signCounts.a += 1;
        return sign(bytes);
      },
    };
  };
  const loginDeps = {
    kdf,
    loadKeyBinding: (a: string) => bindings.get(a) ?? null,
    saveKeyBinding: (a: string, k: string) => void bindings.set(a, k),
    saveSession: () => {},
  };
  const loginA1 = await runSolanaLogin({ indexerUrl: INDEXER }, { ...loginDeps, openConnection: openA });
  ok(signCounts.a === 2, "first (unbound) login paid the determinism double signature");
  const loginA2 = await runSolanaLogin({ indexerUrl: INDEXER }, { ...loginDeps, openConnection: openA });
  ok(signCounts.a === 3, "second login was one signature against the stored binding");
  ok(
    loginA1.identity.compressedPubkey === loginA2.identity.compressedPubkey,
    "the same account re-derives the same key",
  );
  const idA = loginA1.identity as ConsumerWalletIdentity;
  const connA = loginA1.connection;
  const loginB = await runSolanaLogin(
    { indexerUrl: INDEXER },
    { ...loginDeps, openConnection: () => keypairConnection(RPC, SK_B) },
  );
  const idB = loginB.identity as ConsumerWalletIdentity;
  const connB = loginB.connection;

  const ioCfg: SolanaConsumerConfig = {
    genesisHash,
    accounts: { config: CONFIG_ADDR, tree: TREE_ADDR, mint: MINT_ADDR, vault: VAULT_ADDR },
  };

  step(`deposit: consumerRunDeposit mints ${V_DEPOSIT} through the real builders`);
  const depositOutcome = await consumerRunDeposit(
    {
      connection: connA,
      pool: CONFIG_ADDR,
      token: MINT_ADDR,
      explorer: EXPLORER,
      sessionPubkey: idA.compressedPubkey,
    },
    { amount: V_DEPOSIT.toString() },
    (stage) => console.log(`   deposit stage: ${stage}`),
    { keyCache: lockOf(idA), prove: proveCalldata, ...solanaConsumerIo(ioCfg) },
  );
  ok(depositOutcome.txHash.length > 0, `depositPriv landed: ${depositOutcome.txHash}`);
  ok(depositOutcome.approved === false, "no approve leg exists on this rail (signature authority)");
  ok((await getTokenBalance(RPC, ataA)) === PAYER_TOKENS - V_DEPOSIT, "payer token account debited");
  ok((await getTokenBalance(RPC, VAULT_ADDR)) === V_DEPOSIT, "vault escrowed the deposit");

  step("self-scan: the unchanged engine discovers the balance from the public feed");
  await waitFor("indexer ingest of the deposit", async () => (await feed.head()).nextLeafIndex === 2);
  const scanA = { state: await runSelfScan(feed, idA, EMPTY_SCAN_STATE) };
  ok(balanceOf(scanA.state.notes) === V_DEPOSIT, `wallet A self-scanned balance ${V_DEPOSIT}`);
  const rescanA = async (): Promise<ScanNote[]> => {
    scanA.state = await runSelfScan(feed, idA, scanA.state);
    return scanA.state.notes;
  };

  step(`transfer: consumerRunSpendChain pays wallet B ${V_TRANSFER}`);
  const transferOutcome = await consumerRunSpendChain(
    "transfer",
    {
      connection: connA,
      indexerUrl: INDEXER,
      explorer: EXPLORER,
      notes: scanA.state.notes,
      sessionPubkey: idA.compressedPubkey,
      reloadNotes: rescanA,
    },
    { to: selfConsumerRecipient(idB), amount: V_TRANSFER.toString() },
    (stage, leg) => console.log(`   transfer stage: ${stage} (leg ${leg.index + 1}/${leg.count})`),
    {
      keyCache: lockOf(idA),
      prove: proveCalldata,
      poll: { intervalMs: 500, capMs: 60_000 },
      ...solanaConsumerIo(ioCfg),
    },
  );
  ok(transferOutcome.txHash.length > 0, `transferPriv landed: ${transferOutcome.txHash}`);

  await waitFor("indexer ingest of the transfer", async () => (await feed.head()).nextLeafIndex === 4);
  const scanB = { state: await runSelfScan(feed, idB, EMPTY_SCAN_STATE) };
  ok(balanceOf(scanB.state.notes) === V_TRANSFER, `wallet B self-scanned the ${V_TRANSFER} note in`);
  const postTransferA = await rescanA();
  ok(balanceOf(postTransferA) === V_DEPOSIT - V_TRANSFER, "wallet A holds the change");
  const rescanB = async (): Promise<ScanNote[]> => {
    scanB.state = await runSelfScan(feed, idB, scanB.state);
    return scanB.state.notes;
  };

  step(`withdraw: wallet B exits ${V_TRANSFER} to its token account (truncate-253 bound)`);
  const withdrawOutcome = await consumerRunSpendChain(
    "withdraw",
    {
      connection: connB,
      indexerUrl: INDEXER,
      explorer: EXPLORER,
      notes: scanB.state.notes,
      sessionPubkey: idB.compressedPubkey,
      reloadNotes: rescanB,
    },
    { amount: V_TRANSFER.toString(), withdrawTo: boundWithdrawRecipient(ataB) },
    (stage, leg) => console.log(`   withdraw stage: ${stage} (leg ${leg.index + 1}/${leg.count})`),
    {
      keyCache: lockOf(idB),
      prove: proveCalldata,
      poll: { intervalMs: 500, capMs: 60_000 },
      ...solanaConsumerIo({ ...ioCfg, withdrawTokenAccount: ataB }),
    },
  );
  ok(withdrawOutcome.txHash.length > 0, `withdrawPriv landed: ${withdrawOutcome.txHash}`);
  ok((await getTokenBalance(RPC, ataB)) === V_TRANSFER, "wallet B's token account received the payout");
  ok((await getTokenBalance(RPC, VAULT_ADDR)) === V_DEPOSIT - V_TRANSFER, "vault holds the remainder");

  await waitFor("indexer ingest of the withdraw", async () => (await feed.head()).nextLeafIndex === 5);
  const finalB = await rescanB();
  ok(balanceOf(finalB) === 0n, "wallet B's shielded balance is spent after the exit");

  step("done");
  stop();
}

main()
  .then(() => process.exit(failureCount()))
  .catch((e) => {
    console.error("client_leg fatal:", e && (e as Error).stack ? (e as Error).stack : e);
    process.exit(1);
  });
