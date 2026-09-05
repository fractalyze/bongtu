// The Solana consumer-client acceptance driver (SOLR §5.3's client row, run by
// e2e_client.sh): a REAL solana-test-validator + the deployed program + a
// funded SPL mint, driven end to end through the REAL client path —
//
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
// The program has no `initialize` instruction yet (README "Not yet here"), so
// the pool accounts are seeded as validator GENESIS account images — the
// mollusk harness's account-seeding posture carried to a live ledger — built
// from the layout facts in @bongtu/core/solana.
//
// Spawns (and trap-kills) its own validator + indexer; Postgres arrives via
// DATABASE_URL from the gate script. Exits nonzero on the first failed assert.

import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ed25519 } from "@noble/curves/ed25519.js";

import { ImtTree } from "@bongtu/core/imt";
import type { Calldata, ProvingRequest } from "@bongtu/core/proving";
import {
  BATCH_B_CONSUMER,
  CONFIG_OFF_BATCH_B,
  CONFIG_OFF_FLAGS,
  CONFIG_OFF_MINT,
  CONFIG_OFF_VAULT,
  POOL_CONFIG_LEN,
  PROGRAM_ID_BASE58,
  TAG_POOL_CONFIG,
  TAG_TREE_STATE,
  TREE_HEIGHT,
  TREE_OFF_CONFIG,
  TREE_OFF_FRONTIER,
  TREE_OFF_NEXT,
  TREE_OFF_ROOT,
  TREE_STATE_LEN,
  base58ToBytes,
  bytesToBase58,
} from "@bongtu/core/solana";
import type { ConsumerWalletIdentity, WalletIdentity } from "@bongtu/client/derive";
import { consumerRunDeposit, consumerRunSpendChain, selfConsumerRecipient } from "@bongtu/client/consumer";
import { EMPTY_SCAN_STATE, runSelfScan, type ScanNote, type SelfScanState } from "@bongtu/client/selfscan";
import { solanaKeyDerivation } from "@bongtu/client-solana/derive";
import { runSolanaLogin } from "@bongtu/client-solana/identity";
import {
  getGenesisHash,
  getTokenBalance,
  keypairConnection,
  rpcCall,
  type SolanaConnection,
} from "@bongtu/client-solana/connection";
import { boundWithdrawRecipient, type SolanaConsumerConfig } from "@bongtu/client-solana/consumer";
import { solanaConsumerIo } from "@bongtu/client-solana/ops";
import { solanaSelfScanIo } from "@bongtu/client-solana/selfscan";
import { TOKEN_PROGRAM_ADDRESS, associatedTokenAccount, vaultAuthorityPda } from "@bongtu/client-solana/txbuild";

import { failureCount, ok, prove, step } from "../../../deploy/live/lib/proof_toolbox.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", "..");
const SO_PATH = join(ROOT, "chains", "solana", "target", "deploy", "bongtu_pool_solana.so");

const RPC_PORT = Number(process.env.SOLANA_E2E_RPC_PORT || 8949);
const FAUCET_PORT = RPC_PORT + 1000;
const INDEXER_PORT = Number(process.env.SOLANA_E2E_INDEXER_PORT || 8651);
const RPC = `http://127.0.0.1:${RPC_PORT}`;
const INDEXER = `http://127.0.0.1:${INDEXER_PORT}`;
const EXPLORER = "http://localhost/explorer";

const V_DEPOSIT = 100_000n;
const V_TRANSFER = 40_000n;
const PAYER_TOKENS = 1_000_000n;

// --- deterministic actors ----------------------------------------------------

const sha = (label: string): Uint8Array => new Uint8Array(createHash("sha256").update(label).digest());

/** A 64-byte Solana secret key (seed || ed25519 pub) from a fixed label. */
const secretKeyOf = (label: string): Uint8Array => {
  const seed = sha(`bongtu/solana-client-gate/${label}`);
  const out = new Uint8Array(64);
  out.set(seed, 0);
  out.set(ed25519.getPublicKey(seed), 32);
  return out;
};

const addressOfSecret = (sk: Uint8Array): string => bytesToBase58(sk.slice(32));

// Non-wallet pool accounts need no private key — any 32-byte address works
// for a genesis-seeded image (PDAs are off-curve too).
const CONFIG_ADDR = bytesToBase58(sha("bongtu/solana-client-gate/config"));
const TREE_ADDR = bytesToBase58(sha("bongtu/solana-client-gate/tree"));
const VAULT_ADDR = bytesToBase58(sha("bongtu/solana-client-gate/vault"));
const MINT_ADDR = bytesToBase58(sha("bongtu/solana-client-gate/mint"));

const SK_A = secretKeyOf("wallet-a");
const SK_B = secretKeyOf("wallet-b");
const ADDR_A = addressOfSecret(SK_A);
const ADDR_B = addressOfSecret(SK_B);

// --- genesis account images (the layout facts, @bongtu/core/solana) ----------

function configImage(): Uint8Array {
  const data = new Uint8Array(POOL_CONFIG_LEN);
  data[0] = TAG_POOL_CONFIG;
  data[1] = 1;
  // consumer profile: the four P2P family flags, u16 LE.
  data[CONFIG_OFF_FLAGS] = 0x0f;
  data.set(sha("bongtu/solana-client-gate/admin"), 4); // admin: opaque to the ops
  data.set(base58ToBytes(MINT_ADDR), CONFIG_OFF_MINT);
  data.set(base58ToBytes(VAULT_ADDR), CONFIG_OFF_VAULT);
  data[CONFIG_OFF_BATCH_B] = BATCH_B_CONSUMER; // u32 LE, fits one byte
  return data;
}

function emptyTreeImage(): Uint8Array {
  const tree = new ImtTree(TREE_HEIGHT, BATCH_B_CONSUMER);
  const data = new Uint8Array(TREE_STATE_LEN);
  data[0] = TAG_TREE_STATE;
  data[1] = 1;
  data.set(base58ToBytes(CONFIG_ADDR), TREE_OFF_CONFIG);
  // nextLeafIndex u64 LE = 0 (already zero); root + frontier 32 B BE each.
  void TREE_OFF_NEXT;
  const be32 = (v: bigint): Uint8Array =>
    Uint8Array.from({ length: 32 }, (_, i) => Number((v >> BigInt(8 * (31 - i))) & 0xffn));
  data.set(be32(tree.getRoot()), TREE_OFF_ROOT);
  for (const [i, v] of tree.filledSubtrees.entries()) data.set(be32(v), TREE_OFF_FRONTIER + 32 * i);
  return data;
}

/** SPL mint image (82 B, consensus-fixed layout): no authorities, decimals 0,
 *  is_initialized = 1. */
function mintImage(): Uint8Array {
  const data = new Uint8Array(82);
  data[45] = 1;
  return data;
}

/** SPL token account image (165 B): mint, owner, amount u64 LE, Initialized. */
function tokenAccountImage(owner: string, amount: bigint): Uint8Array {
  const data = new Uint8Array(165);
  data.set(base58ToBytes(MINT_ADDR), 0);
  data.set(base58ToBytes(owner), 32);
  for (const i of Array(8).keys()) data[64 + i] = Number((amount >> BigInt(8 * i)) & 0xffn);
  data[108] = 1;
  return data;
}

function accountJson(dir: string, name: string, pubkey: string, owner: string, data: Uint8Array): string {
  const file = join(dir, `${name}.json`);
  writeFileSync(
    file,
    JSON.stringify({
      pubkey,
      account: {
        lamports: 1_000_000_000,
        data: [Buffer.from(data).toString("base64"), "base64"],
        owner,
        executable: false,
        rentEpoch: 0,
        space: data.length,
      },
    }),
  );
  return file;
}

// --- process + polling helpers ----------------------------------------------

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(what: string, probe: () => Promise<boolean>, timeoutMs = 90_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const up = await probe().catch(() => false);
    if (up) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(400);
  }
}

async function airdrop(addr: string): Promise<void> {
  await rpcCall<string>(RPC, "requestAirdrop", [addr, 10_000_000_000]);
  await waitFor(`airdrop to ${addr}`, async () => {
    const r = await rpcCall<{ value: number }>(RPC, "getBalance", [addr, { commitment: "confirmed" }]);
    return r.value > 0;
  });
}

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
  const ataA = await associatedTokenAccount(ADDR_A, MINT_ADDR);
  const ataB = await associatedTokenAccount(ADDR_B, MINT_ADDR);
  const vaultOwner = await vaultAuthorityPda(CONFIG_ADDR);

  step("validator: genesis-seed pool accounts + deploy the program");
  const accounts: [string, string, string, Uint8Array][] = [
    ["config", CONFIG_ADDR, PROGRAM_ID_BASE58, configImage()],
    ["tree", TREE_ADDR, PROGRAM_ID_BASE58, emptyTreeImage()],
    ["mint", MINT_ADDR, TOKEN_PROGRAM_ADDRESS, mintImage()],
    ["vault", VAULT_ADDR, TOKEN_PROGRAM_ADDRESS, tokenAccountImage(vaultOwner, 0n)],
    ["ata-a", ataA, TOKEN_PROGRAM_ADDRESS, tokenAccountImage(ADDR_A, PAYER_TOKENS)],
    ["ata-b", ataB, TOKEN_PROGRAM_ADDRESS, tokenAccountImage(ADDR_B, 0n)],
  ];
  const validatorArgs = [
    "--reset",
    "--quiet",
    "--ledger",
    join(scratch, "ledger"),
    "--rpc-port",
    String(RPC_PORT),
    "--faucet-port",
    String(FAUCET_PORT),
    "--bind-address",
    "127.0.0.1",
    "--bpf-program",
    PROGRAM_ID_BASE58,
    SO_PATH,
    ...accounts.flatMap(([name, pubkey, owner, data]) => [
      "--account",
      pubkey,
      accountJson(scratch, name, pubkey, owner, data),
    ]),
  ];
  const validator: ChildProcess = spawn("solana-test-validator", validatorArgs, { stdio: "ignore" });
  const children: ChildProcess[] = [validator];
  const stop = (): void => {
    for (const c of children) c.kill("SIGTERM");
  };
  process.on("exit", stop);

  await waitFor("validator rpc", async () => (await getGenesisHash(RPC)).length > 0);
  const genesisHash = await getGenesisHash(RPC);
  ok(genesisHash.length >= 32, `validator up, genesis ${genesisHash}`);
  await airdrop(ADDR_A);
  await airdrop(ADDR_B);

  step("indexer: Solana backend over the live validator");
  const indexer = spawn(
    process.execPath,
    ["--import", "tsx", join(ROOT, "apps", "indexer", "src", "index.ts")],
    {
      cwd: ROOT,
      stdio: ["ignore", "inherit", "inherit"],
      env: {
        ...process.env,
        SOLANA_RPC: RPC,
        SOLANA_TREE: TREE_ADDR,
        PORT: String(INDEXER_PORT),
        POLL_MS: "500",
      },
    },
  );
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
