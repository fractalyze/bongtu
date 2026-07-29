// LIVE GIWA payroll e2e — the pay console's production flow, end to end, through
// the REAL running services: faucet mint -> deposit -> (merge legs if the balance
// is fragmented) -> 3-recipient disburse, every proof from the resident GPU prover
// service, every result read back off the arbiter indexer.
//
// The point is FIDELITY: the driver imports the console's own modules rather than
// re-implementing the flow.
//
//   apps/payroll-web/src/lib/payRun.ts   runPayRun   — merges + terminal disburse
//   apps/payroll-web/src/lib/proverClient.ts         — the prover-service adapter
//   @bongtu/client/depositFlow           runDeposit  — approve + prove + submit
//   @bongtu/client/connection            mintTestToken (the console's dev faucet)
//   @bongtu/client/keyCache              KeyCache    — the real lock state machine
//
// What is necessarily FAKED (a node process is not a browser with MetaMask):
//
//   1. The employer's bjj identity comes from a FIXED test signature instead of a
//      live eth_signTypedData_v4 — deriveIdentityFromSignature is the same call the
//      wallet path makes on the signature it gets back, so only the signature's
//      provenance differs. The KeyCache around it is the real one (session check,
//      account check, idle wipe), wired to `derive: () => that identity`.
//   2. The EIP-1193 provider is a shim over the GIWA http RPC standing in for the
//      browser extension: it answers wallet_switchEthereumChain / eth_accounts,
//      SIGNS eth_sendTransaction with the deployer key (the app submits with an
//      address — a JSON-RPC account — exactly as it does against MetaMask), and
//      forwards every other method. ensureChain and the submits run verbatim.
//   3. globalThis.fetch is wrapped to add `Origin: <PROVER_ORIGIN>` on prover-service
//      requests only. The service has PROVER_ALLOWED_ORIGINS set and a browser
//      supplies that header automatically; node does not. Wrapping the transport
//      lets proveViaService be imported unmodified.
//
// Recipient identities are drawn FRESH per run (not fixed scalars): with fixed keys
// a rerun's /notes evidence would be indistinguishable from the previous attempt's
// notes. The employer identity is fixed on purpose — reruns accumulate notes for it,
// which is exactly what exercises the merge legs.
//
//   Run:  npx tsx deploy/giwa_payroll_e2e.ts
//   Env:  DEPLOYER_KEY (required, from .env), GIWA_RPC, INDEXER_URL (default
//         http://localhost:8600), PROVER_URL (default http://127.0.0.1:8700),
//         PROVER_ORIGIN (default http://localhost:5173).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createPublicClient, createWalletClient, custom, decodeEventLog, http, parseAbi, type Address, type PublicClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { B, EXPLORER_BASE, RPC_URL, explorerTxUrl } from "@bongtu/core/network";
import { deriveKeypair } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import { giwaSepolia } from "@bongtu/client/chain";
import type { Connection } from "@bongtu/client/connection";
import { mintTestToken, readTokenState } from "@bongtu/client/connection";
import { deriveIdentityFromSignature } from "@bongtu/client/derive";
import { runDeposit, type DepositStage } from "@bongtu/client/depositFlow";
import { KeyCache } from "@bongtu/client/keyCache";
import { sumUnspent } from "@bongtu/client/balance";
import { buildNotesUrl, fetchNotes, type OwnerNote } from "@bongtu/client/indexerClient";
import type { LegProgress, SpendStage } from "@bongtu/client/spendFlow";
import type { Calldata, ProvingRequest } from "@bongtu/core/proving";

import { proveViaService } from "../apps/payroll-web/src/lib/proverClient.js";
import { runPayRun } from "../apps/payroll-web/src/lib/payRun.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ADDR = JSON.parse(readFileSync(join(HERE, "addresses.91342.json"), "utf8"));

const IDX = (process.env.INDEXER_URL || "http://localhost:8600").replace(/\/$/, "");
const PROVER = (process.env.PROVER_URL || "http://127.0.0.1:8700").replace(/\/$/, "");
const PROVER_ORIGIN = process.env.PROVER_ORIGIN || "http://localhost:5173";

// The employer's stand-in signature (deterministic; a real console derives from the
// wallet's eth_signTypedData_v4 over the same KDF struct).
const SIG_EMPLOYER = "0x" + "e1".repeat(32) + "f2".repeat(32) + "1c";

const KKRW = 10n ** 18n;
const DEPOSIT_AMOUNT = 90n * KKRW;
// Deliberately more than one deposit note holds: the balance is then FRAGMENTED,
// so the run goes through runMergeChain's transfer10x2 leg(s) before the disburse
// — the console's full chain, not just its terminal transaction.
const PAYOUTS = [40n * KKRW, 50n * KKRW, 60n * KKRW];
const PAYOUT_TOTAL = PAYOUTS.reduce((a, b) => a + b, 0n);

const POLL_MS = 3000;
const POLL_TRIES = 40;

// --- assertion ledger (local: this driver proves nothing on CPU, so it must not
// pull deploy/lib/proof_toolbox.ts and its snarkjs load) -------------------------

let failures = 0;
const step = (title: string): void => console.log(`\n=== ${title} ===`);
function ok(cond: unknown, msg: string): void {
  const pass = !!cond;
  if (!pass) failures++;
  console.log(`   ${pass ? "PASS" : "FAIL"}  ${msg}`);
  if (!pass) throw new Error(`assertion failed: ${msg}`);
}
const kkrw = (v: bigint | string): string => `${(BigInt(v) / KKRW).toString()} kKRW`;

// --- the Origin shim: prover-service requests only ------------------------------

const realFetch = globalThis.fetch;
globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  if (!url.startsWith(PROVER)) return realFetch(input, init);
  const headers = new Headers(init?.headers);
  headers.set("Origin", PROVER_ORIGIN);
  return realFetch(input, { ...init, headers });
}) as typeof fetch;

// (proveViaService reads the global `fetch` binding at call time, so the shim above
// applies even though these are hoisted static imports.)

// --- the pool surface this driver reads directly (leaf accounting + the batch's
// start index, which only the SubtreeAppended event carries) ---------------------

const POOL_ABI = parseAbi([
  "function nextLeafIndex() view returns (uint256)",
  "function root() view returns (uint256)",
  "event Appended(uint256 indexed leafIndex, uint256 leaf, uint256 root)",
  "event SubtreeAppended(uint256 indexed startLeafIndex, uint256 subtreeRoot, uint256 root)",
]);

/** The leaf movement a receipt actually caused, read off the pool's own events —
 *  the honest source, because a `nextLeafIndex()` read right after a receipt can
 *  still be served by a GIWA RPC node that is a block behind. */
function leafEvents(logs: { address: string; data: `0x${string}`; topics: string[] }[], pool: string) {
  const single: number[] = [];
  let batchStart: number | null = null;
  for (const l of logs) {
    if (l.address.toLowerCase() !== pool.toLowerCase()) continue;
    let ev;
    try {
      ev = decodeEventLog({ abi: POOL_ABI, data: l.data, topics: l.topics as [] });
    } catch {
      continue;
    }
    if (ev.eventName === "Appended") single.push(Number((ev.args as { leafIndex: bigint }).leafIndex));
    if (ev.eventName === "SubtreeAppended") batchStart = Number((ev.args as { startLeafIndex: bigint }).startLeafIndex);
  }
  return { single: single.sort((a, b) => a - b), batchStart };
}

/** Where a disburse's B-leaf block lands given the tree's current fill: a partial
 *  block is closed to the next B boundary first (_attachSubtree), so the batch
 *  starts one full block past the current block start whenever nextLeafIndex is
 *  not already aligned. */
function expectedBatchStart(before: number): number {
  const rem = before % B;
  return rem === 0 ? before : before - rem + B;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Poll `read` until `done`, at the driver's fixed interval. Answers the last
 *  value read so the caller can assert on it (and print what it actually saw). */
async function pollUntil<T>(read: () => Promise<T>, done: (v: T) => boolean): Promise<T> {
  let last = await read();
  for (let i = 0; i < POLL_TRIES && !done(last); i++) {
    await sleep(POLL_MS);
    last = await read();
  }
  return last;
}

async function main(): Promise<void> {
  const rpc = process.env.GIWA_RPC || RPC_URL;
  const key = process.env.DEPLOYER_KEY;
  if (!key) throw new Error("DEPLOYER_KEY required (set -a; source .env; set +a)");

  const account = privateKeyToAccount(("0x" + key.replace(/^0x/, "")) as `0x${string}`);
  const publicClient: PublicClient = createPublicClient({ chain: giwaSepolia, transport: http(rpc) });
  // The local signer behind the shim — the app's submits arrive as
  // eth_sendTransaction (connection.ts passes an ADDRESS, i.e. a JSON-RPC account,
  // which is what a browser wallet is), so the shim must sign them itself.
  const signer = createWalletClient({ account, chain: giwaSepolia, transport: http(rpc) });
  // The EIP-1193 shim (see header note 2).
  const provider = {
    request: async (args: { method: string; params?: unknown[] }): Promise<unknown> => {
      if (args.method === "wallet_switchEthereumChain" || args.method === "wallet_addEthereumChain") return null;
      if (args.method === "eth_accounts" || args.method === "eth_requestAccounts") return [account.address];
      if (args.method === "eth_sendTransaction") {
        const p = (args.params as Record<string, string>[])[0];
        return signer.sendTransaction({
          to: p.to as Address,
          data: p.data as `0x${string}`,
          ...(p.value ? { value: BigInt(p.value) } : {}),
          ...(p.gas ? { gas: BigInt(p.gas) } : {}),
          // The app pins its own gasPrice (GAS_PRICE); never let it be estimated.
          ...(p.gasPrice ? { gasPrice: BigInt(p.gasPrice) } : {}),
        });
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return publicClient.request(args as any);
    },
  };
  const connection: Connection = {
    address: account.address,
    walletClient: createWalletClient({ account, chain: giwaSepolia, transport: custom(provider) }),
    publicClient,
    injected: provider,
    transport: "injected",
  };

  const employer = deriveIdentityFromSignature(SIG_EMPLOYER);
  const sessionPubkey = employer.compressedPubkey;
  // The real lock, wired to the fixed-signature derivation (header note 1).
  const keyCache = new KeyCache({
    derive: async () => employer,
    currentAccount: async () => account.address.toLowerCase(),
  });

  // What the console injects as its ONE prover, plus a tap that remembers the
  // terminal disburse's witness — the private input value is the only honest
  // source for the expected change note (it never appears in the public signals).
  const seenDisburse: { inputValue: bigint; outputValues: bigint[] }[] = [];
  const prove = async (request: ProvingRequest): Promise<Calldata> => {
    if (request.circuit === "disburse") {
      const inp = request.input as unknown as { inputValues: string[]; outputValues: string[] };
      seenDisburse.push({
        inputValue: BigInt(inp.inputValues[0]),
        outputValues: inp.outputValues.map(BigInt),
      });
    }
    const t0 = Date.now();
    const cd = await proveViaService(PROVER, request);
    console.log(`   proved ${request.circuit} on the service in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
    return cd;
  };

  const pool = { address: ADDR.pool as Address, abi: POOL_ABI } as const;
  const nextLeaf = async (): Promise<number> =>
    Number(await publicClient.readContract({ ...pool, functionName: "nextLeafIndex" }));
  const notesOf = (owner: { compressedPubkey: string; formattedPrivateKey: bigint | string }): Promise<OwnerNote[]> =>
    fetchNotes(buildNotesUrl(IDX, owner.compressedPubkey, owner.formattedPrivateKey));
  const employerNotes = (): Promise<OwnerNote[]> =>
    notesOf({ compressedPubkey: sessionPubkey, formattedPrivateKey: employer.keypair.formattedPrivateKey });

  step("SETUP — live services, live pool");
  const ready = (await (await realFetch(`${PROVER}/ready`)).json()) as { status: string; circuits: string[] };
  ok(ready.status === "ready", `prover service READY: ${ready.circuits.join(", ")}`);
  const head0 = (await (await realFetch(`${IDX}/head`)).json()) as { root: string; nextLeafIndex: number };
  const chainRoot = (await publicClient.readContract({ ...pool, functionName: "root" })).toString();
  ok(head0.root === chainRoot, `arbiter indexer is at the chain head (root matches, nextLeafIndex ${head0.nextLeafIndex})`);
  console.log(`   employer ${sessionPubkey.slice(0, 14)}…  operator EOA ${account.address}  pool ${ADDR.pool}`);

  // ---- FAUCET + DEPOSIT --------------------------------------------------------

  step("DEPOSIT — faucet mint, then the console's deposit flow (prover service)");
  const notes0 = await employerNotes();
  const balance0 = sumUnspent(notes0);
  console.log(`   employer starts with ${notes0.filter((n) => !n.spent).length} unspent note(s), ${kkrw(balance0)}`);

  const before = await readTokenState(connection, ADDR.token, account.address, ADDR.pool);
  if (before.balance < DEPOSIT_AMOUNT) {
    const mint = await mintTestToken(connection, ADDR.token, account.address, DEPOSIT_AMOUNT);
    ok(true, `faucet mint ${kkrw(DEPOSIT_AMOUNT)} (permissionless MockERC20.mint): ${mint.txHash}`);
  } else {
    ok(true, `faucet skipped — operator already holds ${kkrw(before.balance)} public kKRW`);
  }

  const leafBeforeDeposit = await nextLeaf();
  const depositResult = await runDeposit(
    { connection, pool: ADDR.pool, token: ADDR.token, explorer: EXPLORER_BASE, sessionPubkey },
    { amount: DEPOSIT_AMOUNT.toString() },
    (stage: DepositStage) => console.log(`   [deposit] ${stage}`),
    { keyCache, prove },
  );
  const depositRcpt = await publicClient.getTransactionReceipt({ hash: depositResult.txHash as `0x${string}` });
  ok(depositRcpt.status === "success", `deposit mined: ${depositResult.txHash}`);
  console.log(`   gasUsed ${depositRcpt.gasUsed.toString()}  approve tx sent: ${depositResult.approved}  ${explorerTxUrl(depositResult.txHash)}`);

  const depositLeaves = leafEvents(depositRcpt.logs as never, ADDR.pool);
  ok(
    depositLeaves.single.length === 2 && depositLeaves.single[1] === depositLeaves.single[0] + 1,
    `deposit appended exactly 2 leaves at ${depositLeaves.single.join(", ")} (note(V) + note(0)), from nextLeafIndex ${leafBeforeDeposit}`,
  );
  const leafAfterDeposit = depositLeaves.single[1] + 1;
  const leafRead = await pollUntil(nextLeaf, (v) => v >= leafAfterDeposit);
  ok(leafRead === leafAfterDeposit, `pool nextLeafIndex is now ${leafRead}`);

  step("INGEST — the arbiter indexer surfaces the deposited note");
  const afterDeposit = await pollUntil(employerNotes, (ns) => sumUnspent(ns) >= balance0 + DEPOSIT_AMOUNT);
  const balance1 = sumUnspent(afterDeposit);
  ok(
    balance1 === balance0 + DEPOSIT_AMOUNT,
    `employer balance ${kkrw(balance0)} -> ${kkrw(balance1)} (+${kkrw(DEPOSIT_AMOUNT)}) on signed /notes`,
  );
  const headAfterDeposit = await pollUntil(
    async () => (await (await realFetch(`${IDX}/head`)).json()) as { root: string; nextLeafIndex: number },
    (h) => h.nextLeafIndex >= leafAfterDeposit,
  );
  ok(headAfterDeposit.nextLeafIndex >= leafAfterDeposit, `indexer /head caught up (${headAfterDeposit.nextLeafIndex} >= ${leafAfterDeposit})`);

  // ---- THE PAY RUN -------------------------------------------------------------

  step("PAY RUN — runPayRun: merges (if fragmented) + the 3-recipient disburse");
  // Fresh recipients per run (header note): a rerun must not read a previous
  // attempt's note as this run's evidence.
  const recipientKeys = PAYOUTS.map(() => {
    const scalar = BigInt("0x" + Buffer.from(crypto.getRandomValues(new Uint8Array(24))).toString("hex"));
    return deriveKeypair(scalar);
  });
  const recipients = recipientKeys.map((kp, i) => ({ pubkey: packPubkey(kp.publicKey), amount: PAYOUTS[i].toString() }));
  recipients.forEach((r, i) => console.log(`   recipient ${i + 1}: ${r.pubkey.slice(0, 14)}…  ${kkrw(r.amount)}`));
  ok(balance1 >= PAYOUT_TOTAL, `balance ${kkrw(balance1)} covers the sheet total ${kkrw(PAYOUT_TOTAL)}`);

  const freshNotes = await employerNotes();
  const payResult = await runPayRun(
    {
      connection,
      indexerUrl: IDX,
      pool: ADDR.pool,
      explorer: EXPLORER_BASE,
      notes: freshNotes,
      sessionPubkey,
      reloadNotes: employerNotes,
    },
    recipients,
    (stage: SpendStage, leg: LegProgress) => console.log(`   [pay ${leg.index + 1}/${leg.count}] ${stage}`),
    { prove, keyCache },
  );

  const payRcpt = await publicClient.getTransactionReceipt({ hash: payResult.txHash as `0x${string}` });
  ok(payRcpt.status === "success", `disburse mined: ${payResult.txHash}`);
  console.log(`   gasUsed ${payRcpt.gasUsed.toString()}  merges before it: ${payResult.mergeTxs.length}  ${payResult.explorerUrl}`);

  step("LEAVES — merges append 2 each, the disburse attaches one B-block");
  // Where the tree stood when the disburse ran: after the deposit, plus whatever
  // the merge legs appended (2 leaves per transfer10x2).
  let leafBeforeAttach = leafAfterDeposit;
  for (const [i, m] of payResult.mergeTxs.entries()) {
    const r = await publicClient.getTransactionReceipt({ hash: m.txHash as `0x${string}` });
    const ml = leafEvents(r.logs as never, ADDR.pool);
    ok(
      ml.single.length === 2,
      `merge ${i + 1} appended 2 leaves at ${ml.single.join(", ")}: ${m.txHash} (gasUsed ${r.gasUsed})`,
    );
    leafBeforeAttach = ml.single[1] + 1;
  }

  const payLeaves = leafEvents(payRcpt.logs as never, ADDR.pool);
  ok(payLeaves.batchStart !== null, "disburse emitted SubtreeAppended (the batch attach)");
  const batchStart = payLeaves.batchStart!;
  ok(
    batchStart === expectedBatchStart(leafBeforeAttach),
    `batch starts at ${batchStart} — the B-aligned block after leaf ${leafBeforeAttach}`,
  );
  const leafAfterPay = await pollUntil(nextLeaf, (v) => v >= batchStart + B);
  ok(
    leafAfterPay === batchStart + B,
    `attach advanced nextLeafIndex to ${leafAfterPay} = batchStart ${batchStart} + B ${B} (one ${B}-leaf block, ${payResult.recipientCount} of them real)`,
  );

  step("EVIDENCE — every recipient's note on the arbiter indexer");
  const proven = seenDisburse[seenDisburse.length - 1];
  ok(proven !== undefined, "the terminal leg proved a disburse witness through the service");
  const expectedChange = proven.inputValue - PAYOUT_TOTAL;
  ok(
    proven.outputValues.reduce((a, b) => a + b, 0n) === proven.inputValue,
    `the proven witness conserves value: sum(${B} outputs) == input note ${kkrw(proven.inputValue)}`,
  );

  let seen = 0n;
  for (const [i, kp] of recipientKeys.entries()) {
    const want = PAYOUTS[i];
    const ns = await pollUntil(
      () => notesOf({ compressedPubkey: packPubkey(kp.publicKey), formattedPrivateKey: kp.formattedPrivateKey }),
      (list) => list.some((n) => !n.spent && BigInt(n.value) === want),
    );
    const hit = ns.find((n) => !n.spent && BigInt(n.value) === want);
    ok(
      hit !== undefined && hit.leafIndex >= batchStart && hit.leafIndex < batchStart + B,
      `recipient ${i + 1} holds ${kkrw(want)} unspent at leaf ${hit?.leafIndex} (inside the batch block)`,
    );
    seen += BigInt(hit!.value);
  }
  ok(seen === PAYOUT_TOTAL, `the three recipients hold exactly the sheet total ${kkrw(PAYOUT_TOTAL)}`);

  const finalNotes = await pollUntil(employerNotes, (ns) =>
    ns.some((n) => !n.spent && BigInt(n.value) === expectedChange && n.leafIndex >= batchStart),
  );
  const change = finalNotes.find((n) => !n.spent && BigInt(n.value) === expectedChange && n.leafIndex >= batchStart);
  ok(
    change !== undefined,
    `employer's change note ${kkrw(expectedChange)} landed at leaf ${change?.leafIndex} (funding ${kkrw(proven.inputValue)} - paid ${kkrw(PAYOUT_TOTAL)})`,
  );
  const balance2 = sumUnspent(finalNotes);
  ok(
    balance2 === balance1 - PAYOUT_TOTAL,
    `value conserved end to end: employer ${kkrw(balance1)} -> ${kkrw(balance2)}, exactly ${kkrw(PAYOUT_TOTAL)} moved to the three recipients`,
  );

  // The lock arms a 10-minute idle-wipe timer on every use; dropping the key (what
  // logging out does) disarms it, so the process can exit when the run is done.
  keyCache.lock();
  if (failures > 0) {
    console.error(`\nPAYROLL LIVE E2E: ${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log(
    `\nPAYROLL LIVE E2E: PASS — deposit ${kkrw(DEPOSIT_AMOUNT)} + ${payResult.mergeTxs.length} merge leg(s) + 3-recipient disburse ` +
      `(tx ${payResult.txHash}, gas ${payRcpt.gasUsed}) through the console's own code, GPU-proved on the service, verified on the arbiter indexer`,
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
