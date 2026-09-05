// connection/writes.ts — the proof/token submits and reads that operate on a
// live Connection over viem: the ABI tables, the pool-KEM-epoch guard and the
// gas/nonce discipline (split from connection.ts).
import { parseAbi, type Abi, type Address } from "viem";
import { causeChain } from "@bongtu/core/errors";
import type { Calldata } from "@bongtu/core/proving";
import {
  POOL_ABI_FRAGMENTS,
  ERC20_ABI_FRAGMENTS,
  arbiterKemPkGuardError,
  explorerTxUrl,
  isPreKemProbeError,
} from "@bongtu/core/network";
import { liveChain } from "../chain.js";
import { ZERO_EPHEMERAL, type StealthDerivation } from "@bongtu/core/stealth";
import { KEM_CIPHERTEXT_BYTES } from "@bongtu/core/kem";
import type { SubmitResult, TokenState } from "@bongtu/client/rail";
import type { Connection } from "./edge.js";

// The result/token-state shapes are the engine's rail seam (@bongtu/client/rail)
// — re-exported here so submit callers keep importing them beside the submits.
export type { SubmitResult, TokenState } from "@bongtu/client/rail";
// The shared per-function ABI fragments (@bongtu/core/network) — only the pool
// functions the wallet touches, parsed once for viem. deposit is the 0-in/2-out
// mint (a,b,c,pub,kemCiphertext) the shield flow submits.
// transfer10x2 (10-in / 2-out, BongtuPool V5) is the one fragment not yet in the
// shared sdk table: same (a, b, c, pub, kemCiphertext) shape as transfer, with the
// arity-10x2 public vector (68 signals). Move it into POOL_ABI_FRAGMENTS once the
// sdk carries it, so the two apps cannot drift.
const TRANSFER10X2_FRAGMENT =
  "function transfer10x2(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[68] pub, bytes kemCiphertext)";

const POOL_ABI = parseAbi([
  POOL_ABI_FRAGMENTS.deposit,
  POOL_ABI_FRAGMENTS.transfer,
  TRANSFER10X2_FRAGMENT,
  POOL_ABI_FRAGMENTS.withdraw,
  POOL_ABI_FRAGMENTS.root,
  POOL_ABI_FRAGMENTS.nextLeafIndex,
  POOL_ABI_FRAGMENTS.currentEpoch,
  POOL_ABI_FRAGMENTS.arbiterKemPkHash,
]);

// The wrapped kKRW ERC-20 fragments for the deposit/shield flow: approve the pool to
// pull V, read the depositor's balance + pool allowance (view, no gas), and the
// permissionless mock-token `mint` the dev faucet uses to self-fund test kKRW.
const ERC20_ABI = parseAbi([
  ERC20_ABI_FRAGMENTS.approve,
  ERC20_ABI_FRAGMENTS.allowance,
  ERC20_ABI_FRAGMENTS.balanceOf,
  ERC20_ABI_FRAGMENTS.mint,
]);

// One successful verification per pool address is enough for the session: the
// epoch hash only changes on an arbiter key rotation, which ships as a new
// wallet bundle anyway (ARBITER_KEM_PK is a build-time deployment fact).
const kemVerified: { pool: string | null } = { pool: null };

/** viem's shape of "the getter is missing / reverted": a pre-KEM V1 pool probe.
 *  Transport failures (HttpRequestError etc.) carry none of these names and fall
 *  through — folding them in would fail the guard OPEN on an RPC hiccup. */
function isViemPreKemProbeError(e: unknown): boolean {
  return causeChain(e).some(
    (o) =>
      o.name === "ContractFunctionRevertedError" ||
      o.name === "ContractFunctionZeroDataError" ||
      o.name === "AbiDecodingZeroDataError",
  );
}

/**
 * Refuse to encapsulate to a key the chain does not vouch for (design doc
 * §4/§5): read the pool's `arbiterKemPkHash(currentEpoch())` and require it to
 * equal keccak256(ARBITER_KEM_PK). A pre-KEM V1 pool (getter reverts) is also
 * fatal — this build only produces hybrid proofs, so every op would revert
 * unlabeled at submit; failing here yields a readable error instead. The flows
 * call this BEFORE drawing KEM material / proving.
 */
export async function assertPoolKemEpoch(connection: Connection, poolAddr: string): Promise<void> {
  if (kemVerified.pool === poolAddr) return;
  const pool = { address: poolAddr as Address, abi: POOL_ABI } as const;
  const onchainHash = await (async (): Promise<string | null> => {
    try {
      const epoch = await connection.publicClient.readContract({ ...pool, functionName: "currentEpoch" });
      return String(
        await connection.publicClient.readContract({ ...pool, functionName: "arbiterKemPkHash", args: [epoch] }),
      );
    } catch (e) {
      if (!isViemPreKemProbeError(e) && !isPreKemProbeError(e)) throw e;
      return null;
    }
  })();
  const err = arbiterKemPkGuardError(onchainHash);
  if (err) {
    // The technical verdict (which key, which epoch) goes to the console for
    // diagnosis; the thrown message is what a wallet user can act on.
    console.error(err);
    throw new Error("This wallet version doesn't match the network yet. Try again in a moment.");
  }
  kemVerified.pool = poolAddr;
}

// Every pool op carries the op's raw ML-KEM-768 encapsulation ciphertext
// (`bytes kemCiphertext`, 1088 B — the hybrid envelope's PQ half, drawn fresh
// per tx in freshSpendCrypto/freshDepositCrypto). The contract length-checks it
// (WrongKemCiphertextLength) and re-emits it for the arbiter; pre-checking the
// length here turns that revert into a readable client error.
function assertKemCiphertext(kemCiphertext: string): void {
  if (!/^0x[0-9a-fA-F]+$/.test(kemCiphertext) || (kemCiphertext.length - 2) / 2 !== KEM_CIPHERTEXT_BYTES) {
    throw new Error(
      `kemCiphertext must be ${KEM_CIPHERTEXT_BYTES} bytes of 0x-hex (got ${kemCiphertext.length} chars)`,
    );
  }
}

/** The proof calldata's decimal strings as the bigints viem's ABI encoder takes.
 *  Exported: ops/consumer/submit.ts rides the same belt — one home, not three copies
 *  (the payroll copy predates this and migrates when that app is next touched). */
export function asProofArgs(calldata: Calldata) {
  return {
    a: calldata.a.map(BigInt) as [bigint, bigint],
    b: calldata.b.map((r) => r.map(BigInt)) as [[bigint, bigint], [bigint, bigint]],
    c: calldata.c.map(BigInt) as [bigint, bigint],
    pub: calldata.pub.map(BigInt),
  };
}

/** The next nonce from the CHAIN's pending view, not the wallet's tracker.
 *  MetaMask's account cache desyncs after speed-up/cancel surgery and then
 *  assigns stale nonces ("nonce too low" on submit). Every flow here awaits
 *  each tx to its receipt before the next, so the pending count is always the
 *  correct next nonce. */
/** The old fixed pin guarded against wallet-stack fee ESTIMATION (which once
 *  overpaid ~1500x); asking the node directly is not estimation, and a fixed
 *  pin goes stale the day the sequencer moves its floor. */
async function chainGasPrice(connection: Connection): Promise<bigint> {
  // 3x headroom over the node's quote: eth_gasPrice IS the current floor, and a
  // tx priced exactly at it goes pending the moment the floor drifts up a block
  // later (observed live). Still ~40% under the old fixed pin.
  return (await connection.publicClient.getGasPrice()) * 3n;
}

async function nextNonce(connection: Connection): Promise<number> {
  return connection.publicClient.getTransactionCount({
    address: connection.address as Address,
    blockTag: "pending",
  });
}

/**
 * The ONE submit discipline for every write that touches the pool or its token,
 * exported so payroll's disburse submit rides it too (apps/payroll-web/src/lib/
 * chain.ts keeps only its ABI fragment and argument belts). Three rules, each
 * bought with a live incident:
 *   - gas from `chainGasPrice` (the node's floor quote x3) — never wallet-stack
 *     estimation, which once overpaid ~1500x;
 *   - nonce from `nextNonce` (the chain's pending view) — wallet trackers desync
 *     after speed-up/cancel surgery and then assign stale nonces;
 *   - resolve only after the receipt, so callers can sequence txs safely (which
 *     is also what keeps the pending count a correct next nonce).
 * Args are validated at ABI-encode time; the per-function tuple types cannot be
 * expressed for a dynamic (abi, functionName) pair, hence unknown[] + one cast.
 */
export async function submitPoolWrite(
  connection: Connection,
  write: { address: string; abi: Abi; functionName: string; args: readonly unknown[] },
): Promise<`0x${string}`> {
  const hash = await connection.walletClient.writeContract({
    address: write.address as Address,
    abi: write.abi,
    functionName: write.functionName,
    args: write.args as never,
    account: connection.address as Address,
    // The wallet client's own chain binding when it has one, so viem's chain
    // assert checks the binding the client was built on: the apps bind wagmi
    // clients to liveChain (identical behavior), while the heavy e2e gate binds
    // its rig to the gate's anvil chain and must not trip a live-chain mismatch.
    // An unbound client still gets the liveChain pin: the pool exists on one chain.
    chain: connection.walletClient.chain ?? liveChain,
    nonce: await nextNonce(connection),
    gasPrice: await chainGasPrice(connection),
  });
  await connection.publicClient.waitForTransactionReceipt({ hash });
  return hash;
}

async function submit(
  connection: Connection,
  poolAddr: string,
  fn: "deposit" | "transfer" | "transfer10x2" | "withdraw",
  calldata: Calldata,
  kemCiphertext: string,
  explorerBase: string,
  stealth?: StealthDerivation,
): Promise<SubmitResult> {
  assertKemCiphertext(kemCiphertext);
  const { a, b, c, pub } = asProofArgs(calldata);
  // withdraw alone carries the stealth announcement pair after the KEM ct
  // (zeros = "no announcement"). Only the derivation's announcement half goes
  // to calldata: its `address` is deliberately NOT read here — the payout
  // target already rides proof-bound inside pub[26], which is what makes the
  // announced R rediscover exactly the address the proof paid.
  const args =
    fn === "withdraw"
      ? [
          a, b, c, pub, kemCiphertext,
          (stealth?.ephemeralPub ?? ZERO_EPHEMERAL) as `0x${string}`,
          stealth?.viewTag ?? 0,
        ]
      : [a, b, c, pub, kemCiphertext];
  const hash = await submitPoolWrite(connection, {
    address: poolAddr,
    abi: POOL_ABI,
    functionName: fn,
    args,
  });
  return { txHash: hash, explorerUrl: explorerTxUrl(hash, explorerBase) };
}

/** Submit a proven transfer (calldata from browser snarkjs, SPEC §7). */
export function submitTransfer(
  connection: Connection,
  poolAddr: string,
  calldata: Calldata,
  kemCiphertext: string,
  explorerBase: string,
): Promise<SubmitResult> {
  return submit(connection, poolAddr, "transfer", calldata, kemCiphertext, explorerBase);
}

/** Submit a proven transfer10x2 (BongtuPool V5): what every >2-input spend and
 *  every merge leg lands on since transfer10's deprecation (2026-07-28). */
export function submitTransfer10x2(
  connection: Connection,
  poolAddr: string,
  calldata: Calldata,
  kemCiphertext: string,
  explorerBase: string,
): Promise<SubmitResult> {
  return submit(connection, poolAddr, "transfer10x2", calldata, kemCiphertext, explorerBase);
}

/** Submit a proven withdraw. A stealth payout hands the WHOLE core derivation
 *  (@bongtu/core/stealth StealthDerivation); submit maps its (ephemeralPub,
 *  viewTag) half to the calldata announcement pair the recipient discovers the
 *  funds by. Omitted = plain withdraw, zeros on the wire. */
export function submitWithdraw(
  connection: Connection,
  poolAddr: string,
  calldata: Calldata,
  kemCiphertext: string,
  explorerBase: string,
  stealth?: StealthDerivation,
): Promise<SubmitResult> {
  return submit(connection, poolAddr, "withdraw", calldata, kemCiphertext, explorerBase, stealth);
}

/** Submit a proven deposit/shield: the 0-in/2-out mint `(a, b, c, pub, kemCiphertext)`
 *  (pub[0] == V, length 19). Permissionless — the pool has NO onlyOwner on deposit.
 *  Same submit path as transfer/withdraw (its Poseidon authority envelope rides in
 *  `pub`; the KEM ct is the separate bytes arg). */
export function submitDeposit(
  connection: Connection,
  poolAddr: string,
  calldata: Calldata,
  kemCiphertext: string,
  explorerBase: string,
): Promise<SubmitResult> {
  return submit(connection, poolAddr, "deposit", calldata, kemCiphertext, explorerBase);
}

/**
 * Approve `spender` (the pool) to pull exactly `amount` of the ERC-20 at `tokenAddr`
 * from the connected account, and wait for the tx. The deposit flow calls this ONLY
 * when the current allowance is below V (see readTokenState), so at most one approve
 * precedes the deposit. Returns the approve tx hash.
 */
export async function approveToken(
  connection: Connection,
  tokenAddr: string,
  spender: string,
  amount: bigint,
): Promise<string> {
  return submitPoolWrite(connection, {
    address: tokenAddr,
    abi: ERC20_ABI,
    functionName: "approve",
    args: [spender as Address, amount],
  });
}

/**
 * DEV FAUCET: mint `amount` raw units of the mock kKRW ERC-20 at `tokenAddr` to `to`,
 * from the connected wallet. The deployed token is MockERC20 whose `mint` is
 * permissionless (no onlyOwner/cap), so the user self-funds test kKRW and pays their
 * OWN gas — there is no backend faucet service or operator key. Rides the same
 * submitPoolWrite discipline as every other write; returns the tx hash +
 * explorer link so the Deposit screen can surface it. A production token has no mint.
 */
export async function mintTestToken(
  connection: Connection,
  tokenAddr: string,
  to: string,
  amount: bigint,
): Promise<SubmitResult> {
  const hash = await submitPoolWrite(connection, {
    address: tokenAddr,
    abi: ERC20_ABI,
    functionName: "mint",
    args: [to as Address, amount],
  });
  return { txHash: hash, explorerUrl: explorerTxUrl(hash) };
}

/**
 * Read the account's ERC-20 `balanceOf` and its `allowance` to `spender` (the pool) —
 * both view calls (no gas), returned as bigints. Drives the Home/Deposit balance +
 * allowance display and the deposit flow's skip-approve decision.
 */
export async function readTokenState(
  connection: Connection,
  tokenAddr: string,
  owner: string,
  spender: string,
): Promise<TokenState> {
  const token = { address: tokenAddr as Address, abi: ERC20_ABI } as const;
  const [balance, allowance] = await Promise.all([
    connection.publicClient.readContract({ ...token, functionName: "balanceOf", args: [owner as Address] }),
    connection.publicClient.readContract({
      ...token,
      functionName: "allowance",
      args: [owner as Address, spender as Address],
    }),
  ]);
  return { balance, allowance };
}
