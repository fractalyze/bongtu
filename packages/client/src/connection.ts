// The home of `Connection` — the one shape every other module works against
// (SPEC §6/§7) — and everything that operates ON a live one over viem: the
// deterministic eth_signTypedData_v4 signature the KDF consumes (derive.ts),
// the chain guard, the pool-KEM-epoch guard, and the proof/token submits + reads.
// How a browser REACHES a wallet (wagmi, EIP-6963, WalletConnect) is the app's
// business: apps/wallet-web/src/lib/wagmi.ts turns whatever wagmi connected into
// the `Connection` this module consumes. Everything here is wallet-library-free
// and gated headlessly: the account-watch sequences in this package's suite
// (test/accountWatch.test.ts), the submit/guard paths over fake EIP-1193
// transports in apps/wallet-web/test/connection.test.ts — that file also gates
// the app's wagmi half, so it stays where both subjects live.

import {
  parseAbi,
  type Address,
  type WalletClient,
  type PublicClient,
} from "viem";
import { causeChain, classifyChainFailure, errorCode } from "@bongtu/core/errors";
import type { KeyDerivationTypedData } from "./derive.js";
import type { WalletTransport } from "./loginGuard.js";
import type { Calldata } from "@bongtu/core/proving";
import {
  CHAIN_ID,
  EXPLORER_BASE,
  POOL_ABI_FRAGMENTS,
  ERC20_ABI_FRAGMENTS,
  RPC_URL,
  arbiterKemPkGuardError,
  explorerTxUrl,
  isPreKemProbeError,
} from "@bongtu/core/network";
import { giwaSepolia } from "./chain.js";

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

interface Eip1193 {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

/**
 * A connected wallet, whatever it is connected THROUGH. Every downstream module —
 * identity, keyCache, the flows, the submit helpers — sees only this shape, so which
 * connector wagmi picked (an EIP-6963 extension, WalletConnect) reaches none of them.
 */
export interface Connection {
  /** the account, as wagmi reported it at connect time (frozen — see currentAccount). */
  address: string;
  /** viem wallet client over the connector's raw EIP-1193 provider: signatures + txs. */
  walletClient: WalletClient;
  /** viem public client on the GIWA http RPC: reads + receipt waits (never the wallet). */
  publicClient: PublicClient;
  /** the raw EIP-1193 provider behind the connector — vendor brand flags
   *  (walletBrand.ts) and nothing else reads it. */
  injected: unknown;
  /** How the browser reached this wallet. The flows ignore it; the login guard and the
   *  chain guard don't (a remote wallet gets a different determinism rule and a
   *  different network-switch failure message). */
  transport: WalletTransport;
}

/**
 * A human-readable message from ANY wallet/RPC failure. Provider errors
 * (EIP-1193 ProviderRpcError) and viem's layered errors are plain objects or
 * deep cause chains, so the naive `String(e)` renders "[object Object]". The
 * structural digging (cause chain, conventional fields, viem's typed error names)
 * lives in the shared classifier (@bongtu/core/errors classifyChainFailure); this
 * function is only the wallet's WORDS for each verdict — the two failures every
 * tester hits (user rejection, no gas ETH) in plain language, viem's own best
 * text for everything else.
 */
export function walletErrorMessage(e: unknown): string {
  const failure = classifyChainFailure(e);
  switch (failure.kind) {
    case "user_rejected":
      return "Transaction rejected in your wallet.";
    case "insufficient_gas":
      return "Not enough GIWA Sepolia ETH to pay gas. This account needs a little ETH on GIWA Sepolia first.";
    case "chain_switch":
      if (failure.rejected) return "Transaction rejected in your wallet.";
      break; // an un-rejected switch failure reads best in viem's own words below
    default:
      break;
  }
  if (failure.text !== null) return failure.text;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

/** The connected account's native (gas) ETH balance on GIWA. */
export async function readGasBalance(connection: Connection): Promise<bigint> {
  return connection.publicClient.getBalance({ address: connection.address as Address });
}

export interface WalletWatchHandlers {
  accountsChanged?: () => void;
  disconnected?: () => void;
}

/** The slice of wagmi's account snapshot the watcher compares. */
export interface WatchedAccount {
  address?: string;
  status: string;
}

/**
 * The account-transition logic behind watchWallet, as a pure closure over wagmi's
 * (account, prev) change pairs — exported so the sequences gate headlessly
 * (test/accountWatch.test.ts) with no wagmi store.
 *
 * `accountsChanged` fires whenever the connected address DIFFERS from the last
 * address that was ever connected — including across a disconnected gap. The gap
 * case is the security-relevant one: an extension lock → unlock as a DIFFERENT
 * account arrives as connected(A) → disconnected → connected(B), where the naive
 * prev/account comparison sees no A→B pair and would leave account A's spending
 * key unlocked for account B's user. The closure remembers the last non-null
 * address, so B still fires the switch path (App locks the keyCache on it).
 */
export function accountWatchHandler(
  handlers: WalletWatchHandlers,
): (account: WatchedAccount, prev: WatchedAccount) => void {
  let last: string | null = null;
  return (account, prev) => {
    // Seed from `prev` when the watcher attached after the connect happened (the
    // first event it sees may already be the disconnect).
    if (last === null && prev.address) last = prev.address.toLowerCase();
    if (account.address) {
      const now = account.address.toLowerCase();
      if (last !== null && now !== last) handlers.accountsChanged?.();
      last = now;
    }
    if (prev.status === "connected" && account.status === "disconnected") {
      handlers.disconnected?.();
    }
  };
}

// EIP-3085/3326 params for GIWA Sepolia, derived from the ONE network module so a
// chain move cannot fork the wallet's idea of the chain from the sdk's.
const GIWA_CHAIN_HEX = "0x" + CHAIN_ID.toString(16);
const GIWA_CHAIN_PARAMS = {
  chainId: GIWA_CHAIN_HEX,
  chainName: "GIWA Sepolia (Testnet)",
  rpcUrls: [RPC_URL],
  blockExplorerUrls: [EXPLORER_BASE],
  nativeCurrency: { name: "Sepolia Ether", symbol: "ETH", decimals: 18 },
};

/**
 * Put the wallet on GIWA Sepolia: switch if it already knows the chain, otherwise
 * register it (EIP-3085 error 4902) and switch. Raw EIP-1193 requests through the
 * wallet client so the SAME two RPCs reach an extension or relay to a phone.
 * Without this a user connected on any other network would sign txs that go
 * nowhere — the pool only exists on GIWA.
 */
async function ensureGiwaChain(request: Eip1193["request"]): Promise<void> {
  try {
    await request({ method: "wallet_switchEthereumChain", params: [{ chainId: GIWA_CHAIN_HEX }] });
  } catch (e) {
    if (errorCode(e) !== 4902) throw e;
    // MetaMask auto-switches after add, but not every wallet does.
    await request({ method: "wallet_addEthereumChain", params: [GIWA_CHAIN_PARAMS] });
    await request({ method: "wallet_switchEthereumChain", params: [{ chainId: GIWA_CHAIN_HEX }] });
  }
}

/** Put an existing connection's wallet on GIWA Sepolia (silent when the chain is
 *  already added+selected). The action flows call this before reading token state
 *  or submitting — a silently-reconnected session may still sit on another chain. */
export async function ensureChain(connection: Connection): Promise<void> {
  const request: Eip1193["request"] = (args) =>
    connection.walletClient.request(args as never) as Promise<unknown>;
  try {
    await ensureGiwaChain(request);
  } catch (e) {
    // An extension either switches or reports a code the generic message already
    // explains. A remote wallet may simply not implement the switch, or the user may
    // never see the request — so say what to do instead of surfacing the raw relay error.
    if (connection.transport === "walletconnect") throw new Error(chainSwitchMessage(e));
    throw e;
  }
}

/** What to tell a WalletConnect user whose wallet would not move to GIWA Sepolia.
 *  The rejection verdict comes from the shared classifier — a declined EIP-3326
 *  request in any of its shapes (code 4001 / ACTION_REJECTED, viem's typed error,
 *  a SwitchChainError wrapping the user's refusal). */
export function chainSwitchMessage(e: unknown): string {
  const failure = classifyChainFailure(e);
  if (failure.kind === "user_rejected" || (failure.kind === "chain_switch" && failure.rejected)) {
    return "You declined the network switch. bongtu only works on GIWA Sepolia.";
  }
  return (
    "Your wallet didn't switch to GIWA Sepolia. Add or select that network in the wallet " +
    "app, then try again."
  );
}

/**
 * Sign the domain-separated key-derivation struct with eth_signTypedData_v4 (via
 * viem's `signTypedData`, which serialises the payload + calls that RPC method). The
 * returned 65-byte signature is deterministic for a fixed (account, domain, message),
 * so feeding it to the KDF yields the same bjj key every session (SPEC §6).
 * test/deriveDeterminism.test.ts pins the EIP-712 digest of what this sends against
 * the pre-viem (ethers v5) value — the payload is consensus-critical.
 */
export async function signKeyDerivation(
  connection: Connection,
  typed: KeyDerivationTypedData,
): Promise<string> {
  return connection.walletClient.signTypedData({
    account: connection.address as Address,
    domain: {
      name: typed.domain.name,
      version: typed.domain.version,
      chainId: typed.domain.chainId,
      verifyingContract: typed.domain.verifyingContract as Address,
    },
    types: typed.types,
    primaryType: typed.primaryType,
    message: typed.message,
  });
}

export interface SubmitResult {
  txHash: string;
  explorerUrl: string;
}

// One successful verification per pool address is enough for the session: the
// epoch hash only changes on an arbiter key rotation, which ships as a new
// wallet bundle anyway (ARBITER_KEM_PK is a build-time deployment fact).
let kemVerifiedPool: string | null = null;

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
  if (kemVerifiedPool === poolAddr) return;
  const pool = { address: poolAddr as Address, abi: POOL_ABI } as const;
  let onchainHash: string | null;
  try {
    const epoch = await connection.publicClient.readContract({ ...pool, functionName: "currentEpoch" });
    onchainHash = String(
      await connection.publicClient.readContract({ ...pool, functionName: "arbiterKemPkHash", args: [epoch] }),
    );
  } catch (e) {
    if (!isViemPreKemProbeError(e) && !isPreKemProbeError(e)) throw e;
    onchainHash = null;
  }
  const err = arbiterKemPkGuardError(onchainHash);
  if (err) {
    // The technical verdict (which key, which epoch) goes to the console for
    // diagnosis; the thrown message is what a wallet user can act on.
    console.error(err);
    throw new Error("This wallet version doesn't match the network yet. Try again in a moment.");
  }
  kemVerifiedPool = poolAddr;
}

// Every pool op carries the op's raw ML-KEM-768 encapsulation ciphertext
// (`bytes kemCiphertext`, 1088 B — the hybrid envelope's PQ half, drawn fresh
// per tx in freshSpendCrypto/freshDepositCrypto). The contract length-checks it
// (WrongKemCiphertextLength) and re-emits it for the arbiter; pre-checking the
// length here turns that revert into a readable client error.
function assertKemCiphertext(kemCiphertext: string): void {
  if (!/^0x[0-9a-fA-F]+$/.test(kemCiphertext) || (kemCiphertext.length - 2) / 2 !== 1088) {
    throw new Error(`kemCiphertext must be 1088 bytes of 0x-hex (got ${kemCiphertext.length} chars)`);
  }
}

/** The proof calldata's decimal strings as the bigints viem's ABI encoder takes. */
function asProofArgs(calldata: Calldata) {
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
/** The chain's own price word (eth_gasPrice) per tx — GIWA quotes ~0.001 gwei.
 *  The old fixed pin guarded against wallet-stack fee ESTIMATION (which once
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

async function submit(
  connection: Connection,
  poolAddr: string,
  fn: "deposit" | "transfer" | "transfer10x2" | "withdraw",
  calldata: Calldata,
  kemCiphertext: string,
  explorerBase: string,
): Promise<SubmitResult> {
  assertKemCiphertext(kemCiphertext);
  const { a, b, c, pub } = asProofArgs(calldata);
  const hash = await connection.walletClient.writeContract({
    address: poolAddr as Address,
    abi: POOL_ABI,
    functionName: fn,
    // The pub vector's length is per-circuit (19/37/68/26) and checked by the ABI
    // encoder at runtime; a plain bigint[] cannot satisfy the per-function tuple
    // type statically, hence the one cast.
    args: [a, b, c, pub, kemCiphertext as `0x${string}`] as never,
    account: connection.address as Address,
    chain: giwaSepolia,
    nonce: await nextNonce(connection),
    gasPrice: await chainGasPrice(connection),
  });
  await connection.publicClient.waitForTransactionReceipt({ hash });
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

/** Submit a proven withdraw. */
export function submitWithdraw(
  connection: Connection,
  poolAddr: string,
  calldata: Calldata,
  kemCiphertext: string,
  explorerBase: string,
): Promise<SubmitResult> {
  return submit(connection, poolAddr, "withdraw", calldata, kemCiphertext, explorerBase);
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
  const hash = await connection.walletClient.writeContract({
    address: tokenAddr as Address,
    abi: ERC20_ABI,
    functionName: "approve",
    args: [spender as Address, amount],
    account: connection.address as Address,
    chain: giwaSepolia,
    gasPrice: await chainGasPrice(connection),
    nonce: await nextNonce(connection),
  });
  await connection.publicClient.waitForTransactionReceipt({ hash });
  return hash;
}

/**
 * DEV FAUCET: mint `amount` raw units of the mock kKRW ERC-20 at `tokenAddr` to `to`,
 * from the connected wallet. The deployed token is MockERC20 whose `mint` is
 * permissionless (no onlyOwner/cap), so the user self-funds test kKRW and pays their
 * OWN GIWA gas — there is no backend faucet service or operator key. Same submit shape
 * as approveToken/submit (chain-quoted gas, explicit nonce, receipt wait); returns the tx hash +
 * explorer link so the Deposit screen can surface it. A production token has no mint.
 */
export async function mintTestToken(
  connection: Connection,
  tokenAddr: string,
  to: string,
  amount: bigint,
): Promise<SubmitResult> {
  const hash = await connection.walletClient.writeContract({
    address: tokenAddr as Address,
    abi: ERC20_ABI,
    functionName: "mint",
    args: [to as Address, amount],
    account: connection.address as Address,
    chain: giwaSepolia,
    gasPrice: await chainGasPrice(connection),
    nonce: await nextNonce(connection),
  });
  await connection.publicClient.waitForTransactionReceipt({ hash });
  return { txHash: hash, explorerUrl: explorerTxUrl(hash) };
}

/** The depositor's raw kKRW balance and current allowance to the pool. */
export interface TokenState {
  balance: bigint;
  allowance: bigint;
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
