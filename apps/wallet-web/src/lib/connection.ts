// The wallet edge, and the home of `Connection` — the one shape every other module
// works against (SPEC §6/§7). wagmi owns HOW a wallet is reached (every installed
// extension via EIP-6963, WalletConnect for phones — the RainbowKit modal does the
// choosing); this module turns whatever wagmi connected into a `Connection`, obtains
// the deterministic eth_signTypedData_v4 signature the KDF consumes (derive.ts), and
// submits the finished proofs over viem. Everything security-relevant (key
// derivation, balance, witness assembly) lives in the PURE modules and is
// unit-tested; the wagmi-facing half of this file is the thin I/O edge (no wallet in
// the headless env), while the viem half (signing, submits, reads) is gated in
// test/connection.test.ts over fake EIP-1193 transports.

import {
  createPublicClient,
  createWalletClient,
  custom,
  http,
  parseAbi,
  type Address,
  type PublicClient,
  type WalletClient,
} from "viem";
import { disconnect, getAccount, reconnect, watchAccount } from "wagmi/actions";
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
import { GAS_PRICE, giwaSepolia } from "./chain.js";
import { wagmiConfig } from "./wagmi.js";

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

/** Whether an EIP-1193 provider is injected — true in extension browsers AND in
 *  MetaMask Mobile's in-app browser; false in a plain mobile browser, where the
 *  paths to a connection are WalletConnect or the deep link below. */
export function hasInjectedWallet(): boolean {
  return Boolean((globalThis as { ethereum?: unknown }).ethereum);
}

/** MetaMask Mobile deep link that reopens THIS page inside the app's dapp
 *  browser (which injects window.ethereum). Universal-link form, so it also
 *  routes to the app store when the app is missing. Onboarding's last resort
 *  when there is neither an extension nor WalletConnect in the build. */
export function metamaskDeepLink(): string {
  const { host, pathname } = window.location;
  return `https://metamask.app.link/dapp/${host}${pathname}`;
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

/** The one public client — receipts and view reads go to the GIWA RPC directly,
 *  never through the wallet (a phone over WalletConnect shouldn't relay eth_call). */
const publicClient: PublicClient = createPublicClient({ chain: giwaSepolia, transport: http() });

/** Walk an error and its `cause` chain (viem nests the actionable failure several
 *  levels deep); bounded so a cyclic cause cannot spin. */
function causeChain(e: unknown): Record<string, unknown>[] {
  const chain: Record<string, unknown>[] = [];
  for (let cur = e; cur !== null && typeof cur === "object" && chain.length < 8; ) {
    chain.push(cur as Record<string, unknown>);
    cur = (cur as { cause?: unknown }).cause;
  }
  return chain;
}

/**
 * A human-readable message from ANY wallet/RPC failure. Provider errors
 * (EIP-1193 ProviderRpcError) and viem's layered errors are plain objects or
 * deep cause chains, so the naive `String(e)` renders "[object Object]"; dig the
 * conventional fields at every level and translate the two failures every tester
 * hits (user rejection, no gas ETH) into plain words.
 */
export function walletErrorMessage(e: unknown): string {
  const chain = causeChain(e);
  for (const o of chain) {
    // EIP-1193 code 4001, ethers-style ACTION_REJECTED, viem's typed error.
    if (o.code === 4001 || o.code === "ACTION_REJECTED" || o.name === "UserRejectedRequestError") {
      return "Transaction rejected in your wallet.";
    }
  }
  const texts = chain.flatMap((o) =>
    [
      o.reason,
      (o.error as { message?: string } | undefined)?.message,
      (o.data as { message?: string } | undefined)?.message,
      o.shortMessage,
      o.details,
      o.message,
    ].filter((t): t is string => typeof t === "string"),
  );
  if (texts.some((t) => /user rejected|user denied/i.test(t))) {
    return "Transaction rejected in your wallet.";
  }
  if (texts.some((t) => /insufficient funds/i.test(t))) {
    return "Not enough GIWA Sepolia ETH to pay gas. This account needs a little ETH on GIWA Sepolia first.";
  }
  if (texts.length > 0) return texts[0];
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

/** Wrap the connector wagmi has live into the `Connection` the app consumes, or
 *  null when nothing is connected. The wallet client rides the connector's raw
 *  EIP-1193 provider, so signatures and txs reach whichever wallet the user
 *  actually picked in the modal; reads ride the app's own public client. */
export async function currentConnection(): Promise<Connection | null> {
  const account = getAccount(wagmiConfig);
  if (account.status !== "connected" || !account.connector || !account.address) return null;
  const injected = (await account.connector.getProvider()) as Eip1193;
  const walletClient = createWalletClient({
    account: account.address,
    chain: giwaSepolia,
    transport: custom(injected),
  });
  return {
    address: account.address,
    walletClient,
    publicClient,
    injected,
    transport: account.connector.type === "walletConnect" ? "walletconnect" : "injected",
  };
}

/** The login's connection source (loginFlow.runLogin): the wallet the RainbowKit
 *  modal just connected. Throws readably when pressed before any wallet is live —
 *  the Onboarding wiring opens the modal first, so this is a belt, not a path. */
export async function requireConnection(): Promise<Connection> {
  const connection = await currentConnection();
  if (!connection) throw new Error("No wallet connected. Connect a wallet first.");
  return connection;
}

/**
 * SILENT reconnect for a stored session: wagmi re-opens its remembered connector
 * (eth_accounts for an extension — never a popup; the WalletConnect connector
 * reloads its own stored session — never a QR modal), and the same account must
 * still be reported. Returns null when nothing reconnects or the account changed —
 * the caller then falls back to the normal connect flow. Deliberately does NOT
 * switch chains (that can prompt); the action flows call `ensureChain` before
 * anything chain-dependent.
 */
export async function restoreConnection(expectedAddress: string): Promise<Connection | null> {
  try {
    await reconnect(wagmiConfig);
  } catch {
    return null;
  }
  const connection = await currentConnection();
  if (!connection || connection.address.toLowerCase() !== expectedAddress.toLowerCase()) return null;
  return connection;
}

/** Silent, fire-and-forget reconnect with no session to check against: lets the
 *  Onboarding Connect button skip the modal when wagmi still holds an authorised
 *  connector from a previous visit. Never prompts (same guarantee as above). */
export function warmReconnect(): void {
  void reconnect(wagmiConfig).catch(() => {});
}

/**
 * End the wallet connection on an explicit sign-out: wagmi disconnects the live
 * connector (for WalletConnect that ends the session — without it the wallet app
 * keeps showing bongtu as connected) and forgets it, so the next visit cannot
 * silently reconnect a pairing the user believes they closed. Best-effort:
 * signing out must not fail because a relay is down.
 */
export async function endWalletConnection(): Promise<void> {
  try {
    await disconnect(wagmiConfig);
  } catch {
    // the local state is cleared either way; a WC relay will time the pairing out.
  }
}

/**
 * The account the connected wallet has selected RIGHT NOW, lowercased; null when
 * none is connected. wagmi tracks the connector's accountsChanged events, so this
 * follows the wallet live while `connection.address` is frozen at connect time —
 * making this the only honest answer to "whose key would a derivation produce?"
 * after a mid-session account switch (keyCache.ts).
 */
export async function currentAccount(): Promise<string | null> {
  return getAccount(wagmiConfig).address?.toLowerCase() ?? null;
}

/**
 * Subscribe to wallet-account changes through wagmi's one account store; returns
 * one unsubscribe. `accountsChanged` fires on a switch to a DIFFERENT address;
 * `disconnected` when a live connection ends (the WalletConnect peer hanging up,
 * an extension revoking access). What `disconnected` should DO stays the
 * CALLER's choice: App signs out only a WalletConnect session (a remote peer
 * ending the session is a real sign-out; an extension hiccup is not).
 */
export function watchWallet(handlers: {
  accountsChanged?: () => void;
  disconnected?: () => void;
}): () => void {
  return watchAccount(wagmiConfig, {
    onChange(account, prev) {
      if (prev.address && account.address && account.address !== prev.address) {
        handlers.accountsChanged?.();
      }
      if (prev.status === "connected" && account.status === "disconnected") {
        handlers.disconnected?.();
      }
    },
  });
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

function errorCode(e: unknown): number | string | undefined {
  for (const o of causeChain(e)) {
    if (typeof o.code === "number" || typeof o.code === "string") return o.code;
  }
  return undefined;
}

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

/** What to tell a WalletConnect user whose wallet would not move to GIWA Sepolia. */
export function chainSwitchMessage(e: unknown): string {
  const code = errorCode(e);
  if (code === 4001 || code === "ACTION_REJECTED") {
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
    // Pinned, never estimated: wallet-stack auto-estimation once overpaid ~1500x.
    gasPrice: GAS_PRICE,
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
    gasPrice: GAS_PRICE,
  });
  await connection.publicClient.waitForTransactionReceipt({ hash });
  return hash;
}

/**
 * DEV FAUCET: mint `amount` raw units of the mock kKRW ERC-20 at `tokenAddr` to `to`,
 * from the connected wallet. The deployed token is MockERC20 whose `mint` is
 * permissionless (no onlyOwner/cap), so the user self-funds test kKRW and pays their
 * OWN GIWA gas — there is no backend faucet service or operator key. Same submit shape
 * as approveToken/submit (GAS_PRICE floor, wait for the receipt); returns the tx hash +
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
    gasPrice: GAS_PRICE,
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
