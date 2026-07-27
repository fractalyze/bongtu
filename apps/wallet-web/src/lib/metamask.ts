// The injected-wallet (EIP-1193 / ethers v5) edge, and the home of `Connection` — the
// one shape every other module works against (SPEC §6/§7). It connects the injected
// wallet, obtains the deterministic eth_signTypedData_v4 signature the KDF consumes
// (derive.ts), and submits the finished transfer / withdraw proof. Everything
// security-relevant (key derivation, balance, witness assembly) lives in the PURE
// modules and is unit-tested; this file is the thin, un-testable I/O edge (no wallet
// in the headless env).
//
// The second edge is walletconnect.ts, which builds the SAME `Connection` over a
// remote wallet. Everything below `Connection` is transport-blind by construction:
// the submit/read helpers here work unchanged over either.

import { ethers } from "ethers";
import type { KeyDerivationTypedData } from "./derive.js";
import type { WalletTransport } from "./loginGuard.js";
import type { Calldata } from "@bongtu/core/proving";
import {
  CHAIN_ID,
  EXPLORER_BASE,
  GIWA_GAS_FLOOR_GWEI,
  POOL_ABI_FRAGMENTS,
  ERC20_ABI_FRAGMENTS,
  RPC_URL,
  arbiterKemPkGuardError,
  explorerTxUrl,
  isPreKemProbeError,
} from "@bongtu/core/network";

// The GIWA gas floor lives in @bongtu/core/network (ethers' auto-estimate
// overpays ~1500x); the sdk is data-only, so parseUnits happens here.
const GAS_PRICE = ethers.utils.parseUnits(GIWA_GAS_FLOOR_GWEI, "gwei");

// The shared per-function ABI fragments (@bongtu/core/network) — only the pool
// functions the wallet touches. deposit is the 0-in/2-out mint (a,b,c,pub) the
// shield flow submits.
// transfer10 (10-in / 10-out, BongtuPool V4) is the one fragment not yet in the
// shared sdk table: same (a, b, c, pub, kemCiphertext) shape as transfer, with the
// arity-10 public vector (141 signals — 10 nullifiers, 10 output commitments, the
// 64-element authority ciphertext and the per-output receiver ciphertexts). Move it
// into POOL_ABI_FRAGMENTS once the sdk carries it, so the two apps cannot drift.
const TRANSFER10_FRAGMENT =
  "function transfer10(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[141] pub, bytes kemCiphertext)";

const POOL_ABI = [
  POOL_ABI_FRAGMENTS.deposit,
  POOL_ABI_FRAGMENTS.transfer,
  TRANSFER10_FRAGMENT,
  POOL_ABI_FRAGMENTS.withdraw,
  POOL_ABI_FRAGMENTS.root,
  POOL_ABI_FRAGMENTS.nextLeafIndex,
  POOL_ABI_FRAGMENTS.currentEpoch,
  POOL_ABI_FRAGMENTS.arbiterKemPkHash,
];

// The wrapped kKRW ERC-20 fragments for the deposit/shield flow: approve the pool to
// pull V, read the depositor's balance + pool allowance (view, no gas), and the
// permissionless mock-token `mint` the dev faucet uses to self-fund test kKRW.
const ERC20_ABI = [
  ERC20_ABI_FRAGMENTS.approve,
  ERC20_ABI_FRAGMENTS.allowance,
  ERC20_ABI_FRAGMENTS.balanceOf,
  ERC20_ABI_FRAGMENTS.mint,
];

interface Eip1193 {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}
function ethereum(): Eip1193 {
  const eth = (globalThis as { ethereum?: Eip1193 }).ethereum;
  if (!eth) throw new Error("No wallet extension found — install or enable one, then reload.");
  return eth;
}

/** Whether an EIP-1193 provider is injected — true in extension browsers AND in
 *  MetaMask Mobile's in-app browser; false in a plain mobile browser, where the
 *  only path to a connection is the deep link below. */
export function hasInjectedWallet(): boolean {
  return Boolean((globalThis as { ethereum?: unknown }).ethereum);
}

/**
 * A human-readable message from ANY wallet/RPC failure. MetaMask's
 * ProviderRpcError and ethers' wrapped errors are plain objects, so the naive
 * `String(e)` renders "[object Object]"; dig the conventional fields instead
 * and translate the two failures every tester hits (user rejection, no gas
 * ETH) into plain words.
 */
export function walletErrorMessage(e: unknown): string {
  const o = e as {
    code?: number | string;
    reason?: string;
    message?: string;
    error?: { message?: string };
    data?: { message?: string };
  } | null;
  if (o?.code === 4001 || o?.code === "ACTION_REJECTED") return "Transaction rejected in your wallet.";
  const raw = o?.reason ?? o?.error?.message ?? o?.data?.message ?? o?.message;
  if (raw && /insufficient funds/i.test(raw)) {
    return "Not enough GIWA Sepolia ETH to pay gas — this account needs a little ETH on GIWA Sepolia first.";
  }
  if (raw) return raw;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

/** The connected account's native (gas) ETH balance on the current chain. */
export async function readGasBalance(connection: Connection): Promise<bigint> {
  const b = await connection.provider.getBalance(connection.address);
  return BigInt(b.toString());
}

/** MetaMask Mobile deep link that reopens THIS page inside the app's dapp
 *  browser (which injects window.ethereum). Universal-link form, so it also
 *  routes to the app store when the app is missing. */
export function metamaskDeepLink(): string {
  const { host, pathname } = window.location;
  return `https://metamask.app.link/dapp/${host}${pathname}`;
}

/**
 * A connected wallet, whatever it is connected THROUGH. Every downstream module —
 * identity, keyCache, the flows, the submit helpers — sees only this shape, so adding
 * WalletConnect (walletconnect.ts builds the same three fields over its own EIP-1193
 * provider) reached none of them.
 *
 * `provider` is an ethers Web3Provider; the raw EIP-1193 object sits at
 * `provider.provider` (the chain guard and the wallet-identity path both read it).
 */
export interface Connection {
  address: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  provider: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  signer: any;
  /** How the browser reached this wallet. The flows ignore it; the login guard and the
   *  chain guard don't (a remote wallet gets a different determinism rule and a
   *  different network-switch failure message). */
  transport: WalletTransport;
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
 * Put the injected wallet on GIWA Sepolia: switch if MetaMask already knows the
 * chain, otherwise register it (EIP-3085 error 4902) and switch. Without this a
 * user connected on any other network would sign txs that go nowhere — the pool
 * only exists on GIWA.
 */
async function ensureGiwaChain(eth: Eip1193): Promise<void> {
  try {
    await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: GIWA_CHAIN_HEX }] });
  } catch (e) {
    if ((e as { code?: number } | null)?.code !== 4902) throw e;
    // MetaMask auto-switches after add, but not every injected wallet does.
    await eth.request({ method: "wallet_addEthereumChain", params: [GIWA_CHAIN_PARAMS] });
    await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: GIWA_CHAIN_HEX }] });
  }
}

/** Connect MetaMask on GIWA Sepolia (auto add/switch) and return the selected
 *  account + ethers signer. */
export async function connect(): Promise<Connection> {
  const eth = ethereum();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const provider = new ethers.providers.Web3Provider(eth as any, "any");
  await provider.send("eth_requestAccounts", []);
  await ensureGiwaChain(eth);
  const signer = provider.getSigner();
  const address = await signer.getAddress();
  return { address, provider, signer, transport: "injected" };
}

/**
 * SILENT reconnect for a stored session: `eth_accounts` (never a popup — it only
 * reports already-authorised accounts) and a match against the session's account.
 * Returns null when there is no injected wallet, no authorised account, or the
 * selected account changed — the caller then falls back to the normal connect
 * flow. Deliberately does NOT switch chains here (that can prompt); the action
 * flows call `ensureChain` before anything chain-dependent.
 */
export async function reconnect(expectedAddress: string): Promise<Connection | null> {
  if (!hasInjectedWallet()) return null;
  const eth = ethereum();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const provider = new ethers.providers.Web3Provider(eth as any, "any");
  let accounts: string[];
  try {
    accounts = (await provider.send("eth_accounts", [])) as string[];
  } catch {
    return null;
  }
  const addr = accounts?.[0];
  if (!addr || addr.toLowerCase() !== expectedAddress.toLowerCase()) return null;
  return { address: addr, provider, signer: provider.getSigner(), transport: "injected" };
}

/**
 * The account the injected wallet has selected RIGHT NOW, lowercased (`eth_accounts`
 * — a report of already-authorised accounts, never a popup); null when none is
 * authorised or the call fails. `connection.address` is frozen at connect time, so
 * this is the only honest answer to "whose key would a derivation produce?" after a
 * mid-session account switch.
 */
export async function currentAccount(connection: Connection): Promise<string | null> {
  try {
    const accounts = (await connection.provider.send("eth_accounts", [])) as string[];
    return accounts?.[0]?.toLowerCase() ?? null;
  } catch {
    return null;
  }
}

interface WalletEvents {
  on?(event: string, handler: () => void): void;
  removeListener?(event: string, handler: () => void): void;
}

/**
 * Subscribe to the wallet's own EIP-1193 events; returns one unsubscribe for all of
 * them. The emitter is the connection's raw provider when there is a connection (the
 * WalletConnect provider for a remote wallet, the injected object for an extension),
 * and the page's injected wallet before one exists — so the caller wires handlers
 * once and this decides who is actually talking.
 *
 * `disconnect` means different things per transport and is therefore the CALLER's
 * choice: over WalletConnect it is the peer ending the session (a real sign-out),
 * while an injected wallet fires it for a dropped RPC connection, which must not log
 * anyone out. App only passes a handler for the first case.
 */
export function onWalletEvents(
  connection: Connection | null,
  handlers: { accountsChanged?: () => void; disconnect?: () => void },
): () => void {
  const source = (connection?.provider?.provider ??
    (globalThis as { ethereum?: WalletEvents }).ethereum) as WalletEvents | undefined;
  if (!source?.on) return () => {};
  const wired = Object.entries(handlers).filter(
    (e): e is [string, () => void] => typeof e[1] === "function",
  );
  for (const [event, handler] of wired) source.on(event, handler);
  return () => {
    for (const [event, handler] of wired) source.removeListener?.(event, handler);
  };
}

/** Put an existing connection's wallet on GIWA Sepolia (silent when the chain is
 *  already added+selected). The action flows call this before reading token state
 *  or submitting — a silently-reconnected session may still sit on another chain. */
export async function ensureChain(connection: Connection): Promise<void> {
  // The raw EIP-1193 provider sits under the ethers Web3Provider — for a WalletConnect
  // connection that is the WC provider, which relays the same two RPCs to the phone.
  const eth = (connection.provider?.provider ?? ethereum()) as Eip1193;
  try {
    await ensureGiwaChain(eth);
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
  const code = (e as { code?: number | string } | null)?.code;
  if (code === 4001 || code === "ACTION_REJECTED") {
    return "You declined the network switch — bongtu only works on GIWA Sepolia.";
  }
  return (
    "Your wallet didn't switch to GIWA Sepolia. Add or select that network in the wallet " +
    "app, then try again."
  );
}

/**
 * Sign the domain-separated key-derivation struct with eth_signTypedData_v4 (via
 * ethers' `_signTypedData`, which encodes EIP712Domain + calls that RPC method). The
 * returned 65-byte signature is deterministic for a fixed (account, domain, message),
 * so feeding it to the KDF yields the same bjj key every session (SPEC §6).
 */
export async function signKeyDerivation(
  connection: Connection,
  typed: KeyDerivationTypedData,
): Promise<string> {
  return connection.signer._signTypedData(typed.domain, typed.types, typed.message);
}

export interface SubmitResult {
  txHash: string;
  explorerUrl: string;
}

// One successful verification per pool address is enough for the session: the
// epoch hash only changes on an arbiter key rotation, which ships as a new
// wallet bundle anyway (ARBITER_KEM_PK is a build-time deployment fact).
let kemVerifiedPool: string | null = null;

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
  const pool = new ethers.Contract(poolAddr, POOL_ABI, connection.provider);
  let onchainHash: string | null;
  try {
    onchainHash = String(await pool.arbiterKemPkHash(await pool.currentEpoch()));
  } catch (e) {
    if (!isPreKemProbeError(e)) throw e;
    onchainHash = null;
  }
  const err = arbiterKemPkGuardError(onchainHash);
  if (err) {
    // The technical verdict (which key, which epoch) goes to the console for
    // diagnosis; the thrown message is what a wallet user can act on.
    console.error(err);
    throw new Error("This wallet version doesn't match the network yet — try again in a moment.");
  }
  kemVerifiedPool = poolAddr;
}

// Every pool op now carries the op's raw ML-KEM-768 encapsulation ciphertext
// (`bytes kemCiphertext`, 1088 B — the hybrid envelope's PQ half, drawn fresh
// per tx in freshSpendCrypto/freshDepositCrypto). The contract length-checks it
// (WrongKemCiphertextLength) and re-emits it for the arbiter; pre-checking the
// length here turns that revert into a readable client error.
function assertKemCiphertext(kemCiphertext: string): void {
  if (!/^0x[0-9a-fA-F]+$/.test(kemCiphertext) || (kemCiphertext.length - 2) / 2 !== 1088) {
    throw new Error(`kemCiphertext must be 1088 bytes of 0x-hex (got ${kemCiphertext.length} chars)`);
  }
}

async function submit(
  connection: Connection,
  poolAddr: string,
  fn: "deposit" | "transfer" | "transfer10" | "withdraw",
  calldata: Calldata,
  kemCiphertext: string,
  explorerBase: string,
): Promise<SubmitResult> {
  assertKemCiphertext(kemCiphertext);
  const pool = new ethers.Contract(poolAddr, POOL_ABI, connection.signer);
  const tx = await pool[fn](calldata.a, calldata.b, calldata.c, calldata.pub, kemCiphertext, { gasPrice: GAS_PRICE });
  await tx.wait();
  return { txHash: tx.hash, explorerUrl: explorerTxUrl(tx.hash, explorerBase) };
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

/** The arity-10 transfer: what the wallet picks for a payment needing 3–10 notes,
 *  and what a self-merge runs on. Calldata is transfer's, with a longer `pub`. */
export function submitTransfer10(
  connection: Connection,
  poolAddr: string,
  calldata: Calldata,
  kemCiphertext: string,
  explorerBase: string,
): Promise<SubmitResult> {
  return submit(connection, poolAddr, "transfer10", calldata, kemCiphertext, explorerBase);
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
  const token = new ethers.Contract(tokenAddr, ERC20_ABI, connection.signer);
  const tx = await token.approve(spender, amount, { gasPrice: GAS_PRICE });
  await tx.wait();
  return tx.hash;
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
  const token = new ethers.Contract(tokenAddr, ERC20_ABI, connection.signer);
  const tx = await token.mint(to, amount, { gasPrice: GAS_PRICE });
  await tx.wait();
  return { txHash: tx.hash, explorerUrl: explorerTxUrl(tx.hash) };
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
  const token = new ethers.Contract(tokenAddr, ERC20_ABI, connection.provider);
  const [balance, allowance] = await Promise.all([
    token.balanceOf(owner),
    token.allowance(owner, spender),
  ]);
  return { balance: BigInt(balance.toString()), allowance: BigInt(allowance.toString()) };
}
