// MetaMask (EIP-1193 / ethers v5) wiring — the ONLY browser-coupled module of the
// wallet (SPEC §6/§7). It connects the injected wallet, obtains the deterministic
// eth_signTypedData_v4 signature the KDF consumes (derive.ts), and submits the
// finished transfer / withdraw proof. Everything security-relevant (key derivation,
// balance, witness assembly) lives in the PURE modules and is unit-tested; this file
// is the thin, un-testable I/O edge (no MetaMask in the headless env).

import { ethers } from "ethers";
import type { KeyDerivationTypedData } from "./derive.js";
import type { Calldata } from "@bongtu/core/proving";
import {
  GIWA_GAS_FLOOR_GWEI,
  POOL_ABI_FRAGMENTS,
  ERC20_ABI_FRAGMENTS,
  explorerTxUrl,
} from "@bongtu/core/network";

// The GIWA gas floor lives in @bongtu/core/network (ethers' auto-estimate
// overpays ~1500x); the sdk is data-only, so parseUnits happens here.
const GAS_PRICE = ethers.utils.parseUnits(GIWA_GAS_FLOOR_GWEI, "gwei");

// The shared per-function ABI fragments (@bongtu/core/network) — only the pool
// functions the wallet touches. deposit is the 0-in/2-out mint (a,b,c,pub) the
// shield flow submits.
const POOL_ABI = [
  POOL_ABI_FRAGMENTS.deposit,
  POOL_ABI_FRAGMENTS.transfer,
  POOL_ABI_FRAGMENTS.withdraw,
  POOL_ABI_FRAGMENTS.root,
  POOL_ABI_FRAGMENTS.nextLeafIndex,
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
  if (!eth) throw new Error("no injected wallet found (install/enable MetaMask)");
  return eth;
}

export interface Connection {
  address: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  provider: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  signer: any;
}

/** Connect MetaMask and return the selected account + ethers signer. */
export async function connect(): Promise<Connection> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const provider = new ethers.providers.Web3Provider(ethereum() as any, "any");
  await provider.send("eth_requestAccounts", []);
  const signer = provider.getSigner();
  const address = await signer.getAddress();
  return { address, provider, signer };
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

async function submit(
  connection: Connection,
  poolAddr: string,
  fn: "deposit" | "transfer" | "withdraw",
  calldata: Calldata,
  explorerBase: string,
): Promise<SubmitResult> {
  const pool = new ethers.Contract(poolAddr, POOL_ABI, connection.signer);
  const tx = await pool[fn](calldata.a, calldata.b, calldata.c, calldata.pub, { gasPrice: GAS_PRICE });
  await tx.wait();
  return { txHash: tx.hash, explorerUrl: explorerTxUrl(tx.hash, explorerBase) };
}

/** Submit a proven transfer (calldata from browser snarkjs, SPEC §7). */
export function submitTransfer(
  connection: Connection,
  poolAddr: string,
  calldata: Calldata,
  explorerBase: string,
): Promise<SubmitResult> {
  return submit(connection, poolAddr, "transfer", calldata, explorerBase);
}

/** Submit a proven withdraw. */
export function submitWithdraw(
  connection: Connection,
  poolAddr: string,
  calldata: Calldata,
  explorerBase: string,
): Promise<SubmitResult> {
  return submit(connection, poolAddr, "withdraw", calldata, explorerBase);
}

/** Submit a proven deposit/shield: the 0-in/2-out mint `(a, b, c, pub)` (pub[0] == V,
 *  length 18). Permissionless — the pool has NO onlyOwner on deposit. Same submit path
 *  as transfer/withdraw (its single authority envelope rides in `pub`). */
export function submitDeposit(
  connection: Connection,
  poolAddr: string,
  calldata: Calldata,
  explorerBase: string,
): Promise<SubmitResult> {
  return submit(connection, poolAddr, "deposit", calldata, explorerBase);
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
