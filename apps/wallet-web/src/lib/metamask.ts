// MetaMask (EIP-1193 / ethers v5) wiring — the ONLY browser-coupled module of the
// wallet (SPEC §6/§7). It connects the injected wallet, obtains the deterministic
// eth_signTypedData_v4 signature the KDF consumes (derive.ts), and submits the
// finished transfer / withdraw proof. Everything security-relevant (key derivation,
// balance, witness assembly) lives in the PURE modules and is unit-tested; this file
// is the thin, un-testable I/O edge (no MetaMask in the headless env).

import { ethers } from "ethers";
import type { KeyDerivationTypedData } from "./derive.js";
import type { Calldata } from "@bongtu/prover-cli/types";

// GIWA wants ~0.001 gwei; ethers' auto-estimate overpays ~1500x. 0.005 gwei is a safe
// floor (matches deploy/giwa_disburse256.ts and apps/admin-web/src/lib/chain.ts).
const GAS_PRICE = ethers.utils.parseUnits("0.005", "gwei");

// The pool functions the wallet touches. transfer/withdraw take (a,b,c,pub) only —
// their ciphertext rides in `pub` as circuit outputs, so there is no ciphertext arg.
const POOL_ABI = [
  "function transfer(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[36] pub)",
  "function withdraw(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[25] pub)",
  "function root() view returns (uint256)",
  "function nextLeafIndex() view returns (uint256)",
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
  fn: "transfer" | "withdraw",
  calldata: Calldata,
  explorerBase: string,
): Promise<SubmitResult> {
  const pool = new ethers.Contract(poolAddr, POOL_ABI, connection.signer);
  const tx = await pool[fn](calldata.a, calldata.b, calldata.c, calldata.pub, { gasPrice: GAS_PRICE });
  await tx.wait();
  return { txHash: tx.hash, explorerUrl: `${explorerBase.replace(/\/$/, "")}/tx/${tx.hash}` };
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
