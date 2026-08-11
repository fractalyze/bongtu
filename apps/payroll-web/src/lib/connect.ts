// How the payroll console REACHES a wallet: the injected EIP-1193 provider,
// directly. The public wallet carries wagmi + RainbowKit because its users may
// arrive with any extension or a phone over WalletConnect; the pay console is an
// operator tool on the employer's desk — MetaMask-class extension, one account —
// so it mirrors only the minimal part of wallet-web/src/lib/wagmi.ts: turn the
// injected provider into the `Connection` shape @bongtu/client consumes (viem
// wallet client over the provider for signatures/txs, viem public client on the
// chain's RPC for reads/receipts), plus the live-account read the lock's session
// check needs. Everything downstream — derivation, guards, submits, flows — is
// the shared engine.

import { createPublicClient, createWalletClient, custom, http, type PublicClient } from "viem";
import { liveChain } from "@bongtu/client/chain";
import type { Connection } from "@bongtu/client/connection";

interface Eip1193 {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

function injectedProvider(): Eip1193 | null {
  return (globalThis as { ethereum?: Eip1193 }).ethereum ?? null;
}

/** Whether an EIP-1193 provider is injected — the login button's precondition. */
export function hasInjectedWallet(): boolean {
  return injectedProvider() !== null;
}

/** Reads and receipt waits go straight to the chain's RPC via one public client —
 *  never through the wallet. */
const publicClient: PublicClient = createPublicClient({ chain: liveChain, transport: http() });

/**
 * Open the injected wallet (eth_requestAccounts — the connect prompt on first
 * use, silent when already authorised) and wrap it as the engine's `Connection`.
 * Throws readably when no wallet is installed.
 */
export async function openInjectedConnection(): Promise<Connection> {
  const injected = injectedProvider();
  if (!injected) throw new Error("No wallet found in this browser. Install MetaMask and try again.");
  const walletClient = createWalletClient({ chain: liveChain, transport: custom(injected) });
  const [address] = await walletClient.requestAddresses();
  if (!address) throw new Error("The wallet did not share an account. Select one in MetaMask and try again.");
  return {
    address,
    walletClient: createWalletClient({ account: address, chain: liveChain, transport: custom(injected) }),
    publicClient,
    injected,
    transport: "injected",
  };
}

/**
 * The account the injected wallet has selected RIGHT NOW (eth_accounts — never a
 * prompt), lowercased; null when none. `connection.address` is frozen at connect
 * time, so this is the only honest answer to "whose key would a derivation
 * produce?" after a mid-session account switch (keyCache session check).
 */
export async function currentAccount(): Promise<string | null> {
  const injected = injectedProvider();
  if (!injected) return null;
  try {
    const accounts = (await injected.request({ method: "eth_accounts" })) as string[];
    return accounts[0]?.toLowerCase() ?? null;
  } catch {
    return null;
  }
}

/** Subscribe to the injected wallet's accountsChanged (the console locks the key
 *  and signs out on it — an admin session must not survive an account swap). */
export function watchInjectedAccount(onChange: () => void): () => void {
  const injected = injectedProvider() as
    | (Eip1193 & {
        on?: (ev: string, fn: (a: string[]) => void) => void;
        removeListener?: (ev: string, fn: (a: string[]) => void) => void;
      })
    | null;
  if (!injected?.on) return () => {};
  const handler = (): void => onChange();
  injected.on("accountsChanged", handler);
  return () => injected.removeListener?.("accountsChanged", handler);
}
