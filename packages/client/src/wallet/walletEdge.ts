// wallet/walletEdge.ts — the Connection shape, wallet failure copy, account
// watch, chain guard and the deterministic key-derivation signature (split from
// connection.ts; the subpath @bongtu/client/connection re-exports everything).
import type { Address, WalletClient, PublicClient } from "viem";
import { classifyChainFailure, errorCode, fallbackText, failureCopy, type FailureCopyTable } from "@bongtu/core/errors";
import type { KeyDerivationTypedData } from "@bongtu/client/derive";
import type { WalletTransport } from "@bongtu/client/loginGuard";
import {
  CHAIN_ID,
  CHAIN_NAME,
  EXPLORER_BASE,
  GAS_TOKEN_PHRASE,
  NATIVE_CURRENCY,
  RPC_URL,
} from "@bongtu/core/network";
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
  /** viem public client on the chain's http RPC: reads + receipt waits (never the wallet). */
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
 * The wallet's words per ChainFailure kind. The structural digging (cause chain,
 * conventional fields, viem's typed error names) lives in the shared classifier
 * (@bongtu/core/errors classifyChainFailure); this table is only the wallet's
 * WORDS for each verdict. A Record over the full union, so a kind added to the
 * classifier is a tsc error HERE rather than a silent fall-through to raw viem
 * text. Only the failures every tester hits (user rejection, no gas ETH, a
 * declined switch) get wallet wording; the rest keep viem's own best line via
 * the shared fallbackText — a precise revert beats any paraphrase.
 */
export const WALLET_FAILURE_COPY: FailureCopyTable = {
  user_rejected: () => "Transaction rejected in your wallet.",
  insufficient_gas: () =>
    `Not enough ${GAS_TOKEN_PHRASE} to pay gas. This account needs a little ${NATIVE_CURRENCY.symbol} on ${CHAIN_NAME} first.`,
  // an un-rejected switch failure reads best in viem's own words
  chain_switch: (failure, e) =>
    failure.rejected ? "Transaction rejected in your wallet." : fallbackText(failure, e),
  timeout: fallbackText,
  transport: fallbackText,
  other: fallbackText,
};

export function walletErrorMessage(e: unknown): string {
  return failureCopy(WALLET_FAILURE_COPY, classifyChainFailure(e), e);
}

/** The connected account's native (gas) ETH balance on the live chain. */
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
  const seen: { last: string | null } = { last: null };
  return (account, prev) => {
    // Seed from `prev` when the watcher attached after the connect happened (the
    // first event it sees may already be the disconnect).
    if (seen.last === null && prev.address) seen.last = prev.address.toLowerCase();
    if (account.address) {
      const now = account.address.toLowerCase();
      if (seen.last !== null && now !== seen.last) handlers.accountsChanged?.();
      seen.last = now;
    }
    if (prev.status === "connected" && account.status === "disconnected") {
      handlers.disconnected?.();
    }
  };
}

/**
 * The app-side wallet adapter, as one named shape. wallet-web (wagmi + RainbowKit
 * + WalletConnect) and payroll-web (the injected provider, directly) each reach a
 * wallet their own way; naming the quartet keeps the two adapters from drifting
 * apart (an edge that stops satisfying it is a tsc error in its app). Today the
 * engine consumes only the live-account read (keyCache.ts createKeyCache takes
 * exactly that slice); the other three members are the seam future engine
 * threading (login, account watch) lands against — declared now so both apps
 * already export the full shape.
 */
export interface WalletEdge {
  /** Is an EIP-1193 provider present in this browser — the connect button's
   *  precondition (false in a plain mobile browser). */
  hasInjectedWallet(): boolean;
  /** Open (or require) a live wallet as the engine's `Connection`. Throws readably
   *  when nothing is connected/installed. */
  openConnection(): Promise<Connection>;
  /** The account the wallet has selected RIGHT NOW, lowercased; null when none.
   *  `connection.address` is frozen at connect time, so this is the only honest
   *  answer to "whose key would a derivation produce?" after a mid-session switch. */
  currentAccount(): Promise<string | null>;
  /** Subscribe to account transitions (switch, disconnect); returns the
   *  unsubscribe. What the events should DO stays the caller's choice. */
  watchAccount(handlers: WalletWatchHandlers): () => void;
}

// EIP-3085/3326 params for the live chain, derived from the ONE network module so
// a chain move cannot fork the wallet's idea of the chain from the sdk's.
const CHAIN_HEX = "0x" + CHAIN_ID.toString(16);
const CHAIN_PARAMS = {
  chainId: CHAIN_HEX,
  chainName: CHAIN_NAME,
  rpcUrls: [RPC_URL],
  blockExplorerUrls: [EXPLORER_BASE],
  nativeCurrency: NATIVE_CURRENCY,
};

/**
 * Put the wallet on the live chain: switch if it already knows it, otherwise
 * register it (EIP-3085 error 4902) and switch. Raw EIP-1193 requests through the
 * wallet client so the SAME two RPCs reach an extension or relay to a phone.
 * Without this a user connected on any other network would sign txs that go
 * nowhere — the pool exists on exactly one chain.
 */
async function switchOrAddChain(request: Eip1193["request"]): Promise<void> {
  try {
    await request({ method: "wallet_switchEthereumChain", params: [{ chainId: CHAIN_HEX }] });
  } catch (e) {
    if (errorCode(e) !== 4902) throw e;
    // MetaMask auto-switches after add, but not every wallet does.
    await request({ method: "wallet_addEthereumChain", params: [CHAIN_PARAMS] });
    await request({ method: "wallet_switchEthereumChain", params: [{ chainId: CHAIN_HEX }] });
  }
}

/** Put an existing connection's wallet on the live chain (silent when the chain is
 *  already added+selected). The action flows call this before reading token state
 *  or submitting — a silently-reconnected session may still sit on another chain. */
export async function ensureChain(connection: Connection): Promise<void> {
  const request: Eip1193["request"] = (args) =>
    connection.walletClient.request(args as never) as Promise<unknown>;
  try {
    await switchOrAddChain(request);
  } catch (e) {
    // An extension either switches or reports a code the generic message already
    // explains. A remote wallet may simply not implement the switch, or the user may
    // never see the request — so say what to do instead of surfacing the raw relay error.
    if (connection.transport === "walletconnect") throw new Error(chainSwitchMessage(e));
    throw e;
  }
}

/** What to tell a WalletConnect user whose wallet would not move to the live chain.
 *  The rejection verdict comes from the shared classifier — a declined EIP-3326
 *  request in any of its shapes (code 4001 / ACTION_REJECTED, viem's typed error,
 *  a SwitchChainError wrapping the user's refusal). */
export function chainSwitchMessage(e: unknown): string {
  const failure = classifyChainFailure(e);
  if (failure.kind === "user_rejected" || (failure.kind === "chain_switch" && failure.rejected)) {
    return `You declined the network switch. bongtu only works on ${CHAIN_NAME}.`;
  }
  return (
    `Your wallet didn't switch to ${CHAIN_NAME}. Add or select that network in the wallet ` +
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
