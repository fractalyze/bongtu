// Stealth funds discovery: which one-time addresses are mine, and what sits on
// them. Two data sources, deliberately split by trust:
//
//   1. WHICH addresses — the indexer's per-owner announcement slice
//      (`/announcements?owner=`, arbiter mode). The wallet recomputes every
//      record locally: the view key re-derives the address from the announced
//      R, and a record that does not reproduce `recipient` is dropped — so a
//      wrong or tampering indexer can hide funds (availability) but can never
//      make the wallet claim an address that is not derivably the user's.
//   2. HOW MUCH — plain ERC-20 `balanceOf` per address against the chain RPC.
//      Balances never come from the indexer: a stealth address is an ordinary
//      public address once funded, and the chain is the source of truth.
//
// The core is dependency-injected (fetch + balance reader) so the whole
// discovery path tests headlessly; the app wires the signed announcements URL
// and a viem read.

import { parseAbi } from "viem";
import type { PublicClient } from "viem";
import { ERC20_ABI_FRAGMENTS } from "@bongtu/core/network";
import {
  scanStealthAnnouncement,
  recoverStealthKey,
  type StealthKeys,
} from "@bongtu/core/stealth";
import {
  buildAnnouncementsUrl,
  fetchAnnouncements,
  type WithdrawAnnouncementRecord,
} from "@bongtu/core/indexerApi";
import type { FieldInput } from "@bongtu/core/babyjub";

/** One recomputed-and-priced stealth holding. */
export interface StealthFund {
  /** the one-time EOA ("0x" + 20-byte hex, lowercase). */
  address: string;
  /** the announcement's packed bjj ephemeral pubkey R — the key-recovery input. */
  ephemeralPub: string;
  txHash: string;
  blockNumber: number;
  /** raw token units at the address right now (0 = already swept/spent). */
  balance: bigint;
}

export interface StealthDiscovery {
  funds: StealthFund[];
  /** sum over `funds` — the wallet's "stealth balance" headline. */
  total: bigint;
}

export interface DiscoverDeps {
  /** the caller's own announcements (the app wires the signed owner slice). */
  fetchMine: () => Promise<WithdrawAnnouncementRecord[]>;
  /** current token balance of one address (the app wires a viem read). */
  balanceOf: (address: string) => Promise<bigint>;
}

const ZERO32 = /^0x0{64}$/;

/**
 * Discover the user's stealth holdings. Records that announce nothing
 * (ephemeralPub zero — a plain-address withdraw), fail to parse, or do not
 * reproduce their own recipient under this identity's keys are skipped, not
 * fatal: the feed legitimately mixes other users' announcements (public path)
 * and non-stealth withdraws.
 */
export async function discoverStealthFunds(
  keys: StealthKeys,
  deps: DiscoverDeps,
): Promise<StealthDiscovery> {
  const mine: Omit<StealthFund, "balance">[] = [];
  for (const a of await deps.fetchMine()) {
    if (!a.ephemeralPub || ZERO32.test(a.ephemeralPub)) continue;
    let derived: { address: string };
    try {
      derived = scanStealthAnnouncement(keys.viewPriv, keys.meta.spendPub, a.ephemeralPub);
    } catch {
      continue; // malformed R — someone else's scheme or garbage calldata
    }
    if (derived.address.toLowerCase() !== a.recipient.toLowerCase()) continue;
    mine.push({
      address: derived.address,
      ephemeralPub: a.ephemeralPub,
      txHash: a.txHash,
      blockNumber: a.blockNumber,
    });
  }
  const funds = await Promise.all(
    mine.map(async (f) => ({ ...f, balance: await deps.balanceOf(f.address) })),
  );
  return { funds, total: funds.reduce((acc, f) => acc + f.balance, 0n) };
}

/** The one-time EOA's secp256k1 private key (standard 32-byte hex — importable
 *  into any wallet). The caller shows it once and never stores it. */
export function exportStealthFundKey(
  keys: StealthKeys,
  ephemeralPub: string,
): { privateKey: string; address: string } {
  return recoverStealthKey(keys.viewPriv, keys.spendPriv, ephemeralPub);
}

/** App wiring: the signed per-owner announcements fetch (spending-key
 *  read-auth — the same identity /notes reads under). */
export function ownedAnnouncementsFetcher(
  indexerUrl: string,
  ownerCompressed: string,
  ownerPrivateKey: FieldInput,
): () => Promise<WithdrawAnnouncementRecord[]> {
  return () => fetchAnnouncements(buildAnnouncementsUrl(indexerUrl, ownerCompressed, ownerPrivateKey));
}

const BALANCE_ABI = parseAbi([ERC20_ABI_FRAGMENTS.balanceOf]);

/** App wiring: a viem `balanceOf` reader over the deployment's token. */
export function erc20BalanceReader(
  publicClient: PublicClient,
  token: string,
): (address: string) => Promise<bigint> {
  return async (address) =>
    (await publicClient.readContract({
      address: token as `0x${string}`,
      abi: BALANCE_ABI,
      functionName: "balanceOf",
      args: [address as `0x${string}`],
    })) as bigint;
}
