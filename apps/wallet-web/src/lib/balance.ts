// Balance: sum the wallet's UNSPENT notes (SPEC §7 public app). ONE path:
// signed `GET /notes` against an arbiter-mode indexer. The arbiter has already
// decrypted every op's authority envelope into a per-owner note directory with a
// `spent` flag; the wallet proves control of its key (EdDSA-Poseidon read-auth)
// and reads its own row. O(own notes). Balance requires that indexer to be
// reachable — there is no fallback (decision 2026-07-25, architecture-review #17b:
// the product scenario depends on the indexer).
//
// `trialDecryptEvents` + `sumUnspent` below are NOT called by any wallet balance
// path. They remain here as the tested discovery primitive for the SPEC §7/§11-7
// protocol property — every receiver ciphertext slice on the public /events feed
// is key-only recoverable (ECDH-decrypt [value, salt], rebuild the commitment,
// accept iff it equals the on-chain leaf; the Poseidon sponge has no MAC, so the
// leaf-match IS the "is this mine" test) — and for future recovery tooling.
//
// The pure cores (`sumUnspent`, `trialDecryptEvents`) are framework- and
// network-free so the headless balance gate exercises them directly on mock data.

import {
  commitment,
  nullifier,
  poseidonDecrypt,
  ecdhSharedSecret,
} from "@bongtu/sdk/note";
import type { WalletIdentity } from "./derive.js";
import {
  buildNotesUrl,
  fetchNotes,
  type OwnerNote,
  type FeedEvent,
} from "./indexerClient.js";

/** Anything with a decimal value and a spent flag sums the same way. */
export interface UnspentSummable {
  value: string;
  spent: boolean;
}

/** A note the wallet discovered by trial-decrypting the public /events feed. */
export interface DiscoveredNote {
  value: string;
  salt: string;
  leafIndex: number;
  commitment: string;
  nullifier: string;
  txHash: string;
  spent: boolean;
}

/** Balance = sum(value) over the notes that are not spent. PURE. */
export function sumUnspent(notes: UnspentSummable[]): bigint {
  let total = 0n;
  for (const n of notes) if (!n.spent) total += BigInt(n.value);
  return total;
}

/** Context a key-only trial-decrypt needs beyond the /events feed itself. */
export interface TrialDecryptContext {
  /** leafIndex -> the real on-chain leaf commitment (decimal), from Appended events
   *  (the browser getLogs / indexer-mirror boundary, SPEC §11-7). The MAC substitute:
   *  a decrypted note is the wallet's iff its rebuilt commitment equals this leaf. */
  leafCommitments: Map<number, string>;
  /** spent nullifier set (decimal), from GET /nullifiers. */
  spentNullifiers: Set<string>;
}

/**
 * Discover the wallet's notes by trial-decrypting receiver ciphertext slices in the
 * /events feed (SPEC §6 recovery). PURE. A receiver envelope encrypts exactly
 * [value, salt] (2 field elements -> a 4-element Poseidon-sponge ciphertext), so we
 * only attempt 4-element leaf-bearing slices. Decrypting with the wrong key yields
 * garbage whose rebuilt commitment will not match the on-chain leaf, so it is
 * dropped; the surviving notes are genuinely the wallet's.
 */
export function trialDecryptEvents(
  events: FeedEvent[],
  identity: WalletIdentity,
  ctx: TrialDecryptContext,
): DiscoveredNote[] {
  const { keypair } = identity;
  const found: DiscoveredNote[] = [];
  for (const ev of events) {
    if (!ev.ecdhPublicKey || ev.encryptionNonce == null) continue; // no receiver key material
    const ephemeralPub: [bigint, bigint] = [BigInt(ev.ecdhPublicKey[0]), BigInt(ev.ecdhPublicKey[1])];
    const shared = ecdhSharedSecret(keypair.formattedPrivateKey, ephemeralPub);
    const nonce = BigInt(ev.encryptionNonce);
    for (const slice of ev.slices) {
      if (slice.leafIndex == null || slice.elts !== 4) continue; // only per-recipient leaf envelopes
      const ct = ev.ciphertext.slice(slice.offset, slice.offset + slice.elts);
      if (ct.length !== 4) continue;
      let value: bigint;
      let salt: bigint;
      try {
        [value, salt] = poseidonDecrypt(ct.map((x) => BigInt(x)), shared, nonce, 2);
      } catch {
        continue;
      }
      const c = commitment(value, salt, keypair.publicKey);
      const known = ctx.leafCommitments.get(slice.leafIndex);
      if (known === undefined || BigInt(known) !== c) continue; // garbage decrypt or not our leaf
      const nf = nullifier(value, salt, keypair.formattedPrivateKey);
      found.push({
        value: value.toString(),
        salt: salt.toString(),
        leafIndex: slice.leafIndex,
        commitment: c.toString(),
        nullifier: nf.toString(),
        txHash: ev.txHash,
        spent: ctx.spentNullifiers.has(nf.toString()),
      });
    }
  }
  return found;
}

// --- network orchestration (thin; the pure cores above carry the logic) ----------

export interface BalanceResult {
  balance: bigint;
  notes: OwnerNote[];
  source: "notes";
}

/** The wallet's balance path: signed /notes against an arbiter-mode indexer. */
export async function balanceViaNotes(indexerUrl: string, identity: WalletIdentity): Promise<BalanceResult> {
  const url = buildNotesUrl(indexerUrl, identity.compressedPubkey, identity.keypair.formattedPrivateKey);
  const notes = await fetchNotes(url);
  return { balance: sumUnspent(notes), notes, source: "notes" };
}
