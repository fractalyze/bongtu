// Balance: sum the wallet's UNSPENT notes (SPEC §7 public app). ONE path:
// `GET /notes` against an arbiter-mode indexer (view-token auth in the app —
// App.tsx builds the URLs; the one-shot key-signed form covers indexers without
// /auth at connect time). The arbiter has already decrypted every op's authority
// envelope into a per-owner note directory with a `spent` flag; the wallet reads
// its own row. O(own notes). Balance requires that indexer to be reachable —
// there is no fallback (decision 2026-07-25, architecture-review #17b: the
// product scenario depends on the indexer).
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
} from "@bongtu/core/note";
import type { WalletIdentity } from "@bongtu/client/derive";
import { type FeedEvent } from "@bongtu/client/indexerClient";

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
  return notes.reduce<bigint>((total, n) => (n.spent ? total : total + BigInt(n.value)), 0n);
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
 *
 * Per slice we try TWO nonces: the event nonce (pre-U-X3 history + disburse,
 * which share one nonce across outputs) and nonce + ctIndex (the transfer
 * circuit's §11-8 v1.1 per-output offset; ctIndex = the slice's position in the
 * receiver run, offset/4). The commitment-vs-leaf acceptance already rejects
 * every wrong-nonce garbage decrypt, so trying both is sound — old events keep
 * decrypting and post-upgrade self-sends recover BOTH notes.
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
      const ctIndex = BigInt(slice.offset / 4);
      const candidates = ctIndex === 0n ? [nonce] : [nonce, nonce + ctIndex];
      for (const tryNonce of candidates) {
        const decrypted = (() => {
          try {
            return poseidonDecrypt(ct.map((x) => BigInt(x)), shared, tryNonce, 2);
          } catch {
            return null;
          }
        })();
        if (decrypted === null) continue;
        const [value, salt] = decrypted;
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
        break; // a leaf-matched decrypt is THE note; no second nonce can also match
      }
    }
  }
  return found;
}

