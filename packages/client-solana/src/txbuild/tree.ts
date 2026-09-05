// txbuild/tree.ts — the post-op root a submit must pre-compute. The program
// registers ONE KnownRoot PDA per op for the root AFTER its appends
// (chains/solana/README "KnownRoot is per-op"), and PDAs ride the accounts
// list, so the client derives the resulting root BEFORE sending: read the live
// TreeState (account offsets from the ONE rail facts module), hydrate the
// protocol's own ImtTree oracle with the frontier, append the op's output
// commitments, read the root. A concurrent op landing between the read and the
// send simply invalidates the derived PDA — the program re-derives and rejects
// (retryable), never a wrong-state write.

import { ImtTree } from "@bongtu/core/imt";
import {
  BATCH_B_CONSUMER,
  TAG_TREE_STATE,
  TREE_HEIGHT,
  TREE_OFF_FRONTIER,
  TREE_OFF_NEXT,
  TREE_OFF_ROOT,
  TREE_STATE_LEN,
} from "@bongtu/core/solana";

/** The TreeState slice a submit needs (state.rs fixed-offset layout). */
export interface SolanaTreeHead {
  nextLeafIndex: number;
  root: bigint;
  /** filledSubtrees[0..H), 32-byte BE field elements. */
  frontier: bigint[];
}

const be = (data: Uint8Array, off: number): bigint =>
  Array.from({ length: 32 }, (_, i) => data[off + i]).reduce<bigint>((acc, b) => (acc << 8n) | BigInt(b), 0n);

/** Parse a raw TreeState account image (byte rule: field elements 32 B BE,
 *  the nextLeafIndex counter u64 LE — @bongtu/core/solana module doc). */
export function parseTreeState(data: Uint8Array): SolanaTreeHead {
  if (data.length !== TREE_STATE_LEN || data[0] !== TAG_TREE_STATE) {
    throw new Error(`not a TreeState account (len ${data.length}, tag ${data[0]})`);
  }
  const next = Array.from({ length: 8 }, (_, i) => data[TREE_OFF_NEXT + i]).reduce<bigint>(
    (acc, b, i) => acc | (BigInt(b) << BigInt(8 * i)),
    0n,
  );
  return {
    nextLeafIndex: Number(next),
    root: be(data, TREE_OFF_ROOT),
    frontier: Array.from({ length: TREE_HEIGHT }, (_, i) => be(data, TREE_OFF_FRONTIER + 32 * i)),
  };
}

/**
 * The root after appending `leaves` to a tree in state `head` — computed by
 * hydrating the ONE tested IMT implementation (@bongtu/core/imt, the oracle
 * every rail gate folds with) rather than re-implementing the frontier fold.
 * Pure: the caller's head object is not mutated.
 */
export function appendedRoot(head: SolanaTreeHead, leaves: bigint[]): { root: bigint; startLeafIndex: number } {
  const tree = new ImtTree(TREE_HEIGHT, BATCH_B_CONSUMER);
  tree.nextLeafIndex = head.nextLeafIndex;
  for (const [i, v] of head.frontier.entries()) tree.filledSubtrees[i] = v;
  tree.root = head.root;
  const startLeafIndex = head.nextLeafIndex;
  for (const leaf of leaves) tree.appendLeaf(leaf);
  return { root: tree.getRoot(), startLeafIndex };
}
