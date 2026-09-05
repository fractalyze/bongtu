//! Single-frontier IMT (height 32) over `sol_poseidon` — the Rust port of an
//! algebra pinned twice already (packages/core `ImtTree` and the EVM pool's
//! `_insertNode`, held together by the Foundry differential test; SOLR §4.1).
//! Field-for-field mirror of `ImtTree._insertNode(node, startLevel)`:
//! left/right at level i is decided by bit parity of the node index, an even
//! index overwrites `filled_subtrees[i]` before hashing, and `zeros[i]`
//! stands in for the empty right sibling.

use {
    crate::{
        error::PoolError,
        generated::zeros::{TREE_HEIGHT, ZEROS},
        state::{TREE_OFF_FRONTIER, TREE_OFF_NEXT, TREE_OFF_ROOT, TREE_STATE_LEN},
    },
    solana_poseidon::{hashv, Endianness, Parameters},
};

/// Poseidon(2) over 32-byte big-endian field elements — bit-identical to
/// circomlib / packages/core poseidon2 (S0 #2, pinned by gate 1).
pub fn poseidon2(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], PoolError> {
    hashv(Parameters::Bn254X5, Endianness::BigEndian, &[left, right])
        .map(|h| h.to_bytes())
        .map_err(|_| PoolError::SyscallFailed)
}

/// In-memory frontier, deserialized from a `TreeState` account and written
/// back after every append batch in one place.
pub struct Frontier {
    pub next_leaf_index: u64,
    pub current_root: [u8; 32],
    pub filled_subtrees: [[u8; 32]; TREE_HEIGHT],
}

impl Frontier {
    pub fn load(data: &[u8]) -> Result<Self, PoolError> {
        if data.len() != TREE_STATE_LEN {
            return Err(PoolError::InvalidAccount);
        }
        let mut next = [0u8; 8];
        next.copy_from_slice(&data[TREE_OFF_NEXT..TREE_OFF_NEXT + 8]);
        let mut root = [0u8; 32];
        root.copy_from_slice(&data[TREE_OFF_ROOT..TREE_OFF_ROOT + 32]);
        let mut filled = [[0u8; 32]; TREE_HEIGHT];
        for (i, slot) in filled.iter_mut().enumerate() {
            let off = TREE_OFF_FRONTIER + 32 * i;
            slot.copy_from_slice(&data[off..off + 32]);
        }
        Ok(Self {
            next_leaf_index: u64::from_le_bytes(next),
            current_root: root,
            filled_subtrees: filled,
        })
    }

    pub fn store(&self, data: &mut [u8]) {
        data[TREE_OFF_NEXT..TREE_OFF_NEXT + 8].copy_from_slice(&self.next_leaf_index.to_le_bytes());
        data[TREE_OFF_ROOT..TREE_OFF_ROOT + 32].copy_from_slice(&self.current_root);
        for (i, slot) in self.filled_subtrees.iter().enumerate() {
            let off = TREE_OFF_FRONTIER + 32 * i;
            data[off..off + 32].copy_from_slice(slot);
        }
    }

    /// Fold `node` (at `start_level`, position next_leaf_index / 2^level) up
    /// to the root; returns the leaf index the insert started at.
    pub fn insert_node(&mut self, node: [u8; 32], start_level: usize) -> Result<u64, PoolError> {
        let stride = 1u64 << start_level;
        if self.next_leaf_index % stride != 0 {
            return Err(PoolError::MisalignedInsert);
        }
        if self.next_leaf_index + stride > 1u64 << TREE_HEIGHT {
            return Err(PoolError::TreeFull);
        }

        let mut index = self.next_leaf_index / stride;
        let mut current = node;
        for i in start_level..TREE_HEIGHT {
            let (left, right) = if index % 2 == 0 {
                self.filled_subtrees[i] = current;
                (current, ZEROS[i])
            } else {
                (self.filled_subtrees[i], current)
            };
            current = poseidon2(&left, &right)?;
            index /= 2;
        }
        self.current_root = current;
        let start = self.next_leaf_index;
        self.next_leaf_index += stride;
        Ok(start)
    }

    /// Standard single-leaf append (`ImtTree.appendLeaf`).
    pub fn append_leaf(&mut self, leaf: [u8; 32]) -> Result<u64, PoolError> {
        self.insert_node(leaf, 0)
    }

    /// Disburse batch attach — the EVM `_attachSubtree` mirror (BongtuPool
    /// §5.1 / ImtTree.attachSubtree): close the pending partial block up to a
    /// B boundary, then attach `subtree_root` at level `log_b`. Returns the
    /// batch's start leaf index.
    ///
    /// The close is O(LOG_B) folds, NOT O(B) zero-leaf inserts: the partial
    /// block's level-LOG_B node is computed treating positions rem..B-1 as
    /// zeros — bit i of rem selects the real left sibling filled_subtrees[i]
    /// (path node is a right child) or an empty right sibling ZEROS[i].
    /// Root-identical to padding one leaf at a time (pinned by the ImtTree
    /// oracle replay in the disburse256 conformance fixture). The sub-LOG_B
    /// frontier is left STALE, which is safe: next_leaf_index is B-aligned
    /// afterwards, so a fresh block overwrites filled_subtrees[i] (i < LOG_B)
    /// as a left child before any read — same argument as the EVM pool.
    pub fn attach_subtree(
        &mut self,
        subtree_root: [u8; 32],
        log_b: usize,
    ) -> Result<u64, PoolError> {
        let b = 1u64 << log_b;
        let rem = self.next_leaf_index % b;
        if rem != 0 {
            let mut node = ZEROS[0];
            for i in 0..log_b {
                node = if (rem >> i) & 1 == 1 {
                    poseidon2(&self.filled_subtrees[i], &node)?
                } else {
                    poseidon2(&node, &ZEROS[i])?
                };
            }
            self.next_leaf_index -= rem; // back to the B-aligned block start
            self.insert_node(node, log_b)?; // place the closed partial block
        }
        self.insert_node(subtree_root, log_b)
    }
}
