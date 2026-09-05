//! Gate 7 — `Frontier::attach_subtree` differential vectors (SOLR §4.1): the
//! close-loop branch coverage a single rem=1 disburse fixture cannot give.
//! Each committed case (attach_vectors.json, gen_attach_vectors.ts) replays
//! through the Rust frontier: seed by single-leaf appends, attach the depth-8
//! subtree at every pinned rem shape (0 block-aligned — empty tree and after
//! a full block — 1, 0b10101011 = 171, 255, plus one two-attach sequence),
//! and assert the start index, post root, next index, and the full 32-level
//! frontier against the ImtTree-oracle values. Sub-LOG_B levels hold the
//! program's stale pre-close frontier (the generator's splice note).

use {
    bongtu_pool_solana::{
        generated::zeros::{TREE_HEIGHT, ZEROS},
        tree::{poseidon2, Frontier},
    },
    bongtu_solana_harness::{hex32, load_attach_vectors},
};

const LOG_B: usize = 8;
const B: usize = 1 << LOG_B;

fn fresh_frontier() -> Frontier {
    let mut filled = [[0u8; 32]; TREE_HEIGHT];
    for (i, slot) in filled.iter_mut().enumerate() {
        *slot = ZEROS[i];
    }
    Frontier {
        next_leaf_index: 0,
        current_root: ZEROS[TREE_HEIGHT],
        filled_subtrees: filled,
    }
}

/// The depth-8 balanced fold over exactly B leaves — the in-circuit subtree
/// gadget recomputed independently, so each vector's subtreeRoot is pinned
/// against its own leaves before the attach runs.
fn subtree_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    assert_eq!(leaves.len(), B, "a disburse subtree carries exactly B leaves");
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    for _ in 0..LOG_B {
        level = (0..level.len() / 2)
            .map(|j| poseidon2(&level[2 * j], &level[2 * j + 1]).expect("poseidon fold"))
            .collect();
    }
    level[0]
}

#[test]
fn attach_vectors_pin_the_close_loop_shapes() {
    // The vector set itself is part of the contract: losing a rem shape (or
    // the two-attach sequence) silently un-covers a close-loop branch.
    let vx = load_attach_vectors();
    assert_eq!(vx.tree_height, TREE_HEIGHT, "vector tree height");
    assert_eq!(vx.log_b, LOG_B, "vector LOG_B");
    assert_eq!(vx.batch_b, B as u64, "vector B");
    let rems: Vec<u64> = vx.cases.iter().map(|c| c.rem).collect();
    for want in [0, 1, 0b1010_1011, 255] {
        assert!(rems.contains(&want), "missing rem={want} coverage");
    }
    assert!(
        vx.cases.iter().any(|c| c.attaches.len() == 2),
        "missing the two-consecutive-attach sequence"
    );
}

#[test]
fn attach_vectors_replay_the_imt_oracle() {
    let vx = load_attach_vectors();
    for case in &vx.cases {
        let name = &case.name;
        let mut frontier = fresh_frontier();
        for leaf in &case.pre_leaves {
            frontier.append_leaf(hex32(leaf)).expect("seed append");
        }
        assert_eq!(frontier.next_leaf_index, case.pre_state.next_leaf_index, "{name}: pre next");
        assert_eq!(
            frontier.current_root,
            hex32(&case.pre_state.current_root),
            "{name}: pre root != ImtTree oracle"
        );
        assert_eq!(frontier.next_leaf_index % vx.batch_b, case.rem, "{name}: rem shape");

        for (a, step) in case.attaches.iter().enumerate() {
            let leaves: Vec<[u8; 32]> = step.subtree_leaves.iter().map(|l| hex32(l)).collect();
            let root = subtree_root(&leaves);
            assert_eq!(root, hex32(&step.subtree_root), "{name}[{a}]: subtree root");

            let start = frontier.attach_subtree(root, LOG_B).expect("attach");
            assert_eq!(start, step.expected_start_leaf_index, "{name}[{a}]: start index");
            assert_eq!(
                frontier.current_root,
                hex32(&step.post_root),
                "{name}[{a}]: post root != ImtTree oracle"
            );
            assert_eq!(
                frontier.next_leaf_index, step.post_state.next_leaf_index,
                "{name}[{a}]: post next"
            );
            for (i, want) in step.post_state.filled_subtrees.iter().enumerate() {
                assert_eq!(
                    frontier.filled_subtrees[i],
                    hex32(want),
                    "{name}[{a}]: filled_subtrees[{i}]"
                );
            }
        }
    }
}
