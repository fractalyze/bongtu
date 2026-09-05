//! `disburse256` (enterprise 1-in / 256-out) — the 1-tx disclosureHash design
//! (SOLR §3.3): the chain enforces the BINDING (disclosureHash is a proof
//! public persisted per batch in the `DisburseBatch` PDA); the 65,728 B
//! disclosure BYTES are served from institution storage and any party
//! verifies them by refolding against the on-chain hash — no key, no trust,
//! only availability. The program appends nothing per-leaf and hashes no
//! disclosure bytes: the 2054-element fold happened in-circuit; the chain
//! holds its output. (The ~19-tx consensus-forced-publication variant is
//! SOLR §3.3.3, documented only.)
//!
//! Wire: after the 1-byte discriminator the payload is
//!   proof(256) || 8 carried publics (32 B BE each) || 1 × 1088 B kem ct
//! Carried publics are the disburse vector minus `enabled` (pub[7],
//! unconditionally 1 — the sole input is real, guarded by ZeroNullifier) and
//! the arbiter key (pub[9..10], config-injected — a proof against any other
//! key fails):
//!   full publics (11): [0..1]=ecdhPub [2]=disclosureHash [3]=subtreeRoot
//!   [4]=kemBinding [5]=nullifier [6]=root [7]=enabled [8]=nonce
//!   [9..10]=authorityPubKey
//!
//! The 1,088 B arbiter kemCiphertext is length-checked only (FIPS 203 pins
//! the ct size; content is bound off-chain by kemBinding + decapsulation).
//!
//! State effect: spend the nullifier, attach the 256-leaf subtree at LOG_B
//! (closing any pending partial block, the EVM `_attachSubtree` shape),
//! register the post-attach root, and persist the batch's audit anchor
//! `(start_leaf_index, disclosureHash, kemBinding, epoch)` in a
//! `DisburseBatch` PDA. The self-CPI event carries the same tuple.
//!
//! Accounts:
//!   0 pool config (ro)           1 tree state (w)
//!   2 spent KnownRoot PDA (ro)   3 new KnownRoot PDA (w)
//!   4 DisburseBatch PDA (w)      5 payer (w, signer)
//!   6 system program             7 event authority PDA
//!   8 this program (self-CPI target)
//!   9 the Nullifier PDA (w)

use {
    crate::{
        error::PoolError,
        event::{self, FAMILY_TAG_DISBURSE256},
        generated::vk_disburse256,
        groth16::{self, PROOF_LEN},
        op_common,
        state::{
            self, ARBITER_EPOCH_GENESIS, BATCH_OFF_DISCLOSURE_HASH, BATCH_OFF_EPOCH,
            BATCH_OFF_KEM_BINDING, BATCH_OFF_START, DISBURSE_BATCH_LEN, FAMILY_DISBURSE256,
            SEED_DISBURSE_BATCH, TAG_DISBURSE_BATCH,
        },
    },
    solana_program::{account_info::AccountInfo, pubkey::Pubkey},
};

pub const DISCRIMINATOR: u8 = 8;

pub const N_PUBLIC: usize = 11;
pub const CARRIED_PUBLICS: usize = 8;
/// The circuit's output subtree depth: disburse256 folds exactly 256 leaves
/// in-circuit, so the attach level is pinned at 8 regardless of config B.
pub const CIRCUIT_LOG_B: usize = 8;
pub const KEM_CT_LEN: usize = 1088;
pub const KEM_CT_COUNT: usize = 1;
/// proof || carried publics || kem ct — 1,600 B (the SOLR §3.3.1 ~1.7 KB
/// single-tx payload; gate 4 asserts the ceiling).
pub const PAYLOAD_LEN: usize = PROOF_LEN + CARRIED_PUBLICS * 32 + KEM_CT_COUNT * KEM_CT_LEN;

pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), PoolError> {
    // --- accounts ---------------------------------------------------------
    if accounts.len() < 10 {
        return Err(PoolError::InvalidAccount);
    }
    let config = &accounts[0];
    let tree = &accounts[1];
    let spent_root_acc = &accounts[2];
    let new_root_acc = &accounts[3];
    let batch_acc = &accounts[4];
    let payer = &accounts[5];
    let system_program = &accounts[6];
    let event_authority = &accounts[7];
    let program_account = &accounts[8];
    let nf_accounts = &accounts[9..];

    op_common::check_common(program_id, config, tree, system_program, FAMILY_DISBURSE256)?;
    let arbiter = op_common::arbiter_key(config)?;
    let log_b = state::config_batch_log_b(config)?;
    // The subtree root public is proof-bound at depth 8: a future initialize
    // with B != 256 must fail loudly here, not mint an unspendable batch.
    if log_b != CIRCUIT_LOG_B {
        return Err(PoolError::WrongBatchSize);
    }

    // --- wire shape -------------------------------------------------------
    if payload.len() != PAYLOAD_LEN {
        return Err(PoolError::WrongKemCiphertextLength);
    }
    let (proof, carried) = op_common::parse_carried::<CARRIED_PUBLICS>(payload);
    op_common::check_canonical(&carried)?;

    // --- invariant gate ---------------------------------------------------
    let disclosure_hash = carried[2];
    let subtree_root = carried[3];
    let kem_binding = carried[4];
    let nullifier = carried[5];
    let spent_root = carried[6];

    // The 1-in disburse always spends a real note (the EVM `_disburseCore`
    // ZeroNullifier guard), which is what makes injecting enabled=1 sound.
    if groth16::is_zero(&nullifier) {
        return Err(PoolError::ZeroNullifier);
    }
    let checks = op_common::check_spend(
        program_id,
        &[nullifier],
        &spent_root,
        spent_root_acc,
        nf_accounts,
    )?;

    // --- reconstruct the full public vector -------------------------------
    let mut publics = [[0u8; 32]; N_PUBLIC];
    publics[..7].copy_from_slice(&carried[..7]);
    publics[7][31] = 1; // enabled: unconditionally 1 (nonzero nf guaranteed)
    publics[8] = carried[7];
    publics[9] = arbiter[0];
    publics[10] = arbiter[1];

    // --- verify -----------------------------------------------------------
    if !groth16::verify(&vk_disburse256::VK, &proof, &publics)? {
        return Err(PoolError::InvalidProof);
    }

    // --- state writes -----------------------------------------------------
    let rent_lamports = op_common::marker_rent()?;
    op_common::spend_nullifiers(
        program_id,
        payer,
        nf_accounts,
        system_program,
        &checks,
        rent_lamports,
    )?;
    let (start_leaf_index, new_root) = op_common::attach_subtree(tree, &subtree_root, log_b)?;
    op_common::register_new_root(
        program_id,
        payer,
        new_root_acc,
        system_program,
        &new_root,
        rent_lamports,
    )?;

    // DisburseBatch PDA — the durable audit anchor. The seed value is the
    // start leaf index (u64 LE, the counter convention), so the address is
    // deterministic from tree state and unique per batch: a program-owned
    // account here can only mean a corrupted account list.
    let start_le = start_leaf_index.to_le_bytes();
    let (expected_batch, batch_bump) =
        Pubkey::find_program_address(&[SEED_DISBURSE_BATCH, &start_le], program_id);
    if batch_acc.key != &expected_batch {
        return Err(PoolError::PdaMismatch);
    }
    if batch_acc.owner == program_id {
        return Err(PoolError::InvalidAccount);
    }
    op_common::create_pda(
        program_id,
        payer,
        batch_acc,
        system_program,
        &[SEED_DISBURSE_BATCH, &start_le, &[batch_bump]],
        DISBURSE_BATCH_LEN,
        op_common::rent_for(DISBURSE_BATCH_LEN)?,
    )?;
    {
        let mut data = batch_acc
            .try_borrow_mut_data()
            .map_err(|_| PoolError::InvalidAccount)?;
        data[0] = TAG_DISBURSE_BATCH;
        data[1] = 1;
        data[BATCH_OFF_START..BATCH_OFF_START + 8].copy_from_slice(&start_le);
        data[BATCH_OFF_DISCLOSURE_HASH..BATCH_OFF_DISCLOSURE_HASH + 32]
            .copy_from_slice(&disclosure_hash);
        data[BATCH_OFF_KEM_BINDING..BATCH_OFF_KEM_BINDING + 32].copy_from_slice(&kem_binding);
        data[BATCH_OFF_EPOCH..BATCH_OFF_EPOCH + 8]
            .copy_from_slice(&ARBITER_EPOCH_GENESIS.to_le_bytes());
    }

    event::emit_disburse_event(
        program_id,
        event_authority,
        program_account,
        FAMILY_TAG_DISBURSE256,
        start_leaf_index,
        &subtree_root,
        &new_root,
        &nullifier,
        &disclosure_hash,
        &kem_binding,
        ARBITER_EPOCH_GENESIS,
    )
}
