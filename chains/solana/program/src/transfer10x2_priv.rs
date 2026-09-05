//! `transfer10x2_priv` (10-in / 2-out consolidation + payment) —
//! Transfer10x2PrivModule.sol's twin, and the rail's tightest op by bytes
//! (SOLR §3.1.2: the no-derivable-publics wire is what makes it fit).
//!
//! Wire: after the 1-byte discriminator the payload is
//!   proof(256) || 26 carried publics (32 B BE each) || 2 × 1088 B kem cts
//! Carried publics are the transfer10x2Priv vector minus `enabled[10]`
//! (pub[23..33]), reconstructed as `nullifier[i] != 0`:
//!   full publics (36): [0..1]=ecdhPub [2..9]=cts [10..11]=viewTags
//!   [12..21]=nullifiers [22]=root [23..32]=enabled [33..34]=oc [35]=nonce
//!
//! Accounts (the transfer_priv layout, up to 10 Nullifier PDAs):
//!   0 pool config (ro)          1 tree state (w)
//!   2 spent KnownRoot PDA (ro)  3 new KnownRoot PDA (w)
//!   4 payer (w, signer)         5 system program
//!   6 event authority PDA       7 this program (self-CPI target)
//!   8.. one Nullifier PDA (w) per NONZERO nullifier, in signal order

use {
    crate::{
        error::PoolError,
        event::{self, FAMILY_TAG_TRANSFER10X2_PRIV},
        generated::vk_transfer10x2_priv,
        groth16::{self, PROOF_LEN},
        op_common,
        state::FAMILY_TRANSFER10X2_PRIV,
    },
    solana_program::{account_info::AccountInfo, pubkey::Pubkey},
};

pub const DISCRIMINATOR: u8 = 4;

pub const N_PUBLIC: usize = 36;
pub const ARITY: usize = 10;
pub const CARRIED_PUBLICS: usize = 26;
pub const KEM_CT_LEN: usize = 1088;
pub const KEM_CT_COUNT: usize = 2;
/// proof || carried publics || kem cts — 3,264 B (SOLR §3.1.2: the tightest
/// op; the tx-size gate asserts the fully-built worst-case tx fits 4,096 B).
pub const PAYLOAD_LEN: usize = PROOF_LEN + CARRIED_PUBLICS * 32 + KEM_CT_COUNT * KEM_CT_LEN;

pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), PoolError> {
    // --- accounts ---------------------------------------------------------
    if accounts.len() < 8 {
        return Err(PoolError::InvalidAccount);
    }
    let config = &accounts[0];
    let tree = &accounts[1];
    let spent_root_acc = &accounts[2];
    let new_root_acc = &accounts[3];
    let payer = &accounts[4];
    let system_program = &accounts[5];
    let event_authority = &accounts[6];
    let program_account = &accounts[7];
    let nf_accounts = &accounts[8..];

    op_common::check_common(program_id, config, tree, system_program, FAMILY_TRANSFER10X2_PRIV)?;

    // --- wire shape -------------------------------------------------------
    if payload.len() != PAYLOAD_LEN {
        return Err(PoolError::WrongKemCiphertextLength);
    }
    let (proof, carried) = op_common::parse_carried::<CARRIED_PUBLICS>(payload);
    op_common::check_canonical(&carried)?;

    // --- reconstruct the full public vector (enabled[10] injected) --------
    let nullifiers: [[u8; 32]; ARITY] = {
        let mut nfs = [[0u8; 32]; ARITY];
        nfs.copy_from_slice(&carried[12..22]);
        nfs
    };
    let spent_root = carried[22];
    let output_commitments = [carried[23], carried[24]];

    let mut publics = [[0u8; 32]; N_PUBLIC];
    publics[..23].copy_from_slice(&carried[..23]);
    for (i, nf) in nullifiers.iter().enumerate() {
        publics[23 + i][31] = u8::from(!groth16::is_zero(nf));
    }
    publics[33..36].copy_from_slice(&carried[23..26]);

    // --- invariant gate ---------------------------------------------------
    for oc in &output_commitments {
        if groth16::is_zero(oc) {
            return Err(PoolError::ZeroOutputCommitment);
        }
    }
    let checks = op_common::check_spend(
        program_id,
        &nullifiers,
        &spent_root,
        spent_root_acc,
        nf_accounts,
    )?;

    // --- verify -----------------------------------------------------------
    if !groth16::verify(&vk_transfer10x2_priv::VK, &proof, &publics)? {
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
    let (start_leaf_index, new_root) = op_common::append_leaves(tree, &output_commitments)?;
    op_common::register_new_root(
        program_id,
        payer,
        new_root_acc,
        system_program,
        &new_root,
        rent_lamports,
    )?;

    event::emit_op_event(
        program_id,
        event_authority,
        program_account,
        FAMILY_TAG_TRANSFER10X2_PRIV,
        start_leaf_index,
        2,
        &new_root,
        &checks.spending,
    )
}
