//! `transfer10x2` (enterprise 10-in / 2-out consolidation + payment,
//! arbiter-enveloped) — BongtuPool.transfer10x2's twin (S3 pass 2,
//! SOLR §3.3 / OPEN-1 full family), and the widest enterprise wire on the
//! rail. The arbiter key is injected from `PoolConfig` (a proof against any
//! other key fails) and `enabled[i]` is reconstructed as `nullifier[i] != 0`
//! — the EVM injection rules, prover controls neither.
//!
//! Wire: after the 1-byte discriminator the payload is
//!   proof(256) || 56 carried publics (32 B BE each) || 1 × 1088 B kem ct
//! Carried publics are the transfer10x2 vector minus `enabled[10]`
//! (pub[53..62]) and the arbiter key (pub[66..67], config-injected):
//!   full publics (68): [0..1]=ecdhPub [2..9]=cipherTexts[2][4]
//!   [10..40]=cipherTextAuthority[31] [41]=kemBinding [42..51]=nullifiers
//!   [52]=root [53..62]=enabled [63..64]=outputCommitments [65]=nonce
//!   [66..67]=authorityPubKey
//!
//! The 8 receiver elements and the 31-element authority envelope ride INSIDE
//! the verified public vector (the EVM `uint[68]` posture); the free tail is
//! the 1,088 B arbiter ML-KEM ct, length-checked only. Byte worksheet
//! (S3 pass 2): payload 3,136 B, worst-case tx (18 accounts) 3,891 B — under
//! the 4,096 B Transaction v1 cap, and UNDER transfer10x2_priv (3,264 B
//! payload / 4,019 B tx), because the enterprise op carries one kem ct where
//! the consumer op carries two; the consumer 10x2 stays the tightest wire.
//!
//! Accounts (the transfer10x2_priv layout, up to 10 Nullifier PDAs):
//!   0 pool config (ro)          1 tree state (w)
//!   2 spent KnownRoot PDA (ro)  3 new KnownRoot PDA (w)
//!   4 payer (w, signer)         5 system program
//!   6 event authority PDA      7 this program (self-CPI target)
//!   8.. one Nullifier PDA (w) per NONZERO nullifier, in signal order

use {
    crate::{
        error::PoolError,
        event::{self, FAMILY_TAG_TRANSFER10X2},
        generated::vk_transfer10x2,
        groth16::{self, PROOF_LEN},
        op_common,
        state::FAMILY_TRANSFER10X2,
    },
    solana_program::{account_info::AccountInfo, pubkey::Pubkey},
};

pub const DISCRIMINATOR: u8 = 10;

pub const N_PUBLIC: usize = 68;
pub const ARITY: usize = 10;
pub const CARRIED_PUBLICS: usize = 56;
pub const KEM_CT_LEN: usize = 1088;
pub const KEM_CT_COUNT: usize = 1;
/// proof || carried publics || kem ct — 3,136 B (S3 pass 2 worksheet; the
/// tx-size gate asserts the fully-built worst-case tx fits 4,096 B).
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

    op_common::check_common(program_id, config, tree, system_program, FAMILY_TRANSFER10X2)?;
    let arbiter = op_common::arbiter_key(config)?;

    // --- wire shape -------------------------------------------------------
    if payload.len() != PAYLOAD_LEN {
        return Err(PoolError::WrongKemCiphertextLength);
    }
    let (proof, carried) = op_common::parse_carried::<CARRIED_PUBLICS>(payload);
    op_common::check_canonical(&carried)?;

    // --- reconstruct the full public vector (enabled[10] + key injected) --
    let nullifiers: [[u8; 32]; ARITY] = {
        let mut nfs = [[0u8; 32]; ARITY];
        nfs.copy_from_slice(&carried[42..52]);
        nfs
    };
    let spent_root = carried[52];
    let output_commitments = [carried[53], carried[54]];

    let mut publics = [[0u8; 32]; N_PUBLIC];
    publics[..53].copy_from_slice(&carried[..53]);
    for (i, nf) in nullifiers.iter().enumerate() {
        publics[53 + i][31] = u8::from(!groth16::is_zero(nf));
    }
    publics[63..66].copy_from_slice(&carried[53..56]);
    publics[66] = arbiter[0];
    publics[67] = arbiter[1];

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
    if !groth16::verify(&vk_transfer10x2::VK, &proof, &publics)? {
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
        FAMILY_TAG_TRANSFER10X2,
        start_leaf_index,
        2,
        &new_root,
        &checks.spending,
    )
}
