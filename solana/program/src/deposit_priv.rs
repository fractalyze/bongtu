//! `deposit_priv` (0-in / 2-out consumer mint) — DepositPrivModule.sol's twin.
//!
//! Wire (SOLR §2.3 / §3.1.2): after the 1-byte discriminator the payload is
//!   proof(256) || 16 carried publics (32 B BE each) || 2 × 1088 B kem cts
//! A 0-in mint has no `enabled` run and no injected signal, so ALL 16 publics
//! ride the wire:
//!   [0]=out [1..2]=ecdhPub [3..10]=cipherTexts[2][4] [11..12]=viewTags
//!   [13..14]=outputCommitments [15]=nonce
//!
//! Accounts:
//!   0 pool config (ro)        1 tree state (w)
//!   2 new KnownRoot PDA (w)   3 payer (w, signer)
//!   4 system program          5 event authority PDA
//!   6 this program            7 SPL token program
//!   8 payer token account (w) 9 vault (w)
//!
//! Escrow: pulls exactly pub[0] tokens from the payer's token account into
//! the config-bound vault, AFTER all tree writes (the applyOpWithPull CEI
//! order). The pull is proof-bound via pub[0]; the transfer authority is the
//! payer itself (a tx signer), the msg.sender-approves-the-core analogue.

use {
    crate::{
        error::PoolError,
        event::{self, FAMILY_TAG_DEPOSIT_PRIV},
        generated::vk_deposit_priv,
        groth16::{self, PROOF_LEN},
        op_common,
        spl,
        state::{self, FAMILY_DEPOSIT_PRIV},
    },
    solana_program::{account_info::AccountInfo, pubkey::Pubkey},
};

pub const DISCRIMINATOR: u8 = 2;

pub const N_PUBLIC: usize = 16;
pub const CARRIED_PUBLICS: usize = 16;
pub const KEM_CT_LEN: usize = 1088;
pub const KEM_CT_COUNT: usize = 2;
/// proof || carried publics || kem cts — 2,944 B (SOLR §3.1.2 worksheet).
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
    let new_root_acc = &accounts[2];
    let payer = &accounts[3];
    let system_program = &accounts[4];
    let event_authority = &accounts[5];
    let program_account = &accounts[6];
    let token_program = &accounts[7];
    let payer_token = &accounts[8];
    let vault = &accounts[9];

    op_common::check_common(program_id, config, tree, system_program, FAMILY_DEPOSIT_PRIV)?;
    spl::check_token_program(token_program)?;
    if vault.key.to_bytes() != state::config_vault(config)? {
        return Err(PoolError::InvalidAccount);
    }

    // --- wire shape (kem ct count/length is a fixed-layout property) ------
    if payload.len() != PAYLOAD_LEN {
        return Err(PoolError::WrongKemCiphertextLength);
    }
    let (proof, carried) = op_common::parse_carried::<CARRIED_PUBLICS>(payload);
    op_common::check_canonical(&carried)?;

    // --- invariant gate (no spend: the leaf checks and the amount belt) ----
    let output_commitments = [carried[13], carried[14]];
    for oc in &output_commitments {
        if groth16::is_zero(oc) {
            return Err(PoolError::ZeroOutputCommitment);
        }
    }
    let amount = spl::amount_u64(&carried[0])?;

    // --- verify (publics == carried: nothing is injected on a mint) -------
    if !groth16::verify(&vk_deposit_priv::VK, &proof, &carried)? {
        return Err(PoolError::InvalidProof);
    }

    // --- state writes -----------------------------------------------------
    let rent_lamports = op_common::marker_rent()?;
    let (start_leaf_index, new_root) = op_common::append_leaves(tree, &output_commitments)?;
    op_common::register_new_root(
        program_id,
        payer,
        new_root_acc,
        system_program,
        &new_root,
        rent_lamports,
    )?;

    // Escrow pull last (CEI, applyOpWithPull order).
    spl::transfer(token_program, payer_token, vault, payer, amount)?;

    event::emit_op_event(
        program_id,
        event_authority,
        program_account,
        FAMILY_TAG_DEPOSIT_PRIV,
        start_leaf_index,
        2,
        &new_root,
        &[],
    )
}
