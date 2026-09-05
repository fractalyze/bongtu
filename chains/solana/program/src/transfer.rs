//! `transfer` (enterprise 2-in / 2-out, arbiter-enveloped) —
//! BongtuPool.transfer's twin (S3 pass 2, SOLR §3.3 / OPEN-1 full family).
//! The authority envelope's public key is injected from `PoolConfig` before
//! verify, so a transfer not encrypted to the stored arbiter key FAILS the
//! proof (§6b v2 enforced disclosure — the key-injection discipline), and
//! `enabled[i]` is reconstructed as `nullifier[i] != 0` (the EVM injection
//! rule) — the prover controls neither.
//!
//! Wire: after the 1-byte discriminator the payload is
//!   proof(256) || 33 carried publics (32 B BE each) || 1 × 1088 B kem ct
//! Carried publics are the transfer vector minus `enabled[2]` (pub[30..31])
//! and the arbiter key (pub[35..36], config-injected):
//!   full publics (37): [0..1]=ecdhPub [2..9]=cipherTexts[2][4]
//!   [10..25]=cipherTextAuthority[16] [26]=kemBinding [27..28]=nullifiers
//!   [29]=root [30..31]=enabled [32..33]=outputCommitments [34]=nonce
//!   [35..36]=authorityPubKey
//!
//! The receiver ciphertexts and the 16-element authority envelope ride
//! INSIDE the verified public vector (the EVM `uint[37]` posture); the one
//! free tail is the 1,088 B arbiter ML-KEM ct, length-checked only — content
//! is bound off-chain by kemBinding (pub[26]) + arbiter decapsulation,
//! exactly the EVM `_checkKemCiphertext` posture.
//!
//! Accounts (the transfer_priv layout):
//!   0 pool config (ro)          1 tree state (w)
//!   2 spent KnownRoot PDA (ro)  3 new KnownRoot PDA (w)
//!   4 payer (w, signer)         5 system program
//!   6 event authority PDA       7 this program (self-CPI target)
//!   8.. one Nullifier PDA (w) per NONZERO nullifier, in signal order

use {
    crate::{
        error::PoolError,
        event::{self, FAMILY_TAG_TRANSFER},
        generated::vk_transfer,
        groth16::{self, PROOF_LEN},
        op_common,
        state::FAMILY_TRANSFER,
    },
    solana_program::{account_info::AccountInfo, pubkey::Pubkey},
};

pub const DISCRIMINATOR: u8 = 9;

pub const N_PUBLIC: usize = 37;
pub const CARRIED_PUBLICS: usize = 33;
pub const KEM_CT_LEN: usize = 1088;
pub const KEM_CT_COUNT: usize = 1;
/// proof || carried publics || kem ct — 2,400 B (S3 pass 2 worksheet).
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

    op_common::check_common(program_id, config, tree, system_program, FAMILY_TRANSFER)?;
    let arbiter = op_common::arbiter_key(config)?;

    // --- wire shape (kem ct count/length is a fixed-layout property) ------
    if payload.len() != PAYLOAD_LEN {
        return Err(PoolError::WrongKemCiphertextLength);
    }
    let (proof, carried) = op_common::parse_carried::<CARRIED_PUBLICS>(payload);
    op_common::check_canonical(&carried)?;

    // --- reconstruct the full public vector (enabled + arbiter injected) --
    let nullifiers = [carried[27], carried[28]];
    let spent_root = carried[29];
    let output_commitments = [carried[30], carried[31]];

    let mut publics = [[0u8; 32]; N_PUBLIC];
    publics[..30].copy_from_slice(&carried[..30]);
    publics[30][31] = u8::from(!groth16::is_zero(&nullifiers[0]));
    publics[31][31] = u8::from(!groth16::is_zero(&nullifiers[1]));
    publics[32..35].copy_from_slice(&carried[30..33]);
    publics[35] = arbiter[0];
    publics[36] = arbiter[1];

    // --- invariant gate: the _applyOp mirror, run before the expensive
    //     verify (see op_common.rs for why the order deviates from EVM) -----
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
    if !groth16::verify(&vk_transfer::VK, &proof, &publics)? {
        return Err(PoolError::InvalidProof);
    }

    // --- state writes (all checks passed; failures below abort the tx) ----
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
        FAMILY_TAG_TRANSFER,
        start_leaf_index,
        2,
        &new_root,
        &checks.spending,
    )
}
