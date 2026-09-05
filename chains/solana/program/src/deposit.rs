//! `deposit` (enterprise 0-in / 2-out mint, arbiter-enveloped) —
//! BongtuPool.deposit's twin (S3, SOLR §3.3 / OPEN-1). The authority
//! envelope's public key is injected from `PoolConfig` before verify, so a
//! deposit not encrypted to the stored arbiter key FAILS the proof (§6b v2
//! enforced disclosure — the key-injection discipline).
//!
//! Wire: after the 1-byte discriminator the payload is
//!   proof(256) || 17 carried publics (32 B BE each) || 1 × 1088 B kem ct
//! Carried publics are the deposit vector minus the injected arbiter key
//! (pub[17..18]):
//!   full publics (19): [0]=out [1..2]=ecdhPub [3..12]=cipherTextAuthority[10]
//!   [13]=kemBinding [14..15]=outputCommitments [16]=nonce
//!   [17..18]=authorityPubKey (injected)
//!
//! The kem ciphertext is the ML-KEM-768 encapsulation to the arbiter KEM key:
//! length-checked only, content bound off-chain by the proof's kemBinding
//! (pub[13]) + arbiter decapsulation — exactly the EVM `_checkKemCiphertext`
//! posture.
//!
//! Accounts (same layout as deposit_priv):
//!   0 pool config (ro)        1 tree state (w)
//!   2 new KnownRoot PDA (w)   3 payer (w, signer)
//!   4 system program          5 event authority PDA
//!   6 this program            7 SPL token program
//!   8 payer token account (w) 9 vault (w)

use {
    crate::{
        error::PoolError,
        event::{self, FAMILY_TAG_DEPOSIT},
        generated::vk_deposit,
        groth16::{self, PROOF_LEN},
        op_common,
        spl,
        state::{self, FAMILY_DEPOSIT},
    },
    solana_program::{account_info::AccountInfo, pubkey::Pubkey},
};

pub const DISCRIMINATOR: u8 = 6;

pub const N_PUBLIC: usize = 19;
pub const CARRIED_PUBLICS: usize = 17;
pub const KEM_CT_LEN: usize = 1088;
pub const KEM_CT_COUNT: usize = 1;
/// proof || carried publics || kem ct — 1,888 B.
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

    op_common::check_common(program_id, config, tree, system_program, FAMILY_DEPOSIT)?;
    spl::check_token_program(token_program)?;
    if vault.key.to_bytes() != state::config_vault(config)? {
        return Err(PoolError::InvalidAccount);
    }
    let arbiter = op_common::arbiter_key(config)?;

    // --- wire shape (kem ct count/length is a fixed-layout property) ------
    if payload.len() != PAYLOAD_LEN {
        return Err(PoolError::WrongKemCiphertextLength);
    }
    let (proof, carried) = op_common::parse_carried::<CARRIED_PUBLICS>(payload);
    op_common::check_canonical(&carried)?;

    // --- invariant gate (no spend: the leaf checks and the amount belt) ----
    let output_commitments = [carried[14], carried[15]];
    for oc in &output_commitments {
        if groth16::is_zero(oc) {
            return Err(PoolError::ZeroOutputCommitment);
        }
    }
    let amount = spl::amount_u64(&carried[0])?;

    // --- reconstruct the full public vector (arbiter key injected) --------
    let mut publics = [[0u8; 32]; N_PUBLIC];
    publics[..CARRIED_PUBLICS].copy_from_slice(&carried);
    publics[17] = arbiter[0];
    publics[18] = arbiter[1];

    // --- verify ------------------------------------------------------------
    if !groth16::verify(&vk_deposit::VK, &proof, &publics)? {
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

    // Escrow pull last (CEI, the applyOpWithPull order).
    spl::transfer(token_program, payer_token, vault, payer, amount)?;

    event::emit_op_event(
        program_id,
        event_authority,
        program_account,
        FAMILY_TAG_DEPOSIT,
        start_leaf_index,
        2,
        &new_root,
        &[],
    )
}
