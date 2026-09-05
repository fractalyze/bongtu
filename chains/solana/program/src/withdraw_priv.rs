//! `withdraw_priv` (2-in / 1-out change + proof-bound public recipient) —
//! WithdrawPrivModule.sol's twin. RELAYABLE: tokens go to the proof-bound
//! recipient token account, never the fee payer.
//!
//! Wire: after the 1-byte discriminator the payload is
//!   proof(256) || 13 carried publics || 1 × 1088 B kem ct ||
//!   stealth announcement pair (32 B ephemeral pub + 1 B view tag)
//! Carried publics are the withdrawPriv vector minus `enabled[2]`
//! (pub[11..13], reconstructed as `nullifier[i] != 0`) and minus `recipient`
//! (pub[15], bound from the accounts list — SOLR §2.3 / OPEN-3):
//!   full publics (16): [0]=out [1..2]=ecdhPub [3..6]=ctChange [7]=viewTag
//!   [8..9]=nullifiers [10]=root [11..12]=enabled [13]=oc0(change)
//!   [14]=nonce [15]=recipient
//!
//! OPEN-3 recipient binding (truncate-253, recipient_binding.rs): pub[15] is
//! injected as the low 253 bits of the recipient token account address. The
//! prover never controls the injected value; a proof bound to any other
//! recipient fails verify (`InvalidProof`). The SPL owner/mint checks on the
//! recipient run BEFORE the binding, so the bound target is always a real
//! payee of the pool's mint.
//!
//! The stealth pair is calldata-class ledger data (tampering can only break
//! discovery; funds still reach the proof-bound recipient — the EVM
//! WithdrawAnnouncement property); the program checks only its length.
//!
//! Accounts:
//!   0 pool config (ro)           1 tree state (w)
//!   2 spent KnownRoot PDA (ro)   3 new KnownRoot PDA (w)
//!   4 payer (w, signer)          5 system program
//!   6 event authority PDA        7 this program (self-CPI target)
//!   8 SPL token program          9 vault (w)
//!   10 vault authority PDA (ro)  11 recipient token account (w)
//!   12.. one Nullifier PDA (w) per NONZERO nullifier, in signal order

use {
    crate::{
        error::PoolError,
        event::{self, FAMILY_TAG_WITHDRAW_PRIV},
        generated::vk_withdraw_priv,
        groth16::{self, PROOF_LEN},
        op_common,
        recipient_binding,
        spl,
        state::{self, FAMILY_WITHDRAW_PRIV, SEED_VAULT_AUTHORITY},
    },
    solana_program::{account_info::AccountInfo, pubkey::Pubkey},
};

pub const DISCRIMINATOR: u8 = 5;

pub const N_PUBLIC: usize = 16;
pub const CARRIED_PUBLICS: usize = 13;
pub const KEM_CT_LEN: usize = 1088;
pub const KEM_CT_COUNT: usize = 1;
/// 32 B stealth ephemeral pub + 1 B stealth view tag.
pub const STEALTH_TAIL_LEN: usize = 33;
/// proof || carried publics || kem ct || stealth pair — 1,793 B.
pub const PAYLOAD_LEN: usize =
    PROOF_LEN + CARRIED_PUBLICS * 32 + KEM_CT_COUNT * KEM_CT_LEN + STEALTH_TAIL_LEN;

pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), PoolError> {
    // --- accounts ---------------------------------------------------------
    if accounts.len() < 12 {
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
    let token_program = &accounts[8];
    let vault = &accounts[9];
    let vault_authority = &accounts[10];
    let recipient_token = &accounts[11];
    let nf_accounts = &accounts[12..];

    op_common::check_common(program_id, config, tree, system_program, FAMILY_WITHDRAW_PRIV)?;
    spl::check_token_program(token_program)?;
    if vault.key.to_bytes() != state::config_vault(config)? {
        return Err(PoolError::InvalidAccount);
    }
    let (expected_vault_authority, vault_authority_bump) =
        Pubkey::find_program_address(&[SEED_VAULT_AUTHORITY, config.key.as_ref()], program_id);
    if vault_authority.key != &expected_vault_authority {
        return Err(PoolError::PdaMismatch);
    }

    // --- wire shape -------------------------------------------------------
    if payload.len() != PAYLOAD_LEN {
        return Err(PoolError::WrongKemCiphertextLength);
    }
    let (proof, carried) = op_common::parse_carried::<CARRIED_PUBLICS>(payload);
    op_common::check_canonical(&carried)?;

    // --- OPEN-3 recipient binding (SPL checks first, then the mask) --------
    let mint = state::config_mint(config)?;
    spl::check_token_account(recipient_token, &mint)?;
    let bound = recipient_binding::bound_recipient_be(recipient_token.key);
    if groth16::is_zero(&bound) {
        return Err(PoolError::InvalidRecipient);
    }

    // --- reconstruct the full public vector (enabled + recipient injected) -
    let nullifiers = [carried[8], carried[9]];
    let spent_root = carried[10];
    let change_commitment = carried[11];

    let mut publics = [[0u8; 32]; N_PUBLIC];
    publics[..11].copy_from_slice(&carried[..11]);
    publics[11][31] = u8::from(!groth16::is_zero(&nullifiers[0]));
    publics[12][31] = u8::from(!groth16::is_zero(&nullifiers[1]));
    publics[13] = carried[11];
    publics[14] = carried[12];
    publics[15] = bound;

    // --- invariant gate ---------------------------------------------------
    if groth16::is_zero(&change_commitment) {
        return Err(PoolError::ZeroOutputCommitment);
    }
    let amount = spl::amount_u64(&carried[0])?;
    let checks = op_common::check_spend(
        program_id,
        &nullifiers,
        &spent_root,
        spent_root_acc,
        nf_accounts,
    )?;

    // --- verify -----------------------------------------------------------
    if !groth16::verify(&vk_withdraw_priv::VK, &proof, &publics)? {
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
    let (start_leaf_index, new_root) = op_common::append_leaves(tree, &[change_commitment])?;
    op_common::register_new_root(
        program_id,
        payer,
        new_root_acc,
        system_program,
        &new_root,
        rent_lamports,
    )?;

    // Escrow push last (CEI, applyOpWithPush order): vault -> the proof-bound
    // recipient, signed by the vault authority PDA.
    spl::transfer_signed(
        token_program,
        vault,
        recipient_token,
        vault_authority,
        amount,
        &[
            SEED_VAULT_AUTHORITY,
            config.key.as_ref(),
            &[vault_authority_bump],
        ],
    )?;

    event::emit_op_event(
        program_id,
        event_authority,
        program_account,
        FAMILY_TAG_WITHDRAW_PRIV,
        start_leaf_index,
        1,
        &new_root,
        &checks.spending,
    )
}
