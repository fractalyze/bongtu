//! `transfer_priv` (2-in / 2-out consumer transfer) — the S2 tracer bullet,
//! now composed from the shared op skeleton (op_common.rs).
//!
//! Wire (SOLR §2.3 / §3.1.2 — no derivable publics): after the 1-byte
//! discriminator the payload is
//!   proof(256) || 18 carried publics (32 B BE each) || 2 × 1088 B kem cts
//! Carried publics are the transferPriv vector minus `enabled[2]`
//! (pub[15..16]), which the program reconstructs as `nullifier[i] != 0` —
//! the same injection rule as TransferPrivModule.sol, so the prover never
//! controls them.
//!
//! Accounts:
//!   0 pool config (ro)          1 tree state (w)
//!   2 spent KnownRoot PDA (ro)  3 new KnownRoot PDA (w)
//!   4 payer (w, signer)         5 system program
//!   6 event authority PDA       7 this program (self-CPI target)
//!   8.. one Nullifier PDA (w) per NONZERO nullifier, in signal order

use {
    crate::{
        error::PoolError,
        event::{self, FAMILY_TAG_TRANSFER_PRIV},
        generated::vk_transfer_priv,
        groth16::{self, PROOF_LEN},
        op_common,
        state::FAMILY_TRANSFER_PRIV,
    },
    solana_program::{account_info::AccountInfo, pubkey::Pubkey},
};

pub const DISCRIMINATOR: u8 = 3;

pub const N_PUBLIC: usize = 20;
pub const CARRIED_PUBLICS: usize = 18;
pub const KEM_CT_LEN: usize = 1088;
pub const KEM_CT_COUNT: usize = 2;
/// proof || carried publics || kem cts — 3,008 B (SOLR §3.1.2 worksheet).
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

    op_common::check_common(program_id, config, tree, system_program, FAMILY_TRANSFER_PRIV)?;

    // --- wire shape (kem ct count/length is a fixed-layout property) ------
    if payload.len() != PAYLOAD_LEN {
        return Err(PoolError::WrongKemCiphertextLength);
    }
    let (proof, carried) = op_common::parse_carried::<CARRIED_PUBLICS>(payload);
    op_common::check_canonical(&carried)?;
    // kem ciphertext bytes are non-proof-bound discovery material (OPMOD
    // §3.4): count and length are enforced by PAYLOAD_LEN; content is not
    // inspected — it can only break the sender's own delivery.

    // --- reconstruct the full public vector (enabled injected) ------------
    let nullifiers = [carried[12], carried[13]];
    let spent_root = carried[14];
    let output_commitments = [carried[15], carried[16]];

    let mut publics = [[0u8; 32]; N_PUBLIC];
    publics[..15].copy_from_slice(&carried[..15]);
    publics[15][31] = u8::from(!groth16::is_zero(&nullifiers[0]));
    publics[16][31] = u8::from(!groth16::is_zero(&nullifiers[1]));
    publics[17..20].copy_from_slice(&carried[15..18]);

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
    if !groth16::verify(&vk_transfer_priv::VK, &proof, &publics)? {
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
        FAMILY_TAG_TRANSFER_PRIV,
        start_leaf_index,
        2,
        &new_root,
        &checks.spending,
    )
}
