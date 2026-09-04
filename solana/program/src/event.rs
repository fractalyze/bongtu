//! Self-CPI events (SOLR §3.2.1): the program invokes itself with the event
//! payload as instruction data, landing it in the tx's inner instructions —
//! consensus-committed and unstrippable, unlike `sol_log_data` (RPC-truncatable,
//! rejected for anything load-bearing). The event-authority PDA must co-sign,
//! so only the program itself (via `invoke_signed`) can produce the event —
//! an externally-crafted call to the event discriminator cannot forge it.

use {
    crate::{error::PoolError, state::SEED_EVENT_AUTHORITY},
    solana_program::{
        account_info::AccountInfo,
        instruction::{AccountMeta, Instruction},
        program::invoke_signed,
        pubkey::Pubkey,
    },
};

pub const EVENT_DISCRIMINATOR: u8 = 0xF0;

/// Op-family tags in the event payload (instruction discriminators double as
/// family provenance, SOLR §2.1; the event repeats the family for decoders
/// reading only inner instructions). Tag = instruction discriminator - 1.
pub const FAMILY_TAG_DEPOSIT_PRIV: u8 = 1;
pub const FAMILY_TAG_TRANSFER_PRIV: u8 = 2;
pub const FAMILY_TAG_TRANSFER10X2_PRIV: u8 = 3;
pub const FAMILY_TAG_WITHDRAW_PRIV: u8 = 4;

/// Payload: [EVENT_DISCRIMINATOR, family, start_leaf_index u64 LE,
/// leaf_count u8, resulting_root 32B BE, nf_count u8, nullifiers 32B BE each]
/// — the per-op anchor tuple of SOLR §3.2.1; `resulting_root` restores the
/// indexer's per-op mirror assertion.
pub fn emit_op_event<'a>(
    program_id: &Pubkey,
    event_authority: &AccountInfo<'a>,
    program_account: &AccountInfo<'a>,
    family: u8,
    start_leaf_index: u64,
    leaf_count: u8,
    resulting_root: &[u8; 32],
    nullifiers: &[[u8; 32]],
) -> Result<(), PoolError> {
    let (expected_authority, bump) =
        Pubkey::find_program_address(&[SEED_EVENT_AUTHORITY], program_id);
    if event_authority.key != &expected_authority {
        return Err(PoolError::InvalidEventAuthority);
    }

    let mut data = Vec::with_capacity(1 + 1 + 8 + 1 + 32 + 1 + 32 * nullifiers.len());
    data.push(EVENT_DISCRIMINATOR);
    data.push(family);
    data.extend_from_slice(&start_leaf_index.to_le_bytes());
    data.push(leaf_count);
    data.extend_from_slice(resulting_root);
    data.push(nullifiers.len() as u8);
    for nf in nullifiers {
        data.extend_from_slice(nf);
    }

    let ix = Instruction {
        program_id: *program_id,
        accounts: vec![AccountMeta::new_readonly(expected_authority, true)],
        data,
    };
    invoke_signed(
        &ix,
        &[event_authority.clone(), program_account.clone()],
        &[&[SEED_EVENT_AUTHORITY, &[bump]]],
    )
    .map_err(|_| PoolError::InvalidEventAuthority)
}

/// Handler for the event self-CPI: valid only when the event-authority PDA
/// signed, which only `invoke_signed` from this program can arrange. The body
/// is a no-op — the instruction exists to be recorded.
pub fn process_emit_event(program_id: &Pubkey, accounts: &[AccountInfo]) -> Result<(), PoolError> {
    let authority = accounts.first().ok_or(PoolError::InvalidEventAuthority)?;
    let (expected, _) = Pubkey::find_program_address(&[SEED_EVENT_AUTHORITY], program_id);
    if authority.key != &expected || !authority.is_signer {
        return Err(PoolError::InvalidEventAuthority);
    }
    Ok(())
}
