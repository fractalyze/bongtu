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
pub const FAMILY_TAG_DEPOSIT: u8 = 5;
pub const FAMILY_TAG_WITHDRAW: u8 = 6;
pub const FAMILY_TAG_DISBURSE256: u8 = 7;
pub const FAMILY_TAG_TRANSFER: u8 = 8;
pub const FAMILY_TAG_TRANSFER10X2: u8 = 9;

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

    emit(program_id, event_authority, program_account, bump, data)
}

/// Disburse event payload (SOLR §3.3.1 — the self-CPI carries the SAME tuple
/// the `DisburseBatch` PDA persists, for the indexer's streaming path):
/// [EVENT_DISCRIMINATOR, family, start_leaf_index u64 LE, subtree_root 32B BE,
/// resulting_root 32B BE, nullifier 32B BE, disclosure_hash 32B BE,
/// kem_binding 32B BE, epoch u64 LE]. A separate shape from `emit_op_event`
/// because a 256-leaf attach does not fit the per-op event's u8 leaf_count
/// and the batch tuple is the disburse anchor, not per-leaf appends.
#[allow(clippy::too_many_arguments)]
pub fn emit_disburse_event<'a>(
    program_id: &Pubkey,
    event_authority: &AccountInfo<'a>,
    program_account: &AccountInfo<'a>,
    family: u8,
    start_leaf_index: u64,
    subtree_root: &[u8; 32],
    resulting_root: &[u8; 32],
    nullifier: &[u8; 32],
    disclosure_hash: &[u8; 32],
    kem_binding: &[u8; 32],
    epoch: u64,
) -> Result<(), PoolError> {
    let (expected_authority, bump) =
        Pubkey::find_program_address(&[SEED_EVENT_AUTHORITY], program_id);
    if event_authority.key != &expected_authority {
        return Err(PoolError::InvalidEventAuthority);
    }

    let mut data = Vec::with_capacity(2 + 8 + 5 * 32 + 8);
    data.push(EVENT_DISCRIMINATOR);
    data.push(family);
    data.extend_from_slice(&start_leaf_index.to_le_bytes());
    data.extend_from_slice(subtree_root);
    data.extend_from_slice(resulting_root);
    data.extend_from_slice(nullifier);
    data.extend_from_slice(disclosure_hash);
    data.extend_from_slice(kem_binding);
    data.extend_from_slice(&epoch.to_le_bytes());
    emit(program_id, event_authority, program_account, bump, data)
}

/// The shared self-CPI tail: build the event instruction and invoke it with
/// the event-authority PDA signing.
fn emit<'a>(
    program_id: &Pubkey,
    event_authority: &AccountInfo<'a>,
    program_account: &AccountInfo<'a>,
    bump: u8,
    data: Vec<u8>,
) -> Result<(), PoolError> {
    let ix = Instruction {
        program_id: *program_id,
        accounts: vec![AccountMeta::new_readonly(*event_authority.key, true)],
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
