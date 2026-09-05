//! SPL token escrow motion (SOLR §2.3: deposit pulls pub[0] into the vault,
//! withdraw pushes pub[0] to the proof-bound recipient — never the fee payer).
//!
//! The Transfer instruction is hand-rolled (tag 3 + u64 amount LE): the wire
//! format is consensus-fixed, and building it directly avoids an spl-token
//! interface dependency line (the create_account_ix precedent, op_common.rs).
//!
//! Per-rail amount narrowing: the circuits' value belt is 2^100, but SPL
//! amounts are u64 — a proof-bound amount >= 2^64 rejects `AmountOverflow`
//! (documented in chains/solana/README.md consensus conventions).

use {
    crate::error::PoolError,
    solana_program::{
        account_info::AccountInfo,
        instruction::{AccountMeta, Instruction},
        program::{invoke, invoke_signed},
        pubkey::Pubkey,
    },
};

/// TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA (the SPL Token program).
pub const TOKEN_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79,
    0xac, 0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff,
    0x00, 0xa9,
]);

/// SPL token Account layout facts (fixed by the token program):
/// mint 0..32, owner 32..64, amount 64..72 LE, delegate COption 72..108,
/// state 108 (1 = Initialized), … total 165 B.
pub const TOKEN_ACCOUNT_LEN: usize = 165;
const OFF_MINT: usize = 0;
const OFF_STATE: usize = 108;
const STATE_INITIALIZED: u8 = 1;

pub fn check_token_program(acc: &AccountInfo) -> Result<(), PoolError> {
    if acc.key != &TOKEN_PROGRAM_ID {
        return Err(PoolError::InvalidAccount);
    }
    Ok(())
}

/// The normal SPL owner/mint checks (OPEN-3 spec: run on the recipient token
/// account BEFORE the binding check, so the bound target is always a real
/// payee): token-program-owned, initialized, of the pool's mint.
pub fn check_token_account(acc: &AccountInfo, mint: &[u8; 32]) -> Result<(), PoolError> {
    if acc.owner != &TOKEN_PROGRAM_ID {
        return Err(PoolError::InvalidAccount);
    }
    let data = acc.try_borrow_data().map_err(|_| PoolError::InvalidAccount)?;
    if data.len() != TOKEN_ACCOUNT_LEN || data[OFF_STATE] != STATE_INITIALIZED {
        return Err(PoolError::InvalidAccount);
    }
    if data[OFF_MINT..OFF_MINT + 32] != *mint {
        return Err(PoolError::InvalidAccount);
    }
    Ok(())
}

/// The proof-bound escrow amount as u64 (pub[0] is a 32 B big-endian field
/// element; anything above u64 cannot move through SPL and rejects).
pub fn amount_u64(public: &[u8; 32]) -> Result<u64, PoolError> {
    if public[..24].iter().any(|b| *b != 0) {
        return Err(PoolError::AmountOverflow);
    }
    let mut be = [0u8; 8];
    be.copy_from_slice(&public[24..32]);
    Ok(u64::from_be_bytes(be))
}

/// SPL Token Transfer: tag 3, amount u64 LE; accounts [source w, dest w,
/// authority ro signer].
fn transfer_ix(source: &Pubkey, dest: &Pubkey, authority: &Pubkey, amount: u64) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.push(3u8);
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: TOKEN_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new(*dest, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

/// Pull: authority is a transaction signer (the deposit payer), so a plain
/// invoke propagates the signature.
pub fn transfer<'a>(
    token_program: &AccountInfo<'a>,
    source: &AccountInfo<'a>,
    dest: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    amount: u64,
) -> Result<(), PoolError> {
    invoke(
        &transfer_ix(source.key, dest.key, authority.key, amount),
        &[
            source.clone(),
            dest.clone(),
            authority.clone(),
            token_program.clone(),
        ],
    )
    .map_err(|_| PoolError::TokenTransferFailed)
}

/// Push: authority is the program's vault-authority PDA, signing via seeds.
pub fn transfer_signed<'a>(
    token_program: &AccountInfo<'a>,
    source: &AccountInfo<'a>,
    dest: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    amount: u64,
    seeds: &[&[u8]],
) -> Result<(), PoolError> {
    invoke_signed(
        &transfer_ix(source.key, dest.key, authority.key, amount),
        &[
            source.clone(),
            dest.clone(),
            authority.clone(),
            token_program.clone(),
        ],
        &[seeds],
    )
    .map_err(|_| PoolError::TokenTransferFailed)
}
