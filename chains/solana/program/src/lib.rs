//! bongtu_pool — the Solana rail's pool program (SOLR §2: one program,
//! instruction families, config-flag registry).
//!
//! S2 surface: the four consumer P2P ops — `deposit_priv`, `transfer_priv`,
//! `transfer10x2_priv`, `withdraw_priv` — each single-transaction (Groth16
//! verify over alt_bn128 syscalls + sol_poseidon IMT + nullifier/root PDAs +
//! SPL escrow motion + self-CPI event), plus the event handler they invoke.
//! `initialize` / `set_family_flags` keep reserved discriminators 0/1.
//!
//! S3 surface (SOLR §3.3, OPEN-1 decided): the enterprise op set — `deposit`,
//! `withdraw`, and the 1-tx `disburse256` (disclosureHash on-chain, the
//! disclosure BYTES institution-served; `DisburseBatch` PDA as the durable
//! audit anchor). Full on-chain disclosure DA needs ~19 staged write txs plus
//! an incremental in-tx fold (a 2054-element refold alone is over the CU cap),
//! so that variant stays a documented option (SOLR §3.3.3), not an
//! instruction.
//!
//! Shared-verbatim boundary (SOLR §4.1): circuits/zkeys/vkeys are the EVM
//! rail's artifacts byte-for-byte; VK constants and IMT zeros under
//! `generated/` come from checked-in generator scripts, never hand-porting.

pub mod deposit;
pub mod deposit_priv;
pub mod disburse256;
pub mod error;
pub mod event;
pub mod generated;
pub mod groth16;
pub mod op_common;
pub mod recipient_binding;
pub mod spl;
pub mod state;
pub mod transfer10x2_priv;
pub mod transfer_priv;
pub mod tree;
pub mod withdraw;
pub mod withdraw_priv;

use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

solana_program::declare_id!("HGVVfVfRnHauJoQwUttgUoy6ucG47LAXj8e6YBbZkoCj");

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (discriminator, payload) = instruction_data
        .split_first()
        .ok_or(ProgramError::from(error::PoolError::InvalidDiscriminator))?;
    match *discriminator {
        deposit_priv::DISCRIMINATOR => {
            deposit_priv::process(program_id, accounts, payload).map_err(Into::into)
        }
        transfer_priv::DISCRIMINATOR => {
            transfer_priv::process(program_id, accounts, payload).map_err(Into::into)
        }
        transfer10x2_priv::DISCRIMINATOR => {
            transfer10x2_priv::process(program_id, accounts, payload).map_err(Into::into)
        }
        withdraw_priv::DISCRIMINATOR => {
            withdraw_priv::process(program_id, accounts, payload).map_err(Into::into)
        }
        deposit::DISCRIMINATOR => {
            deposit::process(program_id, accounts, payload).map_err(Into::into)
        }
        withdraw::DISCRIMINATOR => {
            withdraw::process(program_id, accounts, payload).map_err(Into::into)
        }
        disburse256::DISCRIMINATOR => {
            disburse256::process(program_id, accounts, payload).map_err(Into::into)
        }
        event::EVENT_DISCRIMINATOR => {
            event::process_emit_event(program_id, accounts).map_err(Into::into)
        }
        _ => Err(error::PoolError::InvalidDiscriminator.into()),
    }
}
