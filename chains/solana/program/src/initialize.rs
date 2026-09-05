//! `initialize` (discriminator 0) — the one-shot pool initializer (SOLR §2.5):
//! the complete deploy profile in one signed transaction, mirroring the EVM
//! one-initializer stance (`initialize()` alone produces the production
//! shape; there is no follow-up ladder).
//!
//! Wire: after the 1-byte discriminator the payload is
//!   family_flags (u16 LE) || batch B (u32 LE) ||
//!   arbiter bjj key x, y (32 B BE each) || arbiter KEM pk hash (32 B)
//! The profile is the flag set (SOLR §2.1: family-enable flags replace the
//! EVM module registry): consumer-only = P2P flags with a ZEROED arbiter key
//! and KEM hash ("no key exists" — attestable from the config account),
//! enterprise/mixed = enterprise flags with a canonical nonzero key.
//!
//! Accounts:
//!   0 pool config PDA ["config", mint] (w)
//!   1 tree state PDA ["tree", config] (w)
//!   2 mint (ro)                3 vault token account (ro)
//!   4 payer (w, signer — becomes the config admin)
//!   5 system program
//!
//! The config and tree accounts move from arbitrary keys to PDAs here: ops
//! validate owner/tag/linkage (not addresses), so pre-initialize harness
//! images stay valid, while a deployed cluster gets deterministic discovery
//! (config from the mint, tree from the config). The nf/root/batch PDA seeds
//! carry no config key, so ONE pool per program deployment holds (SOLR §2.2
//! S3 note) — and one config per mint holds by the seed itself.
//!
//! The vault is created OUTSIDE the program (the ATA of the vault-authority
//! PDA, spl-token CLI or ATA program — deploy runbook): initialize only
//! validates it (token account, pool mint, owned by the vault authority) and
//! records it, keeping the program free of an ATA-program CPI.
//!
//! Enforced preconditions (SOLR §2.2 S3 note (a)): a profile enabling
//! `disburse256` requires B == 256 (`WrongBatchSize`) — the circuit's output
//! subtree is a fixed depth-8 gadget. The KEM pk hash (config bytes 168..200)
//! is recorded but not yet read by any op — arbiter rotation work (note (b)).

use {
    crate::{
        error::PoolError,
        generated::zeros::{TREE_HEIGHT, ZEROS},
        groth16, op_common, spl,
        state::{
            CONFIG_OFF_ARBITER_X, CONFIG_OFF_ARBITER_Y, CONFIG_OFF_BATCH_B, CONFIG_OFF_FLAGS,
            CONFIG_OFF_KEM_PK_HASH, CONFIG_OFF_MINT, CONFIG_OFF_VAULT, FAMILY_DEPOSIT,
            FAMILY_DEPOSIT_PRIV, FAMILY_DISBURSE256, FAMILY_TRANSFER, FAMILY_TRANSFER10X2,
            FAMILY_TRANSFER10X2_PRIV, FAMILY_TRANSFER_PRIV, FAMILY_WITHDRAW,
            FAMILY_WITHDRAW_PRIV, POOL_CONFIG_LEN, SEED_CONFIG, SEED_TREE, SEED_VAULT_AUTHORITY,
            TAG_POOL_CONFIG, TAG_TREE_STATE, TREE_OFF_CONFIG, TREE_OFF_FRONTIER, TREE_OFF_ROOT,
            TREE_STATE_LEN,
        },
    },
    solana_program::{account_info::AccountInfo, pubkey::Pubkey},
};

pub const DISCRIMINATOR: u8 = 0;

/// flags u16 (2) || B u32 (4) || arbiter x (32) || arbiter y (32) ||
/// kem pk hash (32). Literal so the core pin suite parses it as text.
pub const PAYLOAD_LEN: usize = 102;

/// The enterprise family bits (state.rs bits 4..8) — the set whose enablement
/// requires an arbiter key in the config.
const ENTERPRISE_FAMILIES: u16 =
    FAMILY_DEPOSIT | FAMILY_WITHDRAW | FAMILY_DISBURSE256 | FAMILY_TRANSFER | FAMILY_TRANSFER10X2;

/// Every assigned family bit; a flag outside this set names no op and is
/// refused so the config's flag history stays interpretable.
const KNOWN_FAMILIES: u16 = FAMILY_DEPOSIT_PRIV
    | FAMILY_TRANSFER_PRIV
    | FAMILY_TRANSFER10X2_PRIV
    | FAMILY_WITHDRAW_PRIV
    | ENTERPRISE_FAMILIES;

pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), PoolError> {
    // --- accounts ---------------------------------------------------------
    if accounts.len() < 6 {
        return Err(PoolError::InvalidAccount);
    }
    let config = &accounts[0];
    let tree = &accounts[1];
    let mint = &accounts[2];
    let vault = &accounts[3];
    let payer = &accounts[4];
    let system_program = &accounts[5];

    if !payer.is_signer {
        return Err(PoolError::InvalidAccount);
    }
    if system_program.key != &op_common::SYSTEM_PROGRAM_ID {
        return Err(PoolError::InvalidAccount);
    }
    spl::check_mint_account(mint)?;

    // --- wire shape (code 2 = "not exactly the fixed wire shape") ---------
    if payload.len() != PAYLOAD_LEN {
        return Err(PoolError::WrongKemCiphertextLength);
    }
    let flags = u16::from_le_bytes([payload[0], payload[1]]);
    let batch_b = u32::from_le_bytes([payload[2], payload[3], payload[4], payload[5]]);
    let arbiter_x = op_common::as_arr32(&payload[6..38]);
    let arbiter_y = op_common::as_arr32(&payload[38..70]);
    let kem_pk_hash = op_common::as_arr32(&payload[70..102]);

    // --- profile validation -----------------------------------------------
    if flags & !KNOWN_FAMILIES != 0 {
        return Err(PoolError::InvalidAccount);
    }
    if batch_b == 0 || !batch_b.is_power_of_two() {
        return Err(PoolError::InvalidAccount);
    }
    if batch_b.trailing_zeros() as usize >= TREE_HEIGHT {
        return Err(PoolError::InvalidAccount);
    }
    if flags & FAMILY_DISBURSE256 != 0 && batch_b != 256 {
        // The disburse256 circuit folds a fixed depth-8 subtree; any other B
        // would mint an unspendable batch (SOLR §2.2 precondition (a)).
        return Err(PoolError::WrongBatchSize);
    }
    let key_zero = groth16::is_zero(&arbiter_x) && groth16::is_zero(&arbiter_y);
    if flags & ENTERPRISE_FAMILIES != 0 {
        if key_zero {
            return Err(PoolError::ArbiterKeyUnset);
        }
        if !groth16::is_canonical_scalar(&arbiter_x) || !groth16::is_canonical_scalar(&arbiter_y) {
            return Err(PoolError::PublicInputNotCanonical);
        }
    } else if !key_zero || kem_pk_hash != [0u8; 32] {
        // Consumer-only means "no key exists", attestable from the account —
        // a lingering key under disabled enterprise flags would falsify that.
        return Err(PoolError::InvalidAccount);
    }

    // --- PDA derivations + one-shot check ----------------------------------
    let mint_bytes = mint.key.to_bytes();
    let (expected_config, config_bump) =
        Pubkey::find_program_address(&[SEED_CONFIG, &mint_bytes], program_id);
    if config.key != &expected_config {
        return Err(PoolError::PdaMismatch);
    }
    if config.owner == program_id || tree.owner == program_id {
        return Err(PoolError::AlreadyInitialized);
    }
    let config_bytes = expected_config.to_bytes();
    let (expected_tree, tree_bump) =
        Pubkey::find_program_address(&[SEED_TREE, &config_bytes], program_id);
    if tree.key != &expected_tree {
        return Err(PoolError::PdaMismatch);
    }

    // --- vault validation (created outside; recorded here) -----------------
    spl::check_token_account(vault, &mint_bytes)?;
    let (vault_authority, _) =
        Pubkey::find_program_address(&[SEED_VAULT_AUTHORITY, &config_bytes], program_id);
    if spl::token_account_owner(vault)? != vault_authority.to_bytes() {
        return Err(PoolError::InvalidAccount);
    }

    // --- create + write the profile ----------------------------------------
    op_common::create_pda(
        program_id,
        payer,
        config,
        system_program,
        &[SEED_CONFIG, &mint_bytes, &[config_bump]],
        POOL_CONFIG_LEN,
        op_common::rent_for(POOL_CONFIG_LEN)?,
    )?;
    {
        let mut data = config.try_borrow_mut_data().map_err(|_| PoolError::InvalidAccount)?;
        data[0] = TAG_POOL_CONFIG;
        data[1] = 1;
        data[CONFIG_OFF_FLAGS..CONFIG_OFF_FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
        data[4..36].copy_from_slice(&payer.key.to_bytes()); // admin
        data[CONFIG_OFF_MINT..CONFIG_OFF_MINT + 32].copy_from_slice(&mint_bytes);
        data[CONFIG_OFF_VAULT..CONFIG_OFF_VAULT + 32].copy_from_slice(&vault.key.to_bytes());
        data[CONFIG_OFF_BATCH_B..CONFIG_OFF_BATCH_B + 4].copy_from_slice(&batch_b.to_le_bytes());
        data[CONFIG_OFF_ARBITER_X..CONFIG_OFF_ARBITER_X + 32].copy_from_slice(&arbiter_x);
        data[CONFIG_OFF_ARBITER_Y..CONFIG_OFF_ARBITER_Y + 32].copy_from_slice(&arbiter_y);
        data[CONFIG_OFF_KEM_PK_HASH..CONFIG_OFF_KEM_PK_HASH + 32].copy_from_slice(&kem_pk_hash);
    }

    op_common::create_pda(
        program_id,
        payer,
        tree,
        system_program,
        &[SEED_TREE, &config_bytes, &[tree_bump]],
        TREE_STATE_LEN,
        op_common::rent_for(TREE_STATE_LEN)?,
    )?;
    {
        let mut data = tree.try_borrow_mut_data().map_err(|_| PoolError::InvalidAccount)?;
        data[0] = TAG_TREE_STATE;
        data[1] = 1;
        data[TREE_OFF_CONFIG..TREE_OFF_CONFIG + 32].copy_from_slice(&config_bytes);
        // next_leaf_index u64 LE = 0 (already zero); the empty-tree root and
        // the all-empty frontier come from the generated zeros ladder — the
        // byte image a fresh `ImtTree(32, B)` starts from.
        data[TREE_OFF_ROOT..TREE_OFF_ROOT + 32].copy_from_slice(&ZEROS[TREE_HEIGHT]);
        for i in 0..TREE_HEIGHT {
            let off = TREE_OFF_FRONTIER + 32 * i;
            data[off..off + 32].copy_from_slice(&ZEROS[i]);
        }
    }
    Ok(())
}
