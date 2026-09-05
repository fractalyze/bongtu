//! Account layouts (SOLR §2.2). Plain fixed-offset byte layouts, no serde:
//! every field element is a 32-byte big-endian value (the public-input wire
//! encoding — one canonical byte form across verifier, tree, and PDA seeds),
//! counters are u64 little-endian.

use {
    crate::error::PoolError,
    solana_program::{account_info::AccountInfo, pubkey::Pubkey},
};

/// Account-type tags (first data byte).
pub const TAG_POOL_CONFIG: u8 = 1;
pub const TAG_TREE_STATE: u8 = 2;
pub const TAG_DISBURSE_BATCH: u8 = 3;

/// Family-enable flags in `PoolConfig` (SOLR §2.1: the module-registry
/// analogue). Bit assignment is part of the deploy profile. Bits 4..6 are the
/// S3 enterprise set (OPEN-1 decided on issue #8: deposit, withdraw,
/// disburse256) — enterprise flags additionally require a nonzero arbiter key
/// in the config (a consumer-only profile cannot enable them by flag alone).
pub const FAMILY_DEPOSIT_PRIV: u8 = 1 << 0;
pub const FAMILY_TRANSFER_PRIV: u8 = 1 << 1;
pub const FAMILY_TRANSFER10X2_PRIV: u8 = 1 << 2;
pub const FAMILY_WITHDRAW_PRIV: u8 = 1 << 3;
pub const FAMILY_DEPOSIT: u8 = 1 << 4;
pub const FAMILY_WITHDRAW: u8 = 1 << 5;
pub const FAMILY_DISBURSE256: u8 = 1 << 6;

/// Arbiter epoch on this rail. Key rotation (`rotateArbiter`) is not yet a
/// Solana instruction, so every batch records the genesis epoch — dated
/// deviation note in SOLR §3.3.1 (S3, 2026-09-05).
pub const ARBITER_EPOCH_GENESIS: u64 = 0;

/// PDA seed prefixes. Seed values are the 32-byte BIG-ENDIAN public-input
/// encoding of the field element — deliberately the verifier wire form, so no
/// second endianness convention exists on this rail (SOLR §4.1 drift rule;
/// deviation from the §2.2 table's "le_bytes" note, recorded in README).
pub const SEED_NULLIFIER: &[u8] = b"nf";
pub const SEED_KNOWN_ROOT: &[u8] = b"root";
pub const SEED_EVENT_AUTHORITY: &[u8] = b"__event_authority";
/// DisburseBatch PDA (SOLR §2.2 / §3.3.1): seed value is the batch's
/// start_leaf_index as u64 LITTLE-endian — it is a counter, not a field
/// element, so it takes the counter convention (u64 LE) rather than the
/// 32-byte BE field encoding (dated note in SOLR §2.2, S3 2026-09-05).
pub const SEED_DISBURSE_BATCH: &[u8] = b"batch";
/// Vault owner PDA: the SPL token-level owner of the escrow vault
/// (SOLR §2.2 — Vault = ATA of ["authority", config]).
pub const SEED_VAULT_AUTHORITY: &[u8] = b"authority";

/// PoolConfig layout:
///   0      tag (1)
///   1      version (1)
///   2      family_flags (1)
///   3      reserved (1)
///   4..36  admin
///   36..68 mint
///   68..100 vault
///   100..104 batch B, u32 LE
///   104..168 arbiter bjj key (zeroed on consumer-only profiles)
///   168..200 arbiter KEM pk hash (zeroed on consumer-only profiles)
pub const POOL_CONFIG_LEN: usize = 200;
pub const CONFIG_OFF_FLAGS: usize = 2;
pub const CONFIG_OFF_MINT: usize = 36;
pub const CONFIG_OFF_VAULT: usize = 68;
pub const CONFIG_OFF_BATCH_B: usize = 100;
pub const CONFIG_OFF_ARBITER_X: usize = 104;
pub const CONFIG_OFF_ARBITER_Y: usize = 136;

/// DisburseBatch layout (SOLR §3.3.1 — the durable per-batch audit anchor;
/// account state readable forever, no ledger history needed):
///   0      tag (3)
///   1      version (1)
///   2..10  start_leaf_index, u64 LE
///   10..42 disclosure_hash (BE) — disburse pub[2], the proof-bound fold of
///          the 2054-element disclosure blob; served bytes check against it
///   42..74 kem_binding (BE) — pub[4], the arbiter ML-KEM envelope binding
///   74..82 epoch, u64 LE
pub const DISBURSE_BATCH_LEN: usize = 82;
pub const BATCH_OFF_START: usize = 2;
pub const BATCH_OFF_DISCLOSURE_HASH: usize = 10;
pub const BATCH_OFF_KEM_BINDING: usize = 42;
pub const BATCH_OFF_EPOCH: usize = 74;

/// TreeState layout (zero-copy single-frontier IMT, SOLR §2.2):
///   0        tag (2)
///   1        version (1)
///   2..34    config pubkey
///   34..42   next_leaf_index, u64 LE
///   42..74   current_root (BE)
///   74..1098 filled_subtrees[32] (BE each)
pub const TREE_STATE_LEN: usize = 1098;
pub const TREE_OFF_CONFIG: usize = 2;
pub const TREE_OFF_NEXT: usize = 34;
pub const TREE_OFF_ROOT: usize = 42;
pub const TREE_OFF_FRONTIER: usize = 74;

/// Validate owner + tag + length; returns nothing but the guarantee.
pub fn check_pool_config(config: &AccountInfo, program_id: &Pubkey) -> Result<(), PoolError> {
    if config.owner != program_id {
        return Err(PoolError::InvalidAccount);
    }
    let data = config.try_borrow_data().map_err(|_| PoolError::InvalidAccount)?;
    if data.len() != POOL_CONFIG_LEN || data[0] != TAG_POOL_CONFIG {
        return Err(PoolError::InvalidAccount);
    }
    Ok(())
}

pub fn config_family_flags(config: &AccountInfo) -> Result<u8, PoolError> {
    let data = config.try_borrow_data().map_err(|_| PoolError::InvalidAccount)?;
    Ok(data[CONFIG_OFF_FLAGS])
}

fn config_field32(config: &AccountInfo, off: usize) -> Result<[u8; 32], PoolError> {
    let data = config.try_borrow_data().map_err(|_| PoolError::InvalidAccount)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&data[off..off + 32]);
    Ok(out)
}

/// The pool's SPL mint (config bytes 36..68).
pub fn config_mint(config: &AccountInfo) -> Result<[u8; 32], PoolError> {
    config_field32(config, CONFIG_OFF_MINT)
}

/// The pool's escrow vault token account (config bytes 68..100).
pub fn config_vault(config: &AccountInfo) -> Result<[u8; 32], PoolError> {
    config_field32(config, CONFIG_OFF_VAULT)
}

/// The stored arbiter bjj public key (config bytes 104..168) — zeroed on
/// consumer-only profiles. Belt checks (nonzero, canonical) live in
/// `op_common::arbiter_key`, the one path every enterprise op reads through.
pub fn config_arbiter_key(config: &AccountInfo) -> Result<[[u8; 32]; 2], PoolError> {
    Ok([
        config_field32(config, CONFIG_OFF_ARBITER_X)?,
        config_field32(config, CONFIG_OFF_ARBITER_Y)?,
    ])
}

/// LOG_B from the config's batch size B (u32 LE at bytes 100..104) — the
/// level a disburse subtree attaches at (the EVM `_initTreeAndParams`
/// derivation; B must be a power of two below the tree height).
pub fn config_batch_log_b(config: &AccountInfo) -> Result<usize, PoolError> {
    let data = config.try_borrow_data().map_err(|_| PoolError::InvalidAccount)?;
    let mut le = [0u8; 4];
    le.copy_from_slice(&data[CONFIG_OFF_BATCH_B..CONFIG_OFF_BATCH_B + 4]);
    let b = u32::from_le_bytes(le);
    if b == 0 || !b.is_power_of_two() {
        return Err(PoolError::InvalidAccount);
    }
    let log_b = b.trailing_zeros() as usize;
    if log_b >= crate::generated::zeros::TREE_HEIGHT {
        return Err(PoolError::InvalidAccount);
    }
    Ok(log_b)
}

/// Validate the tree account and its linkage to `config`, then load the
/// mutable in-memory frontier view.
pub fn check_tree_state(
    tree: &AccountInfo,
    config_key: &Pubkey,
    program_id: &Pubkey,
) -> Result<(), PoolError> {
    if tree.owner != program_id {
        return Err(PoolError::InvalidAccount);
    }
    let data = tree.try_borrow_data().map_err(|_| PoolError::InvalidAccount)?;
    if data.len() != TREE_STATE_LEN || data[0] != TAG_TREE_STATE {
        return Err(PoolError::InvalidAccount);
    }
    if data[TREE_OFF_CONFIG..TREE_OFF_CONFIG + 32] != config_key.to_bytes() {
        return Err(PoolError::InvalidAccount);
    }
    Ok(())
}
