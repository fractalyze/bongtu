//! Shared op-instruction machinery: the `_applyOp` invariant mirror plus the
//! state-write primitives every consumer op composes (SOLR §2.3).
//!
//! Every consumer op runs the same skeleton: parse the fixed wire (proof +
//! carried publics + kem cts), check canonicality, run the invariant gate
//! (known root iff spending; nullifiers distinct, unspent, PDA-derived;
//! leaves nonzero — the per-op handler owns the leaf checks), verify, then
//! apply state: nullifier marker PDAs, tree appends, the resulting-root
//! KnownRoot PDA, escrow motion last (CEI, mirroring applyOpWithPull/Push).
//!
//! Check order deviates from the EVM modules (which verify first): the cheap
//! invariant checks run BEFORE the ~150-250k-CU verify. The accepted set is
//! identical — all checks are conjunctive and side-effect-free until every
//! one has passed — and the gate-5 conformance table drives each guard with
//! committed real proofs instead of the EVM suite's stub verifiers.

use {
    crate::{
        error::PoolError,
        groth16::{self, PROOF_LEN},
        state::{self, SEED_KNOWN_ROOT, SEED_NULLIFIER, TREE_STATE_LEN},
        tree::Frontier,
    },
    solana_program::{
        account_info::AccountInfo,
        instruction::{AccountMeta, Instruction},
        program::{invoke, invoke_signed},
        pubkey::Pubkey,
        rent::Rent,
        sysvar::Sysvar,
    },
};

pub const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

/// The widest spend arity on the rail (transfer10x2_priv and the enterprise transfer10x2).
pub const MAX_NULLIFIERS: usize = 10;

pub fn as_arr32(slice: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    out
}

/// Split the (already length-checked) payload into proof bytes and the N
/// carried public signals (32 B big-endian each). Bytes past the publics
/// (kem cts, the withdraw stealth tail) stay with the caller.
pub fn parse_carried<const N: usize>(payload: &[u8]) -> ([u8; PROOF_LEN], [[u8; 32]; N]) {
    let mut proof = [0u8; PROOF_LEN];
    proof.copy_from_slice(&payload[..PROOF_LEN]);
    let mut carried = [[0u8; 32]; N];
    for (i, slot) in carried.iter_mut().enumerate() {
        *slot = as_arr32(&payload[PROOF_LEN + 32 * i..PROOF_LEN + 32 * (i + 1)]);
    }
    (proof, carried)
}

/// Every carried public must be a canonical scalar (< r) — a non-canonical
/// limb would alias two byte encodings of one signal (byte equality, not
/// mod-p equivalence: the OPMOD §4.4 rule).
pub fn check_canonical(carried: &[[u8; 32]]) -> Result<(), PoolError> {
    for public in carried {
        if !groth16::is_canonical_scalar(public) {
            return Err(PoolError::PublicInputNotCanonical);
        }
    }
    Ok(())
}

/// Shared account preamble: system program identity, pool config
/// (owner/tag/length), the op's family flag, tree state + config linkage.
pub fn check_common(
    program_id: &Pubkey,
    config: &AccountInfo,
    tree: &AccountInfo,
    system_program: &AccountInfo,
    family_flag: u16,
) -> Result<(), PoolError> {
    if system_program.key != &SYSTEM_PROGRAM_ID {
        return Err(PoolError::InvalidAccount);
    }
    state::check_pool_config(config, program_id)?;
    if state::config_family_flags(config)? & family_flag == 0 {
        return Err(PoolError::FamilyDisabled);
    }
    state::check_tree_state(tree, config.key, program_id)
}

/// The spend half of the `_applyOp` mirror, checks only (no writes):
/// known-root iff spending (a mint claims no membership); every nonzero
/// nullifier distinct in-tx (the sequential-marking rule), matched to its
/// program-derived PDA, and unspent (PDA not yet program-owned).
///
/// `spending` holds the nonzero nullifiers in signal order; `bumps` is the
/// parallel PDA-bump array (first `spending.len()` slots valid).
pub struct SpendChecks {
    pub spending: Vec<[u8; 32]>,
    pub bumps: [u8; MAX_NULLIFIERS],
}

pub fn check_spend(
    program_id: &Pubkey,
    nullifiers: &[[u8; 32]],
    spent_root: &[u8; 32],
    spent_root_acc: &AccountInfo,
    nf_accounts: &[AccountInfo],
) -> Result<SpendChecks, PoolError> {
    let spending: Vec<[u8; 32]> = nullifiers
        .iter()
        .filter(|nf| !groth16::is_zero(nf))
        .copied()
        .collect();
    if spending.len() > MAX_NULLIFIERS {
        return Err(PoolError::InvalidAccount);
    }

    if spending.is_empty() {
        // Mirror of _applyOp: an op spending nothing must claim no membership.
        if !groth16::is_zero(spent_root) {
            return Err(PoolError::UnknownRoot);
        }
    } else {
        // Known-root check: the KnownRoot PDA for the claimed root must exist
        // (be program-owned). The address must equal the program derivation —
        // otherwise any program-owned account (e.g. a nullifier PDA) could
        // stand in as proof that an arbitrary root is known.
        let (expected_root_pda, _) =
            Pubkey::find_program_address(&[SEED_KNOWN_ROOT, spent_root], program_id);
        if spent_root_acc.key != &expected_root_pda {
            return Err(PoolError::PdaMismatch);
        }
        if spent_root_acc.owner != program_id {
            return Err(PoolError::UnknownRoot);
        }
    }

    // In-tx duplicate = the second marking of _applyOp's sequential loop.
    for i in 0..spending.len() {
        for j in (i + 1)..spending.len() {
            if spending[i] == spending[j] {
                return Err(PoolError::NullifierAlreadyUsed);
            }
        }
    }
    if nf_accounts.len() != spending.len() {
        return Err(PoolError::MissingNullifierAccount);
    }
    let mut bumps = [0u8; MAX_NULLIFIERS];
    for (i, nf) in spending.iter().enumerate() {
        let (expected, bump) = Pubkey::find_program_address(&[SEED_NULLIFIER, nf], program_id);
        if nf_accounts[i].key != &expected {
            return Err(PoolError::PdaMismatch);
        }
        if nf_accounts[i].owner == program_id {
            return Err(PoolError::NullifierAlreadyUsed);
        }
        if nf_accounts[i].owner != &SYSTEM_PROGRAM_ID || !nf_accounts[i].data_is_empty() {
            return Err(PoolError::InvalidAccount);
        }
        bumps[i] = bump;
    }
    Ok(SpendChecks { spending, bumps })
}

/// Hand-rolled SystemInstruction::CreateAccount (bincode: u32 tag 0 LE,
/// lamports u64 LE, space u64 LE, owner) — the wire format is consensus-fixed,
/// and building it directly avoids a second solana-interface dependency line.
fn create_account_ix(
    payer: &Pubkey,
    new: &Pubkey,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(52);
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    data.extend_from_slice(owner.as_ref());
    Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![AccountMeta::new(*payer, true), AccountMeta::new(*new, true)],
        data,
    }
}

/// SystemInstruction::Transfer (bincode tag 2 LE + lamports u64 LE): top a
/// pre-funded PDA up to the rent-exempt minimum before Allocate/Assign.
fn transfer_ix(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
        data,
    }
}

/// SystemInstruction::Allocate (bincode tag 8 LE + space u64 LE), signed by
/// the PDA itself via invoke_signed.
fn allocate_ix(pda: &Pubkey, space: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&8u32.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![AccountMeta::new(*pda, true)],
        data,
    }
}

/// SystemInstruction::Assign (bincode tag 1 LE + owner), signed by the PDA
/// itself via invoke_signed.
fn assign_ix(pda: &Pubkey, owner: &Pubkey) -> Instruction {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(owner.as_ref());
    Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![AccountMeta::new(*pda, true)],
        data,
    }
}

/// Rent-exempt lamports for a 0-data marker PDA.
pub fn marker_rent() -> Result<u64, PoolError> {
    rent_for(0)
}

/// Rent-exempt lamports for a data PDA of `space` bytes (DisburseBatch).
pub fn rent_for(space: usize) -> Result<u64, PoolError> {
    Ok(Rent::get().map_err(|_| PoolError::InvalidAccount)?.minimum_balance(space))
}

/// Create a program-owned PDA of `space` bytes at the given seeds.
pub fn create_pda<'a>(
    program_id: &Pubkey,
    payer: &AccountInfo<'a>,
    pda: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    seeds: &[&[u8]],
    space: usize,
    rent_lamports: u64,
) -> Result<(), PoolError> {
    let held = pda.lamports();
    if held == 0 {
        // Empty-account fast path: one-CPI CreateAccount.
        let ix = create_account_ix(payer.key, pda.key, rent_lamports, space as u64, program_id);
        return invoke_signed(&ix, &[payer.clone(), pda.clone(), system.clone()], &[seeds])
            .map_err(|_| PoolError::InvalidAccount);
    }
    // Pre-funded PDA: the address is a pure function of public state (nf,
    // root, batch start index), so anyone can send lamports to it BEFORE the
    // op lands and CreateAccount would then fail AccountAlreadyInUse,
    // freezing the note forever (griefing DoS, S2 review finding). Standard
    // hardening: top up to rent-exempt if short, then Allocate + Assign
    // signed by the PDA. The callers' preconditions (system-owned, 0 data)
    // still hold: only lamport transfers can touch an address without its
    // signature.
    if held < rent_lamports {
        invoke(
            &transfer_ix(payer.key, pda.key, rent_lamports - held),
            &[payer.clone(), pda.clone(), system.clone()],
        )
        .map_err(|_| PoolError::InvalidAccount)?;
    }
    invoke_signed(
        &allocate_ix(pda.key, space as u64),
        &[pda.clone(), system.clone()],
        &[seeds],
    )
    .map_err(|_| PoolError::InvalidAccount)?;
    invoke_signed(&assign_ix(pda.key, program_id), &[pda.clone(), system.clone()], &[seeds])
        .map_err(|_| PoolError::InvalidAccount)
}

/// Create a 0-data PDA owned by this program; its existence is the state bit
/// (Nullifier: spent; KnownRoot: root occurred — SOLR §2.2).
pub fn create_marker_pda<'a>(
    program_id: &Pubkey,
    payer: &AccountInfo<'a>,
    pda: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    seed_prefix: &[u8],
    seed_value: &[u8; 32],
    bump: u8,
    rent_lamports: u64,
) -> Result<(), PoolError> {
    let seeds: &[&[u8]] = &[seed_prefix, seed_value, &[bump]];
    create_pda(program_id, payer, pda, system, seeds, 0, rent_lamports)
}

/// Mark every spent nullifier by creating its marker PDA.
pub fn spend_nullifiers<'a>(
    program_id: &Pubkey,
    payer: &AccountInfo<'a>,
    nf_accounts: &[AccountInfo<'a>],
    system: &AccountInfo<'a>,
    checks: &SpendChecks,
    rent_lamports: u64,
) -> Result<(), PoolError> {
    for (i, nf) in checks.spending.iter().enumerate() {
        create_marker_pda(
            program_id,
            payer,
            &nf_accounts[i],
            system,
            SEED_NULLIFIER,
            nf,
            checks.bumps[i],
            rent_lamports,
        )?;
    }
    Ok(())
}

/// Append the op's output commitments as single leaves; returns the start
/// leaf index and the resulting root.
pub fn append_leaves(
    tree: &AccountInfo,
    leaves: &[[u8; 32]],
) -> Result<(u64, [u8; 32]), PoolError> {
    let mut data = tree.try_borrow_mut_data().map_err(|_| PoolError::InvalidAccount)?;
    if data.len() != TREE_STATE_LEN {
        return Err(PoolError::InvalidAccount);
    }
    let mut frontier = Frontier::load(&data)?;
    let start = frontier.append_leaf(leaves[0])?;
    for leaf in &leaves[1..] {
        frontier.append_leaf(*leaf)?;
    }
    frontier.store(&mut data);
    Ok((start, frontier.current_root))
}

/// Attach a disburse B-leaf subtree at level `log_b` (the append_leaves
/// sibling for the SOLR §3.3 batch shape); returns the batch's start leaf
/// index and the resulting root.
pub fn attach_subtree(
    tree: &AccountInfo,
    subtree_root: &[u8; 32],
    log_b: usize,
) -> Result<(u64, [u8; 32]), PoolError> {
    let mut data = tree.try_borrow_mut_data().map_err(|_| PoolError::InvalidAccount)?;
    if data.len() != TREE_STATE_LEN {
        return Err(PoolError::InvalidAccount);
    }
    let mut frontier = Frontier::load(&data)?;
    let start = frontier.attach_subtree(*subtree_root, log_b)?;
    frontier.store(&mut data);
    Ok((start, frontier.current_root))
}

/// Read the enterprise arbiter key from `PoolConfig` with the belt checks
/// every enterprise op shares: a zeroed key means a consumer-only profile
/// (the family flag alone cannot enable enterprise ops — SOLR §2.2), and a
/// non-canonical key half is a corrupt config, refused before it can reach
/// the verifier as an aliased public input.
pub fn arbiter_key(config: &AccountInfo) -> Result<[[u8; 32]; 2], PoolError> {
    let key = state::config_arbiter_key(config)?;
    if groth16::is_zero(&key[0]) && groth16::is_zero(&key[1]) {
        return Err(PoolError::ArbiterKeyUnset);
    }
    if !groth16::is_canonical_scalar(&key[0]) || !groth16::is_canonical_scalar(&key[1]) {
        return Err(PoolError::InvalidAccount);
    }
    Ok(key)
}

/// Register the post-op root as a KnownRoot PDA (the `knownRoots[root] = true`
/// analogue; one root PDA per root-advancing op, SOLR §2.2).
pub fn register_new_root<'a>(
    program_id: &Pubkey,
    payer: &AccountInfo<'a>,
    new_root_acc: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    new_root: &[u8; 32],
    rent_lamports: u64,
) -> Result<(), PoolError> {
    let (expected_new_root, bump) =
        Pubkey::find_program_address(&[SEED_KNOWN_ROOT, new_root], program_id);
    if new_root_acc.key != &expected_new_root {
        return Err(PoolError::PdaMismatch);
    }
    if new_root_acc.owner != program_id {
        create_marker_pda(
            program_id,
            payer,
            new_root_acc,
            system,
            SEED_KNOWN_ROOT,
            new_root,
            bump,
            rent_lamports,
        )?;
    }
    Ok(())
}
