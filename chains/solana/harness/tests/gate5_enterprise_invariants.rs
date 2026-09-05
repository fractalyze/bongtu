//! Gate 5, enterprise rows (SOLR §3.1.3 #5): the invariant-gate conformance
//! matrix for the S3 op set — deposit, withdraw, disburse256, and the pass-2
//! transfer + transfer10x2 — complete per op (the S2 review rule): double-spend, unknown root, zero leaf/nullifier,
//! kem-ct shape, family flag, canonicality, escrow belts, PLUS the enterprise
//! key-injection rows: a config holding a DIFFERENT arbiter key fails the
//! proof (the SOLR §3.3.1 discipline — the prover never controls the key),
//! and a ZEROED key (consumer-only profile) refuses before verify.
//!
//! Every row runs a committed REAL proof with only state or wire mutated
//! (invariants check before the expensive verify on this rail).

use {
    bongtu_pool_solana::{error::PoolError, state},
    bongtu_solana_harness::{
        carried_offset,
        enterprise::{
            build_disburse256_env, build_ent_deposit_env, build_ent_transfer10x2_env,
            build_ent_transfer_env, build_ent_withdraw_env, load_disburse256_fixture,
            load_ent_deposit_fixture, load_ent_transfer10x2_fixture, load_ent_transfer_fixture,
            load_ent_withdraw_fixture, set_enterprise_batch_b, set_enterprise_config,
            ENTERPRISE_FLAGS,
        },
        hex_u64, program_id, token_account, token_amount, tree_account_data, Env, MINT_BYTES,
    },
    mollusk_svm::result::Check,
    solana_account::Account,
    solana_instruction::AccountMeta,
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
};

/// Run a mutated env, expect the mapped error, and assert the tree did not move.
fn expect_reject(env: &Env, error: PoolError) -> mollusk_svm::result::InstructionResult {
    let result = env.mollusk.process_and_validate_instruction(
        &env.instruction,
        &env.accounts,
        &[Check::err(ProgramError::Custom(error as u32))],
    );
    let tree = result.get_account(&env.tree_key).expect("tree account");
    assert_eq!(tree.data, env.pre_tree_data, "tree mutated by a rejected op");
    result
}

/// A canonical bjj-shaped key that is NOT the fixture arbiter key: the
/// injected publics change, so the committed proof must fail the pairing.
const OTHER_KEY: [u8; 32] = {
    let mut k = [0u8; 32];
    k[31] = 1;
    k
};

/// The BN254 scalar field modulus r as 32 big-endian bytes — the smallest
/// non-canonical wire value (OPMOD §4.4: byte equality, not mod-p).
const R_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
    0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
    0x00, 0x01,
];

fn arbiter_of(env: &Env) -> ([u8; 32], [u8; 32]) {
    let config = env
        .accounts
        .iter()
        .find(|(k, _)| k == &env.config_key)
        .expect("config")
        .1
        .clone();
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&config.data[state::CONFIG_OFF_ARBITER_X..state::CONFIG_OFF_ARBITER_X + 32]);
    y.copy_from_slice(&config.data[state::CONFIG_OFF_ARBITER_Y..state::CONFIG_OFF_ARBITER_Y + 32]);
    (x, y)
}

// --- deposit (enterprise) rows -----------------------------------------------

#[test]
fn ent_deposit_zero_output_commitment_rejected() {
    let fx = load_ent_deposit_fixture();
    let mut env = build_ent_deposit_env(&fx);
    let off = carried_offset(14); // pub[14] = output commitment 0
    env.instruction.data[off..off + 32].fill(0);
    expect_reject(&env, PoolError::ZeroOutputCommitment);
}

#[test]
fn ent_deposit_wrong_kem_ciphertext_length_rejected() {
    let fx = load_ent_deposit_fixture();
    let mut env = build_ent_deposit_env(&fx);
    env.instruction.data.pop();
    expect_reject(&env, PoolError::WrongKemCiphertextLength);
}

#[test]
fn ent_deposit_family_flag_off_rejected() {
    let fx = load_ent_deposit_fixture();
    let mut env = build_ent_deposit_env(&fx);
    let (x, y) = arbiter_of(&env);
    set_enterprise_config(&mut env, ENTERPRISE_FLAGS & !state::FAMILY_DEPOSIT, &x, &y);
    expect_reject(&env, PoolError::FamilyDisabled);
}

#[test]
fn ent_deposit_wrong_arbiter_key_fails_verify() {
    let fx = load_ent_deposit_fixture();
    let mut env = build_ent_deposit_env(&fx);
    let (_, y) = arbiter_of(&env);
    set_enterprise_config(&mut env, ENTERPRISE_FLAGS, &OTHER_KEY, &y);
    expect_reject(&env, PoolError::InvalidProof);
}

#[test]
fn ent_deposit_arbiter_key_unset_rejected() {
    let fx = load_ent_deposit_fixture();
    let mut env = build_ent_deposit_env(&fx);
    set_enterprise_config(&mut env, ENTERPRISE_FLAGS, &[0u8; 32], &[0u8; 32]);
    expect_reject(&env, PoolError::ArbiterKeyUnset);
}

#[test]
fn ent_deposit_amount_over_u64_rejected() {
    let fx = load_ent_deposit_fixture();
    let mut env = build_ent_deposit_env(&fx);
    // pub[0] := 2^64 + amount — canonical (< r) but unrepresentable in SPL.
    env.instruction.data[carried_offset(0) + 23] = 0x01;
    expect_reject(&env, PoolError::AmountOverflow);
}

#[test]
fn ent_deposit_non_canonical_public_rejected() {
    let fx = load_ent_deposit_fixture();
    let mut env = build_ent_deposit_env(&fx);
    // carried[0] := r on the wire — byte-equality, not mod-p (OPMOD §4.4).
    let off = carried_offset(0);
    env.instruction.data[off..off + 32].copy_from_slice(&R_BE);
    expect_reject(&env, PoolError::PublicInputNotCanonical);
}

#[test]
fn ent_deposit_wrong_vault_rejected() {
    let fx = load_ent_deposit_fixture();
    let mut env = build_ent_deposit_env(&fx);
    // A perfectly valid token account that is NOT the config-bound vault.
    let wrong = Pubkey::new_from_array([0x66; 32]);
    let (vault_owner, _) = bongtu_solana_harness::vault_authority();
    env.instruction.accounts[9] = AccountMeta::new(wrong, false);
    let old = env.vault_key;
    let idx = env.accounts.iter().position(|(k, _)| k == &old).unwrap();
    env.accounts[idx] = (wrong, token_account(&MINT_BYTES, &vault_owner, 0));
    expect_reject(&env, PoolError::InvalidAccount);
}

// --- withdraw (enterprise) rows ----------------------------------------------

#[test]
fn ent_withdraw_double_spend_rejected() {
    let fx = load_ent_withdraw_fixture();
    let mut env = build_ent_withdraw_env(&fx);
    let marker = env.existing_marker();
    let nf0 = env.nf_pdas[0];
    env.set_account(&nf0, marker);
    expect_reject(&env, PoolError::NullifierAlreadyUsed);
}

#[test]
fn ent_withdraw_in_tx_duplicate_nullifier_rejected() {
    let fx = load_ent_withdraw_fixture();
    let mut env = build_ent_withdraw_env(&fx);
    // carried[18] (nullifier 1) := carried[17] (nullifier 0).
    let (src, dst) = (carried_offset(17), carried_offset(18));
    let nf0: Vec<u8> = env.instruction.data[src..src + 32].to_vec();
    env.instruction.data[dst..dst + 32].copy_from_slice(&nf0);
    expect_reject(&env, PoolError::NullifierAlreadyUsed);
}

#[test]
fn ent_withdraw_unknown_root_rejected() {
    let fx = load_ent_withdraw_fixture();
    let mut env = build_ent_withdraw_env(&fx);
    let spent = env.spent_root_pda;
    env.set_account(&spent, Account::default());
    expect_reject(&env, PoolError::UnknownRoot);
}

#[test]
fn ent_withdraw_mint_claiming_membership_rejected() {
    let fx = load_ent_withdraw_fixture();
    let mut env = build_ent_withdraw_env(&fx);
    // Zero BOTH nullifiers (carried[17..18]) while the spent root stays
    // nonzero: an op spending nothing must claim no membership.
    for i in [17usize, 18] {
        let off = carried_offset(i);
        env.instruction.data[off..off + 32].fill(0);
    }
    expect_reject(&env, PoolError::UnknownRoot);
}

#[test]
fn ent_withdraw_zero_change_commitment_rejected() {
    let fx = load_ent_withdraw_fixture();
    let mut env = build_ent_withdraw_env(&fx);
    let off = carried_offset(20); // carried[20] == pub[22] (change)
    env.instruction.data[off..off + 32].fill(0);
    expect_reject(&env, PoolError::ZeroOutputCommitment);
}

#[test]
fn ent_withdraw_wrong_kem_ciphertext_length_rejected() {
    let fx = load_ent_withdraw_fixture();
    let mut env = build_ent_withdraw_env(&fx);
    env.instruction.data.pop();
    expect_reject(&env, PoolError::WrongKemCiphertextLength);
}

#[test]
fn ent_withdraw_family_flag_off_rejected() {
    let fx = load_ent_withdraw_fixture();
    let mut env = build_ent_withdraw_env(&fx);
    let (x, y) = arbiter_of(&env);
    set_enterprise_config(&mut env, ENTERPRISE_FLAGS & !state::FAMILY_WITHDRAW, &x, &y);
    expect_reject(&env, PoolError::FamilyDisabled);
}

#[test]
fn ent_withdraw_wrong_arbiter_key_fails_verify() {
    let fx = load_ent_withdraw_fixture();
    let mut env = build_ent_withdraw_env(&fx);
    let (_, y) = arbiter_of(&env);
    set_enterprise_config(&mut env, ENTERPRISE_FLAGS, &OTHER_KEY, &y);
    expect_reject(&env, PoolError::InvalidProof);
}

#[test]
fn ent_withdraw_recipient_substitution_rejected() {
    let fx = load_ent_withdraw_fixture();
    let mut env = build_ent_withdraw_env(&fx);
    // A valid same-mint token account at a DIFFERENT address: the injected
    // truncate-253 binding no longer matches pub[26], so verify fails and
    // funds never move.
    let attacker = Pubkey::new_from_array([0x55; 32]);
    let attacker_owner = Pubkey::new_from_array([0x56; 32]);
    env.instruction.accounts[11] = AccountMeta::new(attacker, false);
    let old = env.recipient_token_key;
    let idx = env.accounts.iter().position(|(k, _)| k == &old).unwrap();
    env.accounts[idx] = (attacker, token_account(&MINT_BYTES, &attacker_owner, 0));
    let result = expect_reject(&env, PoolError::InvalidProof);
    let vault = result.get_account(&env.vault_key).expect("vault");
    assert_eq!(
        token_amount(vault),
        hex_u64(&fx.amount) * 10,
        "vault moved on a rejected withdraw"
    );
}

#[test]
fn ent_withdraw_wrong_mint_recipient_rejected() {
    let fx = load_ent_withdraw_fixture();
    let mut env = build_ent_withdraw_env(&fx);
    // The right address but the wrong mint: SPL owner/mint checks run BEFORE
    // the binding (OPEN-3 spec), so this is InvalidAccount, not InvalidProof.
    let recipient = env.recipient_token_key;
    let owner = Pubkey::new_from_array([0x05; 32]);
    env.set_account(&recipient, token_account(&[0xDD; 32], &owner, 0));
    expect_reject(&env, PoolError::InvalidAccount);
}

#[test]
fn ent_withdraw_amount_over_u64_rejected() {
    let fx = load_ent_withdraw_fixture();
    let mut env = build_ent_withdraw_env(&fx);
    env.instruction.data[carried_offset(0) + 23] = 0x01;
    expect_reject(&env, PoolError::AmountOverflow);
}

#[test]
fn ent_withdraw_non_canonical_public_rejected() {
    let fx = load_ent_withdraw_fixture();
    let mut env = build_ent_withdraw_env(&fx);
    // carried[0] := r on the wire — byte-equality, not mod-p (OPMOD §4.4).
    let off = carried_offset(0);
    env.instruction.data[off..off + 32].copy_from_slice(&R_BE);
    expect_reject(&env, PoolError::PublicInputNotCanonical);
}

#[test]
fn ent_withdraw_arbiter_key_unset_rejected() {
    let fx = load_ent_withdraw_fixture();
    let mut env = build_ent_withdraw_env(&fx);
    set_enterprise_config(&mut env, ENTERPRISE_FLAGS, &[0u8; 32], &[0u8; 32]);
    expect_reject(&env, PoolError::ArbiterKeyUnset);
}

// --- disburse256 rows --------------------------------------------------------

#[test]
fn disburse256_double_spend_rejected() {
    let fx = load_disburse256_fixture();
    let mut env = build_disburse256_env(&fx);
    let marker = env.existing_marker();
    let nf = env.nf_pdas[0];
    env.set_account(&nf, marker);
    expect_reject(&env, PoolError::NullifierAlreadyUsed);
}

#[test]
fn disburse256_unknown_root_rejected() {
    let fx = load_disburse256_fixture();
    let mut env = build_disburse256_env(&fx);
    let spent = env.spent_root_pda;
    env.set_account(&spent, Account::default());
    expect_reject(&env, PoolError::UnknownRoot);
}

#[test]
fn disburse256_zero_nullifier_rejected() {
    // The 1-in disburse always spends a real note (the guard that makes
    // injecting enabled=1 sound) — the EVM ZeroNullifier row.
    let fx = load_disburse256_fixture();
    let mut env = build_disburse256_env(&fx);
    let off = carried_offset(5);
    env.instruction.data[off..off + 32].fill(0);
    expect_reject(&env, PoolError::ZeroNullifier);
}

#[test]
fn disburse256_wrong_kem_ciphertext_length_rejected() {
    let fx = load_disburse256_fixture();
    let mut env = build_disburse256_env(&fx);
    env.instruction.data.pop();
    expect_reject(&env, PoolError::WrongKemCiphertextLength);
}

#[test]
fn disburse256_family_flag_off_rejected() {
    let fx = load_disburse256_fixture();
    let mut env = build_disburse256_env(&fx);
    let (x, y) = arbiter_of(&env);
    set_enterprise_config(&mut env, ENTERPRISE_FLAGS & !state::FAMILY_DISBURSE256, &x, &y);
    expect_reject(&env, PoolError::FamilyDisabled);
}

#[test]
fn disburse256_wrong_arbiter_key_fails_verify() {
    let fx = load_disburse256_fixture();
    let mut env = build_disburse256_env(&fx);
    let (_, y) = arbiter_of(&env);
    set_enterprise_config(&mut env, ENTERPRISE_FLAGS, &OTHER_KEY, &y);
    expect_reject(&env, PoolError::InvalidProof);
}

#[test]
fn disburse256_arbiter_key_unset_rejected() {
    let fx = load_disburse256_fixture();
    let mut env = build_disburse256_env(&fx);
    set_enterprise_config(&mut env, ENTERPRISE_FLAGS, &[0u8; 32], &[0u8; 32]);
    expect_reject(&env, PoolError::ArbiterKeyUnset);
}

#[test]
fn disburse256_non_canonical_public_rejected() {
    let fx = load_disburse256_fixture();
    let mut env = build_disburse256_env(&fx);
    // carried[0] := r on the wire — byte-equality, not mod-p (OPMOD §4.4).
    let off = carried_offset(0);
    env.instruction.data[off..off + 32].copy_from_slice(&R_BE);
    expect_reject(&env, PoolError::PublicInputNotCanonical);
}

#[test]
fn disburse256_wrong_batch_size_rejected() {
    let fx = load_disburse256_fixture();
    let mut env = build_disburse256_env(&fx);
    // A config a future initialize could create with B=16: the circuit's
    // subtree is a fixed depth-8 gadget, so the attach level must be 8 or
    // the batch mints unspendable leaves — refused before verify.
    set_enterprise_batch_b(&mut env, 16);
    expect_reject(&env, PoolError::WrongBatchSize);
}

#[test]
fn disburse256_mismatched_batch_account_rejected() {
    let fx = load_disburse256_fixture();
    let mut env = build_disburse256_env(&fx);
    // A batch account that is not the PDA for the computed start index:
    // caught after verify + attach, and the whole op must roll back.
    let wrong = Pubkey::new_from_array([0x77; 32]);
    env.instruction.accounts[4] = AccountMeta::new(wrong, false);
    let old = bongtu_solana_harness::enterprise::disburse_batch_pda(fx.start_leaf_index);
    let idx = env.accounts.iter().position(|(k, _)| k == &old).unwrap();
    env.accounts[idx] = (wrong, Account::default());
    expect_reject(&env, PoolError::PdaMismatch);
}

#[test]
fn disburse256_prefunded_batch_pda_does_not_block() {
    // The griefing-DoS hardening extends to the DisburseBatch PDA: its
    // address is deterministic from tree state, so an attacker can pre-fund
    // it; the op must still land via the Transfer/Allocate/Assign path.
    let fx = load_disburse256_fixture();
    let mut env = build_disburse256_env(&fx);
    let batch = bongtu_solana_harness::enterprise::disburse_batch_pda(fx.start_leaf_index);
    env.set_account(
        &batch,
        Account {
            lamports: 500_000,
            ..Account::default()
        },
    );
    let result = env.mollusk.process_and_validate_instruction(
        &env.instruction,
        &env.accounts,
        &[Check::success()],
    );
    let acc = result.get_account(&batch).expect("batch pda");
    assert_eq!(acc.owner, program_id(), "batch PDA not claimed");
    assert_eq!(acc.data.len(), state::DISBURSE_BATCH_LEN);
    let tree = result.get_account(&env.tree_key).expect("tree account");
    assert_eq!(
        tree.data,
        tree_account_data(&env.config_key, &fx.post_state),
        "tree did not advance on the pre-funded-batch path"
    );
}

// --- transfer (enterprise, S3 pass 2) rows -----------------------------------
// Carried-public map: [27..28]=nullifiers [29]=root [30..31]=oc [32]=nonce.

#[test]
fn ent_transfer_double_spend_rejected() {
    let fx = load_ent_transfer_fixture();
    let mut env = build_ent_transfer_env(&fx);
    let marker = env.existing_marker();
    let nf0 = env.nf_pdas[0];
    env.set_account(&nf0, marker);
    expect_reject(&env, PoolError::NullifierAlreadyUsed);
}

#[test]
fn ent_transfer_in_tx_duplicate_nullifier_rejected() {
    let fx = load_ent_transfer_fixture();
    let mut env = build_ent_transfer_env(&fx);
    // carried[28] (nullifier 1) := carried[27] (nullifier 0).
    let (src, dst) = (carried_offset(27), carried_offset(28));
    let nf0: Vec<u8> = env.instruction.data[src..src + 32].to_vec();
    env.instruction.data[dst..dst + 32].copy_from_slice(&nf0);
    expect_reject(&env, PoolError::NullifierAlreadyUsed);
}

#[test]
fn ent_transfer_unknown_root_rejected() {
    let fx = load_ent_transfer_fixture();
    let mut env = build_ent_transfer_env(&fx);
    let spent = env.spent_root_pda;
    env.set_account(&spent, Account::default());
    expect_reject(&env, PoolError::UnknownRoot);
}

#[test]
fn ent_transfer_mint_claiming_membership_rejected() {
    let fx = load_ent_transfer_fixture();
    let mut env = build_ent_transfer_env(&fx);
    // Zero BOTH nullifiers (carried[27..28]) while the spent root stays
    // nonzero: an op spending nothing must claim no membership.
    for i in [27usize, 28] {
        let off = carried_offset(i);
        env.instruction.data[off..off + 32].fill(0);
    }
    expect_reject(&env, PoolError::UnknownRoot);
}

#[test]
fn ent_transfer_missing_nullifier_account_rejected() {
    let fx = load_ent_transfer_fixture();
    let mut env = build_ent_transfer_env(&fx);
    // 2 nonzero nullifiers but only 1 PDA account supplied.
    env.instruction.accounts.pop();
    expect_reject(&env, PoolError::MissingNullifierAccount);
}

#[test]
fn ent_transfer_zero_output_commitment_rejected() {
    let fx = load_ent_transfer_fixture();
    let mut env = build_ent_transfer_env(&fx);
    let off = carried_offset(30); // carried[30] == pub[32] (oc 0)
    env.instruction.data[off..off + 32].fill(0);
    expect_reject(&env, PoolError::ZeroOutputCommitment);
}

#[test]
fn ent_transfer_wrong_kem_ciphertext_length_rejected() {
    let fx = load_ent_transfer_fixture();
    let mut env = build_ent_transfer_env(&fx);
    env.instruction.data.pop();
    expect_reject(&env, PoolError::WrongKemCiphertextLength);
}

#[test]
fn ent_transfer_family_flag_off_rejected() {
    let fx = load_ent_transfer_fixture();
    let mut env = build_ent_transfer_env(&fx);
    let (x, y) = arbiter_of(&env);
    set_enterprise_config(&mut env, ENTERPRISE_FLAGS & !state::FAMILY_TRANSFER, &x, &y);
    expect_reject(&env, PoolError::FamilyDisabled);
}

#[test]
fn ent_transfer_non_canonical_public_rejected() {
    let fx = load_ent_transfer_fixture();
    let mut env = build_ent_transfer_env(&fx);
    // carried[0] := r on the wire — byte-equality, not mod-p (OPMOD §4.4).
    let off = carried_offset(0);
    env.instruction.data[off..off + 32].copy_from_slice(&R_BE);
    expect_reject(&env, PoolError::PublicInputNotCanonical);
}

#[test]
fn ent_transfer_wrong_arbiter_key_fails_verify() {
    let fx = load_ent_transfer_fixture();
    let mut env = build_ent_transfer_env(&fx);
    let (_, y) = arbiter_of(&env);
    set_enterprise_config(&mut env, ENTERPRISE_FLAGS, &OTHER_KEY, &y);
    expect_reject(&env, PoolError::InvalidProof);
}

#[test]
fn ent_transfer_arbiter_key_unset_rejected() {
    let fx = load_ent_transfer_fixture();
    let mut env = build_ent_transfer_env(&fx);
    set_enterprise_config(&mut env, ENTERPRISE_FLAGS, &[0u8; 32], &[0u8; 32]);
    expect_reject(&env, PoolError::ArbiterKeyUnset);
}

#[test]
fn ent_transfer_prefunded_marker_pda_does_not_block() {
    // The griefing-DoS hardening (S2 review finding 1) on the enterprise
    // path: nf PDA pre-funded below rent (top-up), new-root PDA above rent
    // (skip-transfer) — the op must still land.
    let fx = load_ent_transfer_fixture();
    let mut env = build_ent_transfer_env(&fx);
    let nf0 = env.nf_pdas[0];
    env.set_account(
        &nf0,
        Account {
            lamports: 500_000,
            ..Account::default()
        },
    );
    let new_root = env.new_root_pda;
    env.set_account(
        &new_root,
        Account {
            lamports: 1_000_000_000,
            ..Account::default()
        },
    );
    let result = env.mollusk.process_and_validate_instruction(
        &env.instruction,
        &env.accounts,
        &[Check::success()],
    );
    for nf in &env.nf_pdas {
        let acc = result.get_account(nf).expect("nullifier pda");
        assert_eq!(acc.owner, program_id(), "nullifier PDA not claimed");
        assert_eq!(acc.data.len(), 0);
    }
    let root_acc = result.get_account(&env.new_root_pda).expect("new root pda");
    assert_eq!(root_acc.owner, program_id(), "new KnownRoot PDA not claimed");
    let tree = result.get_account(&env.tree_key).expect("tree account");
    assert_eq!(
        tree.data,
        tree_account_data(&env.config_key, &fx.post_state),
        "tree did not advance on the pre-funded-PDA path"
    );
}

// --- transfer10x2 (enterprise, S3 pass 2) rows -------------------------------
// Carried-public map: [42..51]=nullifiers [52]=root [53..54]=oc [55]=nonce.
// The merge fixture spends all 10 inputs, so the arity rows run at full width.

#[test]
fn ent_t10x2_double_spend_rejected() {
    let fx = load_ent_transfer10x2_fixture();
    let mut env = build_ent_transfer10x2_env(&fx);
    // The LAST input (slot 9 of 10) already spent: the sequential loop
    // reaches it only after accepting the first nine.
    let marker = env.existing_marker();
    let nf9 = env.nf_pdas[9];
    env.set_account(&nf9, marker);
    expect_reject(&env, PoolError::NullifierAlreadyUsed);
}

#[test]
fn ent_t10x2_in_tx_duplicate_nullifier_rejected() {
    let fx = load_ent_transfer10x2_fixture();
    let mut env = build_ent_transfer10x2_env(&fx);
    // carried[51] (nullifier slot 9) := carried[42] (slot 0) — NON-adjacent
    // slots, so a regression to a neighbors-only duplicate check fails here.
    let (src, dst) = (carried_offset(42), carried_offset(51));
    let nf0: Vec<u8> = env.instruction.data[src..src + 32].to_vec();
    env.instruction.data[dst..dst + 32].copy_from_slice(&nf0);
    expect_reject(&env, PoolError::NullifierAlreadyUsed);
}

#[test]
fn ent_t10x2_unknown_root_rejected() {
    let fx = load_ent_transfer10x2_fixture();
    let mut env = build_ent_transfer10x2_env(&fx);
    let spent = env.spent_root_pda;
    env.set_account(&spent, Account::default());
    expect_reject(&env, PoolError::UnknownRoot);
}

#[test]
fn ent_t10x2_mint_claiming_membership_rejected() {
    let fx = load_ent_transfer10x2_fixture();
    let mut env = build_ent_transfer10x2_env(&fx);
    // Zero ALL TEN nullifiers while the spent root stays nonzero.
    for i in 42..52usize {
        let off = carried_offset(i);
        env.instruction.data[off..off + 32].fill(0);
    }
    expect_reject(&env, PoolError::UnknownRoot);
}

#[test]
fn ent_t10x2_missing_nullifier_account_rejected() {
    let fx = load_ent_transfer10x2_fixture();
    let mut env = build_ent_transfer10x2_env(&fx);
    // 10 nonzero nullifiers but only 9 PDA accounts supplied.
    env.instruction.accounts.pop();
    expect_reject(&env, PoolError::MissingNullifierAccount);
}

#[test]
fn ent_t10x2_zero_output_commitment_rejected() {
    let fx = load_ent_transfer10x2_fixture();
    let mut env = build_ent_transfer10x2_env(&fx);
    let off = carried_offset(53); // carried[53] == pub[63] (oc 0)
    env.instruction.data[off..off + 32].fill(0);
    expect_reject(&env, PoolError::ZeroOutputCommitment);
}

#[test]
fn ent_t10x2_wrong_kem_ciphertext_length_rejected() {
    let fx = load_ent_transfer10x2_fixture();
    let mut env = build_ent_transfer10x2_env(&fx);
    env.instruction.data.pop();
    expect_reject(&env, PoolError::WrongKemCiphertextLength);
}

#[test]
fn ent_t10x2_family_flag_off_rejected() {
    let fx = load_ent_transfer10x2_fixture();
    let mut env = build_ent_transfer10x2_env(&fx);
    let (x, y) = arbiter_of(&env);
    set_enterprise_config(&mut env, ENTERPRISE_FLAGS & !state::FAMILY_TRANSFER10X2, &x, &y);
    expect_reject(&env, PoolError::FamilyDisabled);
}

#[test]
fn ent_t10x2_non_canonical_public_rejected() {
    let fx = load_ent_transfer10x2_fixture();
    let mut env = build_ent_transfer10x2_env(&fx);
    let off = carried_offset(0);
    env.instruction.data[off..off + 32].copy_from_slice(&R_BE);
    expect_reject(&env, PoolError::PublicInputNotCanonical);
}

#[test]
fn ent_t10x2_wrong_arbiter_key_fails_verify() {
    let fx = load_ent_transfer10x2_fixture();
    let mut env = build_ent_transfer10x2_env(&fx);
    let (_, y) = arbiter_of(&env);
    set_enterprise_config(&mut env, ENTERPRISE_FLAGS, &OTHER_KEY, &y);
    expect_reject(&env, PoolError::InvalidProof);
}

#[test]
fn ent_t10x2_arbiter_key_unset_rejected() {
    let fx = load_ent_transfer10x2_fixture();
    let mut env = build_ent_transfer10x2_env(&fx);
    set_enterprise_config(&mut env, ENTERPRISE_FLAGS, &[0u8; 32], &[0u8; 32]);
    expect_reject(&env, PoolError::ArbiterKeyUnset);
}

#[test]
fn ent_t10x2_prefunded_marker_pda_does_not_block() {
    // 10-PDA arity: pre-fund three SCATTERED nfs (slots 0, 4, 9) below rent
    // and the new-root above rent; the op must still create the full marker
    // run and advance the tree.
    let fx = load_ent_transfer10x2_fixture();
    let mut env = build_ent_transfer10x2_env(&fx);
    for slot in [0usize, 4, 9] {
        let nf = env.nf_pdas[slot];
        env.set_account(
            &nf,
            Account {
                lamports: 500_000,
                ..Account::default()
            },
        );
    }
    let new_root = env.new_root_pda;
    env.set_account(
        &new_root,
        Account {
            lamports: 1_000_000_000,
            ..Account::default()
        },
    );
    let result = env.mollusk.process_and_validate_instruction(
        &env.instruction,
        &env.accounts,
        &[Check::success()],
    );
    for nf in &env.nf_pdas {
        let acc = result.get_account(nf).expect("nullifier pda");
        assert_eq!(acc.owner, program_id(), "nullifier PDA not claimed");
        assert_eq!(acc.data.len(), 0);
    }
    let root_acc = result.get_account(&env.new_root_pda).expect("new root pda");
    assert_eq!(root_acc.owner, program_id(), "new KnownRoot PDA not claimed");
    let tree = result.get_account(&env.tree_key).expect("tree account");
    assert_eq!(
        tree.data,
        tree_account_data(&env.config_key, &fx.post_state),
        "tree did not advance on the pre-funded-PDA path"
    );
}
