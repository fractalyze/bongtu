//! Gate 5 — invariant-gate conformance (SOLR §3.1.3 #5), mirroring the EVM
//! enforcement suite (chains/evm/test/Enforcement.t.sol + the _applyOp guard
//! list): double-spend, unknown root, zero leaf, wrong kem-ct length, family
//! flag off, in-tx duplicate nullifier, mismatched result-root PDA, plus the
//! escrow-op rows (wrong vault, amount over u64, recipient substitution and
//! wrong-mint recipient under the OPEN-3 binding) — each rejects with the
//! mapped error and leaves the tree untouched.
//!
//! Where the EVM suite needed stub verifiers (its guards run after verify),
//! this program checks invariants before the expensive verify, so every row
//! runs against a committed REAL proof with only the state or wire mutated.

use {
    bongtu_solana_harness::{
        build_deposit_env, build_env, build_transfer10x2_env, build_withdraw_env, carried_offset,
        is_canonical, load_deposit_fixture, load_fixture, load_transfer10x2_fixture,
        load_withdraw_fixture, program_id, token_account, token_amount, tree_account_data, Env,
        MINT_BYTES,
    },
    bongtu_pool_solana::{error::PoolError, state},
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

/// Swap the config image for one with `flags` — the consumer profile with a
/// family switched off (the ModuleNotRegistered analogue, SOLR §2.1).
fn set_family_flags(env: &mut Env, flags: u8) {
    let config_key = env.config_key;
    let data = bongtu_solana_harness::config_account_data(flags);
    let mut account = env
        .accounts
        .iter()
        .find(|(k, _)| k == &config_key)
        .unwrap()
        .1
        .clone();
    account.data = data;
    env.set_account(&config_key, account);
}

// --- transfer_priv rows (the tracer set) -------------------------------------

#[test]
fn double_spend_rejected() {
    let fx = load_fixture();
    let mut env = build_env(&fx);
    // Nullifier 0 already spent: its PDA exists (program-owned marker).
    let marker = env.existing_marker();
    let nf0 = env.nf_pdas[0];
    env.set_account(&nf0, marker);
    expect_reject(&env, PoolError::NullifierAlreadyUsed);
}

#[test]
fn in_tx_duplicate_nullifier_rejected() {
    let fx = load_fixture();
    let mut env = build_env(&fx);
    // carried[13] (nullifier 1) := carried[12] (nullifier 0) — the _applyOp
    // sequential-marking rule: the second occurrence is a double spend.
    let (src, dst) = (carried_offset(12), carried_offset(13));
    let nf0: Vec<u8> = env.instruction.data[src..src + 32].to_vec();
    env.instruction.data[dst..dst + 32].copy_from_slice(&nf0);
    expect_reject(&env, PoolError::NullifierAlreadyUsed);
}

#[test]
fn unknown_root_rejected() {
    let fx = load_fixture();
    let mut env = build_env(&fx);
    // Un-seed the KnownRoot PDA: account exists in the list but was never
    // created on-chain (system-owned, no lamports).
    let spent = env.spent_root_pda;
    env.set_account(&spent, Account::default());
    expect_reject(&env, PoolError::UnknownRoot);
}

#[test]
fn zero_output_commitment_rejected() {
    let fx = load_fixture();
    let mut env = build_env(&fx);
    // carried[15] == pub[17] (output commitment 0) := 0 — the §6b self-burn
    // guard; a zero commitment is a non-note.
    let off = carried_offset(15);
    env.instruction.data[off..off + 32].fill(0);
    expect_reject(&env, PoolError::ZeroOutputCommitment);
}

#[test]
fn wrong_kem_ciphertext_length_rejected() {
    let fx = load_fixture();
    let mut env = build_env(&fx);
    // One byte short of 2 × 1088: the fixed wire layout catches both a short
    // ciphertext and a wrong count.
    env.instruction.data.pop();
    expect_reject(&env, PoolError::WrongKemCiphertextLength);
}

#[test]
fn family_flag_off_rejected() {
    let fx = load_fixture();
    let mut env = build_env(&fx);
    set_family_flags(&mut env, 0x0F & !state::FAMILY_TRANSFER_PRIV);
    expect_reject(&env, PoolError::FamilyDisabled);
}

#[test]
fn mismatched_new_root_account_rejected() {
    let fx = load_fixture();
    let mut env = build_env(&fx);
    // A new-root account that is not the PDA for the computed resulting root:
    // caught after verify + append, and the whole op (appends included) must
    // roll back.
    let wrong = Pubkey::new_from_array([0x77; 32]);
    env.instruction.accounts[3] = AccountMeta::new(wrong, false);
    let old = env.new_root_pda;
    let idx = env.accounts.iter().position(|(k, _)| k == &old).unwrap();
    env.accounts[idx] = (wrong, Account::default());
    expect_reject(&env, PoolError::PdaMismatch);
}

#[test]
fn non_canonical_public_rejected() {
    let fx = load_fixture();
    let mut env = build_env(&fx);
    // carried[0] := r (the BN254 scalar field modulus) on the wire — the
    // smallest non-canonical encoding; check_canonical must reject before
    // any aliasing (byte-equality, not mod-p) can matter.
    let r_be: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
        0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93,
        0xf0, 0x00, 0x00, 0x01,
    ];
    assert!(!is_canonical(&r_be), "r must be non-canonical by definition");
    let off = carried_offset(0);
    env.instruction.data[off..off + 32].copy_from_slice(&r_be);
    expect_reject(&env, PoolError::PublicInputNotCanonical);
}

#[test]
fn mint_claiming_membership_rejected() {
    let fx = load_fixture();
    let mut env = build_env(&fx);
    // Zero BOTH nullifier publics (carried[12..13]) while the spent root
    // (carried[14]) stays nonzero: an op spending nothing must claim no
    // membership (the _applyOp mirror). Drivable with a real proof because
    // the invariant checks run BEFORE verify on this rail.
    for i in [12usize, 13] {
        let off = carried_offset(i);
        env.instruction.data[off..off + 32].fill(0);
    }
    expect_reject(&env, PoolError::UnknownRoot);
}

#[test]
fn prefunded_marker_pda_does_not_block_spend() {
    let fx = load_fixture();
    let mut env = build_env(&fx);
    // Griefing-DoS hardening (S2 review finding 1): an attacker who sees a
    // pending tx pre-funds the derived marker addresses with lamports. A raw
    // CreateAccount would fail AccountAlreadyInUse and freeze the note
    // forever (nf is a pure function of the note). The op must still succeed
    // via the Transfer/Allocate/Assign path. Two sub-cases in one row:
    // nf PDA below rent (exercises the top-up) and new-root PDA above rent
    // (exercises the skip-transfer path).
    let nf0 = env.nf_pdas[0];
    env.set_account(
        &nf0,
        Account {
            lamports: 500_000, // below the 890,880 rent-exempt minimum
            ..Account::default()
        },
    );
    let new_root = env.new_root_pda;
    env.set_account(
        &new_root,
        Account {
            lamports: 1_000_000_000, // already past rent-exempt
            ..Account::default()
        },
    );
    let result = env.mollusk.process_and_validate_instruction(
        &env.instruction,
        &env.accounts,
        &[Check::success()],
    );
    // Note spent: every marker PDA program-owned, still 0-data.
    for nf in &env.nf_pdas {
        let acc = result.get_account(nf).expect("nullifier pda");
        assert_eq!(acc.owner, program_id(), "nullifier PDA not claimed");
        assert_eq!(acc.data.len(), 0);
        assert!(acc.lamports >= 890_880, "marker below rent-exempt");
    }
    let root_acc = result.get_account(&env.new_root_pda).expect("new root pda");
    assert_eq!(root_acc.owner, program_id(), "new KnownRoot PDA not claimed");
    // Tree advanced to the ImtTree oracle post-state.
    let tree = result.get_account(&env.tree_key).expect("tree account");
    assert_eq!(
        tree.data,
        tree_account_data(&env.config_key, &fx.post_state),
        "tree did not advance on the pre-funded-PDA path"
    );
    println!(
        "CU[transfer_priv prefunded-pda] = {}",
        result.compute_units_consumed
    );
}

// --- transfer10x2_priv rows (10-nullifier arity) -----------------------------

#[test]
fn t10x2_double_spend_rejected() {
    let fx = load_transfer10x2_fixture();
    let mut env = build_transfer10x2_env(&fx);
    // The LAST real input (slot 3 of 4) already spent: the sequential loop
    // reaches it only after accepting the first three.
    let marker = env.existing_marker();
    let nf3 = env.nf_pdas[3];
    env.set_account(&nf3, marker);
    expect_reject(&env, PoolError::NullifierAlreadyUsed);
}

#[test]
fn t10x2_missing_nullifier_account_rejected() {
    let fx = load_transfer10x2_fixture();
    let mut env = build_transfer10x2_env(&fx);
    // 4 nonzero nullifiers but only 3 PDA accounts supplied.
    env.instruction.accounts.pop();
    expect_reject(&env, PoolError::MissingNullifierAccount);
}

#[test]
fn t10x2_in_tx_duplicate_nullifier_rejected() {
    let fx = load_transfer10x2_fixture();
    let mut env = build_transfer10x2_env(&fx);
    // carried[13] (nullifier slot 1) := carried[12] (slot 0).
    let (src, dst) = (carried_offset(12), carried_offset(13));
    let nf0: Vec<u8> = env.instruction.data[src..src + 32].to_vec();
    env.instruction.data[dst..dst + 32].copy_from_slice(&nf0);
    expect_reject(&env, PoolError::NullifierAlreadyUsed);
}

#[test]
fn t10x2_unknown_root_rejected() {
    let fx = load_transfer10x2_fixture();
    let mut env = build_transfer10x2_env(&fx);
    // Un-seed the KnownRoot PDA (right address, never created on-chain).
    let spent = env.spent_root_pda;
    env.set_account(&spent, Account::default());
    expect_reject(&env, PoolError::UnknownRoot);
}

#[test]
fn t10x2_zero_output_commitment_rejected() {
    let fx = load_transfer10x2_fixture();
    let mut env = build_transfer10x2_env(&fx);
    // carried[23] == pub[33] (output commitment 0) := 0.
    let off = carried_offset(23);
    env.instruction.data[off..off + 32].fill(0);
    expect_reject(&env, PoolError::ZeroOutputCommitment);
}

#[test]
fn t10x2_wrong_kem_ciphertext_length_rejected() {
    let fx = load_transfer10x2_fixture();
    let mut env = build_transfer10x2_env(&fx);
    env.instruction.data.pop();
    expect_reject(&env, PoolError::WrongKemCiphertextLength);
}

#[test]
fn t10x2_family_flag_off_rejected() {
    let fx = load_transfer10x2_fixture();
    let mut env = build_transfer10x2_env(&fx);
    set_family_flags(&mut env, 0x0F & !state::FAMILY_TRANSFER10X2_PRIV);
    expect_reject(&env, PoolError::FamilyDisabled);
}

// --- deposit_priv rows (mint + escrow pull) ----------------------------------

#[test]
fn deposit_zero_output_commitment_rejected() {
    let fx = load_deposit_fixture();
    let mut env = build_deposit_env(&fx);
    let off = carried_offset(13); // pub[13] = output commitment 0
    env.instruction.data[off..off + 32].fill(0);
    expect_reject(&env, PoolError::ZeroOutputCommitment);
}

#[test]
fn deposit_wrong_vault_rejected() {
    let fx = load_deposit_fixture();
    let mut env = build_deposit_env(&fx);
    // A perfectly valid token account that is NOT the config-bound vault.
    let wrong = Pubkey::new_from_array([0x66; 32]);
    let (vault_owner, _) = bongtu_solana_harness::vault_authority();
    env.instruction.accounts[9] = AccountMeta::new(wrong, false);
    let old = env.vault_key;
    let idx = env.accounts.iter().position(|(k, _)| k == &old).unwrap();
    env.accounts[idx] = (wrong, token_account(&MINT_BYTES, &vault_owner, 0));
    expect_reject(&env, PoolError::InvalidAccount);
}

#[test]
fn deposit_wrong_kem_ciphertext_length_rejected() {
    let fx = load_deposit_fixture();
    let mut env = build_deposit_env(&fx);
    env.instruction.data.pop();
    expect_reject(&env, PoolError::WrongKemCiphertextLength);
}

#[test]
fn deposit_family_flag_off_rejected() {
    let fx = load_deposit_fixture();
    let mut env = build_deposit_env(&fx);
    set_family_flags(&mut env, 0x0F & !state::FAMILY_DEPOSIT_PRIV);
    expect_reject(&env, PoolError::FamilyDisabled);
}

#[test]
fn deposit_amount_over_u64_rejected() {
    let fx = load_deposit_fixture();
    let mut env = build_deposit_env(&fx);
    // pub[0] := 2^64 + amount — canonical (< r) but unrepresentable in SPL;
    // the per-rail u64 belt must reject before any state or escrow motion.
    env.instruction.data[carried_offset(0) + 23] = 0x01;
    expect_reject(&env, PoolError::AmountOverflow);
}

// --- withdraw_priv rows (OPEN-3 binding + escrow push) -----------------------

#[test]
fn withdraw_recipient_substitution_rejected() {
    let fx = load_withdraw_fixture();
    let mut env = build_withdraw_env(&fx);
    // A valid same-mint token account at a DIFFERENT address: the program
    // injects its truncate-253 binding as pub[15], so the proof (bound to the
    // fixture recipient) must fail verify. Funds never move.
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
        bongtu_solana_harness::hex_u64(&fx.amount) * 10,
        "vault moved on a rejected withdraw"
    );
}

#[test]
fn withdraw_wrong_mint_recipient_rejected() {
    let fx = load_withdraw_fixture();
    let mut env = build_withdraw_env(&fx);
    // The right address but the wrong mint: the SPL owner/mint checks run
    // BEFORE the binding (OPEN-3 spec), so this is InvalidAccount, not a
    // verify failure.
    let recipient = env.recipient_token_key;
    let owner = Pubkey::new_from_array([0x05; 32]);
    env.set_account(&recipient, token_account(&[0xDD; 32], &owner, 0));
    expect_reject(&env, PoolError::InvalidAccount);
}

#[test]
fn withdraw_double_spend_rejected() {
    let fx = load_withdraw_fixture();
    let mut env = build_withdraw_env(&fx);
    let marker = env.existing_marker();
    let nf0 = env.nf_pdas[0];
    env.set_account(&nf0, marker);
    expect_reject(&env, PoolError::NullifierAlreadyUsed);
}

#[test]
fn withdraw_unknown_root_rejected() {
    let fx = load_withdraw_fixture();
    let mut env = build_withdraw_env(&fx);
    let spent = env.spent_root_pda;
    env.set_account(&spent, Account::default());
    expect_reject(&env, PoolError::UnknownRoot);
}

#[test]
fn withdraw_zero_change_commitment_rejected() {
    let fx = load_withdraw_fixture();
    let mut env = build_withdraw_env(&fx);
    // carried[11] == pub[13] (the change commitment, withdraw's only leaf) := 0.
    let off = carried_offset(11);
    env.instruction.data[off..off + 32].fill(0);
    expect_reject(&env, PoolError::ZeroOutputCommitment);
}

#[test]
fn withdraw_wrong_kem_ciphertext_length_rejected() {
    let fx = load_withdraw_fixture();
    let mut env = build_withdraw_env(&fx);
    // One byte short: the fixed wire layout (kem ct + stealth tail) is a
    // single length, so any shape drift maps to WrongKemCiphertextLength.
    env.instruction.data.pop();
    expect_reject(&env, PoolError::WrongKemCiphertextLength);
}

#[test]
fn withdraw_family_flag_off_rejected() {
    let fx = load_withdraw_fixture();
    let mut env = build_withdraw_env(&fx);
    set_family_flags(&mut env, 0x0F & !state::FAMILY_WITHDRAW_PRIV);
    expect_reject(&env, PoolError::FamilyDisabled);
}

#[test]
fn withdraw_amount_over_u64_rejected() {
    let fx = load_withdraw_fixture();
    let mut env = build_withdraw_env(&fx);
    // pub[0] := 2^64 + amount on the withdraw path — canonical (< r) but
    // unrepresentable in SPL; the per-rail u64 belt rejects before verify,
    // state, or escrow motion (the deposit row's push-side twin).
    env.instruction.data[carried_offset(0) + 23] = 0x01;
    expect_reject(&env, PoolError::AmountOverflow);
}
