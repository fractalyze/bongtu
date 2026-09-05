//! Gate 2, enterprise rows (SOLR §3.1.3 #2 / §6 S3 acceptance): each
//! enterprise op's on-SVM verifier accepts its committed realproof fixture —
//! deposit/withdraw/transfer/transfer10x2 replay the EVM realproofs.json
//! proofs (10x2 the MERGE entry: all 10 inputs real), disburse256 the
//! GPU-proven production-arity proof — with the arbiter key injected from the
//! enterprise `PoolConfig`, and rejects a tampered public. State-level replay
//! per SOLR §5.2 (seeded KnownRoot + ImtTree-oracle tree state).
//!
//! Also the enterprise CU recorder (gate 3): every happy path asserts against
//! the committed cu_budget.json ceiling and prints the measured number.

use {
    bongtu_pool_solana::{error::PoolError, state},
    bongtu_solana_harness::{
        carried_offset,
        enterprise::{
            build_disburse256_env, build_ent_deposit_env, build_ent_transfer10x2_env,
            build_ent_transfer_env, build_ent_withdraw_env, disburse_batch_pda,
            load_disburse256_fixture, load_ent_deposit_fixture, load_ent_transfer10x2_fixture,
            load_ent_transfer_fixture, load_ent_withdraw_fixture,
        },
        hex32, hex_u64, load_cu_budget, program_id, token_amount, tree_account_data, Env,
        TreeSnapshot,
    },
    mollusk_svm::result::Check,
    solana_program_error::ProgramError,
};

/// Run the happy path: success, post-state tree == the ImtTree oracle, every
/// expected marker PDA created, CU within the committed budget.
fn run_happy(
    env: &Env,
    op: &str,
    post_state: &TreeSnapshot,
) -> mollusk_svm::result::InstructionResult {
    let result = env.mollusk.process_and_validate_instruction(
        &env.instruction,
        &env.accounts,
        &[Check::success()],
    );

    let tree = result.get_account(&env.tree_key).expect("tree account");
    let expected_post = tree_account_data(&env.config_key, post_state);
    assert_eq!(
        tree.data, expected_post,
        "{op}: post-op TreeState diverged from the ImtTree oracle"
    );

    for nf in &env.nf_pdas {
        let acc = result.get_account(nf).expect("nullifier pda");
        assert_eq!(acc.owner, program_id(), "{op}: nullifier PDA not created");
        assert_eq!(acc.data.len(), 0);
    }
    let root_acc = result.get_account(&env.new_root_pda).expect("new root pda");
    assert_eq!(root_acc.owner, program_id(), "{op}: new KnownRoot PDA not created");

    // CU regression budget (SOLR §3.1.3 #3) — moves only by commit.
    let budget = load_cu_budget(op);
    println!(
        "CU[{op}] = {} (budget {})",
        result.compute_units_consumed, budget
    );
    assert!(
        result.compute_units_consumed <= budget,
        "{op} consumed {} CU, budget {}",
        result.compute_units_consumed,
        budget
    );
    result
}

/// Tamper one carried public (the encryption nonce: it passes every invariant
/// check, so the rejection can only come from the Groth16 verify itself) and
/// assert InvalidProof with the tree untouched.
fn run_tamper(env: &mut Env, op: &str, nonce_carried_index: usize) {
    let off = carried_offset(nonce_carried_index) + 31;
    env.instruction.data[off] ^= 0x01;
    let result = env.mollusk.process_and_validate_instruction(
        &env.instruction,
        &env.accounts,
        &[Check::err(ProgramError::Custom(PoolError::InvalidProof as u32))],
    );
    let tree = result.get_account(&env.tree_key).expect("tree account");
    assert_eq!(tree.data, env.pre_tree_data, "{op}: tree mutated by a rejected op");
}

// --- deposit (enterprise) ----------------------------------------------------

#[test]
fn ent_deposit_accepts_committed_evm_realproof_and_pulls_escrow() {
    let fx = load_ent_deposit_fixture();
    let env = build_ent_deposit_env(&fx);
    let result = run_happy(&env, "deposit", &fx.post_state);

    // Escrow pull: exactly pub[0] moved payer -> vault.
    let amount = hex_u64(&fx.amount);
    let vault = result.get_account(&env.vault_key).expect("vault");
    assert_eq!(token_amount(vault), amount, "vault did not receive the deposit");
    let payer_token = result.get_account(&env.payer_token_key).expect("payer token");
    assert_eq!(token_amount(payer_token), amount, "payer token balance wrong (had 2x)");
}

#[test]
fn ent_deposit_rejects_tampered_public() {
    let fx = load_ent_deposit_fixture();
    let mut env = build_ent_deposit_env(&fx);
    run_tamper(&mut env, "deposit", 16); // carried[16] == pub[16] (nonce)
}

// --- withdraw (enterprise) ---------------------------------------------------

#[test]
fn ent_withdraw_accepts_committed_evm_realproof_and_pushes_escrow() {
    let fx = load_ent_withdraw_fixture();
    let env = build_ent_withdraw_env(&fx);
    let result = run_happy(&env, "withdraw", &fx.post_state);

    // Escrow push: exactly pub[0] moved vault -> the proof-bound recipient
    // (the fixture recipient token account sits at BE32(pub[26]), so the
    // truncate-253 binding reproduces the proof's recipient exactly).
    let amount = hex_u64(&fx.amount);
    let recipient = result
        .get_account(&env.recipient_token_key)
        .expect("recipient token");
    assert_eq!(token_amount(recipient), amount, "recipient did not receive the payout");
    let vault = result.get_account(&env.vault_key).expect("vault");
    assert_eq!(
        token_amount(vault),
        amount * 10 - amount,
        "vault balance wrong after push"
    );
}

#[test]
fn ent_withdraw_rejects_tampered_public() {
    let fx = load_ent_withdraw_fixture();
    let mut env = build_ent_withdraw_env(&fx);
    run_tamper(&mut env, "withdraw", 21); // carried[21] == pub[23] (nonce)
}

// --- disburse256 -------------------------------------------------------------

#[test]
fn disburse256_accepts_committed_gpu_realproof_and_persists_batch() {
    let fx = load_disburse256_fixture();
    let env = build_disburse256_env(&fx);
    let result = run_happy(&env, "disburse256", &fx.post_state);

    // The durable audit anchor (SOLR §3.3.1): DisburseBatch persists
    // (start_leaf_index, disclosureHash, kemBinding, epoch).
    let batch = result
        .get_account(&disburse_batch_pda(fx.start_leaf_index))
        .expect("disburse batch pda");
    assert_eq!(batch.owner, program_id(), "DisburseBatch PDA not created");
    assert_eq!(batch.data.len(), state::DISBURSE_BATCH_LEN);
    assert_eq!(batch.data[0], state::TAG_DISBURSE_BATCH);
    assert_eq!(
        batch.data[state::BATCH_OFF_START..state::BATCH_OFF_START + 8],
        fx.start_leaf_index.to_le_bytes(),
        "batch start_leaf_index"
    );
    assert_eq!(
        batch.data[state::BATCH_OFF_DISCLOSURE_HASH..state::BATCH_OFF_DISCLOSURE_HASH + 32],
        hex32(&fx.disclosure_hash),
        "batch disclosureHash != the proof's pub[2]"
    );
    assert_eq!(
        batch.data[state::BATCH_OFF_KEM_BINDING..state::BATCH_OFF_KEM_BINDING + 32],
        hex32(&fx.kem_binding),
        "batch kemBinding != the proof's pub[4]"
    );
    assert_eq!(
        batch.data[state::BATCH_OFF_EPOCH..state::BATCH_OFF_EPOCH + 8],
        fx.batch_epoch.to_le_bytes(),
        "batch epoch"
    );
}

#[test]
fn disburse256_rejects_tampered_public() {
    let fx = load_disburse256_fixture();
    let mut env = build_disburse256_env(&fx);
    run_tamper(&mut env, "disburse256", 7); // carried[7] == pub[8] (nonce)
}

#[test]
fn disburse256_rejects_tampered_disclosure_hash() {
    // The binding the whole §3.3 design hangs on: a different disclosureHash
    // is a different statement, and the proof must fail against it.
    let fx = load_disburse256_fixture();
    let mut env = build_disburse256_env(&fx);
    run_tamper(&mut env, "disburse256", 2); // carried[2] == pub[2]
}

// --- transfer (enterprise, S3 pass 2) ----------------------------------------

#[test]
fn ent_transfer_accepts_committed_evm_realproof() {
    let fx = load_ent_transfer_fixture();
    let env = build_ent_transfer_env(&fx);
    let result = run_happy(&env, "transfer", &fx.post_state);
    drop(result);
}

#[test]
fn ent_transfer_rejects_tampered_public() {
    let fx = load_ent_transfer_fixture();
    let mut env = build_ent_transfer_env(&fx);
    run_tamper(&mut env, "transfer", 32); // carried[32] == pub[34] (nonce)
}

// --- transfer10x2 (enterprise, S3 pass 2) ------------------------------------

#[test]
fn ent_transfer10x2_accepts_committed_evm_realproof_all_ten_inputs() {
    // The merge fixture: all 10 nullifiers real, so the happy path creates
    // the full 10-nullifier-PDA run — the worst-case CU the budget records.
    let fx = load_ent_transfer10x2_fixture();
    assert_eq!(fx.nullifiers.len(), 10);
    let env = build_ent_transfer10x2_env(&fx);
    assert_eq!(env.nf_pdas.len(), 10, "merge fixture must drive 10 nf PDAs");
    let result = run_happy(&env, "transfer10x2", &fx.post_state);
    drop(result);
}

#[test]
fn ent_transfer10x2_rejects_tampered_public() {
    let fx = load_ent_transfer10x2_fixture();
    let mut env = build_ent_transfer10x2_env(&fx);
    run_tamper(&mut env, "transfer10x2", 55); // carried[55] == pub[65] (nonce)
}
