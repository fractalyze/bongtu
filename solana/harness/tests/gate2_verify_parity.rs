//! Gate 2 — verify parity (SOLR §3.1.3 #2): each op's on-SVM verifier accepts
//! its committed realproof fixture (same circuit artifacts, VK constants
//! generated from the committed vkeys) and rejects a tampered public.
//! State-level replay per SOLR §5.2: each fixture's spend root is seeded as a
//! KnownRoot PDA and the tree state matches the ImtTree oracle replay.
//!
//! Sources: depositPriv / transferPriv / transfer10x2Priv replay the
//! committed EVM fixtures unchanged; the op-level withdraw runs the ONE
//! re-proven Solana-recipient fixture (OPEN-3 truncate-253), while the EVM
//! withdrawPriv fixture still replays at VERIFY level (its pub[15] binds an
//! EVM address, unreachable through the account-bound instruction wire).
//!
//! Also the CU recorder (gate 3): every happy path asserts against the
//! committed cu_budget.json ceiling and prints the measured number.

use {
    bongtu_pool_solana::{
        error::PoolError,
        generated::vk_withdraw_priv,
        groth16,
    },
    bongtu_solana_harness::{
        build_deposit_env, build_env, build_transfer10x2_env, build_withdraw_env, carried_offset,
        hex_bytes, hex32, hex_u64, load_cu_budget, load_deposit_fixture, load_fixture,
        load_transfer10x2_fixture, load_withdraw_fixture, program_id, token_amount,
        tree_account_data, Env, TreeSnapshot,
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
        "{op}: post-append TreeState diverged from the ImtTree oracle"
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

// --- deposit_priv ------------------------------------------------------------

#[test]
fn deposit_accepts_committed_evm_realproof_and_pulls_escrow() {
    let fx = load_deposit_fixture();
    let env = build_deposit_env(&fx);
    let result = run_happy(&env, "deposit_priv", &fx.post_state);

    // Escrow pull: exactly pub[0] moved payer -> vault.
    let amount = hex_u64(&fx.amount);
    let vault = result.get_account(&env.vault_key).expect("vault");
    assert_eq!(token_amount(vault), amount, "vault did not receive the deposit");
    let payer_token = result.get_account(&env.payer_token_key).expect("payer token");
    assert_eq!(token_amount(payer_token), amount, "payer token balance wrong (had 2x)");
}

#[test]
fn deposit_rejects_tampered_public() {
    let fx = load_deposit_fixture();
    let mut env = build_deposit_env(&fx);
    run_tamper(&mut env, "deposit_priv", 15); // carried[15] == pub[15] (nonce)
}

// --- transfer_priv -----------------------------------------------------------

#[test]
fn transfer_accepts_committed_evm_realproof_and_applies_state() {
    let fx = load_fixture();
    let env = build_env(&fx);
    run_happy(&env, "transfer_priv", &fx.post_state);
}

#[test]
fn transfer_rejects_tampered_public() {
    let fx = load_fixture();
    let mut env = build_env(&fx);
    run_tamper(&mut env, "transfer_priv", 17); // carried[17] == pub[19] (nonce)
}

// --- transfer10x2_priv -------------------------------------------------------

#[test]
fn transfer10x2_accepts_committed_evm_realproof_and_applies_state() {
    let fx = load_transfer10x2_fixture();
    let env = build_transfer10x2_env(&fx);
    assert_eq!(env.nf_pdas.len(), 4, "fixture spends 4 real inputs of 10");
    run_happy(&env, "transfer10x2_priv", &fx.post_state);
}

#[test]
fn transfer10x2_rejects_tampered_public() {
    let fx = load_transfer10x2_fixture();
    let mut env = build_transfer10x2_env(&fx);
    run_tamper(&mut env, "transfer10x2_priv", 25); // carried[25] == pub[35] (nonce)
}

// --- withdraw_priv (the re-proven Solana-recipient fixture) ------------------

#[test]
fn withdraw_accepts_reproven_solana_fixture_and_pushes_escrow() {
    let fx = load_withdraw_fixture();
    let env = build_withdraw_env(&fx);
    let result = run_happy(&env, "withdraw_priv", &fx.post_state);

    // Escrow push: exactly pub[0] moved vault -> the proof-bound recipient.
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
fn withdraw_rejects_tampered_public() {
    let fx = load_withdraw_fixture();
    let mut env = build_withdraw_env(&fx);
    run_tamper(&mut env, "withdraw_priv", 12); // carried[12] == pub[14] (nonce)
}

// --- the committed EVM withdrawPriv fixture: verify-level replay -------------
// (SOLR §5.2: it binds an EVM recipient in pub[15], so it exercises the
// verifier + VK generation directly, not the account-bound instruction.)

#[derive(serde::Deserialize)]
struct EvmWithdraw {
    a: Vec<String>,
    b: Vec<Vec<String>>,
    c: Vec<String>,
    #[serde(rename = "pub")]
    publics: Vec<String>,
}

fn load_evm_withdraw() -> ([u8; 256], Vec<[u8; 32]>) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/test/fixtures/consumer_realproofs.json"
    );
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("consumer_realproofs.json"))
            .unwrap();
    let fx: EvmWithdraw = serde_json::from_value(v["withdrawPriv"].clone()).expect("withdrawPriv");
    let mut proof = Vec::with_capacity(256);
    for part in [
        &fx.a[0], &fx.a[1], &fx.b[0][0], &fx.b[0][1], &fx.b[1][0], &fx.b[1][1], &fx.c[0], &fx.c[1],
    ] {
        proof.extend_from_slice(&hex_bytes(part));
    }
    let mut arr = [0u8; 256];
    arr.copy_from_slice(&proof);
    let publics: Vec<[u8; 32]> = fx.publics.iter().map(|p| hex32(p)).collect();
    assert_eq!(publics.len(), 16);
    (arr, publics)
}

#[test]
fn evm_withdraw_fixture_verifies_at_verify_level() {
    let (proof, publics) = load_evm_withdraw();
    assert!(
        groth16::verify(&vk_withdraw_priv::VK, &proof, &publics).expect("verify"),
        "committed EVM withdrawPriv realproof rejected by the generated VK"
    );
}

#[test]
fn evm_withdraw_fixture_rejects_tampered_recipient() {
    let (proof, mut publics) = load_evm_withdraw();
    publics[15][31] ^= 0x01; // a different recipient must fail the pairing
    assert!(
        !groth16::verify(&vk_withdraw_priv::VK, &proof, &publics).expect("verify"),
        "tampered recipient accepted"
    );
}
