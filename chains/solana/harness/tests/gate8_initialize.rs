//! Gate 8 — `initialize` (S6 deploy profile): the one-shot initializer
//! produces the production shape, and every profile precondition refuses
//! loudly (SOLR §2.5 / §2.2 S3 note).
//!
//! The crux row chains a REAL committed consumer deposit proof through a
//! pool the instruction just created: initialize is not merely writing
//! bytes, it is producing accounts the op set accepts as-is.

use {
    bongtu_pool_solana::{
        error::PoolError,
        generated::zeros::{TREE_HEIGHT, ZEROS},
        initialize, spl, state,
    },
    bongtu_solana_harness::{
        enterprise::load_disburse256_fixture, hex32, hex_bytes, hex_u64, load_deposit_fixture,
        mollusk_with_program, program_id, token_account, token_amount,
    },
    mollusk_svm::{program::keyed_account_for_system_program, result::Check},
    solana_account::Account,
    solana_instruction::{AccountMeta, Instruction},
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
};

/// The BN254 scalar field modulus r as 32 big-endian bytes — the smallest
/// non-canonical wire value (the gate-5 constant).
const R_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
    0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
    0x00, 0x01,
];

const CONSUMER_FLAGS: u16 = 0x000F;
const ENTERPRISE_FLAGS: u16 = 0x01FF;

fn payload(flags: u16, b: u32, x: &[u8; 32], y: &[u8; 32], kem: &[u8; 32]) -> Vec<u8> {
    let mut data = vec![initialize::DISCRIMINATOR];
    data.extend_from_slice(&flags.to_le_bytes());
    data.extend_from_slice(&b.to_le_bytes());
    data.extend_from_slice(x);
    data.extend_from_slice(y);
    data.extend_from_slice(kem);
    data
}

/// SPL Mint image (82 B): no authorities, decimals 0, is_initialized = 1.
fn mint_account() -> Account {
    let mut data = vec![0u8; spl::MINT_ACCOUNT_LEN];
    data[45] = 1;
    Account {
        lamports: 1_461_600,
        data,
        owner: spl::TOKEN_PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    }
}

struct InitEnv {
    ix: Instruction,
    accounts: Vec<(Pubkey, Account)>,
    config_pda: Pubkey,
    tree_pda: Pubkey,
    mint_key: Pubkey,
    vault_key: Pubkey,
    payer: Pubkey,
}

fn build(flags: u16, b: u32, x: &[u8; 32], y: &[u8; 32], kem: &[u8; 32]) -> InitEnv {
    let pid = program_id();
    let mint_key = Pubkey::new_from_array([0xB0; 32]);
    let (config_pda, _) =
        Pubkey::find_program_address(&[state::SEED_CONFIG, &mint_key.to_bytes()], &pid);
    let (tree_pda, _) =
        Pubkey::find_program_address(&[state::SEED_TREE, &config_pda.to_bytes()], &pid);
    let (vault_authority, _) =
        Pubkey::find_program_address(&[state::SEED_VAULT_AUTHORITY, &config_pda.to_bytes()], &pid);
    let vault_key = Pubkey::new_from_array([0xC0; 32]);
    let payer = Pubkey::new_from_array([0x03; 32]);

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(config_pda, false),
            AccountMeta::new(tree_pda, false),
            AccountMeta::new_readonly(mint_key, false),
            AccountMeta::new_readonly(vault_key, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data: payload(flags, b, x, y, kem),
    };
    let accounts = vec![
        (config_pda, Account::default()),
        (tree_pda, Account::default()),
        (mint_key, mint_account()),
        (
            vault_key,
            token_account(&mint_key.to_bytes(), &vault_authority, 0),
        ),
        (
            payer,
            Account {
                lamports: 10_000_000_000,
                ..Account::default()
            },
        ),
        keyed_account_for_system_program(),
    ];
    InitEnv {
        ix,
        accounts,
        config_pda,
        tree_pda,
        mint_key,
        vault_key,
        payer,
    }
}

fn expect_reject(env: &InitEnv, error: PoolError) {
    let mollusk = mollusk_with_program(false);
    mollusk.process_and_validate_instruction(
        &env.ix,
        &env.accounts,
        &[Check::err(ProgramError::Custom(error as u32))],
    );
}

/// The expected PoolConfig image the instruction must have written.
fn expected_config(env: &InitEnv, flags: u16, b: u32, x: &[u8; 32], y: &[u8; 32], kem: &[u8; 32]) -> Vec<u8> {
    let mut data = vec![0u8; state::POOL_CONFIG_LEN];
    data[0] = state::TAG_POOL_CONFIG;
    data[1] = 1;
    data[state::CONFIG_OFF_FLAGS..state::CONFIG_OFF_FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
    data[4..36].copy_from_slice(&env.payer.to_bytes());
    data[state::CONFIG_OFF_MINT..state::CONFIG_OFF_MINT + 32]
        .copy_from_slice(&env.mint_key.to_bytes());
    data[state::CONFIG_OFF_VAULT..state::CONFIG_OFF_VAULT + 32]
        .copy_from_slice(&env.vault_key.to_bytes());
    data[state::CONFIG_OFF_BATCH_B..state::CONFIG_OFF_BATCH_B + 4]
        .copy_from_slice(&b.to_le_bytes());
    data[state::CONFIG_OFF_ARBITER_X..state::CONFIG_OFF_ARBITER_X + 32].copy_from_slice(x);
    data[state::CONFIG_OFF_ARBITER_Y..state::CONFIG_OFF_ARBITER_Y + 32].copy_from_slice(y);
    data[state::CONFIG_OFF_KEM_PK_HASH..state::CONFIG_OFF_KEM_PK_HASH + 32].copy_from_slice(kem);
    data
}

/// The expected empty TreeState image (the byte image a fresh ImtTree(32, B)
/// starts from — root and frontier are the generated zeros ladder).
fn expected_tree(config_pda: &Pubkey) -> Vec<u8> {
    let mut data = vec![0u8; state::TREE_STATE_LEN];
    data[0] = state::TAG_TREE_STATE;
    data[1] = 1;
    data[state::TREE_OFF_CONFIG..state::TREE_OFF_CONFIG + 32]
        .copy_from_slice(&config_pda.to_bytes());
    data[state::TREE_OFF_ROOT..state::TREE_OFF_ROOT + 32].copy_from_slice(&ZEROS[TREE_HEIGHT]);
    for i in 0..TREE_HEIGHT {
        let off = state::TREE_OFF_FRONTIER + 32 * i;
        data[off..off + 32].copy_from_slice(&ZEROS[i]);
    }
    data
}

#[test]
fn consumer_profile_initializes_and_accepts_a_real_deposit() {
    let zero = [0u8; 32];
    let env = build(CONSUMER_FLAGS, 16, &zero, &zero, &zero);
    let mollusk = mollusk_with_program(true);
    let init = mollusk.process_and_validate_instruction(&env.ix, &env.accounts, &[Check::success()]);

    let config = init.get_account(&env.config_pda).expect("config created");
    assert_eq!(config.owner, program_id(), "config is program-owned");
    assert_eq!(config.data, expected_config(&env, CONSUMER_FLAGS, 16, &zero, &zero, &zero));
    let tree = init.get_account(&env.tree_pda).expect("tree created");
    assert_eq!(tree.owner, program_id(), "tree is program-owned");
    assert_eq!(tree.data, expected_tree(&env.config_pda));

    // The crux: a committed REAL deposit_priv proof executes against the
    // just-initialized pool unchanged — initialize produced the production
    // shape, not merely plausible bytes.
    let fx = load_deposit_fixture();
    let amount = hex_u64(&fx.amount);
    let pid = program_id();
    let (new_root_pda, _) =
        Pubkey::find_program_address(&[state::SEED_KNOWN_ROOT, &hex32(&fx.new_root)], &pid);
    let (event_authority, _) =
        Pubkey::find_program_address(&[state::SEED_EVENT_AUTHORITY], &pid);
    let payer_token = Pubkey::new_from_array([0x04; 32]);

    let mut data = vec![2u8]; // deposit_priv discriminator
    data.extend_from_slice(&hex_bytes(&fx.proof));
    for p in &fx.publics_carried {
        data.extend_from_slice(&hex32(p));
    }
    for k in &fx.kem_ciphertexts {
        data.extend_from_slice(&hex_bytes(k));
    }

    let deposit_ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new_readonly(env.config_pda, false),
            AccountMeta::new(env.tree_pda, false),
            AccountMeta::new(new_root_pda, false),
            AccountMeta::new(env.payer, true),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(event_authority, false),
            AccountMeta::new_readonly(pid, false),
            AccountMeta::new_readonly(spl::TOKEN_PROGRAM_ID, false),
            AccountMeta::new(payer_token, false),
            AccountMeta::new(env.vault_key, false),
        ],
        data,
    };
    let accounts = vec![
        (env.config_pda, config.clone()),
        (env.tree_pda, tree.clone()),
        (new_root_pda, Account::default()),
        (
            env.payer,
            init.get_account(&env.payer).expect("payer").clone(),
        ),
        keyed_account_for_system_program(),
        (event_authority, Account::default()),
        (
            pid,
            mollusk_svm::program::create_program_account_loader_v3(&pid),
        ),
        mollusk_svm_programs_token::token::keyed_account(),
        (
            payer_token,
            token_account(&env.mint_key.to_bytes(), &env.payer, amount * 2),
        ),
        (
            env.vault_key,
            init.get_account(&env.vault_key).expect("vault").clone(),
        ),
    ];
    let dep = mollusk.process_and_validate_instruction(&deposit_ix, &accounts, &[Check::success()]);

    let post_tree = dep.get_account(&env.tree_pda).expect("tree");
    let mut next = [0u8; 8];
    next.copy_from_slice(&post_tree.data[state::TREE_OFF_NEXT..state::TREE_OFF_NEXT + 8]);
    assert_eq!(u64::from_le_bytes(next), 2, "deposit appended two leaves");
    let vault = dep.get_account(&env.vault_key).expect("vault");
    assert_eq!(token_amount(vault), amount, "vault escrowed the fixture amount");
}

#[test]
fn enterprise_profile_records_the_full_profile() {
    let fx = load_disburse256_fixture();
    let x = hex32(&fx.publics_full[9]);
    let y = hex32(&fx.publics_full[10]);
    let kem = [0x11u8; 32];
    let env = build(ENTERPRISE_FLAGS, 256, &x, &y, &kem);
    let mollusk = mollusk_with_program(false);
    let init = mollusk.process_and_validate_instruction(&env.ix, &env.accounts, &[Check::success()]);
    let config = init.get_account(&env.config_pda).expect("config created");
    assert_eq!(config.data, expected_config(&env, ENTERPRISE_FLAGS, 256, &x, &y, &kem));
}

#[test]
fn reinitialize_is_refused() {
    let zero = [0u8; 32];
    let env = build(CONSUMER_FLAGS, 16, &zero, &zero, &zero);
    let mollusk = mollusk_with_program(false);
    let init = mollusk.process_and_validate_instruction(&env.ix, &env.accounts, &[Check::success()]);
    let rerun: Vec<(Pubkey, Account)> = env
        .accounts
        .iter()
        .map(|(k, a)| (*k, init.get_account(k).cloned().unwrap_or_else(|| a.clone())))
        .collect();
    mollusk.process_and_validate_instruction(
        &env.ix,
        &rerun,
        &[Check::err(ProgramError::Custom(PoolError::AlreadyInitialized as u32))],
    );
}

#[test]
fn wrong_pda_addresses_are_refused() {
    let zero = [0u8; 32];
    let intruder = Pubkey::new_from_array([0x07; 32]);

    let mut env = build(CONSUMER_FLAGS, 16, &zero, &zero, &zero);
    env.ix.accounts[0] = AccountMeta::new(intruder, false);
    env.accounts[0] = (intruder, Account::default());
    expect_reject(&env, PoolError::PdaMismatch);

    let mut env = build(CONSUMER_FLAGS, 16, &zero, &zero, &zero);
    env.ix.accounts[1] = AccountMeta::new(intruder, false);
    env.accounts[1] = (intruder, Account::default());
    expect_reject(&env, PoolError::PdaMismatch);
}

#[test]
fn profile_preconditions_are_enforced() {
    let zero = [0u8; 32];
    let fx = load_disburse256_fixture();
    let x = hex32(&fx.publics_full[9]);
    let y = hex32(&fx.publics_full[10]);

    // B not a power of two.
    expect_reject(&build(CONSUMER_FLAGS, 12, &zero, &zero, &zero), PoolError::InvalidAccount);
    // disburse256 enabled with B != 256 (SOLR §2.2 precondition (a)).
    expect_reject(&build(ENTERPRISE_FLAGS, 16, &x, &y, &zero), PoolError::WrongBatchSize);
    // Enterprise family with no key to inject.
    expect_reject(&build(ENTERPRISE_FLAGS, 256, &zero, &zero, &zero), PoolError::ArbiterKeyUnset);
    // Enterprise family with a non-canonical key limb.
    expect_reject(&build(ENTERPRISE_FLAGS, 256, &R_BE, &y, &zero), PoolError::PublicInputNotCanonical);
    // Consumer-only profile carrying a lingering key falsifies "no key exists".
    expect_reject(&build(CONSUMER_FLAGS, 16, &x, &y, &zero), PoolError::InvalidAccount);
    // A flag bit that names no family.
    expect_reject(&build(1 << 9 | CONSUMER_FLAGS, 16, &zero, &zero, &zero), PoolError::InvalidAccount);
}

#[test]
fn vault_and_mint_are_validated() {
    let zero = [0u8; 32];

    // Vault of a different mint.
    let mut env = build(CONSUMER_FLAGS, 16, &zero, &zero, &zero);
    let (vault_authority, _) = Pubkey::find_program_address(
        &[state::SEED_VAULT_AUTHORITY, &env.config_pda.to_bytes()],
        &program_id(),
    );
    env.accounts[3] = (env.vault_key, token_account(&[0xDD; 32], &vault_authority, 0));
    expect_reject(&env, PoolError::InvalidAccount);

    // Vault whose token owner is not the vault-authority PDA.
    let mut env = build(CONSUMER_FLAGS, 16, &zero, &zero, &zero);
    let other_owner = Pubkey::new_from_array([0x05; 32]);
    env.accounts[3] = (env.vault_key, token_account(&env.mint_key.to_bytes(), &other_owner, 0));
    expect_reject(&env, PoolError::InvalidAccount);

    // Uninitialized mint.
    let mut env = build(CONSUMER_FLAGS, 16, &zero, &zero, &zero);
    let mut mint = mint_account();
    mint.data[45] = 0;
    env.accounts[2] = (env.mint_key, mint);
    expect_reject(&env, PoolError::InvalidAccount);
}

#[test]
fn wire_and_signer_shape_are_enforced() {
    let zero = [0u8; 32];

    // Truncated payload = not the fixed wire shape.
    let mut env = build(CONSUMER_FLAGS, 16, &zero, &zero, &zero);
    env.ix.data.truncate(env.ix.data.len() - 1);
    expect_reject(&env, PoolError::WrongKemCiphertextLength);

    // Payer must sign (it becomes the admin and funds the PDAs).
    let mut env = build(CONSUMER_FLAGS, 16, &zero, &zero, &zero);
    env.ix.accounts[4] = AccountMeta::new(env.payer, false);
    expect_reject(&env, PoolError::InvalidAccount);
}
