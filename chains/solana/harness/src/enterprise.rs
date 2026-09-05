//! Enterprise (S3) mollusk environments — the SOLR §3.3 op set decided under
//! OPEN-1 (full family): `deposit`, `withdraw`, `transfer`, `transfer10x2`,
//! `disburse256`. Same construction discipline
//! as the consumer envs in the crate root: fixture-seeded tree state, a
//! KnownRoot PDA for the spend root, wire-shaped instructions — but against
//! an ENTERPRISE `PoolConfig` (B=256, arbiter key set, enterprise family
//! flags), so the config-injected arbiter key genuinely gates every verify.
//!
//! Fixture sources (SOLR §5.2): the committed EVM enterprise realproofs
//! replay at op level with zero re-proving — including withdraw, whose
//! proof-bound uint160 recipient IS a reachable Solana token-account address
//! under the truncate-253 binding (the generator places the recipient token
//! account at BE32(pub[26])).

use {
    crate::{
        hex32, hex_bytes, hex_u64, token_account, DepositFixture, Env, TransferFixture,
        TreeSnapshot, WithdrawFixture, MINT_BYTES, VAULT_BYTES,
    },
    bongtu_pool_solana::{spl, state},
    serde::Deserialize,
    solana_account::Account,
    solana_instruction::{AccountMeta, Instruction},
    solana_pubkey::Pubkey,
};

/// Enterprise profile: every family on (consumer bits 0..3 + enterprise 4..8;
/// flags are u16 since the S3 pass-2 widening).
pub const ENTERPRISE_FLAGS: u16 = 0x01FF;

/// The enterprise batch size (production disburse arity — LOG_B = 8).
pub const BATCH_B: u32 = 256;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisburseFixture {
    pub proof: String,
    pub publics_carried: Vec<String>,
    pub publics_full: Vec<String>,
    pub kem_ciphertexts: Vec<String>,
    pub nullifier: String,
    pub spent_root: String,
    pub subtree_root: String,
    pub disclosure_hash: String,
    pub kem_binding: String,
    pub new_root: String,
    pub start_leaf_index: u64,
    pub batch_epoch: u64,
    pub pre_state: TreeSnapshot,
    pub post_state: TreeSnapshot,
    pub disclosure_elements: Vec<String>,
}

pub fn load_ent_deposit_fixture() -> DepositFixture {
    crate::load_json("deposit_fixture.json")
}
pub fn load_ent_withdraw_fixture() -> WithdrawFixture {
    crate::load_json("withdraw_fixture.json")
}
pub fn load_disburse256_fixture() -> DisburseFixture {
    crate::load_json("disburse256_fixture.json")
}
pub fn load_ent_transfer_fixture() -> TransferFixture {
    crate::load_json("transfer_fixture.json")
}
pub fn load_ent_transfer10x2_fixture() -> TransferFixture {
    crate::load_json("transfer10x2_fixture.json")
}

/// Serialize an ENTERPRISE `PoolConfig` image: B=256, the arbiter bjj key at
/// its fixed offsets, harness mint/vault bytes (state.rs layout).
pub fn enterprise_config_account_data(
    flags: u16,
    arbiter_x: &[u8; 32],
    arbiter_y: &[u8; 32],
) -> Vec<u8> {
    let mut data = vec![0u8; state::POOL_CONFIG_LEN];
    data[0] = state::TAG_POOL_CONFIG;
    data[1] = 1;
    data[state::CONFIG_OFF_FLAGS..state::CONFIG_OFF_FLAGS + 2]
        .copy_from_slice(&flags.to_le_bytes());
    data[4..36].copy_from_slice(&[0xAA; 32]); // admin: opaque to the ops
    data[state::CONFIG_OFF_MINT..state::CONFIG_OFF_MINT + 32].copy_from_slice(&MINT_BYTES);
    data[state::CONFIG_OFF_VAULT..state::CONFIG_OFF_VAULT + 32].copy_from_slice(&VAULT_BYTES);
    data[state::CONFIG_OFF_BATCH_B..state::CONFIG_OFF_BATCH_B + 4]
        .copy_from_slice(&BATCH_B.to_le_bytes());
    data[state::CONFIG_OFF_ARBITER_X..state::CONFIG_OFF_ARBITER_X + 32]
        .copy_from_slice(arbiter_x);
    data[state::CONFIG_OFF_ARBITER_Y..state::CONFIG_OFF_ARBITER_Y + 32]
        .copy_from_slice(arbiter_y);
    data
}

/// Swap the env's config for an enterprise image with the given flags and
/// arbiter key — the gate-5 mutation hook (family off, wrong key, unset key).
pub fn set_enterprise_config(env: &mut Env, flags: u16, arbiter_x: &[u8; 32], arbiter_y: &[u8; 32]) {
    let key = env.config_key;
    let mut account = env
        .accounts
        .iter()
        .find(|(k, _)| k == &key)
        .expect("config account")
        .1
        .clone();
    account.data = enterprise_config_account_data(flags, arbiter_x, arbiter_y);
    env.set_account(&key, account);
}

/// Patch the env's config batch size B (bytes 100..104) in place — the
/// gate-5 hook for the disburse256 `log_b == 8` assert (a config a future
/// initialize could create with B != 256).
pub fn set_enterprise_batch_b(env: &mut Env, b: u32) {
    let key = env.config_key;
    let mut account = env
        .accounts
        .iter()
        .find(|(k, _)| k == &key)
        .expect("config account")
        .1
        .clone();
    account.data[state::CONFIG_OFF_BATCH_B..state::CONFIG_OFF_BATCH_B + 4]
        .copy_from_slice(&b.to_le_bytes());
    env.set_account(&key, account);
}

struct EntBase {
    config_key: Pubkey,
    tree_key: Pubkey,
    payer: Pubkey,
    event_authority: Pubkey,
    pre_tree_data: Vec<u8>,
    accounts: Vec<(Pubkey, Account)>,
}

fn program_owned(data: Vec<u8>) -> Account {
    Account {
        lamports: 1_000_000_000,
        data,
        owner: crate::program_id(),
        executable: false,
        rent_epoch: 0,
    }
}

/// The account material every enterprise op shares — the crate-root `base`
/// with the enterprise config image (arbiter key from the fixture's own
/// publics, so the config-injected key matches what the proof was made for).
fn ent_base(pre_state: &TreeSnapshot, arbiter_x: &[u8; 32], arbiter_y: &[u8; 32]) -> EntBase {
    let pid = crate::program_id();
    let config_key = Pubkey::new_from_array([0x01; 32]);
    let tree_key = Pubkey::new_from_array([0x02; 32]);
    let payer = Pubkey::new_from_array([0x03; 32]);
    let (event_authority, _) =
        Pubkey::find_program_address(&[state::SEED_EVENT_AUTHORITY], &pid);
    let pre_tree_data = crate::tree_account_data(&config_key, pre_state);
    let accounts = vec![
        (
            config_key,
            program_owned(enterprise_config_account_data(
                ENTERPRISE_FLAGS,
                arbiter_x,
                arbiter_y,
            )),
        ),
        (tree_key, program_owned(pre_tree_data.clone())),
        (
            payer,
            Account {
                lamports: 10_000_000_000,
                ..Account::default()
            },
        ),
        mollusk_svm::program::keyed_account_for_system_program(),
        (event_authority, Account::default()),
        (pid, mollusk_svm::program::create_program_account_loader_v3(&pid)),
    ];
    EntBase {
        config_key,
        tree_key,
        payer,
        event_authority,
        pre_tree_data,
        accounts,
    }
}

fn known_root_pda(root: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[state::SEED_KNOWN_ROOT, root], &crate::program_id()).0
}

fn nullifier_pda(nf: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[state::SEED_NULLIFIER, nf], &crate::program_id()).0
}

/// The `DisburseBatch` PDA for a batch start index (u64 LE seed — the
/// counter convention, state.rs SEED_DISBURSE_BATCH note).
pub fn disburse_batch_pda(start_leaf_index: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[state::SEED_DISBURSE_BATCH, &start_leaf_index.to_le_bytes()],
        &crate::program_id(),
    )
    .0
}

fn wire(discriminator: u8, proof: &str, carried: &[String], tails: &[Vec<u8>]) -> Vec<u8> {
    let mut data = vec![discriminator];
    data.extend_from_slice(&hex_bytes(proof));
    for p in carried {
        data.extend_from_slice(&hex32(p));
    }
    for tail in tails {
        data.extend_from_slice(tail);
    }
    data
}

/// The shared enterprise spend env (transfer / transfer10x2): the consumer
/// `build_spend_env` shape against an enterprise config whose arbiter key
/// comes from the fixture's own injected publics, so the config-injected key
/// matches what the committed proof was made for.
fn build_ent_spend_env(
    discriminator: u8,
    fx: &TransferFixture,
    arbiter_x: &[u8; 32],
    arbiter_y: &[u8; 32],
) -> Env {
    let pid = crate::program_id();
    let mollusk = crate::mollusk_with_program(false);
    let mut b = ent_base(&fx.pre_state, arbiter_x, arbiter_y);

    let spent_root_pda = known_root_pda(&hex32(&fx.spent_root));
    let new_root_pda = known_root_pda(&hex32(&fx.new_root));
    let nf_pdas: Vec<Pubkey> = fx
        .nullifiers
        .iter()
        .filter(|nf| hex32(nf) != [0u8; 32])
        .map(|nf| nullifier_pda(&hex32(nf)))
        .collect();

    let kems: Vec<Vec<u8>> = fx.kem_ciphertexts.iter().map(|k| hex_bytes(k)).collect();
    let data = wire(discriminator, &fx.proof, &fx.publics_carried, &kems);

    let mut metas = vec![
        AccountMeta::new_readonly(b.config_key, false),
        AccountMeta::new(b.tree_key, false),
        AccountMeta::new_readonly(spent_root_pda, false),
        AccountMeta::new(new_root_pda, false),
        AccountMeta::new(b.payer, true),
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new_readonly(b.event_authority, false),
        AccountMeta::new_readonly(pid, false),
    ];
    for nf in &nf_pdas {
        metas.push(AccountMeta::new(*nf, false));
    }

    b.accounts.push((spent_root_pda, program_owned(vec![])));
    b.accounts.push((new_root_pda, Account::default()));
    for nf in &nf_pdas {
        b.accounts.push((*nf, Account::default()));
    }

    Env {
        mollusk,
        instruction: Instruction {
            program_id: pid,
            accounts: metas,
            data,
        },
        accounts: b.accounts,
        config_key: b.config_key,
        tree_key: b.tree_key,
        spent_root_pda,
        new_root_pda,
        payer: b.payer,
        nf_pdas,
        pre_tree_data: b.pre_tree_data,
        vault_key: Pubkey::new_from_array(crate::VAULT_BYTES),
        payer_token_key: Pubkey::default(),
        recipient_token_key: Pubkey::default(),
    }
}

/// Enterprise transfer env (wire = disc 9, 33 carried publics, ONE kem ct;
/// arbiter key at pub[35..36]).
pub fn build_ent_transfer_env(fx: &TransferFixture) -> Env {
    build_ent_spend_env(
        bongtu_pool_solana::transfer::DISCRIMINATOR,
        fx,
        &hex32(&fx.publics_full[35]),
        &hex32(&fx.publics_full[36]),
    )
}

/// Enterprise transfer10x2 env (wire = disc 10, 56 carried publics, ONE kem
/// ct; arbiter key at pub[66..67]; the merge fixture drives all 10 nf PDAs).
pub fn build_ent_transfer10x2_env(fx: &TransferFixture) -> Env {
    build_ent_spend_env(
        bongtu_pool_solana::transfer10x2::DISCRIMINATOR,
        fx,
        &hex32(&fx.publics_full[66]),
        &hex32(&fx.publics_full[67]),
    )
}

/// Enterprise deposit env (accounts mirror `deposit_priv`; wire = disc 6,
/// 17 carried publics, ONE kem ct).
pub fn build_ent_deposit_env(fx: &DepositFixture) -> Env {
    let pid = crate::program_id();
    let mollusk = crate::mollusk_with_program(true);
    let arbiter_x = hex32(&fx.publics_full[17]);
    let arbiter_y = hex32(&fx.publics_full[18]);
    let mut b = ent_base(&fx.pre_state, &arbiter_x, &arbiter_y);

    let new_root_pda = known_root_pda(&hex32(&fx.new_root));
    let vault_key = Pubkey::new_from_array(VAULT_BYTES);
    let payer_token_key = Pubkey::new_from_array([0x04; 32]);
    let (vault_owner, _) = crate::vault_authority();
    let amount = hex_u64(&fx.amount);

    let kems: Vec<Vec<u8>> = fx.kem_ciphertexts.iter().map(|k| hex_bytes(k)).collect();
    let data = wire(
        bongtu_pool_solana::deposit::DISCRIMINATOR,
        &fx.proof,
        &fx.publics_carried,
        &kems,
    );

    let metas = vec![
        AccountMeta::new_readonly(b.config_key, false),
        AccountMeta::new(b.tree_key, false),
        AccountMeta::new(new_root_pda, false),
        AccountMeta::new(b.payer, true),
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new_readonly(b.event_authority, false),
        AccountMeta::new_readonly(pid, false),
        AccountMeta::new_readonly(spl::TOKEN_PROGRAM_ID, false),
        AccountMeta::new(payer_token_key, false),
        AccountMeta::new(vault_key, false),
    ];

    b.accounts.push((new_root_pda, Account::default()));
    b.accounts.push(mollusk_svm_programs_token::token::keyed_account());
    // Payer token account holds 2× the deposit so a partial pull would show.
    b.accounts
        .push((payer_token_key, token_account(&MINT_BYTES, &b.payer, amount * 2)));
    b.accounts
        .push((vault_key, token_account(&MINT_BYTES, &vault_owner, 0)));

    Env {
        mollusk,
        instruction: Instruction {
            program_id: pid,
            accounts: metas,
            data,
        },
        accounts: b.accounts,
        config_key: b.config_key,
        tree_key: b.tree_key,
        spent_root_pda: Pubkey::default(),
        new_root_pda,
        payer: b.payer,
        nf_pdas: vec![],
        pre_tree_data: b.pre_tree_data,
        vault_key,
        payer_token_key,
        recipient_token_key: Pubkey::default(),
    }
}

/// Enterprise withdraw env (accounts mirror `withdraw_priv`; wire = disc 7,
/// 22 carried publics, ONE kem ct + the 33 B stealth tail).
pub fn build_ent_withdraw_env(fx: &WithdrawFixture) -> Env {
    let pid = crate::program_id();
    let mollusk = crate::mollusk_with_program(true);
    let arbiter_x = hex32(&fx.publics_full[24]);
    let arbiter_y = hex32(&fx.publics_full[25]);
    let mut b = ent_base(&fx.pre_state, &arbiter_x, &arbiter_y);

    let spent_root_pda = known_root_pda(&hex32(&fx.spent_root));
    let new_root_pda = known_root_pda(&hex32(&fx.new_root));
    let nf_pdas: Vec<Pubkey> = fx
        .nullifiers
        .iter()
        .filter(|nf| hex32(nf) != [0u8; 32])
        .map(|nf| nullifier_pda(&hex32(nf)))
        .collect();
    let vault_key = Pubkey::new_from_array(VAULT_BYTES);
    let (vault_owner, _) = crate::vault_authority();
    let recipient_token_key = Pubkey::new_from_array(hex32(&fx.recipient_token_account));
    let recipient_owner = Pubkey::new_from_array([0x05; 32]);
    let amount = hex_u64(&fx.amount);

    let mut stealth = hex_bytes(&fx.stealth_ephemeral_pub);
    stealth.push(fx.stealth_view_tag);
    assert_eq!(stealth.len(), 33);
    let kems: Vec<Vec<u8>> = fx.kem_ciphertexts.iter().map(|k| hex_bytes(k)).collect();
    let tails: Vec<Vec<u8>> = kems.into_iter().chain([stealth]).collect();
    let data = wire(
        bongtu_pool_solana::withdraw::DISCRIMINATOR,
        &fx.proof,
        &fx.publics_carried,
        &tails,
    );

    let mut metas = vec![
        AccountMeta::new_readonly(b.config_key, false),
        AccountMeta::new(b.tree_key, false),
        AccountMeta::new_readonly(spent_root_pda, false),
        AccountMeta::new(new_root_pda, false),
        AccountMeta::new(b.payer, true),
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new_readonly(b.event_authority, false),
        AccountMeta::new_readonly(pid, false),
        AccountMeta::new_readonly(spl::TOKEN_PROGRAM_ID, false),
        AccountMeta::new(vault_key, false),
        AccountMeta::new_readonly(vault_owner, false),
        AccountMeta::new(recipient_token_key, false),
    ];
    for nf in &nf_pdas {
        metas.push(AccountMeta::new(*nf, false));
    }

    b.accounts.push((spent_root_pda, program_owned(vec![])));
    b.accounts.push((new_root_pda, Account::default()));
    b.accounts.push(mollusk_svm_programs_token::token::keyed_account());
    // Vault funded well past the withdrawal so a wrong-amount push would show.
    b.accounts
        .push((vault_key, token_account(&MINT_BYTES, &vault_owner, amount * 10)));
    b.accounts.push((vault_owner, Account::default()));
    b.accounts
        .push((recipient_token_key, token_account(&MINT_BYTES, &recipient_owner, 0)));
    for nf in &nf_pdas {
        b.accounts.push((*nf, Account::default()));
    }

    Env {
        mollusk,
        instruction: Instruction {
            program_id: pid,
            accounts: metas,
            data,
        },
        accounts: b.accounts,
        config_key: b.config_key,
        tree_key: b.tree_key,
        spent_root_pda,
        new_root_pda,
        payer: b.payer,
        nf_pdas,
        pre_tree_data: b.pre_tree_data,
        vault_key,
        payer_token_key: Pubkey::default(),
        recipient_token_key,
    }
}

/// disburse256 env: config, tree, spent/new KnownRoot, the `DisburseBatch`
/// PDA at the fixture's start index, payer, system, event authority, the
/// program, and ONE nullifier PDA. Wire = disc 8, 8 carried publics, one
/// kem ct.
pub fn build_disburse256_env(fx: &DisburseFixture) -> Env {
    let pid = crate::program_id();
    let mollusk = crate::mollusk_with_program(false);
    let arbiter_x = hex32(&fx.publics_full[9]);
    let arbiter_y = hex32(&fx.publics_full[10]);
    let mut b = ent_base(&fx.pre_state, &arbiter_x, &arbiter_y);

    let spent_root_pda = known_root_pda(&hex32(&fx.spent_root));
    let new_root_pda = known_root_pda(&hex32(&fx.new_root));
    let nf_pda = nullifier_pda(&hex32(&fx.nullifier));
    let batch_pda = disburse_batch_pda(fx.start_leaf_index);

    let kems: Vec<Vec<u8>> = fx.kem_ciphertexts.iter().map(|k| hex_bytes(k)).collect();
    let data = wire(
        bongtu_pool_solana::disburse256::DISCRIMINATOR,
        &fx.proof,
        &fx.publics_carried,
        &kems,
    );

    let metas = vec![
        AccountMeta::new_readonly(b.config_key, false),
        AccountMeta::new(b.tree_key, false),
        AccountMeta::new_readonly(spent_root_pda, false),
        AccountMeta::new(new_root_pda, false),
        AccountMeta::new(batch_pda, false),
        AccountMeta::new(b.payer, true),
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new_readonly(b.event_authority, false),
        AccountMeta::new_readonly(pid, false),
        AccountMeta::new(nf_pda, false),
    ];

    b.accounts.push((spent_root_pda, program_owned(vec![])));
    b.accounts.push((new_root_pda, Account::default()));
    b.accounts.push((batch_pda, Account::default()));
    b.accounts.push((nf_pda, Account::default()));

    Env {
        mollusk,
        instruction: Instruction {
            program_id: pid,
            accounts: metas,
            data,
        },
        accounts: b.accounts,
        config_key: b.config_key,
        tree_key: b.tree_key,
        spent_root_pda,
        new_root_pda,
        payer: b.payer,
        nf_pdas: vec![nf_pda],
        pre_tree_data: b.pre_tree_data,
        vault_key: Pubkey::new_from_array(VAULT_BYTES),
        payer_token_key: Pubkey::default(),
        recipient_token_key: Pubkey::default(),
    }
}
