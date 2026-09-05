//! Shared mollusk environment for the S2 gate tests (SOLR §3.1.3).
//!
//! Builds full per-op execution contexts from the generated conformance
//! fixtures: seeded tree state, KnownRoot PDA for the fixture's spend root,
//! fresh nullifier PDAs, SPL token accounts for the escrow ops, and the
//! wire-shaped instruction. Tests mutate the returned `Env` to drive each
//! invariant-gate row.

pub mod enterprise;

use {
    bongtu_pool_solana::{spl, state, groth16},
    mollusk_svm::Mollusk,
    serde::Deserialize,
    solana_account::Account,
    solana_instruction::{AccountMeta, Instruction},
    solana_pubkey::Pubkey,
    std::str::FromStr,
};

/// Must match the program's `declare_id!`.
pub const PROGRAM_ID_STR: &str = "HGVVfVfRnHauJoQwUttgUoy6ucG47LAXj8e6YBbZkoCj";

/// Rent-exempt minimum for a 0-data account (128 bytes overhead × the default
/// rent rate) — what the program pays per marker PDA.
pub const MARKER_PDA_LAMPORTS: u64 = 890_880;

/// The harness mint: must equal the config image's mint filler bytes.
pub const MINT_BYTES: [u8; 32] = [0xBB; 32];
/// The harness vault address: must equal the config image's vault field.
pub const VAULT_BYTES: [u8; 32] = [0xCC; 32];

pub fn program_id() -> Pubkey {
    Pubkey::from_str(PROGRAM_ID_STR).unwrap()
}

pub fn hex_bytes(s: &str) -> Vec<u8> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

pub fn hex32(s: &str) -> [u8; 32] {
    let v = hex_bytes(s);
    assert_eq!(v.len(), 32, "expected 32-byte hex, got {s}");
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// A fixture amount public (32 B BE, must fit u64 — the program's belt).
pub fn hex_u64(s: &str) -> u64 {
    let v = hex32(s);
    assert!(v[..24].iter().all(|b| *b == 0), "fixture amount exceeds u64");
    let mut be = [0u8; 8];
    be.copy_from_slice(&v[24..32]);
    u64::from_be_bytes(be)
}

// --- fixture shapes (chains/solana/conformance/*_fixture.json, gen_vectors.ts) -----

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeSnapshot {
    pub next_leaf_index: u64,
    pub current_root: String,
    pub filled_subtrees: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositFixture {
    pub proof: String,
    pub publics_carried: Vec<String>,
    pub publics_full: Vec<String>,
    pub kem_ciphertexts: Vec<String>,
    pub output_commitments: Vec<String>,
    pub amount: String,
    pub new_root: String,
    pub start_leaf_index: u64,
    pub pre_state: TreeSnapshot,
    pub post_state: TreeSnapshot,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferFixture {
    pub proof: String,
    pub publics_carried: Vec<String>,
    pub publics_full: Vec<String>,
    pub kem_ciphertexts: Vec<String>,
    pub nullifiers: Vec<String>,
    pub output_commitments: Vec<String>,
    pub spent_root: String,
    pub new_root: String,
    pub start_leaf_index: u64,
    pub pre_state: TreeSnapshot,
    pub post_state: TreeSnapshot,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawFixture {
    pub proof: String,
    pub publics_carried: Vec<String>,
    pub publics_full: Vec<String>,
    pub kem_ciphertexts: Vec<String>,
    pub nullifiers: Vec<String>,
    pub change_commitment: String,
    pub amount: String,
    pub recipient_token_account: String,
    pub stealth_ephemeral_pub: String,
    pub stealth_view_tag: u8,
    pub spent_root: String,
    pub new_root: String,
    pub start_leaf_index: u64,
    pub pre_state: TreeSnapshot,
    pub post_state: TreeSnapshot,
}

fn load_json<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let path = format!("{}/../conformance/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture json"))
        .expect("fixture shape")
}

pub fn load_deposit_fixture() -> DepositFixture {
    load_json("deposit_priv_fixture.json")
}
pub fn load_fixture() -> TransferFixture {
    load_json("transfer_priv_fixture.json")
}
pub fn load_transfer10x2_fixture() -> TransferFixture {
    load_json("transfer10x2_priv_fixture.json")
}
pub fn load_withdraw_fixture() -> WithdrawFixture {
    load_json("withdraw_priv_fixture.json")
}

// --- attach differential vectors (attach_vectors.json, gen_attach_vectors.ts) --

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachStep {
    pub subtree_leaves: Vec<String>,
    pub subtree_root: String,
    pub expected_start_leaf_index: u64,
    pub post_root: String,
    pub post_state: TreeSnapshot,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachCase {
    pub name: String,
    pub rem: u64,
    pub pre_leaves: Vec<String>,
    pub pre_state: TreeSnapshot,
    pub attaches: Vec<AttachStep>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachVectors {
    pub tree_height: usize,
    pub batch_b: u64,
    pub log_b: usize,
    pub cases: Vec<AttachCase>,
}

/// The gate-7 attach differential vectors: `Frontier::attach_subtree` vs the
/// ImtTree oracle at every close-loop rem shape (SOLR §4.1).
pub fn load_attach_vectors() -> AttachVectors {
    load_json("attach_vectors.json")
}

pub fn load_cu_budget(op: &str) -> u64 {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../cu_budget.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("cu_budget.json")).unwrap();
    v[op].as_u64().unwrap_or_else(|| panic!("no CU budget for {op}"))
}

// --- account images ---------------------------------------------------------

/// Serialize a `TreeState` account image from a snapshot (the program's
/// fixed-offset layout in state.rs).
pub fn tree_account_data(config_key: &Pubkey, snap: &TreeSnapshot) -> Vec<u8> {
    let mut data = vec![0u8; state::TREE_STATE_LEN];
    data[0] = state::TAG_TREE_STATE;
    data[1] = 1;
    data[state::TREE_OFF_CONFIG..state::TREE_OFF_CONFIG + 32]
        .copy_from_slice(&config_key.to_bytes());
    data[state::TREE_OFF_NEXT..state::TREE_OFF_NEXT + 8]
        .copy_from_slice(&snap.next_leaf_index.to_le_bytes());
    data[state::TREE_OFF_ROOT..state::TREE_OFF_ROOT + 32]
        .copy_from_slice(&hex32(&snap.current_root));
    assert_eq!(snap.filled_subtrees.len(), 32);
    for (i, s) in snap.filled_subtrees.iter().enumerate() {
        let off = state::TREE_OFF_FRONTIER + 32 * i;
        data[off..off + 32].copy_from_slice(&hex32(s));
    }
    data
}

/// Serialize a `PoolConfig` account image (consumer-only profile: arbiter
/// fields zeroed, all four family flags on unless a test clears one). The
/// mint/vault fields carry the harness MINT/VAULT bytes so the escrow ops'
/// config-binding checks are exercised for real.
pub fn config_account_data(flags: u16) -> Vec<u8> {
    let mut data = vec![0u8; state::POOL_CONFIG_LEN];
    data[0] = state::TAG_POOL_CONFIG;
    data[1] = 1;
    data[state::CONFIG_OFF_FLAGS..state::CONFIG_OFF_FLAGS + 2]
        .copy_from_slice(&flags.to_le_bytes());
    data[4..36].copy_from_slice(&[0xAA; 32]); // admin: opaque to the ops
    data[state::CONFIG_OFF_MINT..state::CONFIG_OFF_MINT + 32].copy_from_slice(&MINT_BYTES);
    data[state::CONFIG_OFF_VAULT..state::CONFIG_OFF_VAULT + 32].copy_from_slice(&VAULT_BYTES);
    data[100..104].copy_from_slice(&16u32.to_le_bytes());
    data
}

/// Hand-serialized SPL token Account (165 B: mint, owner, amount u64 LE,
/// delegate COption none, state = Initialized, is_native none, …) — the
/// layout is consensus-fixed by the token program; serializing directly
/// avoids an spl-token interface dependency (the program-side precedent).
pub fn token_account_data(mint: &[u8; 32], owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut data = vec![0u8; spl::TOKEN_ACCOUNT_LEN];
    data[0..32].copy_from_slice(mint);
    data[32..64].copy_from_slice(&owner.to_bytes());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    data[108] = 1; // AccountState::Initialized
    data
}

pub fn token_account(mint: &[u8; 32], owner: &Pubkey, amount: u64) -> Account {
    Account {
        lamports: 2_039_280, // rent-exempt minimum for 165 B
        data: token_account_data(mint, owner, amount),
        owner: spl::TOKEN_PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    }
}

/// Token-account balance (amount u64 LE at offset 64).
pub fn token_amount(account: &Account) -> u64 {
    let mut le = [0u8; 8];
    le.copy_from_slice(&account.data[64..72]);
    u64::from_le_bytes(le)
}

// --- environments ------------------------------------------------------------

pub struct Env {
    pub mollusk: Mollusk,
    pub instruction: Instruction,
    pub accounts: Vec<(Pubkey, Account)>,
    pub config_key: Pubkey,
    pub tree_key: Pubkey,
    pub spent_root_pda: Pubkey,
    pub new_root_pda: Pubkey,
    pub payer: Pubkey,
    pub nf_pdas: Vec<Pubkey>,
    pub pre_tree_data: Vec<u8>,
    pub vault_key: Pubkey,
    pub payer_token_key: Pubkey,
    pub recipient_token_key: Pubkey,
}

/// Byte offset of carried public `i` inside the instruction data.
pub fn carried_offset(i: usize) -> usize {
    1 + bongtu_pool_solana::groth16::PROOF_LEN + 32 * i
}

pub fn mollusk_with_program(load_token_program: bool) -> Mollusk {
    let pid = program_id();
    std::env::set_var(
        "SBF_OUT_DIR",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../target/deploy"),
    );
    let mut mollusk = Mollusk::new(&pid, "bongtu_pool_solana");
    if load_token_program {
        mollusk_svm_programs_token::token::add_program(&mut mollusk);
    }
    mollusk
}

fn program_owned(data: Vec<u8>) -> Account {
    Account {
        lamports: 1_000_000_000,
        data,
        owner: program_id(),
        executable: false,
        rent_epoch: 0,
    }
}

struct Base {
    config_key: Pubkey,
    tree_key: Pubkey,
    payer: Pubkey,
    event_authority: Pubkey,
    pre_tree_data: Vec<u8>,
    accounts: Vec<(Pubkey, Account)>,
}

/// The account material every op shares: config (flags 0x0F), seeded tree,
/// funded payer, system program, event authority, the program itself.
fn base(pre_state: &TreeSnapshot) -> Base {
    let pid = program_id();
    let config_key = Pubkey::new_from_array([0x01; 32]);
    let tree_key = Pubkey::new_from_array([0x02; 32]);
    let payer = Pubkey::new_from_array([0x03; 32]);
    let (event_authority, _) = Pubkey::find_program_address(&[state::SEED_EVENT_AUTHORITY], &pid);
    let pre_tree_data = tree_account_data(&config_key, pre_state);
    let accounts = vec![
        (config_key, program_owned(config_account_data(0x0F))),
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
    Base {
        config_key,
        tree_key,
        payer,
        event_authority,
        pre_tree_data,
        accounts,
    }
}

fn known_root_pda(root: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[state::SEED_KNOWN_ROOT, root], &program_id()).0
}

fn nullifier_pda(nf: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[state::SEED_NULLIFIER, nf], &program_id()).0
}

pub fn vault_authority() -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[state::SEED_VAULT_AUTHORITY, &[0x01; 32]],
        &program_id(),
    )
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

/// transfer_priv / transfer10x2_priv share one env shape; `discriminator`
/// picks the family and the nullifier list drives the PDA count.
fn build_spend_env(
    discriminator: u8,
    proof: &str,
    carried: &[String],
    kem_cts: &[String],
    nullifiers: &[String],
    spent_root: &str,
    new_root: &str,
    pre_state: &TreeSnapshot,
) -> Env {
    let pid = program_id();
    let mollusk = mollusk_with_program(false);
    let mut b = base(pre_state);

    let spent_root_pda = known_root_pda(&hex32(spent_root));
    let new_root_pda = known_root_pda(&hex32(new_root));
    let nf_pdas: Vec<Pubkey> = nullifiers
        .iter()
        .filter(|nf| hex32(nf) != [0u8; 32])
        .map(|nf| nullifier_pda(&hex32(nf)))
        .collect();

    let kems: Vec<Vec<u8>> = kem_cts.iter().map(|k| hex_bytes(k)).collect();
    let data = wire(discriminator, proof, carried, &kems);

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

    // Seeded KnownRoot for the fixture's spend root (SOLR §5.2 state-level
    // replay: mollusk writes the fixture root as a KnownRoot PDA).
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
        vault_key: Pubkey::new_from_array(VAULT_BYTES),
        payer_token_key: Pubkey::default(),
        recipient_token_key: Pubkey::default(),
    }
}

pub fn build_env(fx: &TransferFixture) -> Env {
    build_spend_env(
        bongtu_pool_solana::transfer_priv::DISCRIMINATOR,
        &fx.proof,
        &fx.publics_carried,
        &fx.kem_ciphertexts,
        &fx.nullifiers,
        &fx.spent_root,
        &fx.new_root,
        &fx.pre_state,
    )
}

pub fn build_transfer10x2_env(fx: &TransferFixture) -> Env {
    build_spend_env(
        bongtu_pool_solana::transfer10x2_priv::DISCRIMINATOR,
        &fx.proof,
        &fx.publics_carried,
        &fx.kem_ciphertexts,
        &fx.nullifiers,
        &fx.spent_root,
        &fx.new_root,
        &fx.pre_state,
    )
}

pub fn build_deposit_env(fx: &DepositFixture) -> Env {
    let pid = program_id();
    let mollusk = mollusk_with_program(true);
    let mut b = base(&fx.pre_state);

    let new_root_pda = known_root_pda(&hex32(&fx.new_root));
    let vault_key = Pubkey::new_from_array(VAULT_BYTES);
    let payer_token_key = Pubkey::new_from_array([0x04; 32]);
    let (vault_owner, _) = vault_authority();
    let amount = hex_u64(&fx.amount);

    let kems: Vec<Vec<u8>> = fx.kem_ciphertexts.iter().map(|k| hex_bytes(k)).collect();
    let data = wire(
        bongtu_pool_solana::deposit_priv::DISCRIMINATOR,
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

pub fn build_withdraw_env(fx: &WithdrawFixture) -> Env {
    let pid = program_id();
    let mollusk = mollusk_with_program(true);
    let mut b = base(&fx.pre_state);

    let spent_root_pda = known_root_pda(&hex32(&fx.spent_root));
    let new_root_pda = known_root_pda(&hex32(&fx.new_root));
    let nf_pdas: Vec<Pubkey> = fx
        .nullifiers
        .iter()
        .map(|nf| nullifier_pda(&hex32(nf)))
        .collect();
    let vault_key = Pubkey::new_from_array(VAULT_BYTES);
    let (vault_owner, _) = vault_authority();
    let recipient_token_key = Pubkey::new_from_array(hex32(&fx.recipient_token_account));
    let recipient_owner = Pubkey::new_from_array([0x05; 32]);
    let amount = hex_u64(&fx.amount);

    let mut stealth = hex_bytes(&fx.stealth_ephemeral_pub);
    stealth.push(fx.stealth_view_tag);
    assert_eq!(stealth.len(), 33);
    let kems: Vec<Vec<u8>> = fx.kem_ciphertexts.iter().map(|k| hex_bytes(k)).collect();
    let tails: Vec<Vec<u8>> = kems.into_iter().chain([stealth]).collect();
    let data = wire(
        bongtu_pool_solana::withdraw_priv::DISCRIMINATOR,
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

impl Env {
    /// Replace the account entry for `key` (metas untouched).
    pub fn set_account(&mut self, key: &Pubkey, account: Account) {
        let slot = self
            .accounts
            .iter_mut()
            .find(|(k, _)| k == key)
            .unwrap_or_else(|| panic!("no account {key}"));
        slot.1 = account;
    }

    /// A 0-data account owned by the program — an existing marker PDA.
    pub fn existing_marker(&self) -> Account {
        Account {
            lamports: MARKER_PDA_LAMPORTS,
            data: vec![],
            owner: program_id(),
            executable: false,
            rent_epoch: 0,
        }
    }
}

// --- gate 4: transaction-size calculator -------------------------------------

/// shortvec (compact-u16) encoded length.
fn shortvec_len(n: usize) -> usize {
    assert!(n < 16384);
    if n < 128 {
        1
    } else {
        2
    }
}

/// Exact serialized size of the v0 transaction wrapping `op_ix` plus the two
/// ComputeBudget instructions a realistic submission carries
/// (SetComputeUnitLimit + SetComputeUnitPrice), one fee-payer signature and
/// no address-lookup tables — computed from the consensus wire format
/// (signatures shortvec + 64/sig; header 3 B; account keys shortvec + 32/key;
/// blockhash 32 B; instructions shortvec + per-ix program index, accounts
/// shortvec + 1/account, data shortvec + data; v0 adds 1 version byte and an
/// empty ALT shortvec).
///
/// Account keys = the op instruction's metas (payer and this program are
/// already among them; all metas are distinct in every op layout) + the
/// ComputeBudget program id.
pub fn v0_tx_size(op_accounts: usize, op_data_len: usize) -> usize {
    let keys = op_accounts + 1;
    let cb_limit_ix = 1 + shortvec_len(0) + shortvec_len(5) + 5;
    let cb_price_ix = 1 + shortvec_len(0) + shortvec_len(9) + 9;
    let op_ix = 1 + shortvec_len(op_accounts) + op_accounts + shortvec_len(op_data_len) + op_data_len;
    let legacy = (shortvec_len(1) + 64)
        + 3
        + (shortvec_len(keys) + 32 * keys)
        + 32
        + shortvec_len(3)
        + cb_limit_ix
        + cb_price_ix
        + op_ix;
    legacy + 1 + shortvec_len(0) // version byte + empty ALT vec
}

/// Canonicality helper re-export for verify-level gates.
pub fn is_canonical(v: &[u8; 32]) -> bool {
    groth16::is_canonical_scalar(v)
}
