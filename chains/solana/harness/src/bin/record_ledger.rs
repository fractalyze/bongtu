//! record_ledger — generate the S4 recorded-ledger conformance fixtures
//! (SOLR §5.3: the indexer conformance suite's Solana leg is driven by
//! recorded ledger data, no validator in the loop).
//!
//! Replays the committed per-op conformance fixtures through mollusk as ONE
//! CHAINED ledger per profile (consumer B=16, enterprise B=256): every op
//! executes against the running tree account produced by the previous op, so
//! the recorded per-op anchors (start index, resulting root) form exactly the
//! from-genesis history the indexer mirror replays. Spend membership is
//! state-level replay per SOLR §5.2 — each op's fixture spend root is seeded
//! as a KnownRoot PDA (mollusk standing in for chain history); the tree
//! frontier itself is never seeded, it GROWS from the empty tree through the
//! executed ops, which is what makes the ledger mirror-replayable.
//!
//! What is recorded per transaction:
//!   - the op instruction exactly as built (program id, account list, data),
//!   - the inner-instruction list: the SPL escrow CPI (foreign program — the
//!     indexer's program-id dispatch filter must skip it) and the self-CPI
//!     event, whose bytes come from the program's OWN payload builders
//!     (event::op_event_payload / disburse_event_payload) applied to the
//!     SVM-executed outcome — one byte-builder, no reconstruction drift.
//!     (System-program marker-PDA CPIs are elided: foreign-program skipping
//!     is already exercised by the SPL entry.)
//!   - the post-op TreeState (root + nextLeafIndex) read back from the
//!     mollusk result — the anchor the kill-and-resume leg checks its
//!     rebuilt frontier against at the cursor.
//!
//! Two ledger shapes exercise the dispatch walk beyond single-op txs:
//!   - the consumer transferPriv + transfer10x2Priv share ONE recorded tx
//!     (two top-level pool ops), pinning the FIFO op/event pairing and its
//!     imbalance throw;
//!   - the consumer withdrawPriv is recorded as an INNER instruction under an
//!     opaque wrapper top-level. Mollusk executes one instruction at a time
//!     and composing a real CPI-caller program just for fixtures is
//!     impractical, so the transaction SHAPE is constructed here — the
//!     RECORDED SHAPE is what the ingest dispatch consumes, and it matches
//!     what the RPC adapter yields for a wrapper-invoked op (the op, its SPL
//!     CPI, and its self-CPI event flattened into the inner list, the op
//!     record carrying its account metas for decodeOp's recipient read).
//!
//! Run from chains/solana (the program .so must be built first):
//!   cargo-build-sbf --manifest-path program/Cargo.toml
//!   cargo run -p bongtu-solana-harness --bin record_ledger
//! Writes conformance/ledger_consumer.json + conformance/ledger_enterprise.json.

use {
    bongtu_pool_solana::{event, spl, state, tree::Frontier},
    bongtu_solana_harness::{
        build_deposit_env, build_env, build_transfer10x2_env, build_withdraw_env,
        enterprise::{
            build_disburse256_env, build_ent_deposit_env, build_ent_transfer10x2_env,
            build_ent_transfer_env, build_ent_withdraw_env, load_disburse256_fixture,
            load_ent_deposit_fixture, load_ent_transfer10x2_fixture, load_ent_transfer_fixture,
            load_ent_withdraw_fixture,
        },
        hex32, hex_u64, load_deposit_fixture, load_fixture, load_transfer10x2_fixture,
        load_withdraw_fixture, program_id, Env,
    },
    mollusk_svm::result::Check,
    serde_json::{json, Value},
    solana_account::Account,
    solana_pubkey::Pubkey,
};

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + 2 * bytes.len());
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn pk_hex(pk: &Pubkey) -> String {
    hex_of(&pk.to_bytes())
}

/// Program-owned account image for the chained tree state.
fn program_owned(data: Vec<u8>) -> Account {
    Account {
        lamports: 1_000_000_000,
        data,
        owner: program_id(),
        executable: false,
        rent_epoch: 0,
    }
}

/// Swap the env's new-root KnownRoot PDA (meta + account) for the address the
/// CHAINED post root derives — the fixture's own new_root only matches on the
/// first op of a ledger.
fn retarget_new_root(env: &mut Env, predicted_root: &[u8; 32]) {
    let new_pda =
        Pubkey::find_program_address(&[state::SEED_KNOWN_ROOT, predicted_root], &program_id()).0;
    let old = env.new_root_pda;
    if new_pda == old {
        return;
    }
    for meta in env.instruction.accounts.iter_mut() {
        if meta.pubkey == old {
            meta.pubkey = new_pda;
        }
    }
    for slot in env.accounts.iter_mut() {
        if slot.0 == old {
            *slot = (new_pda, Account::default());
        }
    }
    env.new_root_pda = new_pda;
}

/// Chained-execution outcome of one op.
struct Executed {
    start_leaf_index: u64,
    resulting_root: [u8; 32],
    post_next_leaf_index: u64,
    post_tree_data: Vec<u8>,
}

/// Point the env at the chained tree, predict the post frontier (to derive
/// the new-root PDA), execute under mollusk, and assert the SVM outcome
/// matches the Frontier prediction — the recorded anchors are then the SVM's
/// own numbers, cross-checked twice.
fn execute_chained(
    env: &mut Env,
    chained_tree: &[u8],
    appends: &[[u8; 32]],
    attach: Option<[u8; 32]>,
) -> Executed {
    let tree_key = env.tree_key;
    env.set_account(&tree_key, program_owned(chained_tree.to_vec()));

    let mut predicted = Frontier::load(chained_tree).expect("chained tree data");
    let start = match attach {
        Some(subtree_root) => predicted.attach_subtree(subtree_root, 8).expect("attach"),
        None => {
            let first = predicted.append_leaf(appends[0]).expect("append");
            for leaf in &appends[1..] {
                predicted.append_leaf(*leaf).expect("append");
            }
            first
        }
    };
    retarget_new_root(env, &predicted.current_root);

    let result = env.mollusk.process_and_validate_instruction(
        &env.instruction,
        &env.accounts,
        &[Check::success()],
    );
    let tree = result.get_account(&env.tree_key).expect("tree account");
    let post = Frontier::load(&tree.data).expect("post tree data");
    assert_eq!(post.current_root, predicted.current_root, "SVM root != Frontier prediction");
    assert_eq!(post.next_leaf_index, predicted.next_leaf_index, "SVM nli != prediction");

    Executed {
        start_leaf_index: start,
        resulting_root: post.current_root,
        post_next_leaf_index: post.next_leaf_index,
        post_tree_data: tree.data.clone(),
    }
}

/// SPL token Transfer CPI data (tag 3 + amount u64 LE) — the foreign inner
/// instruction the escrow ops actually invoke (spl.rs wire).
fn spl_transfer_data(amount: u64) -> Vec<u8> {
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

fn inner_entry(program: &Pubkey, data: Vec<u8>) -> Value {
    json!({ "programId": pk_hex(program), "data": hex_of(&data) })
}

/// The executed op instruction as a record WITH its account metas — used both
/// top-level and (wrapper shape) inner: decodeOp reads meta 11 for the
/// withdraw recipient, and the live RPC adapter records accounts on inner
/// instructions too.
fn op_ix_entry(env: &Env) -> Value {
    json!({
        "programId": pk_hex(&env.instruction.program_id),
        "accounts": env.instruction.accounts.iter().map(|m| pk_hex(&m.pubkey)).collect::<Vec<_>>(),
        "data": hex_of(&env.instruction.data),
    })
}

/// One recorded transaction: `tops` and `inner` are parallel (the RPC
/// innerInstructions grouping); `ex` is the LAST executed op, whose post
/// tree is the tx-level treeStatePost.
fn tx_entry_multi(slot: u64, signature: String, tops: Vec<Value>, inner: Vec<Vec<Value>>, ex: &Executed) -> Value {
    json!({
        "slot": slot,
        "blockTime": 1_700_000_000u64 + slot,
        "signature": signature,
        "instructions": tops,
        "inner": inner,
        "treeStatePost": {
            "nextLeafIndex": ex.post_next_leaf_index,
            "currentRoot": hex_of(&ex.resulting_root),
        },
    })
}

fn tx_entry(slot: u64, signature: String, env: &Env, inner: Vec<Value>, ex: &Executed) -> Value {
    tx_entry_multi(slot, signature, vec![op_ix_entry(env)], vec![inner], ex)
}

fn nonzero(nfs: &[String]) -> Vec<[u8; 32]> {
    nfs.iter().map(|s| hex32(s)).filter(|nf| nf != &[0u8; 32]).collect()
}

fn write_ledger(
    name: &str,
    program: &Pubkey,
    batch_b: u32,
    txs: Vec<Value>,
    final_tree: &Executed,
    comment: &str,
) {
    let out = json!({
        "comment": comment,
        "programId": pk_hex(program),
        "batchB": batch_b,
        "txs": txs,
        "final": {
            "nextLeafIndex": final_tree.post_next_leaf_index,
            "currentRoot": hex_of(&final_tree.resulting_root),
        },
    });
    let path = format!("{}/../conformance/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::write(&path, serde_json::to_string_pretty(&out).unwrap() + "\n").expect("write ledger");
    println!("wrote {path}");
}

fn consumer_ledger() {
    let pid = program_id();
    let empty = bongtu_solana_harness::tree_account_data(
        &Pubkey::new_from_array([0x01; 32]),
        &empty_snapshot(),
    );
    let mut txs: Vec<Value> = Vec::new();

    // -- deposit_priv: the genesis op, empty tree -> leaves 0,1 --------------
    let dep = load_deposit_fixture();
    let mut env = build_deposit_env(&dep);
    let ocs = [hex32(&dep.output_commitments[0]), hex32(&dep.output_commitments[1])];
    let ex = execute_chained(&mut env, &empty, &ocs, None);
    let ev = event::op_event_payload(
        event::FAMILY_TAG_DEPOSIT_PRIV, ex.start_leaf_index, 2, &ex.resulting_root, &[],
    );
    let inner = vec![
        inner_entry(&spl::TOKEN_PROGRAM_ID, spl_transfer_data(hex_u64(&dep.amount))),
        inner_entry(&pid, ev),
    ];
    txs.push(tx_entry(10, "SOLSIM-C-10-depositPriv".into(), &env, inner, &ex));
    let mut chained = ex.post_tree_data;

    // -- transfer_priv + transfer10x2_priv: ONE tx, leaves 2..5 --------------
    // Two pool ops recorded in a single transaction pin the ingest's FIFO
    // op/event pairing (i-th op ↔ i-th event) and back its imbalance throw.
    // Mollusk executes one instruction at a time, so the ops run back-to-back
    // against the chained tree and the recorded tx merges them; the recorded
    // shape is what the ingest dispatch consumes.
    let trf = load_fixture();
    let mut env_t = build_env(&trf);
    let ocs = [hex32(&trf.output_commitments[0]), hex32(&trf.output_commitments[1])];
    let ex_t = execute_chained(&mut env_t, &chained, &ocs, None);
    let nfs_t = nonzero(&trf.nullifiers);
    let ev_t = event::op_event_payload(
        event::FAMILY_TAG_TRANSFER_PRIV, ex_t.start_leaf_index, 2, &ex_t.resulting_root, &nfs_t,
    );
    chained = ex_t.post_tree_data.clone();

    let t10 = load_transfer10x2_fixture();
    let mut env_x = build_transfer10x2_env(&t10);
    let ocs = [hex32(&t10.output_commitments[0]), hex32(&t10.output_commitments[1])];
    let ex = execute_chained(&mut env_x, &chained, &ocs, None);
    let nfs = nonzero(&t10.nullifiers);
    let ev_x = event::op_event_payload(
        event::FAMILY_TAG_TRANSFER10X2_PRIV, ex.start_leaf_index, 2, &ex.resulting_root, &nfs,
    );
    txs.push(tx_entry_multi(
        20,
        "SOLSIM-C-20-transferPriv+transfer10x2Priv".into(),
        vec![op_ix_entry(&env_t), op_ix_entry(&env_x)],
        vec![vec![inner_entry(&pid, ev_t)], vec![inner_entry(&pid, ev_x)]],
        &ex,
    ));
    chained = ex.post_tree_data;

    // -- withdraw_priv: leaf 6 (change), invoked as an INNER instruction -----
    // The wrapper-invoked shape: an opaque top-level wrapper instruction with
    // the executed pool op in ITS inner list. Composing a real CPI-caller
    // program is impractical under mollusk (see the module doc), so the
    // transaction SHAPE is constructed — the RECORDED SHAPE is what the
    // ingest dispatch consumes, and it matches the RPC adapter's flattening
    // of a wrapper call (op, then its SPL CPI, then its self-CPI event). The
    // op record carries its account metas: decodeOp reads meta 11 (the
    // proof-bound recipient token account) for the withdraw announcement,
    // which the suite pins on /announcements.
    let wd = load_withdraw_fixture();
    let mut env = build_withdraw_env(&wd);
    let ex = execute_chained(&mut env, &chained, &[hex32(&wd.change_commitment)], None);
    let nfs = nonzero(&wd.nullifiers);
    let ev = event::op_event_payload(
        event::FAMILY_TAG_WITHDRAW_PRIV, ex.start_leaf_index, 1, &ex.resulting_root, &nfs,
    );
    let wrapper_pid = Pubkey::new_from_array([0xEE; 32]);
    let inner = vec![
        op_ix_entry(&env),
        inner_entry(&spl::TOKEN_PROGRAM_ID, spl_transfer_data(hex_u64(&wd.amount))),
        inner_entry(&pid, ev),
    ];
    txs.push(tx_entry_multi(
        40,
        "SOLSIM-C-40-withdrawPriv".into(),
        vec![json!({ "programId": pk_hex(&wrapper_pid), "accounts": Vec::<String>::new(), "data": "0x01" })],
        vec![inner],
        &ex,
    ));

    write_ledger(
        "ledger_consumer.json", &pid, 16, txs, &ex,
        "GENERATED by chains/solana/harness record_ledger: the four consumer P2P ops \
         chained through mollusk from the empty tree (SOLR S4 recorded-ledger fixture); \
         transferPriv + transfer10x2Priv share one multi-op transaction (FIFO op/event \
         pairing) and withdrawPriv is recorded as an inner (wrapper-invoked) instruction \
         with its account metas. Event bytes come from the program's own event payload \
         builders applied to the SVM-executed outcome. Regenerate: cargo run -p \
         bongtu-solana-harness --bin record_ledger.",
    );
}

fn enterprise_ledger() {
    let pid = program_id();
    let empty = bongtu_solana_harness::tree_account_data(
        &Pubkey::new_from_array([0x01; 32]),
        &empty_snapshot(),
    );
    let mut txs: Vec<Value> = Vec::new();

    // -- deposit: empty tree -> leaves 0,1 -----------------------------------
    let dep = load_ent_deposit_fixture();
    let mut env = build_ent_deposit_env(&dep);
    let ocs = [hex32(&dep.output_commitments[0]), hex32(&dep.output_commitments[1])];
    let ex = execute_chained(&mut env, &empty, &ocs, None);
    let ev = event::op_event_payload(
        event::FAMILY_TAG_DEPOSIT, ex.start_leaf_index, 2, &ex.resulting_root, &[],
    );
    let inner = vec![
        inner_entry(&spl::TOKEN_PROGRAM_ID, spl_transfer_data(hex_u64(&dep.amount))),
        inner_entry(&pid, ev),
    ];
    txs.push(tx_entry(100, "SOLSIM-E-100-deposit".into(), &env, inner, &ex));
    let mut chained = ex.post_tree_data;

    // -- disburse256: closes the partial block, attaches at 256 --------------
    let dis = load_disburse256_fixture();
    let mut env = build_disburse256_env(&dis);
    let ex = execute_chained(&mut env, &chained, &[], Some(hex32(&dis.subtree_root)));
    assert_eq!(
        ex.start_leaf_index, dis.start_leaf_index,
        "chained attach start moved off the fixture's DisburseBatch PDA seed"
    );
    let ev = event::disburse_event_payload(
        event::FAMILY_TAG_DISBURSE256,
        ex.start_leaf_index,
        &hex32(&dis.subtree_root),
        &ex.resulting_root,
        &hex32(&dis.nullifier),
        &hex32(&dis.disclosure_hash),
        &hex32(&dis.kem_binding),
        state::ARBITER_EPOCH_GENESIS,
    );
    txs.push(tx_entry(110, "SOLSIM-E-110-disburse256".into(), &env, vec![inner_entry(&pid, ev)], &ex));
    chained = ex.post_tree_data;

    // -- withdraw: leaf 512 (change, first append after the batch) -----------
    let wd = load_ent_withdraw_fixture();
    let mut env = build_ent_withdraw_env(&wd);
    let ex = execute_chained(&mut env, &chained, &[hex32(&wd.change_commitment)], None);
    let nfs = nonzero(&wd.nullifiers);
    let ev = event::op_event_payload(
        event::FAMILY_TAG_WITHDRAW, ex.start_leaf_index, 1, &ex.resulting_root, &nfs,
    );
    let inner = vec![
        inner_entry(&spl::TOKEN_PROGRAM_ID, spl_transfer_data(hex_u64(&wd.amount))),
        inner_entry(&pid, ev),
    ];
    txs.push(tx_entry(120, "SOLSIM-E-120-withdraw".into(), &env, inner, &ex));
    chained = ex.post_tree_data;

    // -- transfer: leaves 513,514 --------------------------------------------
    let trf = load_ent_transfer_fixture();
    let mut env = build_ent_transfer_env(&trf);
    let ocs = [hex32(&trf.output_commitments[0]), hex32(&trf.output_commitments[1])];
    let ex = execute_chained(&mut env, &chained, &ocs, None);
    let nfs = nonzero(&trf.nullifiers);
    let ev = event::op_event_payload(
        event::FAMILY_TAG_TRANSFER, ex.start_leaf_index, 2, &ex.resulting_root, &nfs,
    );
    txs.push(tx_entry(130, "SOLSIM-E-130-transfer".into(), &env, vec![inner_entry(&pid, ev)], &ex));
    chained = ex.post_tree_data;

    // -- transfer10x2 (the merge fixture: all 10 nullifiers real) ------------
    let t10 = load_ent_transfer10x2_fixture();
    let mut env = build_ent_transfer10x2_env(&t10);
    let ocs = [hex32(&t10.output_commitments[0]), hex32(&t10.output_commitments[1])];
    let ex = execute_chained(&mut env, &chained, &ocs, None);
    let nfs = nonzero(&t10.nullifiers);
    let ev = event::op_event_payload(
        event::FAMILY_TAG_TRANSFER10X2, ex.start_leaf_index, 2, &ex.resulting_root, &nfs,
    );
    txs.push(tx_entry(140, "SOLSIM-E-140-transfer10x2".into(), &env, vec![inner_entry(&pid, ev)], &ex));

    write_ledger(
        "ledger_enterprise.json", &pid, 256, txs, &ex,
        "GENERATED by chains/solana/harness record_ledger: the enterprise family \
         (deposit, disburse256, withdraw, transfer, transfer10x2) chained through mollusk \
         from the empty tree; the 1-tx disburse anchors (disclosureHash, kemBinding, epoch) \
         ride the recorded self-CPI event. Regenerate: cargo run -p bongtu-solana-harness \
         --bin record_ledger.",
    );
}

fn empty_snapshot() -> bongtu_solana_harness::TreeSnapshot {
    // The all-empty frontier: filled_subtrees[i] = ZEROS[i], root = ZEROS[H].
    let zeros = &bongtu_pool_solana::generated::zeros::ZEROS;
    bongtu_solana_harness::TreeSnapshot {
        next_leaf_index: 0,
        current_root: hex_of(&zeros[zeros.len() - 1]),
        filled_subtrees: zeros[..zeros.len() - 1].iter().map(|z| hex_of(z)).collect(),
    }
}

fn main() {
    consumer_ledger();
    enterprise_ledger();
}
