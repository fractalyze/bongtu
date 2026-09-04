//! Gate 4 — tx-size regression (SOLR §3.1.3 #4): every fully-built op
//! transaction must fit the Transaction v1 4,096 B format, asserted from the
//! consensus wire format so a wire change that silently breaks
//! single-tx-ness fails here, not on chain.
//!
//! Two layers: the WORST-CASE shape per op (maximum nullifier-PDA count —
//! account count is the only variable; the payload is fixed per family), and
//! the real fixture instructions as built by the harness (which must come in
//! at or under the worst case).

use {
    bongtu_pool_solana::{deposit_priv, transfer10x2_priv, transfer_priv, withdraw_priv},
    bongtu_solana_harness::{
        build_deposit_env, build_env, build_transfer10x2_env, build_withdraw_env,
        load_deposit_fixture, load_fixture, load_transfer10x2_fixture, load_withdraw_fixture,
        v0_tx_size,
    },
};

const TX_V1_LIMIT: usize = 4096;

/// (op, worst-case account metas, instruction data length). Account counts
/// come from the instruction layouts (module docs): the base accounts plus
/// the maximum nullifier-PDA run; data = 1-byte discriminator + payload.
const WORST_CASES: [(&str, usize, usize); 4] = [
    ("deposit_priv", 10, 1 + deposit_priv::PAYLOAD_LEN),
    ("transfer_priv", 10, 1 + transfer_priv::PAYLOAD_LEN),
    ("transfer10x2_priv", 18, 1 + transfer10x2_priv::PAYLOAD_LEN),
    ("withdraw_priv", 14, 1 + withdraw_priv::PAYLOAD_LEN),
];

#[test]
fn every_op_worst_case_tx_fits_transaction_v1() {
    for (op, accounts, data_len) in WORST_CASES {
        let size = v0_tx_size(accounts, data_len);
        println!("tx size[{op}] = {size} B (worst case, limit {TX_V1_LIMIT})");
        assert!(
            size <= TX_V1_LIMIT,
            "{op} worst-case tx is {size} B, over the {TX_V1_LIMIT} B Transaction v1 limit"
        );
    }
}

#[test]
fn fixture_instructions_are_within_their_worst_case() {
    let deposit = build_deposit_env(&load_deposit_fixture());
    let transfer = build_env(&load_fixture());
    let t10x2 = build_transfer10x2_env(&load_transfer10x2_fixture());
    let withdraw = build_withdraw_env(&load_withdraw_fixture());

    for (env, (op, worst_accounts, worst_data)) in
        [deposit, transfer, t10x2, withdraw].iter().zip(WORST_CASES)
    {
        let accounts = env.instruction.accounts.len();
        let data_len = env.instruction.data.len();
        assert!(
            accounts <= worst_accounts,
            "{op}: fixture instruction has {accounts} accounts, worst case {worst_accounts}"
        );
        assert_eq!(
            data_len, worst_data,
            "{op}: instruction data length is wire-fixed and must equal the worst case"
        );
        let size = v0_tx_size(accounts, data_len);
        assert!(size <= TX_V1_LIMIT, "{op}: fixture tx is {size} B");
    }
}
