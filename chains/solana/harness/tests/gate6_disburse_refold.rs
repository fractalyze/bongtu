//! Gate 6 — the refold check (SOLR §3.3.2 / §6 S3 acceptance): reconstruct
//! `disclosureChain` over the served-blob fixture (the 2054-element
//! disclosure array re-derived by gen_enterprise_vectors.ts through
//! packages/core envelope.ts, the one fold implementation) and assert
//! equality with the `DisburseBatch.disclosureHash` the on-SVM attach stored.
//!
//! This is the verifier ANY party runs against institution-served bytes: no
//! key, no trust — refold with the canonical-form rule (reject >= r before
//! folding; byte equality, not mod-p — OPMOD §4.4) and compare to account
//! state. The Rust fold here goes through the same sol_poseidon
//! implementation the program's tree uses, so the fold algebra is pinned
//! end to end: TS envelope.ts == in-circuit gadget (core p2 test) ==
//! this refold == the chain-persisted hash.

use {
    bongtu_pool_solana::state,
    bongtu_solana_harness::{
        enterprise::{build_disburse256_env, disburse_batch_pda, load_disburse256_fixture},
        hex32, is_canonical, program_id,
    },
    mollusk_svm::result::Check,
    solana_poseidon::{hashv, Endianness, Parameters},
};

/// disclosureChain: Poseidon(2) fold of the element list, seeded at 0
/// (packages/core envelope.ts — every receiver element then every authority
/// element). Rejects (Err = element index) any non-canonical element BEFORE
/// folding — the SOLR §3.3.2 canonical-form rule as verifier behavior, so
/// the >= r reject is exercised by a vector, not asserted away.
/// The S4 indexer's served-blob verifier must inherit these vectors (the
/// canonical LE wire decode) — SOLR §3.3.2.
fn refold(elements: &[String]) -> Result<[u8; 32], usize> {
    let mut dh = [0u8; 32];
    for (i, el) in elements.iter().enumerate() {
        let e = hex32(el);
        if !is_canonical(&e) {
            return Err(i);
        }
        dh = hashv(Parameters::Bn254X5, Endianness::BigEndian, &[&dh, &e])
            .expect("poseidon fold")
            .to_bytes();
    }
    Ok(dh)
}

/// The BN254 scalar field modulus r (32 B big-endian).
const R_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
    0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
    0x00, 0x01,
];

/// element + r over 32-byte big-endian bytes — a canonical element's smallest
/// non-canonical alias (e < r < 2^254, so the sum never overflows 256 bits).
fn add_r(e: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = e[i] as u16 + R_BE[i] as u16 + carry;
        out[i] = (s & 0xFF) as u8;
        carry = s >> 8;
    }
    assert_eq!(carry, 0, "alias overflowed 256 bits");
    out
}

#[test]
fn served_blob_refolds_to_the_disclosure_hash_the_batch_stored() {
    let fx = load_disburse256_fixture();
    assert_eq!(
        fx.disclosure_elements.len(),
        2054,
        "disclosure blob is receiverCts[1024] ++ authorityEnvelope[1030]"
    );

    // 1. Independent refold of the served bytes == the proof's public.
    let dh = refold(&fx.disclosure_elements).expect("canonical served blob");
    assert_eq!(
        dh,
        hex32(&fx.disclosure_hash),
        "refolded disclosureChain != the proof's disclosureHash public"
    );

    // 2. On-SVM: the 1-tx disburse persists exactly that hash in the
    //    DisburseBatch PDA — the account any verifier checks served bytes
    //    against, forever, with no ledger history.
    let env = build_disburse256_env(&fx);
    let result = env.mollusk.process_and_validate_instruction(
        &env.instruction,
        &env.accounts,
        &[Check::success()],
    );
    let batch = result
        .get_account(&disburse_batch_pda(fx.start_leaf_index))
        .expect("disburse batch pda");
    assert_eq!(batch.owner, program_id());
    assert_eq!(
        batch.data[state::BATCH_OFF_DISCLOSURE_HASH..state::BATCH_OFF_DISCLOSURE_HASH + 32],
        dh,
        "DisburseBatch.disclosureHash != the refolded served blob"
    );
}

#[test]
fn refold_detects_a_tampered_served_blob() {
    // The mismatch alarm class (SOLR §3.3.2): an institution serving
    // different bytes cannot match the chain-committed hash.
    let fx = load_disburse256_fixture();
    let mut elements = fx.disclosure_elements.clone();
    // Flip the LAST element (the authority-envelope checksum tail — the
    // position only the chain fold catches; earlier flips also garble
    // decryption, later there is nothing).
    let last = elements.last_mut().unwrap();
    let mut e = hex32(last);
    e[31] ^= 0x01;
    *last = format!("0x{}", e.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let dh = refold(&elements).expect("canonical served blob");
    assert_ne!(
        dh,
        hex32(&fx.disclosure_hash),
        "a tampered blob refolded to the committed hash"
    );
}

#[test]
fn non_canonical_alias_rejected_before_folding() {
    // element' = element + r: the same scalar mod r under a different byte
    // encoding. The canonical-form rule must reject the alias at its index,
    // BEFORE folding (byte equality, not mod-p — OPMOD §4.4): folding it
    // would reproduce the committed hash for bytes the wire must refuse.
    let fx = load_disburse256_fixture();
    let mut elements = fx.disclosure_elements.clone();
    let aliased = add_r(&hex32(&elements[0]));
    assert!(!is_canonical(&aliased));
    elements[0] = format!(
        "0x{}",
        aliased.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    assert_eq!(
        refold(&elements),
        Err(0),
        "a non-canonical alias must be rejected before folding"
    );
}

#[test]
fn swapped_adjacent_elements_change_the_fold() {
    // Order sensitivity, pinned explicitly: disclosureChain is a sequential
    // fold, so serving two adjacent elements reordered cannot refold to the
    // committed hash.
    let fx = load_disburse256_fixture();
    let mut elements = fx.disclosure_elements.clone();
    assert_ne!(elements[0], elements[1], "vector degenerate: equal neighbors");
    elements.swap(0, 1);
    let dh = refold(&elements).expect("canonical served blob");
    assert_ne!(
        dh,
        hex32(&fx.disclosure_hash),
        "a reordered blob refolded to the committed hash"
    );
}
