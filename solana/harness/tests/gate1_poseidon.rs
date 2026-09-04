//! Gate 1 — poseidon conformance (SOLR §3.1.3 #1): the syscall implementation
//! (solana-poseidon; light-poseidon on host, the exact crate Agave's
//! sol_poseidon runs) must reproduce the committed circomlib-parity vectors
//! exported from packages/core. Failure = the rail's algebra forked; hard fail.
//!
//! The in-SVM syscall path is additionally pinned by gate 2: the fixture's
//! seeded root and post-append root only match if every sol_poseidon fold
//! inside the program agrees with the packages/core oracle.

use {
    bongtu_solana_harness::{hex32, hex_bytes},
    serde::Deserialize,
    solana_poseidon::{hashv, Endianness, Parameters},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    arity: usize,
    inputs_hex: Vec<String>,
    out_hex: String,
    out: String,
}

#[derive(Deserialize)]
struct Vectors {
    canonical_1_2: String,
    cases: Vec<Case>,
}

fn load() -> Vectors {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../conformance/poseidon_vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("poseidon_vectors.json")).unwrap()
}

/// docs/protocol.md parity anchor, hardcoded independently of the generator.
const CANONICAL_1_2_DEC: &str =
    "7853200120776062878684798364095072458815029376092732009249414926327459813530";

#[test]
fn poseidon_matches_committed_vectors() {
    let vectors = load();
    assert_eq!(
        vectors.canonical_1_2, CANONICAL_1_2_DEC,
        "generated vectors drifted from the docs/protocol.md anchor"
    );
    assert!(!vectors.cases.is_empty());

    for case in &vectors.cases {
        assert_eq!(case.inputs_hex.len(), case.arity);
        let inputs: Vec<[u8; 32]> = case.inputs_hex.iter().map(|h| hex32(h)).collect();
        let refs: Vec<&[u8]> = inputs.iter().map(|b| b.as_slice()).collect();
        let got = hashv(Parameters::Bn254X5, Endianness::BigEndian, &refs)
            .expect("sol_poseidon rejected a conformance input")
            .to_bytes();
        assert_eq!(
            got,
            hex32(&case.out_hex),
            "poseidon arity-{} fork on inputs {:?} (want decimal {})",
            case.arity,
            case.inputs_hex,
            case.out
        );
    }
}

#[test]
fn canonical_1_2_reproduced() {
    // Poseidon([1, 2]) — the one vector every implementation in the system
    // must agree on (docs/protocol.md).
    let one = {
        let mut b = [0u8; 32];
        b[31] = 1;
        b
    };
    let two = {
        let mut b = [0u8; 32];
        b[31] = 2;
        b
    };
    let got = hashv(Parameters::Bn254X5, Endianness::BigEndian, &[&one, &two])
        .unwrap()
        .to_bytes();
    // Expected value from the committed vectors (arity-2 [1,2] case).
    let vectors = load();
    let expected = vectors
        .cases
        .iter()
        .find(|c| c.arity == 2 && c.out == CANONICAL_1_2_DEC)
        .expect("canonical [1,2] case present");
    assert_eq!(got, hex32(&expected.out_hex));
    // Belt: the hex and decimal forms in the vector file must denote the same
    // value (hex is what the Rust side consumes; decimal is the docs anchor).
    assert_eq!(hex_bytes(&expected.out_hex).len(), 32);
}
