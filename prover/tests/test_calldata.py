# calldata.py gate — snarkjs exportSolidityCallData compatibility (CPU-only).
#
# The reference behaviour (snarkjs groth16_exportsoliditycalldata.js):
#   a   = [p256(pi_a[0]), p256(pi_a[1])]
#   b   = [[p256(pi_b[0][1]), p256(pi_b[0][0])], [p256(pi_b[1][1]), p256(pi_b[1][0])]]
#   c   = [p256(pi_c[0]), p256(pi_c[1])]
#   pub = [p256(x) for x in publicSignals]
# where p256(n) = "0x" + hex(n) left-padded to 64 nibbles. The G2 inner swap on
# `b` is the part a verifier call would silently get wrong — pinned two ways:
# hand-restated on synthetic proofs below, AND differentially against
# chains/evm/test/fixtures/disburse256.calldata.json, which snarkjs ITSELF
# produced from the committed real proof (so a shared misunderstanding of the
# rule cannot pass — the reference implementation is in the loop via a
# committed byte-level artifact).

import json
from pathlib import Path

import pytest

from prover_service import config
from prover_service.calldata import to_solidity_calldata

FIXTURES = Path(__file__).resolve().parents[2] / "chains" / "evm" / "test" / "fixtures"


def snarkjs_proof(a0=11, a1=12, b00=21, b01=22, b10=23, b11=24, c0=31, c1=32) -> dict:
    """A proof dict in Groth16Proof.to_json() / snarkjs-native shape."""
    return {
        "pi_a": [str(a0), str(a1), "1"],
        "pi_b": [[str(b00), str(b01)], [str(b10), str(b11)], ["1", "0"]],
        "pi_c": [str(c0), str(c1), "1"],
        "protocol": "groth16",
        "curve": "bn128",
    }


def test_g2_inner_swap_is_applied_on_b():
    cd = to_solidity_calldata(snarkjs_proof(), ["7"])
    def n(x):
        return int(x, 16)
    assert [n(x) for x in cd.a] == [11, 12]
    # snarkjs swaps each G2 coordinate pair: [[b01, b00], [b11, b10]].
    assert [[n(x) for x in row] for row in cd.b] == [[22, 21], [24, 23]]
    assert [n(x) for x in cd.c] == [31, 32]
    assert [n(x) for x in cd.pub] == [7]


def test_words_are_0x_padded_64_nibbles():
    big = (1 << 254) - 3
    cd = to_solidity_calldata(snarkjs_proof(a0=big), [str(big), "0"])
    for x in [*cd.a, *cd.b[0], *cd.b[1], *cd.c, *cd.pub]:
        assert x.startswith("0x") and len(x) == 66, x
        int(x, 16)  # parses as hex
    assert cd.a[0] == "0x" + format(big, "064x")
    assert cd.pub[1] == "0x" + "0" * 64


def test_pub_preserves_order_and_length():
    pubs = [str(i * 1000 + 7) for i in range(11)]  # disburse256 exposes 11 publics
    cd = to_solidity_calldata(snarkjs_proof(), pubs)
    assert [int(x, 16) for x in cd.pub] == [int(p) for p in pubs]


@pytest.mark.parametrize("name", ["disburse256", "transfer10x2"])
def test_per_circuit_pub_length_comes_from_the_registry(name):
    # engine.prove passes the registry's num_public (11 / 68); the exact count
    # passes and off-by-one fails naming both numbers.
    n = config.CIRCUITS[name].num_public
    ok = to_solidity_calldata(snarkjs_proof(), ["1"] * n, expected_pub_len=n)
    assert len(ok.pub) == n
    with pytest.raises(ValueError, match=f"expected {n} public signals, got {n - 1}"):
        to_solidity_calldata(snarkjs_proof(), ["1"] * (n - 1), expected_pub_len=n)


def test_pub_length_unchecked_when_no_expectation_is_given():
    # backward-compatible default: callers outside the engine (tests, tools)
    # may format any pub list.
    assert len(to_solidity_calldata(snarkjs_proof(), ["7"]).pub) == 1


def test_out_of_range_value_is_rejected():
    with pytest.raises(ValueError, match="uint256"):
        to_solidity_calldata(snarkjs_proof(a0=1 << 256), ["1"])


def test_committed_real_proof_matches_snarkjs_calldata_fixture():
    # True differential: the committed disburse256 proof re-encoded here must
    # equal, byte for byte, what snarkjs exportSolidityCallData emitted for the
    # same proof (the committed disburse256.calldata.json). Any padding/order/
    # G2-swap drift fails naming the first divergent field instead of an
    # on-chain InvalidProof revert.
    proof = json.loads((FIXTURES / "disburse256.proof.json").read_text())
    pub = json.loads((FIXTURES / "disburse256.public.json").read_text())
    want = json.loads((FIXTURES / "disburse256.calldata.json").read_text())
    got = to_solidity_calldata(proof, pub).model_dump()
    assert got == want
