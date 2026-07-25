# calldata.py gate — snarkjs exportSolidityCallData compatibility (CPU-only).
#
# The reference behaviour (snarkjs groth16_exportsoliditycalldata.js):
#   a   = [p256(pi_a[0]), p256(pi_a[1])]
#   b   = [[p256(pi_b[0][1]), p256(pi_b[0][0])], [p256(pi_b[1][1]), p256(pi_b[1][0])]]
#   c   = [p256(pi_c[0]), p256(pi_c[1])]
#   pub = [p256(x) for x in publicSignals]
# where p256(n) = "0x" + hex(n) left-padded to 64 nibbles. The G2 inner swap on
# `b` is the part a verifier call would silently get wrong — pinned here.

import pytest

from prover_service.calldata import to_solidity_calldata


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
    pubs = [str(i * 1000 + 7) for i in range(10)]  # disburse256 exposes 10 publics
    cd = to_solidity_calldata(snarkjs_proof(), pubs)
    assert [int(x, 16) for x in cd.pub] == [int(p) for p in pubs]


def test_out_of_range_value_is_rejected():
    with pytest.raises(ValueError, match="uint256"):
        to_solidity_calldata(snarkjs_proof(a0=1 << 256), ["1"])
