# Groth16 proof JSON -> solidity calldata, byte-compatible with snarkjs
# `groth16.exportSolidityCallData`.
#
# rabbitsnark's Groth16Proof.to_json() emits the snarkjs-native proof shape
# (pi_a/pi_b/pi_c as decimal strings, projective 1-coordinates appended).
# exportSolidityCallData turns that into the verifier-ready form:
#   a   = [pi_a[0], pi_a[1]]
#   b   = [[pi_b[0][1], pi_b[0][0]], [pi_b[1][1], pi_b[1][0]]]   # G2 inner swap
#   c   = [pi_c[0], pi_c[1]]
#   pub = the public signals
# with every value hex-encoded as a 0x-prefixed, zero-padded 32-byte word.
# The TS consumers (payroll-web chain.ts, deploy runners) splat this straight into
# BongtuPool verifier calls, so the format here must never drift from snarkjs.

from __future__ import annotations

from .schema import Calldata


def _word(v: str | int) -> str:
    """A uint256 calldata word: 0x + 64 lowercase hex nibbles (snarkjs p256)."""
    n = int(v)
    if n < 0 or n >= 1 << 256:
        raise ValueError(f"value out of uint256 range: {v!r}")
    return "0x" + format(n, "064x")


def to_solidity_calldata(proof: dict, public_signals: list[str]) -> Calldata:
    """Convert a snarkjs-shape proof dict + decimal public signals to Calldata."""
    pi_a, pi_b, pi_c = proof["pi_a"], proof["pi_b"], proof["pi_c"]
    return Calldata(
        a=[_word(pi_a[0]), _word(pi_a[1])],
        b=[
            [_word(pi_b[0][1]), _word(pi_b[0][0])],
            [_word(pi_b[1][1]), _word(pi_b[1][0])],
        ],
        c=[_word(pi_c[0]), _word(pi_c[1])],
        pub=[_word(x) for x in public_signals],
    )
