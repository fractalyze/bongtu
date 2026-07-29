# Python mirror of the shared proving wire types.
#
# SOURCE OF TRUTH: packages/core/src/proving.ts (TS). This module mirrors it 1:1
# — same circuit tags, same per-circuit input field names, same Calldata shape —
# so a ProvingRequest assembled by the TS apps deserializes here unchanged. Keep
# the two files in sync; a field added there must be added here.
#
# One deliberate omission: the TS `Circuit` union also has "transfer10" (10-in /
# 10-out). This service registers only the circuits in config.CIRCUITS
# (disburse256 + transfer10x2 + deposit), and transfer10 proves in-browser on
# CPU like transfer/withdraw, so there is no variant for it here — an unknown
# tag is rejected at validation, which is the right answer for a circuit this
# service cannot prove. Add one only if it ever joins the registry.
#
# Field elements arrive as decimal strings (JSON has no bigint; the TS side
# stringifies) or small ints; points are [x, y] pairs. The §11-8 two-time-pad
# guard (a DISBURSE batch's output owners must be DISTINCT, because all B outputs
# share one ephemeral key + nonce) is enforced at validation time, mirroring
# @bongtu/core assertDistinctOwnerPubkeys — the prover MUST reject such a request
# before any proving work (SPEC §4). transfer is exempt since U-X3: its base
# encrypts ct_i under `encryptionNonce + i`, which is what makes a self-send
# legal (docs/circuits.md).

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator

BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def _field_element(v: object) -> str:
    """Coerce a FieldInput (decimal string | int) to a canonical decimal string."""
    if isinstance(v, bool):
        raise ValueError("field element must be a decimal string or int, not bool")
    if isinstance(v, int):
        n = v
    elif isinstance(v, str):
        s = v.strip()
        if not s or not s.isdigit():
            raise ValueError(f"field element must be a non-negative decimal string, got {v!r}")
        n = int(s)
    else:
        raise ValueError(f"field element must be a decimal string or int, got {type(v).__name__}")
    if n < 0 or n >= BN254_R:
        raise ValueError("field element out of range [0, r)")
    return str(n)


FieldInput = Annotated[str, BeforeValidator(_field_element)]
PointInput = Annotated[list[FieldInput], Field(min_length=2, max_length=2)]
# The hybrid authority envelope's ML-KEM-768 shared-secret limbs (two exact
# LE-uint128 halves of the 32-byte secret, pq-envelope-design.md §2) — a
# REQUIRED witness input of every circuit since the PQ upgrade. The 1088-byte
# kemCiphertext never reaches the prover (it is tx calldata, not witness).
KemSs = Annotated[list[FieldInput], Field(min_length=2, max_length=2)]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DepositInput(_StrictModel):
    """deposit (0-in / 2-out): mint; authority envelope only."""

    outputCommitments: list[FieldInput]
    outputValues: list[FieldInput]
    outputSalts: list[FieldInput]
    outputOwnerPublicKeys: list[PointInput]
    ecdhPrivateKey: FieldInput
    kemSs: KemSs
    encryptionNonce: FieldInput
    authorityPublicKey: PointInput


class _SpendInput(_StrictModel):
    """Shared shape of the three membership-spending circuits."""

    nullifiers: list[FieldInput]
    inputCommitments: list[FieldInput]
    inputValues: list[FieldInput]
    inputSalts: list[FieldInput]
    inputOwnerPrivateKey: FieldInput
    ecdhPrivateKey: FieldInput
    root: FieldInput
    pathElements: list[list[FieldInput]]
    leafIndices: list[FieldInput]
    enabled: list[FieldInput]
    outputCommitments: list[FieldInput]
    outputValues: list[FieldInput]
    outputSalts: list[FieldInput]
    outputOwnerPublicKeys: list[PointInput]
    kemSs: KemSs
    encryptionNonce: FieldInput
    authorityPublicKey: PointInput


def _assert_distinct_owner_pubkeys(pubkeys: list[list[str]]) -> None:
    """Mirror of @bongtu/core assertDistinctOwnerPubkeys (§11-8)."""
    seen: set[tuple[str, str]] = set()
    for pk in pubkeys:
        key = (pk[0], pk[1])
        if key in seen:
            raise ValueError(
                f"duplicate output owner pubkey ({pk[0]},{pk[1]}): all outputs share one "
                "ephemeral key + nonce, so a repeated recipient leaks value/salt via a "
                "two-time pad (SPEC §4 / §11-8). Reject before proving."
            )
        seen.add(key)


class TransferInput(_SpendInput):
    """transfer (2-in / 2-out): duplicate output owners are LEGAL since U-X3.

    The transfer base encrypts receiver ciphertext i under `encryptionNonce + i`
    (§11-8 v1.1, encrypt-outputs-per-output-nonce.circom), so two outputs to one
    owner are no longer a two-time pad — that is exactly what makes a self-send
    provable. disburse still shares one nonce across the batch and keeps the
    guard (packages/core/src/proving.ts, docs/circuits.md).
    """


class Transfer10x2Input(_SpendInput):
    """transfer10x2 (10-in / 2-out): the transfer base at 10 inputs, 2 outputs.

    The merge/pay leg the employer console proves on the GPU service (and
    wallets prove on CPU). Same per-output-nonce base as transfer, so duplicate
    output owners are LEGAL — a pure self-merge (both outputs to the sender) is
    the headline use (proving.ts Transfer10x2Input, docs/circuits.md). Like
    transfer/withdraw, arity is not re-checked here: the committed fixture pins
    the 10/2 shape, and a wrong-arity input fails witness generation (400).
    """


class WithdrawInput(_SpendInput):
    """withdraw (2-in / 1-out): single change output, no distinctness needed."""


class DisburseInput(_SpendInput):
    """disburse (1-in / B-out): single always-real input; distinct output owners (§11-8)."""

    @model_validator(mode="after")
    def _shape_and_two_time_pad_guard(self) -> "DisburseInput":
        for name in ("nullifiers", "inputCommitments", "inputValues", "inputSalts",
                     "pathElements", "leafIndices", "enabled"):
            if len(getattr(self, name)) != 1:
                raise ValueError(f"disburse takes exactly one input: len({name}) != 1")
        n_out = len(self.outputCommitments)
        for name in ("outputValues", "outputSalts", "outputOwnerPublicKeys"):
            if len(getattr(self, name)) != n_out:
                raise ValueError(f"output arrays must agree in length: len({name}) != {n_out}")
        _assert_distinct_owner_pubkeys(self.outputOwnerPublicKeys)
        return self


class DepositRequest(_StrictModel):
    circuit: Literal["deposit"]
    input: DepositInput
    backend: Literal["cpu", "gpu"] | None = None


class TransferRequest(_StrictModel):
    circuit: Literal["transfer"]
    input: TransferInput
    backend: Literal["cpu", "gpu"] | None = None


class Transfer10x2Request(_StrictModel):
    circuit: Literal["transfer10x2"]
    input: Transfer10x2Input
    backend: Literal["cpu", "gpu"] | None = None


class WithdrawRequest(_StrictModel):
    circuit: Literal["withdraw"]
    input: WithdrawInput
    backend: Literal["cpu", "gpu"] | None = None


class DisburseRequest(_StrictModel):
    circuit: Literal["disburse"]
    input: DisburseInput
    backend: Literal["cpu", "gpu"] | None = None


ProvingRequest = Annotated[
    Union[
        DepositRequest, TransferRequest, Transfer10x2Request, WithdrawRequest, DisburseRequest
    ],
    Field(discriminator="circuit"),
]


class Calldata(_StrictModel):
    """Groth16 proof in snarkjs exportSolidityCallData form (G2 inner-swap applied
    on b), every value a 0x-prefixed 32-byte hex word — splat into a BongtuPool
    verifier call (a, b, c, pub)."""

    a: list[str]
    b: list[list[str]]
    c: list[str]
    pub: list[str]
