# schema.py gate — the Python mirror of packages/sdk/src/proving.ts.
#
# CPU-only (no GPU / rabbitsnark import): validates that (1) the repo's real
# disburse256 fixture input parses as a DisburseRequest unchanged, (2) every
# committed circuits/inputs/{deposit,transfer,withdraw,disburse}.json — the
# same files the TS generators type against the proving.ts interfaces —
# round-trips through the discriminated union unchanged, so all edges of the
# circom-main / fixture / proving.ts / schema.py triangle are pinned by real
# artifacts rather than hand-written literals, (3) the §11-8 two-time-pad
# guard and the field-element/shape validators reject what the TS prover
# rejected.

import json
from pathlib import Path

import pytest
from pydantic import TypeAdapter, ValidationError

from prover_service.schema import (
    BN254_R,
    Calldata,
    DisburseRequest,
    ProvingRequest,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
INPUTS = REPO_ROOT / "circuits" / "inputs"
FIXTURE = INPUTS / "disburse256.json"

request_adapter = TypeAdapter(ProvingRequest)


def minimal_disburse_input(**overrides) -> dict:
    d = {
        "nullifiers": ["11"],
        "inputCommitments": ["22"],
        "inputValues": ["100"],
        "inputSalts": ["3"],
        "inputOwnerPrivateKey": "4",
        "ecdhPrivateKey": "5",
        "root": "6",
        "pathElements": [["0"] * 32],
        "leafIndices": ["1"],
        "enabled": ["1"],
        "outputCommitments": ["7", "8"],
        "outputValues": ["60", "40"],
        "outputSalts": ["9", "10"],
        "outputOwnerPublicKeys": [["1", "2"], ["3", "4"]],
        "encryptionNonce": "12",
        "authorityPublicKey": ["13", "14"],
    }
    d.update(overrides)
    return d


def test_repo_disburse256_fixture_parses_unchanged():
    raw = json.loads(FIXTURE.read_text())
    req = request_adapter.validate_python({"circuit": "disburse", "input": raw, "backend": "gpu"})
    assert isinstance(req, DisburseRequest)
    assert len(req.input.outputCommitments) == 256
    assert len(req.input.pathElements) == 1 and len(req.input.pathElements[0]) == 32
    assert req.input.enabled == ["1"]
    # the mirror round-trips the fixture byte-for-byte (canonical decimal strings).
    assert req.input.model_dump() == raw


@pytest.mark.parametrize(
    "circuit,fixture",
    [
        ("deposit", "deposit.json"),
        ("transfer", "transfer.json"),
        ("withdraw", "withdraw.json"),
        ("disburse", "disburse.json"),  # the M0 1x16 dev build (shape guards are B-agnostic)
    ],
)
def test_all_four_committed_fixtures_round_trip(circuit, fixture):
    # The committed fixture is the executable wire contract: the TS generator
    # that wrote it is typed against proving.ts, and this mirror must accept and
    # reproduce it byte-for-byte. A field drifting on either side turns this red
    # naming the circuit + field.
    raw = json.loads((INPUTS / fixture).read_text())
    req = request_adapter.validate_python({"circuit": circuit, "input": raw})
    assert req.circuit == circuit
    assert req.input.model_dump() == raw


def test_all_four_circuit_tags_parse():
    deposit_input = {
        "outputCommitments": ["1", "2"],
        "outputValues": ["5", "0"],
        "outputSalts": ["1", "2"],
        "outputOwnerPublicKeys": [["1", "2"], ["3", "4"]],
        "ecdhPrivateKey": "7",
        "encryptionNonce": "42",
        "authorityPublicKey": ["1", "2"],
    }
    spend_input = minimal_disburse_input(
        nullifiers=["1", "0"],
        inputCommitments=["1", "2"],
        inputValues=["50", "0"],
        inputSalts=["1", "2"],
        pathElements=[["0"] * 32, ["0"] * 32],
        leafIndices=["0", "0"],
        enabled=["1", "0"],
    )
    for circuit, inp in [
        ("deposit", deposit_input),
        ("transfer", spend_input),
        ("withdraw", {**spend_input, "outputCommitments": ["7"], "outputValues": ["100"],
                      "outputSalts": ["9"], "outputOwnerPublicKeys": [["1", "2"]]}),
        ("disburse", minimal_disburse_input()),
    ]:
        req = request_adapter.validate_python({"circuit": circuit, "input": inp})
        assert req.circuit == circuit
        assert req.backend is None


def test_two_time_pad_guard_rejects_duplicate_disburse_owners():
    dup = minimal_disburse_input(outputOwnerPublicKeys=[["1", "2"], ["1", "2"]])
    with pytest.raises(ValidationError, match="duplicate output owner pubkey"):
        request_adapter.validate_python({"circuit": "disburse", "input": dup})


def test_two_time_pad_guard_rejects_duplicate_transfer_owners():
    dup = minimal_disburse_input(
        nullifiers=["1", "0"],
        inputCommitments=["1", "2"],
        inputValues=["50", "0"],
        inputSalts=["1", "2"],
        pathElements=[["0"] * 32, ["0"] * 32],
        leafIndices=["0", "0"],
        enabled=["1", "0"],
        outputOwnerPublicKeys=[["1", "2"], ["1", "2"]],
    )
    with pytest.raises(ValidationError, match="duplicate output owner pubkey"):
        request_adapter.validate_python({"circuit": "transfer", "input": dup})


@pytest.mark.parametrize(
    "bad",
    ["", "0x12", "-1", "1.5", "abc", str(BN254_R), None, 1.5, True],
)
def test_bad_field_elements_are_rejected(bad):
    with pytest.raises(ValidationError):
        request_adapter.validate_python(
            {"circuit": "disburse", "input": minimal_disburse_input(root=bad)}
        )


def test_int_field_elements_canonicalize_to_decimal_strings():
    req = request_adapter.validate_python(
        {"circuit": "disburse", "input": minimal_disburse_input(root=6, leafIndices=[1])}
    )
    assert req.input.root == "6"
    assert req.input.leafIndices == ["1"]


def test_disburse_shape_guards():
    with pytest.raises(ValidationError, match="exactly one input"):
        request_adapter.validate_python(
            {"circuit": "disburse", "input": minimal_disburse_input(nullifiers=["1", "2"])}
        )
    with pytest.raises(ValidationError, match="agree in length"):
        request_adapter.validate_python(
            {"circuit": "disburse", "input": minimal_disburse_input(outputValues=["60"])}
        )


def test_unknown_fields_and_circuits_are_rejected():
    with pytest.raises(ValidationError):
        request_adapter.validate_python(
            {"circuit": "disburse", "input": minimal_disburse_input(extraField="1")}
        )
    with pytest.raises(ValidationError):
        request_adapter.validate_python(
            {"circuit": "mint", "input": minimal_disburse_input()}
        )


def test_calldata_shape():
    word = "0x" + "0" * 63 + "1"
    cd = Calldata(a=[word, word], b=[[word, word], [word, word]], c=[word, word], pub=[word] * 10)
    assert len(cd.pub) == 10
