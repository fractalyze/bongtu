# engine.py boot gate — the .so/zkey artifact-pair check.
#
# A circuit's proving artifacts come from two independent pipelines over the
# same .circom: circuits/build_witness_so.sh emits the witness calculator
# (lib<name>.so + <name>_w2s.json) and the snarkjs setup emits the .zkey. A
# stale half is the expected drift after any circuit edit, and nothing else in
# the boot notices it — the worker computes a witness of ITS length, the prover
# MSMs it against the zkey's point arrays, and the mismatch surfaces as a
# malformed proof rather than an error. This gate is the one place the two
# lengths meet, so it runs at boot and refuses to serve.
#
# CPU-only: engine.py's rabbitsnark/jax imports are all deferred into methods,
# so the module imports fine under CI's pydantic+pytest-only install.

import pytest

from prover_service import config
from prover_service.engine import check_witness_size

DISBURSE = config.CIRCUITS["disburse256"]


def test_matching_lengths_pass():
    check_witness_size(DISBURSE, 2_800_000, 2_800_000)


def test_a_short_witness_fails_the_boot_naming_both_artifacts():
    with pytest.raises(RuntimeError) as excinfo:
        check_witness_size(DISBURSE, 2_800_000, 2_800_001)
    detail = str(excinfo.value)
    assert "2800000" in detail and "2800001" in detail  # both counts
    assert str(DISBURSE.so) in detail and str(DISBURSE.zkey) in detail  # both paths
    assert "BONGTU_DISBURSE_SO" in detail and "BONGTU_DISBURSE_ZKEY" in detail


def test_a_long_witness_fails_the_boot_too():
    # A longer witness is not spare room: everything past the zkey's m is
    # dropped from every MSM, so the proof is wrong rather than absent. The
    # check is equality, never `>=`.
    with pytest.raises(RuntimeError, match="different circuit revisions"):
        check_witness_size(config.CIRCUITS["transfer10x2"], 500, 499)


def test_the_gate_names_the_failing_circuits_own_env_family():
    with pytest.raises(RuntimeError) as excinfo:
        check_witness_size(config.CIRCUITS["deposit"], 1, 2)
    assert "BONGTU_DEPOSIT_SO" in str(excinfo.value)
