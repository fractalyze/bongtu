# engine._generate_witness gate — fault classification at the subprocess seam
# (CPU-only: no jax/rabbitsnark import, no circuit artifacts; the stub
# calculator stands in for circom's generate_witness.js).
#
# The seam decides the client/server fault boundary of the one production HTTP
# surface: 'Assert Failed' on stderr (circom's unsatisfiable-constraint
# signature) => WitnessGenerationError (app.py: 400, "your batch is
# unprovable"); every other failure — non-assert crash, missing .wtns, timeout,
# unlaunchable node — => WitnessInfraError (app.py: 500, "the service is
# broken"), with a detail pointing at the config knobs to check.

import importlib
from pathlib import Path

import pytest

from prover_service import config
from prover_service.engine import (
    Disburse256Prover,
    WitnessGenerationError,
    WitnessInfraError,
)

STUB = Path(__file__).resolve().parent / "stub_generate_witness.js"


@pytest.fixture
def run_stub(monkeypatch, tmp_path):
    """Point the engine's env-overridable config paths at the stub calculator
    and return a runner: run_stub(mode) -> the .wtns path (monkeypatch restores
    the real config attributes at teardown)."""
    monkeypatch.setattr(config, "DISBURSE_GEN_WITNESS", STUB)
    monkeypatch.setattr(config, "DISBURSE_WASM", tmp_path / "stub.wasm")
    monkeypatch.setattr(config, "WITNESS_TIMEOUT", 2.0)

    prover = Disburse256Prover()

    def run(mode: str) -> Path:
        wtns = tmp_path / "out.wtns"
        prover._generate_witness({"mode": mode}, tmp_path / "input.json", wtns)
        return wtns

    return run


def test_success_writes_the_wtns(run_stub):
    assert run_stub("success").exists()


def test_assert_failed_is_a_client_fault(run_stub):
    with pytest.raises(WitnessGenerationError, match="Assert Failed"):
        run_stub("assert")


def test_nonassert_crash_is_an_infra_fault(run_stub):
    with pytest.raises(WitnessInfraError, match="BONGTU_DISBURSE_WASM"):
        run_stub("infra")


def test_zero_exit_without_wtns_is_an_infra_fault(run_stub):
    with pytest.raises(WitnessInfraError, match="wtns_exists=False"):
        run_stub("no-wtns")


def test_timeout_is_an_infra_fault(run_stub):
    with pytest.raises(WitnessInfraError, match="timed out"):
        run_stub("hang")


def test_infra_is_not_a_subclass_of_client_fault():
    # app.py's except order relies on the two being disjoint: an infra error
    # caught by the WitnessGenerationError handler would 400 a server fault.
    assert not issubclass(WitnessInfraError, WitnessGenerationError)
    assert not issubclass(WitnessGenerationError, WitnessInfraError)


def test_witness_paths_are_env_overridable(monkeypatch):
    # The stub seam above patches config attributes; this pins the layer the
    # ops contract actually promises — the env knobs — end to end via reload.
    monkeypatch.setenv("BONGTU_DISBURSE_GEN_WITNESS", str(STUB))
    monkeypatch.setenv("BONGTU_WITNESS_TIMEOUT", "2")
    try:
        importlib.reload(config)
        assert config.DISBURSE_GEN_WITNESS == STUB
        assert config.WITNESS_TIMEOUT == 2.0
    finally:
        monkeypatch.undo()
        importlib.reload(config)
