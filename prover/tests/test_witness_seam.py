# engine._generate_witness gate — fault classification at the subprocess seam
# (CPU-only: no jax/rabbitsnark import, no circuit artifacts; the stub
# calculator stands in for circom's generate_witness.js).
#
# The seam decides the client/server fault boundary of the one production HTTP
# surface: 'Assert Failed' on stderr (circom's unsatisfiable-constraint
# signature) => WitnessGenerationError (app.py: 400, "your batch is
# unprovable"); every other failure — non-assert crash, missing .wtns, timeout,
# unlaunchable node — => WitnessInfraError (app.py: 500, "the service is
# broken"), with a detail pointing at the config knobs to check. The engine is
# per-circuit since the registry (CircuitProver over a CircuitConfig), so
# the stub is wired via dataclasses.replace of the disburse256 entry — the same
# seam a differently-pathed registry entry uses.

import dataclasses
import importlib
from pathlib import Path

import pytest

from prover_service import config
from prover_service.engine import (
    CircuitProver,
    WitnessGenerationError,
    WitnessInfraError,
)

STUB = Path(__file__).resolve().parent / "stub_generate_witness.js"


def stub_circuit(tmp_path, base: str = "disburse256") -> config.CircuitConfig:
    """The registry entry for `base`, re-pathed at the stub calculator."""
    return dataclasses.replace(
        config.CIRCUITS[base], gen_witness=STUB, wasm=tmp_path / "stub.wasm"
    )


@pytest.fixture
def run_stub(monkeypatch, tmp_path):
    """Build a CircuitProver over the stub-pathed disburse256 registry entry and
    return a runner: run_stub(mode) -> the .wtns path (monkeypatch restores the
    timeout at teardown)."""
    # Generous: a COLD node spawn on a 2-core CI runner can exceed 2s, which
    # failed the success leg there. The timeout leg overrides this locally.
    monkeypatch.setattr(config, "WITNESS_TIMEOUT", 30.0)

    prover = CircuitProver(stub_circuit(tmp_path))

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


def test_infra_hint_names_the_circuits_own_env_knobs(monkeypatch, tmp_path):
    # The hint must point at the FAILING circuit's env family, not disburse's.
    monkeypatch.setattr(config, "WITNESS_TIMEOUT", 30.0)
    prover = CircuitProver(stub_circuit(tmp_path, base="transfer10x2"))
    with pytest.raises(WitnessInfraError, match="BONGTU_TRANSFER10X2_WASM"):
        prover._generate_witness({"mode": "infra"}, tmp_path / "input.json", tmp_path / "out.wtns")


def test_zero_exit_without_wtns_is_an_infra_fault(run_stub):
    with pytest.raises(WitnessInfraError, match="wtns_exists=False"):
        run_stub("no-wtns")


def test_timeout_is_an_infra_fault(run_stub, monkeypatch):
    monkeypatch.setattr(config, "WITNESS_TIMEOUT", 2.0)
    with pytest.raises(WitnessInfraError, match="timed out"):
        run_stub("hang")


def test_infra_is_not_a_subclass_of_client_fault():
    # app.py's except order relies on the two being disjoint: an infra error
    # caught by the WitnessGenerationError handler would 400 a server fault.
    assert not issubclass(WitnessInfraError, WitnessGenerationError)
    assert not issubclass(WitnessGenerationError, WitnessInfraError)


def test_witness_paths_are_env_overridable(monkeypatch):
    # The stub seam above swaps CircuitConfig fields; this pins the layer the
    # ops contract actually promises — the env knobs — end to end via reload,
    # for both the legacy disburse256 names and the transfer10x2 family.
    monkeypatch.setenv("BONGTU_DISBURSE_GEN_WITNESS", str(STUB))
    monkeypatch.setenv("BONGTU_TRANSFER10X2_GEN_WITNESS", str(STUB))
    monkeypatch.setenv("BONGTU_WITNESS_TIMEOUT", "2")
    try:
        importlib.reload(config)
        assert config.CIRCUITS["disburse256"].gen_witness == STUB
        assert config.CIRCUITS["transfer10x2"].gen_witness == STUB
        assert config.WITNESS_TIMEOUT == 2.0
    finally:
        monkeypatch.undo()
        importlib.reload(config)
