# witness.WitnessHost gate — fault classification at the resident-worker seam
# (CPU-only: no jax/rabbitsnark/numpy import, no compiled .so; the stdlib stub
# worker stands in for witness_worker.py over the same pipe protocol).
#
# The seam decides the client/server fault boundary of the one production HTTP
# surface: the worker dying with circom's 'assertion failed at line N' on
# stderr (the cf.assert abort an unsatisfiable input triggers) =>
# WitnessGenerationError (app.py: 400, "your batch is unprovable"); every other
# failure — non-assert death, wedged worker, missing artifacts, failed boot —
# => WitnessInfraError (app.py: 500, "the service is broken"), with a detail
# pointing at the config knobs to check. Input-shape faults (wrong keys,
# non-integer values) are client faults too and never reach the worker.

import dataclasses
import importlib
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from prover_service import config
from prover_service import witness as witness_module
from prover_service.witness import (
    WitnessGenerationError,
    WitnessHost,
    WitnessInfraError,
    classify_worker_death,
    flatten_ordered,
)

STUB = Path(__file__).resolve().parent / "stub_witness_worker.py"
FAKE_WITNESS = b"".join(i.to_bytes(32, "little") for i in (1, 7, 8, 9))
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def stub_circuit(tmp_path, base: str = "disburse256") -> config.CircuitConfig:
    """The registry entry for `base`, re-pathed at throwaway .so/w2s files
    (start() requires them to exist; the stub worker never opens them)."""
    so, w2s = tmp_path / "stub.so", tmp_path / "stub_w2s.json"
    so.touch()
    w2s.touch()
    return dataclasses.replace(
        config.CIRCUITS[base], so=so, w2s=w2s, input_order=("a", "b")
    )


@pytest.fixture
def make_host(monkeypatch, tmp_path):
    """make_host(mode) -> a WitnessHost whose worker is the stub in `mode`."""
    monkeypatch.setattr(config, "WITNESS_TIMEOUT", 30.0)

    def make(mode: str, base: str = "disburse256", echo: Path | None = None) -> WitnessHost:
        host = WitnessHost(stub_circuit(tmp_path, base))
        argv = [sys.executable, str(STUB), mode] + ([str(echo)] if echo else [])
        monkeypatch.setattr(host, "_argv", lambda: argv)
        return host

    yield make


@pytest.fixture
def spawned_workers(monkeypatch):
    """Every worker subprocess the host starts, so a test can prove a failed
    start() left no child behind (a leaked worker holds a pid + 3 pipe fds)."""
    procs: list[subprocess.Popen] = []
    real_popen = subprocess.Popen

    def record(*args, **kwargs):
        proc = real_popen(*args, **kwargs)
        procs.append(proc)
        return proc

    monkeypatch.setattr(witness_module.subprocess, "Popen", record)
    return procs


GOOD_INPUT = {"a": ["1", "2"], "b": [["3"], ["4"]]}  # 4 values, nested like circom's


def test_success_returns_the_witness_bytes(make_host):
    host = make_host("success")
    assert host.compute(GOOD_INPUT) == FAKE_WITNESS
    host.close()


def test_inputs_are_reordered_flattened_and_reduced_mod_p(make_host, tmp_path):
    # The request dict arrives in pydantic-schema key order; the worker must
    # see the CIRCUIT's declaration order, flat, canonical field elements.
    echo = tmp_path / "echo.jsonl"
    host = make_host("success", echo=echo)
    host.compute({"b": [[str(P + 3)], [-1]], "a": ["1", 2]})  # b first, junk forms
    (req,) = [json.loads(line) for line in echo.read_text().splitlines()]
    assert req == {"values": ["1", "2", "3", str(P - 1)]}
    host.close()


def test_assert_death_is_a_client_fault_with_the_circom_line(make_host):
    with pytest.raises(WitnessGenerationError, match="assertion failed at line 118"):
        make_host("assert").compute(GOOD_INPUT)


def test_worker_respawns_after_an_assert_death(make_host, monkeypatch):
    # One unsatisfiable batch must not wedge the service: the NEXT request
    # respawns the worker and proves normally.
    host = make_host("assert")
    with pytest.raises(WitnessGenerationError):
        host.compute(GOOD_INPUT)
    monkeypatch.setattr(
        host, "_argv", lambda: [sys.executable, str(STUB), "success"]
    )
    assert host.compute(GOOD_INPUT) == FAKE_WITNESS
    host.close()


def test_nonassert_death_is_an_infra_fault(make_host):
    with pytest.raises(WitnessInfraError, match="BONGTU_DISBURSE_SO"):
        make_host("infra").compute(GOOD_INPUT)


def test_hang_is_an_infra_fault_via_timeout(make_host, monkeypatch):
    monkeypatch.setattr(config, "WITNESS_TIMEOUT", 2.0)
    host = make_host("hang")
    with pytest.raises(WitnessInfraError, match="did not answer within"):
        host.compute(GOOD_INPUT)
    assert host.proc is None  # the wedged worker was killed, not leaked


def test_boot_death_is_an_infra_fault(make_host):
    with pytest.raises(WitnessInfraError):
        make_host("boot-fail").start()


# -- the worker is not a trusted narrator -----------------------------------
#
# The worker is a separate process running a compiled artifact that can be
# stale, wrong, or dying. What it SAYS about itself (the handshake counts, the
# per-answer length) is checked, never taken on faith — a witness vector that
# is merely the wrong length is worse than one that never arrives: engine.py
# would MSM it against the zkey's full-length point arrays and answer 200 with
# a proof built off the end of a buffer.


def test_garbage_handshake_is_an_infra_fault_leaving_no_worker(make_host, spawned_workers):
    host = make_host("garbage-handshake")
    with pytest.raises(WitnessInfraError, match="unreadable handshake"):
        host.start()
    assert host.proc is None
    (child,) = spawned_workers
    # The stub sleeps for a minute after its bad line: a poll() of None here
    # would mean the raise escaped past the cleanup and leaked a live worker.
    assert child.poll() is not None
    assert all(s.closed for s in (child.stdin, child.stdout, child.stderr))


def test_handshake_without_witness_size_is_an_infra_fault_leaving_no_worker(
    make_host, spawned_workers
):
    host = make_host("handshake-no-size")
    with pytest.raises(WitnessInfraError, match="bad witness_size"):
        host.start()
    assert host.proc is None
    (child,) = spawned_workers
    assert child.poll() is not None


def test_payload_shorter_than_the_handshake_promised_is_an_infra_fault(make_host):
    # The stub advertises witness_size=4 (=128 bytes) and then answers with 64.
    host = make_host("short-payload")
    with pytest.raises(WitnessInfraError) as excinfo:
        host.compute(GOOD_INPUT)
    detail = str(excinfo.value)
    assert "64 payload bytes" in detail  # what the worker claimed
    assert "128 bytes" in detail  # what the handshake promised
    host.close()


def test_payload_truncated_mid_stream_is_an_infra_fault(make_host):
    # An HONEST 128-byte header followed by 64 bytes and EOF: the short read
    # must never surface as a successful (short) witness.
    with pytest.raises(WitnessInfraError):
        make_host("truncated-payload").compute(GOOD_INPUT)


# -- stderr backpressure -----------------------------------------------------
#
# The worker's stderr is a ~64KB pipe it writes freely — its own logging plus
# the C-level stdout witness_worker re-points there so cf.assert's puts() can't
# corrupt the protocol stream. A parent that only read it after death would let
# the worker block in write() once that pipe filled, which is not a slow
# request but a WRONG ANSWER: the client's unsatisfiable batch (400) would
# surface as a witness-timeout 500, holding app.py's global prove lock for the
# full WITNESS_TIMEOUT.


def test_noisy_worker_still_reports_its_assert_instead_of_wedging(make_host, monkeypatch):
    monkeypatch.setattr(config, "WITNESS_TIMEOUT", 12.0)
    host = make_host("assert-noisy")  # 200KB of stderr, THEN the assert line
    t0 = time.monotonic()
    with pytest.raises(WitnessGenerationError, match="assertion failed at line 118"):
        host.compute(GOOD_INPUT)
    assert time.monotonic() - t0 < 8  # the classified death, not the timeout leg


def test_chatty_worker_stays_healthy_past_the_stderr_pipe_capacity(make_host, monkeypatch):
    monkeypatch.setattr(config, "WITNESS_TIMEOUT", 15.0)
    host = make_host("chatty")  # ~8KB of stderr per request, answered normally
    for _ in range(20):  # >160KB cumulative over one RESIDENT worker
        assert host.compute(GOOD_INPUT) == FAKE_WITNESS
    assert host.proc is not None and host.proc.poll() is None  # never respawned
    # Drained, not hoarded: the parent keeps a bounded tail, not the transcript.
    assert len(host._errbuf) <= 64 * 1024
    host.close()


def test_missing_so_artifact_fails_start_naming_the_knob(tmp_path):
    circuit = dataclasses.replace(stub_circuit(tmp_path), so=tmp_path / "gone.so")
    with pytest.raises(WitnessInfraError, match="BONGTU_DISBURSE_SO"):
        WitnessHost(circuit).start()


def test_wrong_keys_are_a_client_fault_before_any_worker_runs(make_host):
    host = make_host("boot-fail")  # would explode if the worker were spawned
    with pytest.raises(WitnessGenerationError, match="missing keys \\['b'\\]"):
        host.compute({"a": ["1"], "c": ["2"]})


def test_noninteger_value_is_a_client_fault(make_host):
    host = make_host("boot-fail")
    with pytest.raises(WitnessGenerationError, match="non-integer"):
        host.compute({"a": ["1", "nope"], "b": ["3", "4"]})


# -- pure units -------------------------------------------------------------


def test_flatten_ordered_walks_nested_lists_in_circuit_order():
    order = ("y", "x")
    flat = flatten_ordered({"x": [["1", "2"], ["3"]], "y": "9"}, order, "c")
    assert flat == ["9", "1", "2", "3"]


def test_classify_death_infra_hint_names_the_circuits_own_env_knobs():
    # The hint must point at the FAILING circuit's env family, not disburse's.
    err = classify_worker_death(config.CIRCUITS["transfer10x2"], -7, "boom")
    assert isinstance(err, WitnessInfraError)
    assert "BONGTU_TRANSFER10X2_SO" in str(err)


def test_classify_death_assert_signature_wins_over_exit_code():
    err = classify_worker_death(
        config.CIRCUITS["disburse256"], -6, "assertion failed at line 42\n"
    )
    assert isinstance(err, WitnessGenerationError)
    assert "line 42" in str(err)


def test_infra_is_not_a_subclass_of_client_fault():
    # app.py's except order relies on the two being disjoint: an infra error
    # caught by the WitnessGenerationError handler would 400 a server fault.
    assert not issubclass(WitnessInfraError, WitnessGenerationError)
    assert not issubclass(WitnessGenerationError, WitnessInfraError)


def test_witness_paths_are_env_overridable(monkeypatch):
    # The stub seam above swaps CircuitConfig fields; this pins the layer the
    # ops contract actually promises — the env knobs — end to end via reload,
    # for both the disburse256 family and the transfer10x2 family.
    monkeypatch.setenv("BONGTU_DISBURSE_SO", "/x/d.so")
    monkeypatch.setenv("BONGTU_TRANSFER10X2_W2S", "/x/t_w2s.json")
    monkeypatch.setenv("BONGTU_WITNESS_TIMEOUT", "2")
    try:
        importlib.reload(config)
        assert config.CIRCUITS["disburse256"].so == Path("/x/d.so")
        assert config.CIRCUITS["transfer10x2"].w2s == Path("/x/t_w2s.json")
        assert config.WITNESS_TIMEOUT == 2.0
    finally:
        monkeypatch.undo()
        importlib.reload(config)
