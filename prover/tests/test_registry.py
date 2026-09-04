# config.py gate — the circuit registry + BONGTU_CIRCUITS / PROVER_ALLOWED_ORIGINS
# env parsing (CPU-only, no fastapi: the origin decision is a pure function in
# config so this file runs under CI's pydantic+pytest-only install; the
# HTTP-level 403/routing behavior over the same function is tests/test_app.py,
# which importorskips fastapi).

import base64
import hashlib
import importlib
import json
from pathlib import Path

import pytest

from prover_service import config

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def reload_config(monkeypatch):
    """setenv-then-reload runner; always reloads a clean config at teardown."""

    def run(**env: str):
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        return importlib.reload(config)

    yield run
    monkeypatch.undo()
    importlib.reload(config)


# -- registry ---------------------------------------------------------------


def test_registry_has_every_circuit_with_pinned_wire_tags_and_pub_counts():
    assert set(config.CIRCUITS) == {"disburse256", "transfer10x2", "deposit", "disbursePriv256"}
    d, t, p, dp = (
        config.CIRCUITS["disburse256"],
        config.CIRCUITS["transfer10x2"],
        config.CIRCUITS["deposit"],
        config.CIRCUITS["disbursePriv256"],
    )
    assert (d.wire_tag, d.num_public) == ("disburse", 11)
    assert (t.wire_tag, t.num_public) == ("transfer10x2", 68)
    assert (p.wire_tag, p.num_public) == ("deposit", 19)
    assert (dp.wire_tag, dp.num_public) == ("disbursePriv", 8)
    assert config.WIRE_TAG_TO_CIRCUIT == {
        "disburse": "disburse256",
        "transfer10x2": "transfer10x2",
        "deposit": "deposit",
        "disbursePriv": "disbursePriv256",
    }


@pytest.mark.parametrize("name", ["disburse256", "transfer10x2", "deposit", "disbursePriv256"])
def test_registry_num_public_matches_the_built_vkey_when_present(name):
    # circuits/out is a gitignored build product — absent on CI runners, present
    # on any box that can actually serve the circuit. Where it exists, the
    # registry pin must equal the ground truth (vkey nPublic == len(public)).
    vkey = config.CIRCUITS_OUT / f"{name}.vkey.json"
    public = config.CIRCUITS_OUT / f"{name}.public.json"
    if not (vkey.exists() and public.exists()):
        pytest.skip(f"{name} artifacts not built under {config.CIRCUITS_OUT}")
    n = config.CIRCUITS[name].num_public
    assert json.loads(vkey.read_text())["nPublic"] == n
    assert len(json.loads(public.read_text())) == n


def test_default_is_the_enterprise_trio_not_the_registry():
    # Registering a new circuit must not change what an unconfigured box serves:
    # consumer circuits are opt-in (their artifacts are absent on enterprise boxes).
    assert config.ENABLED_CIRCUITS == ["disburse256", "transfer10x2", "deposit"]
    assert "disbursePriv256" in config.CIRCUITS
    assert "disbursePriv256" not in config.ENABLED_CIRCUITS


def test_bongtu_circuits_selects_a_subset(reload_config):
    cfg = reload_config(BONGTU_CIRCUITS="disburse256")
    assert cfg.ENABLED_CIRCUITS == ["disburse256"]


def test_bongtu_circuits_tolerates_spaces_and_dups_and_keeps_order(reload_config):
    cfg = reload_config(BONGTU_CIRCUITS=" transfer10x2 , disburse256 ,transfer10x2 ")
    assert cfg.ENABLED_CIRCUITS == ["transfer10x2", "disburse256"]


@pytest.mark.parametrize("raw", ["disburse", "disburse256,transfer10"])
def test_bongtu_circuits_rejects_unknown_names(reload_config, raw):
    # wire tags are NOT registry names — 'disburse' must fail loudly, naming
    # the knob and the valid names, instead of silently booting nothing.
    with pytest.raises(ValueError, match="BONGTU_CIRCUITS"):
        reload_config(BONGTU_CIRCUITS=raw)


def test_bongtu_circuits_rejects_an_empty_list(reload_config):
    with pytest.raises(ValueError, match="empty"):
        reload_config(BONGTU_CIRCUITS=" , ")


def test_per_circuit_env_overrides_land_on_their_circuit(reload_config, tmp_path):
    cfg = reload_config(
        BONGTU_DISBURSE_ZKEY=str(tmp_path / "d.zkey"),
        BONGTU_TRANSFER10X2_ZKEY=str(tmp_path / "t.zkey"),
        BONGTU_WARMUP_INPUT=str(tmp_path / "warm.json"),  # legacy disburse name
        BONGTU_TRANSFER10X2_WARMUP_INPUT=str(tmp_path / "t_warm.json"),
    )
    assert cfg.CIRCUITS["disburse256"].zkey == tmp_path / "d.zkey"
    assert cfg.CIRCUITS["disburse256"].warmup_input == tmp_path / "warm.json"
    assert cfg.CIRCUITS["transfer10x2"].zkey == tmp_path / "t.zkey"
    assert cfg.CIRCUITS["transfer10x2"].warmup_input == tmp_path / "t_warm.json"
    # the override families are disjoint: the transfer10x2 zkey stayed put above
    # and vice versa
    assert cfg.CIRCUITS["transfer10x2"].so.name == "libtransfer10x2.so"


@pytest.mark.parametrize("name", ["transfer10x2", "deposit"])
def test_default_warmup_input_is_the_committed_fixture(name):
    assert config.CIRCUITS[name].warmup_input == (
        REPO_ROOT / "circuits" / "fixtures" / "inputs" / f"{name}.json"
    )
    assert config.CIRCUITS[name].warmup_input.exists()


# -- PROVER_ALLOWED_ORIGINS -------------------------------------------------


def test_unset_or_empty_allowlist_means_allow_all(reload_config):
    assert config.ALLOWED_ORIGINS is None  # unset in the test env
    assert reload_config(PROVER_ALLOWED_ORIGINS="  ").ALLOWED_ORIGINS is None


def test_allowlist_parses_commas_and_strips_trailing_slashes(reload_config):
    cfg = reload_config(
        PROVER_ALLOWED_ORIGINS="https://payroll.fractalyze.io/, http://localhost:5173"
    )
    assert cfg.ALLOWED_ORIGINS == ["https://payroll.fractalyze.io", "http://localhost:5173"]


ALLOWED = "https://payroll.fractalyze.io"


def test_origin_rejection_matrix_when_set(monkeypatch):
    monkeypatch.setattr(config, "ALLOWED_ORIGINS", [ALLOWED])
    assert config.origin_rejection(ALLOWED) is None
    assert config.origin_rejection(ALLOWED + "/") is None  # trailing-slash tolerant
    assert "not in PROVER_ALLOWED_ORIGINS" in config.origin_rejection("https://evil.example")
    assert "missing Origin" in config.origin_rejection(None)
    # exact compare: scheme, port and case all matter
    assert config.origin_rejection("http://payroll.fractalyze.io") is not None
    assert config.origin_rejection("https://payroll.fractalyze.io:8443") is not None
    assert config.origin_rejection("https://PAYROLL.fractalyze.io") is not None


def test_origin_rejection_matrix_when_unset(monkeypatch):
    monkeypatch.setattr(config, "ALLOWED_ORIGINS", None)
    assert config.origin_rejection(None) is None
    assert config.origin_rejection("https://evil.example") is None


# -- PROVER_AUTH_SHA256 -----------------------------------------------------
#
# Throwaway credentials minted HERE — no real credential (or its hash) may
# ever appear in the repo; the live pair lives only in the service's env.


def _basic(creds: str) -> str:
    return "Basic " + base64.b64encode(creds.encode()).decode()


TEST_CREDS = "matrix-id:matrix-only-pw"
TEST_DIGEST = hashlib.sha256(TEST_CREDS.encode()).hexdigest()


def test_unset_or_empty_auth_means_open(reload_config):
    assert config.AUTH_SHA256 is None  # unset in the test env
    assert reload_config(PROVER_AUTH_SHA256="  ").AUTH_SHA256 is None


def test_auth_env_normalizes_to_lowercase_hex(reload_config):
    assert reload_config(PROVER_AUTH_SHA256=TEST_DIGEST.upper()).AUTH_SHA256 == TEST_DIGEST


def test_auth_env_rejects_a_malformed_digest(reload_config):
    # A typo'd knob must kill the boot, not silently lock everyone out.
    for bad in ("deadbeef", TEST_DIGEST + "00", TEST_DIGEST[:-1] + "g"):
        with pytest.raises(ValueError, match="PROVER_AUTH_SHA256"):
            reload_config(PROVER_AUTH_SHA256=bad)


def test_auth_rejection_matrix_when_set(monkeypatch):
    monkeypatch.setattr(config, "AUTH_SHA256", TEST_DIGEST)
    assert config.auth_rejection(_basic(TEST_CREDS)) is None
    assert config.auth_rejection("basic " + _basic(TEST_CREDS)[6:]) is None  # scheme is case-insensitive
    assert "missing Authorization" in config.auth_rejection(None)
    assert "wrong ID or password" in config.auth_rejection(_basic("matrix-id:nope"))
    assert "wrong ID or password" in config.auth_rejection(_basic("other:matrix-only-pw"))
    # id:password is ONE hashed string — a colon shuffle is just a wrong credential
    assert "wrong ID or password" in config.auth_rejection(_basic("matrix-id:matrix:only-pw"))
    assert "HTTP Basic" in config.auth_rejection("Bearer sometoken")
    assert "HTTP Basic" in config.auth_rejection("Basic ")
    assert "not base64" in config.auth_rejection("Basic %%%not-base64%%%")


def test_auth_rejection_matrix_when_unset(monkeypatch):
    monkeypatch.setattr(config, "AUTH_SHA256", None)
    assert config.auth_rejection(None) is None
    assert config.auth_rejection("Bearer junk") is None
    assert config.auth_rejection(_basic("anything:at-all")) is None
