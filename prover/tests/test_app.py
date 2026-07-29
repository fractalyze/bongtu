# app.py gate — Origin allowlist + circuit routing over stub engines (CPU-only:
# no GPU, no rabbitsnark import — engines are replaced with stubs and the init
# thread never runs because TestClient is used without entering its lifespan).
#
# Needs fastapi+httpx (prover/.venv has them; CI's prover-pytest job installs
# only pydantic+pytest, so this whole file skips there — the origin DECISION
# matrix itself is CI-covered as a pure function in tests/test_registry.py).

import base64
import hashlib
import json
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from prover_service import app as app_module  # noqa: E402
from prover_service import config  # noqa: E402
from prover_service.witness import WitnessGenerationError  # noqa: E402
from prover_service.schema import Calldata  # noqa: E402
from test_schema import minimal_disburse_input  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
ALLOWED = "https://payroll.fractalyze.io"
WORD = "0x" + "0" * 64


class StubEngine:
    """Stands in for a warm CircuitProver: canned calldata, no GPU."""

    def __init__(self, name: str):
        self.circuit = config.CIRCUITS[name]
        self.num_public = self.circuit.num_public
        self.boot_seconds = {"stub": 0.0}
        self.proved_inputs: list[dict] = []

    def prove(self, input_json: dict) -> Calldata:
        self.proved_inputs.append(input_json)
        return Calldata(
            a=[WORD, WORD],
            b=[[WORD, WORD], [WORD, WORD]],
            c=[WORD, WORD],
            pub=[WORD] * self.num_public,
        )


@pytest.fixture
def client(monkeypatch):
    """A ready service with EVERY registry circuit stubbed in."""
    monkeypatch.setattr(
        app_module,
        "engines",
        {name: StubEngine(name) for name in ("disburse256", "transfer10x2", "deposit")},
    )
    monkeypatch.setitem(app_module.state, "status", "ready")
    # The anti-guessing pause is real-time sleep — zeroed so the 401 matrix
    # doesn't cost 0.3s per case (its presence is an app.py code fact).
    monkeypatch.setattr(config, "AUTH_FAILURE_DELAY", 0.0)
    # TestClient outside a `with` never runs the lifespan -> no init thread.
    return TestClient(app_module.app)


def disburse_body() -> dict:
    return {"circuit": "disburse", "input": minimal_disburse_input(), "backend": "gpu"}


def transfer10x2_body() -> dict:
    fixture = REPO_ROOT / "circuits" / "fixtures" / "inputs" / "transfer10x2.json"
    return {"circuit": "transfer10x2", "input": json.loads(fixture.read_text())}


def deposit_body() -> dict:
    fixture = REPO_ROOT / "circuits" / "fixtures" / "inputs" / "deposit.json"
    return {"circuit": "deposit", "input": json.loads(fixture.read_text())}


# -- origin gate (G3 matrix) ------------------------------------------------


def test_allowlist_set_missing_origin_is_403(client, monkeypatch):
    monkeypatch.setattr(config, "ALLOWED_ORIGINS", [ALLOWED])
    r = client.post("/prove", json=disburse_body())
    assert r.status_code == 403
    assert "missing Origin" in r.json()["detail"]


def test_allowlist_set_evil_origin_is_403(client, monkeypatch):
    monkeypatch.setattr(config, "ALLOWED_ORIGINS", [ALLOWED])
    r = client.post("/prove", json=disburse_body(), headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert "https://evil.example" in r.json()["detail"]


def test_allowlist_set_allowed_origin_proves(client, monkeypatch):
    monkeypatch.setattr(config, "ALLOWED_ORIGINS", [ALLOWED])
    r = client.post("/prove", json=disburse_body(), headers={"Origin": ALLOWED})
    assert r.status_code == 200
    assert len(r.json()["pub"]) == 11


def test_allowlist_set_health_stays_open_without_origin(client, monkeypatch):
    monkeypatch.setattr(config, "ALLOWED_ORIGINS", [ALLOWED])
    assert client.get("/healthz").status_code == 200
    assert client.get("/ready").status_code == 200  # state stubbed ready


def test_allowlist_unset_allows_everything(client, monkeypatch):
    monkeypatch.setattr(config, "ALLOWED_ORIGINS", None)
    assert client.post("/prove", json=disburse_body()).status_code == 200
    r = client.post("/prove", json=disburse_body(), headers={"Origin": "https://evil.example"})
    assert r.status_code == 200


def test_403_fires_before_the_body_is_parsed(client, monkeypatch):
    # The gate is middleware: a drive-by with garbage json is refused as 403,
    # not answered with a schema 422 that leaks endpoint shape.
    monkeypatch.setattr(config, "ALLOWED_ORIGINS", [ALLOWED])
    r = client.post("/prove", json={"circuit": "nonsense"})
    assert r.status_code == 403


# -- auth gate (PROVER_AUTH_SHA256, U-P6) -----------------------------------
#
# Throwaway pair minted here — no real credential (or its hash) in the repo.

AUTH_ID, AUTH_PW = "http-matrix-id", "http-matrix-pw"
AUTH_DIGEST = hashlib.sha256(f"{AUTH_ID}:{AUTH_PW}".encode()).hexdigest()


def basic(id_: str, pw: str) -> dict:
    return {"Authorization": "Basic " + base64.b64encode(f"{id_}:{pw}".encode()).decode()}


@pytest.fixture
def authed(monkeypatch):
    monkeypatch.setattr(config, "AUTH_SHA256", AUTH_DIGEST)


def test_auth_set_prove_without_credentials_is_401(client, authed):
    r = client.post("/prove", json=disburse_body())
    assert r.status_code == 401
    assert "missing Authorization" in r.json()["detail"]
    assert "www-authenticate" not in r.headers  # never the browser's native dialog


def test_auth_set_prove_with_wrong_credentials_is_401(client, authed):
    r = client.post("/prove", json=disburse_body(), headers=basic(AUTH_ID, "wrong"))
    assert r.status_code == 401
    assert "wrong ID or password" in r.json()["detail"]


def test_auth_set_prove_with_right_credentials_proves(client, authed):
    r = client.post("/prove", json=disburse_body(), headers=basic(AUTH_ID, AUTH_PW))
    assert r.status_code == 200
    assert len(r.json()["pub"]) == 11


def test_auth_check_answers_the_sign_in_probe(client, authed):
    assert client.get("/auth/check", headers=basic(AUTH_ID, AUTH_PW)).json() == {"ok": True}
    assert client.get("/auth/check", headers=basic(AUTH_ID, "wrong")).status_code == 401
    assert client.get("/auth/check").status_code == 401


def test_auth_unset_keeps_everything_open(client, monkeypatch):
    monkeypatch.setattr(config, "AUTH_SHA256", None)
    assert client.get("/auth/check").status_code == 200  # dev login accepts anything
    assert client.post("/prove", json=disburse_body()).status_code == 200


def test_auth_set_health_and_ready_stay_open(client, authed):
    assert client.get("/healthz").status_code == 200
    assert client.get("/ready").status_code == 200  # state stubbed ready


def test_auth_composes_with_the_origin_gate(client, authed, monkeypatch):
    # BOTH gates must pass on /prove: right credentials + wrong Origin -> 403,
    # right Origin + wrong credentials -> 401 (auth first — a drive-by with no
    # credential learns nothing about the origin list), both right -> 200.
    monkeypatch.setattr(config, "ALLOWED_ORIGINS", [ALLOWED])
    creds = basic(AUTH_ID, AUTH_PW)
    r = client.post("/prove", json=disburse_body(), headers={**creds, "Origin": "https://evil.example"})
    assert r.status_code == 403
    r = client.post("/prove", json=disburse_body(), headers={**basic(AUTH_ID, "wrong"), "Origin": ALLOWED})
    assert r.status_code == 401
    r = client.post("/prove", json=disburse_body(), headers={**creds, "Origin": ALLOWED})
    assert r.status_code == 200


def test_auth_401_fires_before_the_body_is_parsed(client, authed):
    r = client.post("/prove", json={"circuit": "nonsense"})
    assert r.status_code == 401


def test_auth_401_carries_cors_headers_for_a_browser_origin(client, authed):
    # CORS wraps the gates (middleware order): without ACAO on the 401, a
    # cross-origin login page could not READ the status and would report
    # "unreachable" instead of "wrong ID or password".
    r = client.get("/auth/check", headers={"Origin": ALLOWED})
    assert r.status_code == 401
    assert "access-control-allow-origin" in r.headers


# -- circuit routing --------------------------------------------------------


def test_transfer10x2_routes_to_its_engine(client):
    r = client.post("/prove", json=transfer10x2_body())
    assert r.status_code == 200
    assert len(r.json()["pub"]) == 68
    assert app_module.engines["transfer10x2"].proved_inputs  # that engine, not disburse's
    assert not app_module.engines["disburse256"].proved_inputs


def test_deposit_routes_to_its_engine_with_its_pub_len(client):
    # The payroll funding path (U-P3): the committed deposit fixture proves on the
    # deposit engine, whose calldata carries the vkey's 19 public signals.
    r = client.post("/prove", json=deposit_body())
    assert r.status_code == 200
    assert len(r.json()["pub"]) == 19
    assert app_module.engines["deposit"].proved_inputs
    assert not app_module.engines["disburse256"].proved_inputs


def test_deposit_off_this_instance_is_400_naming_bongtu_circuits(client, monkeypatch):
    monkeypatch.setattr(app_module, "engines", {"disburse256": StubEngine("disburse256")})
    monkeypatch.setattr(config, "ENABLED_CIRCUITS", ["disburse256"])
    r = client.post("/prove", json=deposit_body())
    assert r.status_code == 400
    assert "BONGTU_CIRCUITS=disburse256" in r.json()["detail"]


def test_wellformed_but_unregistered_circuit_is_400_naming_bongtu_circuits(
    client, monkeypatch
):
    monkeypatch.setattr(
        app_module, "engines", {"disburse256": StubEngine("disburse256")}
    )
    monkeypatch.setattr(config, "ENABLED_CIRCUITS", ["disburse256"])
    r = client.post("/prove", json=transfer10x2_body())
    assert r.status_code == 400
    assert "BONGTU_CIRCUITS=disburse256" in r.json()["detail"]


def test_cpu_side_circuit_is_400(client):
    body = {
        "circuit": "transfer",
        "input": minimal_disburse_input(
            nullifiers=["1", "0"], inputCommitments=["1", "2"], inputValues=["50", "0"],
            inputSalts=["1", "2"], pathElements=[["0"] * 32] * 2, leafIndices=["0", "0"],
            enabled=["1", "0"],
        ),
    }
    r = client.post("/prove", json=body)
    assert r.status_code == 400
    assert "CPU-side" in r.json()["detail"]


def test_unknown_circuit_tag_is_422(client):
    r = client.post("/prove", json={"circuit": "mint", "input": minimal_disburse_input()})
    assert r.status_code == 422


def test_cpu_backend_is_400(client):
    r = client.post("/prove", json={**disburse_body(), "backend": "cpu"})
    assert r.status_code == 400
    assert "GPU-only" in r.json()["detail"]


def test_unsatisfiable_input_is_400(client, monkeypatch):
    def boom(_input):
        raise WitnessGenerationError("Assert Failed in template X")

    monkeypatch.setattr(app_module.engines["disburse256"], "prove", boom)
    r = client.post("/prove", json=disburse_body())
    assert r.status_code == 400
    assert "Assert Failed" in r.json()["detail"]


def test_ready_reports_wire_tags_and_per_circuit_num_public(client):
    body = client.get("/ready").json()
    assert body["circuits"] == ["disburse", "transfer10x2", "deposit"]
    assert body["num_public"] == {"disburse": 11, "transfer10x2": 68, "deposit": 19}
    # Every circuit-keyed /ready field speaks WIRE tags, boot_seconds included.
    assert set(body["boot_seconds"]) == {"disburse", "transfer10x2", "deposit"}
