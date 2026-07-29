# Env-resolved configuration for the bongtu prover service.
#
# Everything filesystem/network is overridable by env; defaults point at the
# repo's circuits/out artifacts (prover/ is a top-level sibling of circuits/).
# CUDA_VISIBLE_DEVICES defaults to GPU 0 — the repo GPU contract (CLAUDE.md) —
# and is pinned HERE, before any jax/rabbitsnark import can bind a device.
#
# The service is a CIRCUIT REGISTRY: CIRCUITS holds one entry per GPU-served
# circuit (zkey + witness-calculator pair + warm-up input + the public-signal
# count the zkey must expose), and BONGTU_CIRCUITS (comma list, default: all)
# selects which entries boot resident. Each registered circuit gets its own
# CircuitProver (engine.py); /prove routes by the request's wire tag (app.py).

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")

# prover/prover_service/config.py -> prover/ -> repo root
REPO_ROOT = Path(__file__).resolve().parents[2]

CIRCUITS_OUT = Path(os.environ.get("BONGTU_CIRCUITS_OUT", REPO_ROOT / "circuits" / "out"))
INPUTS_DIR = REPO_ROOT / "circuits" / "inputs"


@dataclass(frozen=True)
class CircuitConfig:
    """One registry entry: everything a resident CircuitProver needs.

    `name` is the artifact stem under circuits/out (disburse256, transfer10x2);
    `wire_tag` is the ProvingRequest `circuit` tag the TS apps send (proving.ts
    names the 1x256 circuit "disburse" on the wire, its artifacts disburse256).
    `num_public` is the public-signal count the zkey MUST expose — boot fails
    fast on a mismatch (wrong zkey wired), and calldata.py rejects a proof whose
    pub length disagrees with it.
    """

    name: str
    wire_tag: str
    env_prefix: str  # the BONGTU_* env-override family, e.g. BONGTU_DISBURSE
    zkey: Path
    wasm: Path
    gen_witness: Path
    warmup_input: Path
    num_public: int


def _path(env_key: str, default: Path) -> Path:
    return Path(os.environ.get(env_key, default))


# The registry of every circuit this service knows how to hold resident.
#
# num_public values are pinned from the snarkjs vkey `nPublic` of the committed
# builds (circuits/out/<name>.vkey.json == len(<name>.public.json)):
#   disburse256  11  (also the committed contracts/test/fixtures/disburse256.public.json)
#   transfer10x2 68
# tests/test_registry.py cross-checks these against circuits/out when the
# artifacts exist locally.
#
# disburse256 keeps its pre-registry env names (BONGTU_DISBURSE_ZKEY /
# BONGTU_DISBURSE_WASM / BONGTU_DISBURSE_GEN_WITNESS / BONGTU_WARMUP_INPUT)
# byte-compatible; transfer10x2 follows the same scheme under
# BONGTU_TRANSFER10X2_* (warm-up override: BONGTU_TRANSFER10X2_WARMUP_INPUT).
CIRCUITS: dict[str, CircuitConfig] = {
    "disburse256": CircuitConfig(
        name="disburse256",
        wire_tag="disburse",
        env_prefix="BONGTU_DISBURSE",
        # The 1.24GB disburse256 Groth16 proving key (gitignored artifact; the
        # GPU regen recipe lives in CLAUDE.md "GPU regen recipe" +
        # .dev/milestone-m1.md — the CPU pipeline in docs/toolchain.md builds
        # the wasm/witness pair).
        zkey=_path("BONGTU_DISBURSE_ZKEY", CIRCUITS_OUT / "disburse256.zkey"),
        wasm=_path("BONGTU_DISBURSE_WASM", CIRCUITS_OUT / "disburse256_js" / "disburse256.wasm"),
        gen_witness=_path(
            "BONGTU_DISBURSE_GEN_WITNESS", CIRCUITS_OUT / "disburse256_js" / "generate_witness.js"
        ),
        # The committed satisfying input used for the boot warm-up proof
        # (circuits/gen_disburse256_input.ts writes it).
        warmup_input=_path("BONGTU_WARMUP_INPUT", INPUTS_DIR / "disburse256.json"),
        num_public=11,
    ),
    "transfer10x2": CircuitConfig(
        name="transfer10x2",
        wire_tag="transfer10x2",
        env_prefix="BONGTU_TRANSFER10X2",
        # 95MB zkey — the 10-in/2-out merge/pay leg the employer console proves
        # here (212,386 constraints; CPU-provable in a wallet, GPU-warm for the
        # payroll console's merge chains).
        zkey=_path("BONGTU_TRANSFER10X2_ZKEY", CIRCUITS_OUT / "transfer10x2.zkey"),
        wasm=_path(
            "BONGTU_TRANSFER10X2_WASM", CIRCUITS_OUT / "transfer10x2_js" / "transfer10x2.wasm"
        ),
        gen_witness=_path(
            "BONGTU_TRANSFER10X2_GEN_WITNESS",
            CIRCUITS_OUT / "transfer10x2_js" / "generate_witness.js",
        ),
        warmup_input=_path("BONGTU_TRANSFER10X2_WARMUP_INPUT", INPUTS_DIR / "transfer10x2.json"),
        num_public=68,
    ),
}

# wire tag -> registry name, for /prove routing (every tag maps to exactly one
# registered circuit; tags absent here — deposit/transfer/withdraw — are the
# CPU-side circuits this service never serves).
WIRE_TAG_TO_CIRCUIT: dict[str, str] = {c.wire_tag: c.name for c in CIRCUITS.values()}


def _parse_enabled_circuits(raw: str) -> list[str]:
    names = [s.strip() for s in raw.split(",") if s.strip()]
    unknown = sorted(set(names) - set(CIRCUITS))
    if unknown:
        raise ValueError(
            f"BONGTU_CIRCUITS names unknown circuit(s) {unknown}; "
            f"known circuits: {sorted(CIRCUITS)}"
        )
    if not names:
        raise ValueError(f"BONGTU_CIRCUITS is empty; pick from {sorted(CIRCUITS)}")
    # de-dup, first occurrence wins boot order (one GPU — engines boot serially)
    return list(dict.fromkeys(names))


# Which registry entries boot resident (comma list; default: every circuit).
ENABLED_CIRCUITS: list[str] = _parse_enabled_circuits(
    os.environ.get("BONGTU_CIRCUITS", ",".join(CIRCUITS))
)


def _parse_allowed_origins(raw: str | None) -> list[str] | None:
    """PROVER_ALLOWED_ORIGINS -> normalized origin list, or None = allow all.

    Unset/empty keeps the pre-allowlist behavior (local dev, loopback bind).
    Origins compare exactly (scheme+host+port), trailing-slash tolerant.
    """
    if raw is None or not raw.strip():
        return None
    return [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]


ALLOWED_ORIGINS: list[str] | None = _parse_allowed_origins(os.environ.get("PROVER_ALLOWED_ORIGINS"))


def origin_rejection(origin: str | None) -> str | None:
    """The one-line 403 reason for a /prove Origin header, or None = allowed.

    Reads ALLOWED_ORIGINS at call time (tests monkeypatch it). This is a
    drive-by-browser gate, not authentication: a non-browser client can forge
    any Origin (docs/security-model.md).
    """
    allowed = ALLOWED_ORIGINS
    if allowed is None:
        return None
    if origin is None:
        return "missing Origin header and PROVER_ALLOWED_ORIGINS is set on this service"
    if origin.rstrip("/") not in allowed:
        return f"Origin {origin!r} is not in PROVER_ALLOWED_ORIGINS"
    return None


# node runs the circom witness calculator; node is not on the default PATH on the
# dev box (CLAUDE.md), so fall back to the known nvm install.
NODE_BIN = os.environ.get(
    "BONGTU_NODE_BIN",
    shutil.which("node") or str(Path.home() / ".nvm/versions/node/v22.17.1/bin/node"),
)

# Wall-clock cap on one witness-calculator subprocess (a healthy disburse256
# witness-gen is ~5s; 300s means "wedged", an infra fault). Overridable so the
# CPU-only seam tests can exercise the timeout leg in seconds.
WITNESS_TIMEOUT = float(os.environ.get("BONGTU_WITNESS_TIMEOUT", "300"))

# The bind address/port (PROVER_HOST/PROVER_PORT, loopback:8700 default) are
# owned by run.sh, which passes them to uvicorn directly — not duplicated here.

# PROVER_DETERMINISTIC=1 -> fixed r,s blinding for byte-stable proofs (tests only;
# production proofs must stay randomized).
DETERMINISTIC = os.environ.get("PROVER_DETERMINISTIC", "0") == "1"
