# Env-resolved configuration for the bongtu prover service.
#
# Everything filesystem/network is overridable by env; defaults point at the
# repo's circuits/out artifacts (prover/ is a top-level sibling of circuits/).
# CUDA_VISIBLE_DEVICES defaults to GPU 0 — the repo GPU contract (CLAUDE.md) —
# and is pinned HERE, before any jax/rabbitsnark import can bind a device.

from __future__ import annotations

import os
import shutil
from pathlib import Path

os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")

# prover/prover_service/config.py -> prover/ -> repo root
REPO_ROOT = Path(__file__).resolve().parents[2]

CIRCUITS_OUT = Path(os.environ.get("BONGTU_CIRCUITS_OUT", REPO_ROOT / "circuits" / "out"))

# The 1.24GB disburse256 Groth16 proving key (gitignored artifact; the GPU regen
# recipe lives in CLAUDE.md "GPU regen recipe" + docs/milestone-m1.md — the CPU
# pipeline in docs/toolchain.md builds the wasm/witness pair) and the circom
# witness-calculator pair.
DISBURSE_ZKEY = Path(os.environ.get("BONGTU_DISBURSE_ZKEY", CIRCUITS_OUT / "disburse256.zkey"))
DISBURSE_WASM = Path(
    os.environ.get("BONGTU_DISBURSE_WASM", CIRCUITS_OUT / "disburse256_js" / "disburse256.wasm")
)
DISBURSE_GEN_WITNESS = Path(
    os.environ.get(
        "BONGTU_DISBURSE_GEN_WITNESS", CIRCUITS_OUT / "disburse256_js" / "generate_witness.js"
    )
)

# The committed satisfying input used for the boot warm-up proof
# (circuits/gen_disburse256_input.ts writes it).
WARMUP_INPUT = Path(
    os.environ.get("BONGTU_WARMUP_INPUT", REPO_ROOT / "circuits" / "inputs" / "disburse256.json")
)

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
