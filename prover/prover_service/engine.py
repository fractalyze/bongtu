# Disburse256Prover — the rabbitsnark GPU proving engine, held resident.
#
# Lifecycle (the measured-cost contract this design follows):
#   initialize(), ONCE at boot (~2.5min total, then ~25GB GPU resident):
#     parse_zkey(1.24GB)            ~23s
#     zkey_to_terms -> coefficients  ~3s   (CACHED — compile_circom discards them)
#     compile_circom -> CompiledProver ~2min (reusable across proofs)
#     one warm-up prove              ~4s   (JAX JIT; after it, proves are ~0.5s)
#   prove(input), per request (~seconds warm):
#     node generate_witness.js (circom wasm, subprocess) -> .wtns
#     parse_wtns -> witness (np bn254_sf; NEVER the int-converting .witnesses
#       property — slice _witnesses for the publics instead)
#     compute_abc(witness as mont view) -> Az, Bz
#     compiled.prove -> Groth16Proof -> snarkjs-compatible calldata
#
# The compiled state pins ~25GB of the 32GB GPU (the PJRT plugin ignores
# XLA_PYTHON_CLIENT_PREALLOCATE), so there is exactly ONE engine per GPU and the
# service serializes proves with a lock (app.py). All rabbitsnark/jax imports are
# deferred into methods so CPU-only unit tests never touch the GPU stack.

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path

from . import config
from .calldata import to_solidity_calldata
from .schema import Calldata, DisburseInput


class WitnessGenerationError(Exception):
    """The circom witness calculator rejected the input (unsatisfiable request).

    Client fault: the request was well-formed but violates a circuit constraint
    (bad membership witness, sums, keys). app.py maps this to HTTP 400.
    """


class WitnessInfraError(Exception):
    """Witness generation failed for a reason that is NOT the client's input.

    Server fault: missing/stale wasm or generate_witness.js, a broken node
    binary, a wedged subprocess (timeout) — the circom calculator only reaches
    its 'Assert Failed' message when the INPUT is unsatisfiable, so anything
    else is the service's environment. app.py maps this to HTTP 500 so the
    employer app doesn't tell the user their batch is unprovable.
    """


class Disburse256Prover:
    """One resident, compiled disburse256 prover (exactly one per GPU)."""

    def __init__(self) -> None:
        self.compiled = None  # rabbitsnark CompiledProver
        self.coefficients = None  # np coefficient table (compile_circom discards it)
        self.num_public: int = 0
        self.boot_seconds: dict[str, float] = {}

    # -- boot ---------------------------------------------------------------

    def initialize(self) -> None:
        """Parse + compile the zkey and run one warm-up prove. Blocking, ~2.5min."""
        from rabbitsnark.circom.zkey import parse_zkey
        from rabbitsnark.circom.zkey_to_terms import zkey_to_terms
        from rabbitsnark.groth16 import compile_circom

        t0 = time.monotonic()
        zkey = parse_zkey(str(config.DISBURSE_ZKEY))
        self.boot_seconds["parse_zkey"] = round(time.monotonic() - t0, 2)

        t0 = time.monotonic()
        _terms, self.coefficients = zkey_to_terms(zkey)
        self.boot_seconds["zkey_to_terms"] = round(time.monotonic() - t0, 2)

        t0 = time.monotonic()
        self.compiled = compile_circom(zkey)
        self.boot_seconds["compile_circom"] = round(time.monotonic() - t0, 2)
        self.num_public = self.compiled.config.num_public
        del zkey  # the compiled prover + coefficients carry everything we need

        t0 = time.monotonic()
        warmup_input = json.loads(config.WARMUP_INPUT.read_text())
        self.prove(warmup_input)
        self.boot_seconds["warmup_prove"] = round(time.monotonic() - t0, 2)

    # -- per proof ----------------------------------------------------------

    def prove(self, input_json: dict | DisburseInput) -> Calldata:
        """Witness-gen the circuit input, then GPU-prove it to solidity calldata."""
        if self.compiled is None:
            raise RuntimeError("Disburse256Prover.initialize() has not completed")
        if isinstance(input_json, DisburseInput):
            input_json = input_json.model_dump()

        with tempfile.TemporaryDirectory(prefix="bongtu-prove-") as scratch:
            wtns_path = Path(scratch) / "disburse.wtns"
            self._generate_witness(input_json, Path(scratch) / "input.json", wtns_path)
            proof_json, publics = self._prove_wtns(wtns_path)
        return to_solidity_calldata(proof_json, publics)

    def _generate_witness(self, input_json: dict, input_path: Path, wtns_path: Path) -> None:
        """Run the circom witness calculator (node subprocess, CPU).

        Classifies failures at this seam, where the evidence is: circom's
        calculator prints 'Assert Failed' on stderr iff a circuit constraint is
        unsatisfied by the input => WitnessGenerationError (client, 400).
        Everything else — unlaunchable node, timeout, a crash that never
        produced the .wtns — is WitnessInfraError (service, 500).
        """
        input_path.write_text(json.dumps(input_json))
        infra_hint = (
            "check BONGTU_DISBURSE_WASM / BONGTU_DISBURSE_GEN_WITNESS / BONGTU_NODE_BIN "
            "(prover_service/config.py) and the circuits/out artifacts"
        )
        try:
            res = subprocess.run(
                [
                    config.NODE_BIN,
                    str(config.DISBURSE_GEN_WITNESS),
                    str(config.DISBURSE_WASM),
                    str(input_path),
                    str(wtns_path),
                ],
                capture_output=True,
                text=True,
                timeout=config.WITNESS_TIMEOUT,
            )
        except subprocess.TimeoutExpired as e:
            raise WitnessInfraError(
                f"witness generation timed out after {config.WITNESS_TIMEOUT}s "
                f"(healthy disburse256 witness-gen is ~5s); {infra_hint}"
            ) from e
        except OSError as e:
            raise WitnessInfraError(
                f"could not launch the witness calculator ({e}); {infra_hint}"
            ) from e
        if res.returncode != 0 or not wtns_path.exists():
            detail = (res.stderr or res.stdout or "").strip()[-2000:]
            if "Assert Failed" in (res.stderr or ""):
                raise WitnessGenerationError(
                    f"witness generation failed (rc={res.returncode}): {detail}"
                )
            raise WitnessInfraError(
                f"witness calculator failed without a circuit assert "
                f"(rc={res.returncode}, wtns_exists={wtns_path.exists()}): "
                f"{detail or '<no output>'}; {infra_hint}"
            )

    def _prove_wtns(self, wtns_path: Path) -> tuple[dict, list[str]]:
        """rabbitsnark in-process prove of a .wtns file (the rabbitsnark cli flow)."""
        import numpy as np
        from zk_dtypes import bn254_sf_mont

        from rabbitsnark.circom.wtns import parse_wtns
        from rabbitsnark.r1cs_solver import compute_abc

        wtns = parse_wtns(str(wtns_path))
        # Standard-form np array; the mont view feeds compute_abc. The publics are
        # sliced from the raw array — the .witnesses property would int-convert all
        # ~5.5M elements.
        z_std = wtns.data._witnesses
        witness_mont = z_std.view(np.dtype(bn254_sf_mont))
        publics = [str(int(x)) for x in z_std[1 : self.num_public + 1]]

        az_mont, bz_mont = compute_abc(
            witness_mont,
            self.compiled.terms,
            self.coefficients,
            self.compiled.domain_size,
            self.compiled.domain_size,
        )
        proof, publics = self.compiled.prove(
            z_std,
            az_mont,
            bz_mont,
            publics,
            no_zk=False,
            deterministic=config.DETERMINISTIC,
        )
        return proof.to_json(), publics
