# CircuitProver — the rabbitsnark GPU proving engine, held resident.
#
# One CircuitProver per registry entry (config.CIRCUITS); app.py boots one for
# every BONGTU_CIRCUITS name. Lifecycle (the measured-cost contract this design
# follows, numbers for disburse256, the big one):
#   initialize(), ONCE at boot (~2.5min total, then ~25GB GPU resident):
#     witness host spawn+load        ~2s   (the resident CPU witness worker)
#     parse_zkey(1.24GB)            ~23s
#     zkey_to_terms -> coefficients  ~3s   (CACHED — compile_circom discards them)
#     compile_circom -> CompiledProver ~2min (reusable across proofs)
#     one warm-up prove              ~4s   (JAX JIT; after it, proves are ~0.5s)
#   prove(input), per request (~1.5s warm for disburse256):
#     WitnessHost.compute (in-process compiled .so, resident CPU worker) ~1s
#       — U-P5: replaced the ~7.5s node/WASM subprocess; witness bytes travel
#       over pipes, no input JSON spooled to disk
#     compute_abc(witness as mont view) -> Az, Bz
#     compiled.prove -> Groth16Proof -> snarkjs-compatible calldata
#
# The witness seam lives in witness.py (WitnessHost + the 400-vs-500 fault
# split); it is a resident worker PROCESS, not a plain in-process call, because
# a constraint failure aborts the calling process (rationale there).
#
# The compiled disburse256 state pins ~25GB of the 32GB GPU (the PJRT plugin
# ignores XLA_PYTHON_CLIENT_PREALLOCATE), so there is exactly ONE service
# process per GPU and app.py serializes ALL proves — across every engine — with
# one lock. All rabbitsnark/jax imports are deferred into methods so CPU-only
# unit tests never touch the GPU stack.

from __future__ import annotations

import json
import time

from . import config
from .calldata import to_solidity_calldata
from .config import CircuitConfig
from .schema import Calldata
from .witness import WitnessHost


def check_witness_size(circuit: CircuitConfig, witness_size: int, num_vars: int) -> None:
    """Boot gate: the .so's witness length must EQUAL the zkey's (pure).

    The two halves of a circuit's artifact set are built by different pipelines
    from the same .circom — `circuits/build/build_witness_so.sh` emits the .so + w2s,
    the snarkjs setup emits the zkey — so a stale half is the expected drift,
    and it is silent: the worker happily computes a witness of its own length.

    The comparison is exact, not a bound. `num_vars` is Groth16's m, the length
    of the zkey's points_a1/pb1/pb2 arrays that `CompiledProver.prove` MSMs the
    witness against, so a SHORT witness reads past the end of a point array and
    a LONG one silently drops its tail variables — either way a proof that is
    wrong rather than absent, which is the failure mode this service must never
    ship. Fail the boot instead, naming the two artifacts to rebuild together.
    """
    if witness_size != num_vars:
        raise RuntimeError(
            f"{circuit.name}: the witness calculator at {circuit.so} produces "
            f"{witness_size} witness elements but the zkey at {circuit.zkey} "
            f"expects {num_vars} (Groth16 m) — the .so/w2s pair and the zkey "
            f"were built from different circuit revisions; rebuild both "
            f"(circuits/build/build_witness_so.sh + the zkey setup) or fix "
            f"{circuit.env_prefix}_SO / {circuit.env_prefix}_ZKEY"
        )


class CircuitProver:
    """One resident, compiled prover for one registry circuit."""

    def __init__(self, circuit: CircuitConfig) -> None:
        self.circuit = circuit
        self.witness = WitnessHost(circuit)
        self.compiled = None  # rabbitsnark CompiledProver
        self.coefficients = None  # np coefficient table (compile_circom discards it)
        self.num_public: int = 0
        self.boot_seconds: dict[str, float] = {}

    # -- boot ---------------------------------------------------------------

    def initialize(self) -> None:
        """Spawn the witness worker, parse + compile the zkey, warm-up prove. Blocking."""
        from rabbitsnark.circom.zkey import parse_zkey
        from rabbitsnark.circom.zkey_to_terms import zkey_to_terms
        from rabbitsnark.groth16 import compile_circom

        t0 = time.monotonic()
        self.witness.start()  # first: fails fast on missing .so/w2s, no GPU cost yet
        self.boot_seconds["witness_host"] = round(time.monotonic() - t0, 2)

        t0 = time.monotonic()
        zkey = parse_zkey(str(self.circuit.zkey))
        self.boot_seconds["parse_zkey"] = round(time.monotonic() - t0, 2)

        # Gate the .so/zkey pair here, before the ~2min compile: both artifacts
        # are now parsed and this is the last cheap moment to catch a stale one.
        check_witness_size(
            self.circuit, self.witness.witness_size, zkey.header_groth.num_vars
        )

        t0 = time.monotonic()
        _terms, self.coefficients = zkey_to_terms(zkey)
        self.boot_seconds["zkey_to_terms"] = round(time.monotonic() - t0, 2)

        t0 = time.monotonic()
        self.compiled = compile_circom(zkey)
        self.boot_seconds["compile_circom"] = round(time.monotonic() - t0, 2)
        self.num_public = self.compiled.config.num_public
        if self.num_public != self.circuit.num_public:
            raise RuntimeError(
                f"{self.circuit.name}: the zkey at {self.circuit.zkey} exposes "
                f"{self.num_public} public signals but the registry pins "
                f"{self.circuit.num_public} — wrong zkey wired "
                f"(check {self.circuit.env_prefix}_ZKEY)?"
            )
        del zkey  # the compiled prover + coefficients carry everything we need

        t0 = time.monotonic()
        warmup_input = json.loads(self.circuit.warmup_input.read_text())
        self.prove(warmup_input)
        self.boot_seconds["warmup_prove"] = round(time.monotonic() - t0, 2)

    # -- per proof ----------------------------------------------------------

    def prove(self, input_json: dict) -> Calldata:
        """Witness-gen the circuit input, then GPU-prove it to solidity calldata."""
        if self.compiled is None:
            raise RuntimeError(f"CircuitProver({self.circuit.name}).initialize() has not completed")
        witness_bytes = self.witness.compute(input_json)
        proof_json, publics = self._prove_witness(witness_bytes)
        return to_solidity_calldata(proof_json, publics, expected_pub_len=self.circuit.num_public)

    def _prove_witness(self, witness_bytes: bytes) -> tuple[dict, list[str]]:
        """rabbitsnark in-process prove of a full witness vector (standard-form
        32-byte LE elements, the exact .wtns data section layout)."""
        import numpy as np
        from zk_dtypes import bn254_sf, bn254_sf_mont

        from rabbitsnark.r1cs_solver import compute_abc

        # bytearray copy: frombuffer over bytes would be read-only, and the
        # prover mutates views of z_std.
        z_std = np.frombuffer(bytearray(witness_bytes), dtype=np.dtype(bn254_sf))
        witness_mont = z_std.view(np.dtype(bn254_sf_mont))
        # The publics are sliced from the raw array — an int-conversion of all
        # ~2.8M elements (e.g. a .witnesses-style property) would dominate the
        # request.
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
