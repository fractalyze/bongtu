# WitnessHost — the in-process witness seam: one resident CPU worker per engine.
#
# U-P5 replaced the per-request `node generate_witness.js` (WASM) subprocess
# with the rabbitsnark compiled-.so calculator: disburse256 witness-gen went
# ~7.5s -> ~1s. The calculator CANNOT run in the service process itself: a
# circuit constraint failure is a cf.assert compiled to `puts(...); abort()`,
# so one unsatisfiable client request would SIGABRT the resident ~25GB GPU
# prover. Hence this shape — a small resident WORKER process per circuit
# (witness_worker.py) that loads the .so + w2s once and computes each request
# over pipes (~1s warm, no JSON spooled to disk); on a constraint failure the
# WORKER aborts, the parent reads circom's "assertion failed at line N" off
# its stderr, raises the client-fault error, and respawns the worker.
#
# Fault classification (the 400-vs-500 boundary app.py serves):
#   WitnessGenerationError (client, 400)
#     - worker died with the assert signature on stderr (unsatisfiable input)
#     - the input JSON's keys/element-counts don't fit the circuit
#   WitnessInfraError (server, 500)
#     - worker died any other way (bad .so, SIGBUS, python traceback)
#     - worker did not answer within config.WITNESS_TIMEOUT (wedged)
#     - worker failed to boot/handshake (missing artifacts, junk handshake)
#     - worker answered with a payload length its own handshake contradicts
#
# This module is deliberately stdlib-only at import time (numpy stays inside
# engine.py's deferred imports and the worker): the CPU-only CI pytest job
# installs pydantic+pytest alone and still imports/exercises this seam.

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

from . import config
from .config import CircuitConfig

_WORKER_SCRIPT = Path(__file__).with_name("witness_worker.py")

# BN254 scalar field modulus: inputs are reduced like circom's own input
# loader would (accepts negatives / non-canonical values as field elements).
_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# One witness element on the wire = one 32-byte LE field element (the .wtns
# data-section layout the prover reads as bn254_sf).
_FIELD_ELEM_BYTES = 32

# One worker boot = dlopen the .so + parse the w2s JSON (~1-2s); generous cap
# so a cold page cache can't false-fail a boot.
_HANDSHAKE_TIMEOUT = 60.0

# How much worker stderr the parent keeps (the TAIL — circom prints
# 'assertion failed at line N' immediately before abort(), so the end is the
# diagnostic). Bounded because the worker's stderr is also its C stdout and a
# resident worker logs over its whole lifetime.
_STDERR_RING_BYTES = 64 * 1024

_ASSERT_SIGNATURE = "assertion failed"


class WitnessGenerationError(Exception):
    """The witness calculator rejected the input (unsatisfiable request).

    Client fault: the request was well-formed but violates a circuit constraint
    (bad membership witness, sums, keys) or doesn't fit the circuit's input
    shape. app.py maps this to HTTP 400.
    """


class WitnessInfraError(Exception):
    """Witness generation failed for a reason that is NOT the client's input.

    Server fault: missing/stale .so or w2s, a crashed or wedged worker — the
    compiled calculator only prints 'assertion failed at line N' when the INPUT
    is unsatisfiable, so any other death is the service's environment. app.py
    maps this to HTTP 500 so the employer app doesn't tell the user their batch
    is unprovable.
    """


def flatten_ordered(input_json: dict, order: tuple[str, ...], circuit_name: str) -> list[str]:
    """Flatten the request's input dict into the circuit's signal order.

    The compiled calculator takes inputs positionally (snarkjs witness layout:
    declaration order, public signals first) — the JSON dict's own key order is
    the pydantic schema's, so each registry entry pins its circuit's true order
    (config.CircuitConfig.input_order). Values may be nested lists of decimal
    strings/ints; everything is reduced mod p, circom-style.
    """
    got, want = set(input_json), set(order)
    if got != want:
        missing, extra = sorted(want - got), sorted(got - want)
        raise WitnessGenerationError(
            f"input JSON does not fit the {circuit_name} circuit: "
            f"missing keys {missing}, unexpected keys {extra}"
        )
    flat: list[str] = []

    def walk(v, key: str) -> None:
        if isinstance(v, (str, int)):
            try:
                flat.append(str(int(v) % _P))
            except ValueError as e:
                raise WitnessGenerationError(
                    f"input '{key}' contains a non-integer value: {v!r}"
                ) from e
        else:
            for e in v:
                walk(e, key)

    for key in order:
        walk(input_json[key], key)
    return flat


def classify_worker_death(
    circuit: CircuitConfig, returncode: int | None, stderr_text: str
) -> Exception:
    """Map a dead worker to the client/server fault boundary (pure function).

    The compiled calculator's only voluntary death is the constraint-failure
    abort, which always prints 'assertion failed at line N' first — that line
    is the whole diagnostic circom gives us, so it rides in the 400 detail.
    """
    detail = stderr_text.strip()[-2000:]
    if _ASSERT_SIGNATURE in stderr_text:
        return WitnessGenerationError(
            f"witness generation failed: the input does not satisfy the "
            f"{circuit.name} circuit ({detail or _ASSERT_SIGNATURE})"
        )
    return WitnessInfraError(
        f"witness worker for {circuit.name} died without a circuit assert "
        f"(rc={returncode}): {detail or '<no stderr>'}; {_infra_hint(circuit)}"
    )


def _infra_hint(circuit: CircuitConfig) -> str:
    return (
        f"check {circuit.env_prefix}_SO / {circuit.env_prefix}_W2S "
        "(prover_service/config.py) and the circuits/out artifacts "
        "(circuits/build/build_witness_so.sh regenerates them)"
    )


class WitnessHost:
    """Owns one resident witness worker for one registry circuit."""

    def __init__(self, circuit: CircuitConfig) -> None:
        self.circuit = circuit
        self.proc: subprocess.Popen | None = None
        self.witness_size: int = 0  # elements the worker's .so promises per compute
        self.num_inputs: int = 0  # input signals the .so takes (worker-side check)
        self._rbuf = bytearray()  # stdout carry-over (os.read can span messages)
        self._errbuf = bytearray()  # stderr ring, last _STDERR_RING_BYTES
        self._err_eof = False

    # -- worker lifecycle ---------------------------------------------------

    def _argv(self) -> list[str]:
        return [
            sys.executable,
            str(_WORKER_SCRIPT),
            str(self.circuit.so),
            str(self.circuit.w2s),
        ]

    def start(self) -> None:
        """Spawn the worker and wait for its loaded-and-ready handshake.

        EVERY failure past the spawn kills and reaps the child before raising —
        not just the two Witness*Error classes. A handshake line that is not
        JSON, or is JSON without the counts, raises out of json/dict access; a
        parent that let that propagate raw would leak the child process and its
        3 pipe fds AND leave self.proc pointing at a worker nothing is reading,
        so every later compute() would write into a dead-end and burn the full
        WITNESS_TIMEOUT while holding app.py's global prove lock.
        """
        for path, knob in ((self.circuit.so, "_SO"), (self.circuit.w2s, "_W2S")):
            if not path.exists():
                raise WitnessInfraError(
                    f"{self.circuit.name} witness artifact missing: {path} "
                    f"(set {self.circuit.env_prefix}{knob} or run "
                    "circuits/build/build_witness_so.sh)"
                )
        self.proc = subprocess.Popen(
            self._argv(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._err_eof = False
        line = b""
        try:
            line = self._read_line(_HANDSHAKE_TIMEOUT)
            hello = json.loads(line)
            if not hello.get("ready"):
                raise WitnessInfraError(f"unexpected worker handshake: {hello}")
            self.witness_size = self._handshake_count(hello, "witness_size")
            self.num_inputs = self._handshake_count(hello, "num_inputs")
        except (WitnessGenerationError, WitnessInfraError):
            self._kill()
            raise
        except Exception as e:
            self._kill()
            raise WitnessInfraError(
                f"{self.circuit.name} witness worker sent an unreadable handshake "
                f"({type(e).__name__}: {e}); line was {line[:200]!r}; "
                f"{_infra_hint(self.circuit)}"
            ) from e

    def _handshake_count(self, hello: dict, key: str) -> int:
        """Read one positive-int count out of the handshake, or fail the boot.

        The counts are load-bearing, not decoration: witness_size is what
        compute() measures the returned payload against, and num_inputs is what
        the worker checks the flattened request against. A missing/zero/junk
        count would silently disable those checks.
        """
        value = hello.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise WitnessInfraError(
                f"{self.circuit.name} witness worker handshake has a bad {key}: "
                f"{value!r} (expected a positive int); {_infra_hint(self.circuit)}"
            )
        return value

    def close(self) -> None:
        self._kill()

    def _kill(self) -> None:
        self._rbuf.clear()
        self._errbuf.clear()
        self._err_eof = False
        if self.proc is not None:
            self.proc.kill()
            self.proc.wait()
            for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
                if stream:
                    stream.close()
            self.proc = None

    # -- per request --------------------------------------------------------

    def compute(self, input_json: dict) -> bytes:
        """Compute the full witness vector (standard-form 32-byte LE elements).

        Raises WitnessGenerationError / WitnessInfraError per the module
        docstring. After a worker death the NEXT compute respawns it, so one
        bad batch never wedges the service.
        """
        values = flatten_ordered(input_json, self.circuit.input_order, self.circuit.name)
        if self.proc is None or self.proc.poll() is not None:
            self._kill()
            self.start()
        assert self.proc is not None and self.proc.stdin is not None
        try:
            self.proc.stdin.write(json.dumps({"values": values}).encode() + b"\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            raise self._death() from None

        deadline = time.monotonic() + config.WITNESS_TIMEOUT
        header = json.loads(self._read_line_until(deadline))
        if not header.get("ok"):
            raise WitnessGenerationError(
                f"witness generation failed for {self.circuit.name}: {header.get('error')}"
            )
        # The handshake's witness_size is the CONTRACT for every later answer,
        # so measure against it instead of trusting the per-request header: a
        # short vector is not a small proof, it is a wrong one (engine.py MSMs
        # it against the zkey's full-length point arrays), and returning it
        # would answer 200 with a witness the prover then reads past the end of.
        expected = self.witness_size * _FIELD_ELEM_BYTES
        nbytes = header.get("nbytes")
        if nbytes != expected:
            raise self._wrong_payload_length(nbytes, expected)
        witness = self._read_exact(nbytes, deadline)
        if len(witness) != expected:
            raise self._wrong_payload_length(len(witness), expected)
        return witness

    def _wrong_payload_length(self, got: object, expected: int) -> Exception:
        return WitnessInfraError(
            f"{self.circuit.name} witness worker answered with {got!r} payload "
            f"bytes but its handshake promised witness_size={self.witness_size} "
            f"({expected} bytes) — the worker lied or the pipe truncated; "
            f"{_infra_hint(self.circuit)}"
        )

    # -- pipe plumbing ------------------------------------------------------

    def _death(self) -> Exception:
        """The worker died mid-request: classify it, leave it for respawn.

        Kill first, THEN drain — never wait-then-read. Reading a pipe whose
        writer may still be alive is the deadlock this seam exists to avoid,
        and a worker blocked writing stderr would never reach the exit the wait
        is waiting for. Most of the diagnostic is already in the ring (_fill
        drains continuously); this only picks up what was still in the pipe.
        """
        assert self.proc is not None
        self.proc.kill()
        self.proc.wait()
        rc = self.proc.returncode
        self._drain_stderr_to_eof()
        stderr_text = self._errbuf.decode(errors="replace")
        self._kill()
        return classify_worker_death(self.circuit, rc, stderr_text)

    def _timeout(self) -> Exception:
        tail = self._errbuf.decode(errors="replace").strip()[-2000:]
        self._kill()
        return WitnessInfraError(
            f"witness worker for {self.circuit.name} did not answer within "
            f"{config.WITNESS_TIMEOUT}s (healthy compute is ~1s); worker killed; "
            f"{_infra_hint(self.circuit)}"
            + (f"; last worker stderr: {tail}" if tail else "")
        )

    def _read_line(self, timeout: float) -> bytes:
        return self._read_line_until(time.monotonic() + timeout)

    def _read_line_until(self, deadline: float) -> bytes:
        while b"\n" not in self._rbuf:
            self._fill(deadline)
        i = self._rbuf.index(b"\n") + 1
        line = bytes(self._rbuf[:i])
        del self._rbuf[:i]
        return line

    def _read_exact(self, n: int, deadline: float) -> bytes:
        while len(self._rbuf) < n:
            self._fill(deadline)
        out = bytes(self._rbuf[:n])
        del self._rbuf[:n]
        return out

    def _fill(self, deadline: float) -> None:
        """Append >=1 byte from the worker's stdout to the carry buffer, or
        raise the classified death/timeout.

        Watches stderr in the SAME select loop, because stderr is a 64KB pipe
        the worker writes freely — every log line, plus the C-level stdout
        witness_worker re-points there so cf.assert's puts() cannot corrupt the
        protocol stream. A parent that only read it after death would let the
        worker block in write() once that pipe filled: a noisy unsatisfiable
        input (a client fault, a 400) would surface as a timeout 500 holding
        app.py's global prove lock, and a chatty RESIDENT worker would wedge
        after ~64KB of accumulated logging even on the success path.

        os.read on the raw fds, never the BufferedReaders: buffered reads would
        strand bytes invisible to select() and wedge the next wait.
        """
        assert self.proc is not None
        assert self.proc.stdout is not None and self.proc.stderr is not None
        out_fd = self.proc.stdout.fileno()
        err_fd = self.proc.stderr.fileno()
        watch = [out_fd] if self._err_eof else [out_fd, err_fd]
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise self._timeout()
            ready, _, _ = select.select(watch, [], [], min(remaining, 1.0))
            if err_fd in ready and not self._drain_stderr_once(err_fd):
                watch = [out_fd]  # stderr hit EOF; selecting on it would spin
            if out_fd in ready:
                chunk = os.read(out_fd, 1 << 20)
                if chunk == b"":
                    raise self._death()  # EOF: the worker is gone
                self._rbuf += chunk
                return

    def _drain_stderr_once(self, fd: int) -> bool:
        """Read one ready chunk of worker stderr into the ring; False at EOF."""
        chunk = os.read(fd, 1 << 16)
        if chunk == b"":
            self._err_eof = True
            return False
        self._errbuf += chunk
        if len(self._errbuf) > _STDERR_RING_BYTES:
            del self._errbuf[: len(self._errbuf) - _STDERR_RING_BYTES]
        return True

    def _drain_stderr_to_eof(self, budget: float = 5.0) -> None:
        """Read a DEAD worker's remaining stderr — bounded, never blocking.

        Only ever called after the child is killed and reaped, so the pipe
        drains to EOF; the budget and the select timeout are belts against an
        inherited write end keeping it open.
        """
        if self.proc is None or self.proc.stderr is None or self._err_eof:
            return
        fd = self.proc.stderr.fileno()
        deadline = time.monotonic() + budget
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.1)
            if not ready:
                return  # writer is dead and the pipe is empty
            if not self._drain_stderr_once(fd):
                return
