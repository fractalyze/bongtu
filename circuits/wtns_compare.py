#!/usr/bin/env python3
"""Element-wise compare a snarkjs .wtns against a raw witness dump.

The byte-identity gate for the compiled witness calculator: U-P5 replaced the
`node generate_witness.js` (WASM) path with the rabbitsnark .so calculator, and
the only thing that makes that swap safe is that the two produce the SAME
witness vector — a witness that merely proves is not enough, because a wrong
one still yields a valid-looking Groth16 proof of a different statement.

    python3 wtns_compare.py <reference.wtns> <candidate.bin>

`reference.wtns` is a real snarkjs witness file (magic "wtns", v2); its data
section is the witness vector as N little-endian 32-byte field elements.
`candidate.bin` is that same data section raw — exactly the bytes
prover_service.witness.WitnessHost.compute returns. Exits 0 on identity, 1 on
the first differing element (printing its index and both values) or on a length
mismatch. prover/README.md "byte-identity gate" has the three-command recipe.

Stdlib only, on purpose: this must run against a plain python3 with no venv,
no numpy and no rabbitsnark, so a mismatch can be checked anywhere.
"""

import struct
import sys

WTNS_MAGIC = b"wtns"
HEADER_SECTION = 1
DATA_SECTION = 2


def read_sections(blob: bytes) -> dict[int, bytes]:
    """Split a circom binary-format file into {section_type: body}.

    Layout: magic[4] version:u32 num_sections:u32, then per section
    type:u32 size:u64 body[size].
    """
    if blob[:4] != WTNS_MAGIC:
        raise SystemExit(f"not a wtns file: magic is {blob[:4]!r}, expected {WTNS_MAGIC!r}")
    version, num_sections = struct.unpack_from("<II", blob, 4)
    if version != 2:
        raise SystemExit(f"unsupported wtns version {version} (expected 2)")
    sections: dict[int, bytes] = {}
    off = 12
    for _ in range(num_sections):
        sec_type, sec_len = struct.unpack_from("<IQ", blob, off)
        sections[sec_type] = blob[off + 12 : off + 12 + sec_len]
        off += 12 + sec_len
    return sections


def reference_witness(path: str) -> tuple[bytes, int]:
    """The .wtns data section plus the field-element size its header declares."""
    with open(path, "rb") as f:
        sections = read_sections(f.read())
    for needed in (HEADER_SECTION, DATA_SECTION):
        if needed not in sections:
            raise SystemExit(f"{path}: no section {needed}")
    header = sections[HEADER_SECTION]
    # header = field_size:u32 modulus[field_size] num_witness:u32
    (field_size,) = struct.unpack_from("<I", header, 0)
    (num_witness,) = struct.unpack_from("<I", header, 4 + field_size)
    data = sections[DATA_SECTION]
    if len(data) != num_witness * field_size:
        raise SystemExit(
            f"{path}: data section is {len(data)} bytes but the header declares "
            f"{num_witness} x {field_size} = {num_witness * field_size}"
        )
    return data, field_size


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        raise SystemExit(f"usage: {argv[0]} <reference.wtns> <candidate.bin>")
    reference, elem_size = reference_witness(argv[1])
    with open(argv[2], "rb") as f:
        candidate = f.read()

    n_ref = len(reference) // elem_size
    if len(candidate) != len(reference):
        print(
            f"LENGTH MISMATCH: {argv[1]} has {n_ref} elements of {elem_size} "
            f"bytes ({len(reference)} bytes), {argv[2]} has {len(candidate)} bytes"
        )
        return 1

    for i in range(n_ref):
        lo, hi = i * elem_size, (i + 1) * elem_size
        if reference[lo:hi] != candidate[lo:hi]:
            print(f"MISMATCH at witness element {i} of {n_ref}:")
            print(f"  {argv[1]}: {int.from_bytes(reference[lo:hi], 'little')}")
            print(f"  {argv[2]}: {int.from_bytes(candidate[lo:hi], 'little')}")
            return 1

    print(f"BYTE-IDENTICAL: {n_ref} witness elements ({len(reference)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
