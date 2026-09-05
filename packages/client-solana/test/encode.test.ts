// Instruction-encoding vectors: the committed conformance fixtures
// (chains/solana/conformance/*_priv_fixture.json) are the ORACLE — the exact
// bytes the program accepted in the mollusk gates — and encodeConsumerOpData
// must reproduce them from prover-shaped calldata byte-for-byte (the harness
// `wire()` composition: discriminator || proof || carried || kem cts || tail).
// A layout-table drift, a limb-order slip in proofBytes, or a carried-index
// slip all land here as a byte diff, not as an on-chain InvalidProof.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { Calldata } from "@bongtu/core/proving";
import { SOLANA_OPS, wireLenOf } from "@bongtu/core/solanaOps";
import { KEM_CT_LEN } from "@bongtu/core/solana";
import { encodeConsumerOpData, proofBytes, publicField, type ConsumerOpName } from "@bongtu/client-solana/txbuild";

const CONFORMANCE = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "chains",
  "solana",
  "conformance",
);

interface Fixture {
  proof: string;
  publicsFull: string[];
  publicsCarried: string[];
  kemCiphertexts: string[];
  stealthEphemeralPub?: string;
  stealthViewTag?: number;
}

const FIXTURE_OF: Record<ConsumerOpName, string> = {
  depositPriv: "deposit_priv_fixture.json",
  transferPriv: "transfer_priv_fixture.json",
  transfer10x2Priv: "transfer10x2_priv_fixture.json",
  withdrawPriv: "withdraw_priv_fixture.json",
};

const loadFixture = (op: ConsumerOpName): Fixture =>
  JSON.parse(readFileSync(join(CONFORMANCE, FIXTURE_OF[op]), "utf8")) as Fixture;

const hexBytes = (hex: string): Uint8Array => {
  const h = hex.replace(/^0x/, "");
  return Uint8Array.from({ length: h.length / 2 }, (_, i) => parseInt(h.slice(2 * i, 2 * i + 2), 16));
};

/** The fixture's 256-byte proof split back into prover-calldata limb form —
 *  the inverse of fixture_lib.ts proofHex, so a round trip through proofBytes
 *  is exactly the committed byte string. */
const calldataOf = (fx: Fixture): Calldata => {
  const h = fx.proof.replace(/^0x/, "");
  assert.equal(h.length, 512, "fixture proof must be 256 bytes");
  const limb = (i: number): string => "0x" + h.slice(64 * i, 64 * (i + 1));
  return {
    a: [limb(0), limb(1)],
    b: [
      [limb(2), limb(3)],
      [limb(4), limb(5)],
    ],
    c: [limb(6), limb(7)],
    pub: fx.publicsFull,
  };
};

const concatBytes = (parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  parts.reduce((off, p) => {
    out.set(p, off);
    return off + p.length;
  }, 0);
  return out;
};

for (const op of Object.keys(FIXTURE_OF) as ConsumerOpName[]) {
  test(`${op}: encoded instruction data is byte-identical to the conformance fixture wire`, () => {
    const fx = loadFixture(op);
    const layout = SOLANA_OPS[op];
    const tail =
      layout.stealthTailLen === 0
        ? new Uint8Array(0)
        : concatBytes([hexBytes(fx.stealthEphemeralPub as string), Uint8Array.of(fx.stealthViewTag as number)]);
    const got = encodeConsumerOpData(op, calldataOf(fx), fx.kemCiphertexts, tail);

    const want = concatBytes([
      Uint8Array.of(layout.discriminator),
      hexBytes(fx.proof),
      ...fx.publicsCarried.map(hexBytes),
      ...fx.kemCiphertexts.map(hexBytes),
      tail,
    ]);
    assert.equal(got.length, wireLenOf(layout), "wire length equals the layout table's");
    assert.deepEqual(Buffer.from(got).toString("hex"), Buffer.from(want).toString("hex"));
  });
}

test("proofBytes reproduces the fixture proof exactly (EVM limb order untouched)", () => {
  const fx = loadFixture("transferPriv");
  assert.deepEqual(proofBytes(calldataOf(fx)), hexBytes(fx.proof));
});

test("publicField reads named fields off the FULL calldata vector via the layout table", () => {
  const fx = loadFixture("transferPriv");
  const cd = calldataOf(fx);
  const nfs = publicField("transferPriv", cd, "nullifiers");
  assert.equal(nfs.length, 2);
  assert.deepEqual(
    nfs.map((v) => v),
    SOLANA_OPS.transferPriv.fields.nullifiers.map((i) => BigInt(fx.publicsFull[i])),
  );
  assert.throws(() => publicField("transferPriv", cd, "noSuchField"), /no public field/);
});

test("the belts: kem ct count, kem ct length, stealth tail length, public count", () => {
  const fx = loadFixture("transferPriv");
  const cd = calldataOf(fx);
  assert.throws(() => encodeConsumerOpData("transferPriv", cd, [fx.kemCiphertexts[0]]), /carries 2 kem/);
  assert.throws(
    () => encodeConsumerOpData("transferPriv", cd, [fx.kemCiphertexts[0], "0x" + "ab".repeat(KEM_CT_LEN - 1)]),
    /must be 1088 bytes/,
  );
  assert.throws(
    () => encodeConsumerOpData("transferPriv", cd, fx.kemCiphertexts, Uint8Array.of(1)),
    /stealth tail/,
  );
  const short = { ...cd, pub: cd.pub.slice(1) };
  assert.throws(() => encodeConsumerOpData("transferPriv", short, fx.kemCiphertexts), /expected 20 public/);
});
