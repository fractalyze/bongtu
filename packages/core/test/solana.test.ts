// Equality gate for the Solana rail facts (src/chain/solana.ts) and the
// per-op layout table (src/chain/solanaOps.ts) — the network.test.ts pattern
// applied to the Solana rail.
//
// The Rust program (chains/solana/program/src) is the hand-written second
// implementation and stays the OWNER of every mirrored fact; this suite
// parses the Rust sources AS TEXT (node:fs is test-only — the src modules
// stay browser-safe) and holds the TypeScript mirrors to them
// field-for-field, so a transcription slip fails in milliseconds instead of
// at ledger decode or mollusk time. Coverage asserts (`pinAll`) require the
// pin-row set to EQUAL the parsed constant set, so a NEW mirrored Rust
// constant fails this suite until it gets a row (and usually a mirror).
//
// The layout table is additionally reconciled against the committed
// conformance fixtures (chains/solana/conformance/*_fixture.json): the
// fixtures were generated FROM the table (vectorsByteIdentical gate), but
// they are committed artifacts the mollusk gates replay, so pinning
// publicsFull/publicsCarried/enabled against them here catches a table edit
// that silently diverges from what the program was gated on.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { B, H } from "@bongtu/core/network";
import {
  ARBITER_EPOCH_GENESIS,
  BATCH_B_CONSUMER,
  BATCH_B_ENTERPRISE,
  BATCH_OFF_DISCLOSURE_HASH,
  BATCH_OFF_EPOCH,
  BATCH_OFF_KEM_BINDING,
  BATCH_OFF_START,
  CONFIG_OFF_ARBITER_X,
  CONFIG_OFF_ARBITER_Y,
  CONFIG_OFF_KEM_PK_HASH,
  INITIALIZE_DISCRIMINATOR,
  INITIALIZE_PAYLOAD_LEN,
  CONFIG_OFF_BATCH_B,
  CONFIG_OFF_FLAGS,
  CONFIG_OFF_MINT,
  CONFIG_OFF_VAULT,
  DISBURSE_BATCH_LEN,
  EVENT_DISCRIMINATOR,
  KEM_CT_LEN,
  LOG_B_CONSUMER,
  LOG_B_ENTERPRISE,
  POOL_CONFIG_LEN,
  PROGRAM_ID_BASE58,
  PROOF_LEN,
  SEED_CONFIG,
  SEED_DISBURSE_BATCH,
  SEED_EVENT_AUTHORITY,
  SEED_KNOWN_ROOT,
  SEED_NULLIFIER,
  SEED_TREE,
  SEED_VAULT_AUTHORITY,
  TAG_DISBURSE_BATCH,
  TAG_POOL_CONFIG,
  TAG_TREE_STATE,
  TREE_HEIGHT,
  TREE_OFF_CONFIG,
  TREE_OFF_FRONTIER,
  TREE_OFF_NEXT,
  TREE_OFF_ROOT,
  TREE_STATE_LEN,
  base58ToBytes,
  base58ToHex,
  bytesToBase58,
} from "@bongtu/core/solana";
import {
  SOLANA_OPS,
  familyFlagOf,
  familyTagOf,
  wireLenOf,
  type SolanaOpName,
} from "@bongtu/core/solanaOps";

// packages/core/test -> repo root (tests run under tsx/node, not the browser).
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROGRAM_SRC = join(REPO_ROOT, "chains", "solana", "program", "src");
const CONFORMANCE = join(REPO_ROOT, "chains", "solana", "conformance");

const rust = (name: string): string => readFileSync(join(PROGRAM_SRC, name), "utf8");

/** Parse every numeric `pub const NAME: <int type> = <literal or 1 << k>;`
 *  in a Rust source. Expression-valued consts (e.g. PAYLOAD_LEN, a sum of
 *  named consts) deliberately do NOT match — their factors are each pinned
 *  individually, so pinning the sum again would be a second transcription. */
function numericConsts(src: string): Map<string, number> {
  const out = new Map<string, number>();
  for (const m of src.matchAll(
    /pub const (\w+): (?:u8|u16|u32|u64|usize) = (0x[0-9a-fA-F_]+|\d+)(?:\s*<<\s*(\d+))?;/g,
  )) {
    const base = Number(m[2].replace(/_/g, ""));
    out.set(m[1], m[3] === undefined ? base : base << Number(m[3]));
  }
  return out;
}

/** Parse every `pub const NAME: &[u8] = b"...";` seed string. */
function seedConsts(src: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of src.matchAll(/pub const (\w+): &\[u8\] = b"([^"]*)";/g)) out.set(m[1], m[2]);
  return out;
}

/** The coverage assert: `rows` (Rust const name -> the TS mirror's value)
 *  must name EXACTLY the parsed constant set — a new mirrored Rust constant
 *  fails here until it gets a pin row — and every row must be value-equal. */
function pinAll(
  parsed: Map<string, number | string>,
  rows: Record<string, number | string>,
  file: string,
): void {
  assert.deepEqual(
    [...parsed.keys()].sort(),
    Object.keys(rows).sort(),
    `${file}: every mirrored constant needs a pin row (and every row a constant)`,
  );
  for (const [name, moduleValue] of Object.entries(rows)) {
    assert.equal(moduleValue, parsed.get(name), `solana module disagrees with ${file} "${name}"`);
  }
}

const OP_FILES: Record<SolanaOpName, string> = {
  depositPriv: "deposit_priv.rs",
  transferPriv: "transfer_priv.rs",
  transfer10x2Priv: "transfer10x2_priv.rs",
  withdrawPriv: "withdraw_priv.rs",
  deposit: "deposit.rs",
  withdraw: "withdraw.rs",
  disburse256: "disburse256.rs",
  transfer: "transfer.rs",
  transfer10x2: "transfer10x2.rs",
};

const FIXTURE_FILES: Record<SolanaOpName, string> = {
  depositPriv: "deposit_priv_fixture.json",
  transferPriv: "transfer_priv_fixture.json",
  transfer10x2Priv: "transfer10x2_priv_fixture.json",
  withdrawPriv: "withdraw_priv_fixture.json",
  deposit: "deposit_fixture.json",
  withdraw: "withdraw_fixture.json",
  disburse256: "disburse256_fixture.json",
  transfer: "transfer_fixture.json",
  transfer10x2: "transfer10x2_fixture.json",
};

test("program id: declare_id!, harness PROGRAM_ID_STR and the module agree; base58 round-trips", () => {
  const declared = /declare_id!\("([1-9A-HJ-NP-Za-km-z]+)"\)/.exec(rust("lib.rs"));
  assert.ok(declared, "lib.rs declare_id! not found");
  assert.equal(PROGRAM_ID_BASE58, declared[1], "module program id != lib.rs declare_id!");
  const harness = readFileSync(
    join(REPO_ROOT, "chains", "solana", "harness", "src", "lib.rs"),
    "utf8",
  );
  const pinned = /pub const PROGRAM_ID_STR: &str = "([^"]+)";/.exec(harness);
  assert.ok(pinned, "harness PROGRAM_ID_STR not found");
  assert.equal(PROGRAM_ID_BASE58, pinned[1], "module program id != harness PROGRAM_ID_STR");

  // The codec that turns the operator-facing base58 id into the indexer's
  // internal 0x-hex byte convention (moved out of apps/indexer rpc.ts).
  const bytes = base58ToBytes(PROGRAM_ID_BASE58);
  assert.equal(bytes.length, 32, "program id is a 32-byte pubkey");
  assert.equal(bytesToBase58(bytes), PROGRAM_ID_BASE58);
  assert.equal(
    base58ToHex(PROGRAM_ID_BASE58),
    "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(""),
  );
  // Leading '1's are leading zero bytes — the round trip must keep them.
  assert.deepEqual([...base58ToBytes("11z").subarray(0, 2)], [0, 0]);
  assert.equal(bytesToBase58(base58ToBytes("11z")), "11z");
  assert.throws(() => base58ToBytes("0"), /invalid character/);
});

test("state.rs constants equal the module field-for-field (with coverage)", () => {
  const src = rust("state.rs");
  const rows: Record<string, number | string> = {
    // account-type tags
    TAG_POOL_CONFIG,
    TAG_TREE_STATE,
    TAG_DISBURSE_BATCH,
    // family-enable flags: DERIVED from the layout table's discriminators
    // (flag = 1 << (familyTag - 1)), never retyped.
    FAMILY_DEPOSIT_PRIV: familyFlagOf(SOLANA_OPS.depositPriv),
    FAMILY_TRANSFER_PRIV: familyFlagOf(SOLANA_OPS.transferPriv),
    FAMILY_TRANSFER10X2_PRIV: familyFlagOf(SOLANA_OPS.transfer10x2Priv),
    FAMILY_WITHDRAW_PRIV: familyFlagOf(SOLANA_OPS.withdrawPriv),
    FAMILY_DEPOSIT: familyFlagOf(SOLANA_OPS.deposit),
    FAMILY_WITHDRAW: familyFlagOf(SOLANA_OPS.withdraw),
    FAMILY_DISBURSE256: familyFlagOf(SOLANA_OPS.disburse256),
    FAMILY_TRANSFER: familyFlagOf(SOLANA_OPS.transfer),
    FAMILY_TRANSFER10X2: familyFlagOf(SOLANA_OPS.transfer10x2),
    ARBITER_EPOCH_GENESIS,
    // PDA seeds
    SEED_NULLIFIER,
    SEED_KNOWN_ROOT,
    SEED_EVENT_AUTHORITY,
    SEED_DISBURSE_BATCH,
    SEED_VAULT_AUTHORITY,
    SEED_CONFIG,
    SEED_TREE,
    // account layouts
    POOL_CONFIG_LEN,
    CONFIG_OFF_FLAGS,
    CONFIG_OFF_MINT,
    CONFIG_OFF_VAULT,
    CONFIG_OFF_BATCH_B,
    CONFIG_OFF_ARBITER_X,
    CONFIG_OFF_ARBITER_Y,
    CONFIG_OFF_KEM_PK_HASH,
    DISBURSE_BATCH_LEN,
    BATCH_OFF_START,
    BATCH_OFF_DISCLOSURE_HASH,
    BATCH_OFF_KEM_BINDING,
    BATCH_OFF_EPOCH,
    TREE_STATE_LEN,
    TREE_OFF_CONFIG,
    TREE_OFF_NEXT,
    TREE_OFF_ROOT,
    TREE_OFF_FRONTIER,
  };
  const parsed = new Map<string, number | string>([...numericConsts(src), ...seedConsts(src)]);
  pinAll(parsed, rows, "state.rs");

  // Internal layout consistency: lengths equal last-offset + field width.
  assert.equal(TREE_STATE_LEN, TREE_OFF_FRONTIER + 32 * TREE_HEIGHT);
  assert.equal(POOL_CONFIG_LEN, CONFIG_OFF_ARBITER_Y + 32 + 32);
  assert.equal(DISBURSE_BATCH_LEN, BATCH_OFF_EPOCH + 8);
});

test("event.rs: EVENT_DISCRIMINATOR + family tags equal discriminator - 1 (with coverage)", () => {
  const rows: Record<string, number> = {
    EVENT_DISCRIMINATOR,
    FAMILY_TAG_DEPOSIT_PRIV: familyTagOf(SOLANA_OPS.depositPriv),
    FAMILY_TAG_TRANSFER_PRIV: familyTagOf(SOLANA_OPS.transferPriv),
    FAMILY_TAG_TRANSFER10X2_PRIV: familyTagOf(SOLANA_OPS.transfer10x2Priv),
    FAMILY_TAG_WITHDRAW_PRIV: familyTagOf(SOLANA_OPS.withdrawPriv),
    FAMILY_TAG_DEPOSIT: familyTagOf(SOLANA_OPS.deposit),
    FAMILY_TAG_WITHDRAW: familyTagOf(SOLANA_OPS.withdraw),
    FAMILY_TAG_DISBURSE256: familyTagOf(SOLANA_OPS.disburse256),
    FAMILY_TAG_TRANSFER: familyTagOf(SOLANA_OPS.transfer),
    FAMILY_TAG_TRANSFER10X2: familyTagOf(SOLANA_OPS.transfer10x2),
  };
  pinAll(numericConsts(rust("event.rs")), rows, "event.rs");
  // The two derivations are one truth: flag = 1 << (tag - 1), tag = disc - 1.
  for (const l of Object.values(SOLANA_OPS)) {
    assert.equal(familyTagOf(l), l.discriminator - 1);
    assert.equal(familyFlagOf(l), 1 << (familyTagOf(l) - 1));
  }
});

test("initialize.rs wire constants equal the module (with coverage)", () => {
  // The deploy instruction's wire facts — not an op row (no publics), so it
  // pins here instead of the SOLANA_OPS table.
  pinAll(
    numericConsts(rust("initialize.rs")),
    { DISCRIMINATOR: INITIALIZE_DISCRIMINATOR, PAYLOAD_LEN: INITIALIZE_PAYLOAD_LEN },
    "initialize.rs",
  );
});

test("groth16.rs PROOF_LEN + generated zeros.rs TREE_HEIGHT pin the module; one protocol H/B", () => {
  assert.equal(PROOF_LEN, numericConsts(rust("groth16.rs")).get("PROOF_LEN"));
  // zeros.rs is GENERATED by gen_vectors.ts from the same TS ImtTree, so this
  // pins the committed artifact, not an independent second implementation —
  // the independent anchors are the Rust op consts and the TREE_HEIGHT == H
  // assert above.
  assert.equal(TREE_HEIGHT, numericConsts(rust(join("generated", "zeros.rs"))).get("TREE_HEIGHT"));
  // network.ts stays the protocol-wide owner: TREE_HEIGHT references H, and
  // the enterprise batch arity equals the EVM live pool's B because the
  // disburse256 circuit is shared verbatim across rails (SOLR §4.1).
  assert.equal(TREE_HEIGHT, H);
  assert.equal(BATCH_B_ENTERPRISE, B);
  assert.equal(1 << LOG_B_CONSUMER, BATCH_B_CONSUMER);
  assert.equal(1 << LOG_B_ENTERPRISE, BATCH_B_ENTERPRISE);
});

test("per-op layout rows equal every numeric constant of the 9 op modules (with coverage)", () => {
  // The table must cover exactly the op modules that exist: a 10th op file
  // (or a removed one) fails here before anything ever decodes it. An op
  // module carries a public vector (N_PUBLIC); `initialize` declares a
  // DISCRIMINATOR but no publics/wire row — it is the deploy instruction,
  // not an op, and gets its own pin test below.
  const opFilesOnDisk = readdirSync(PROGRAM_SRC)
    .filter((f) => f.endsWith(".rs") && /pub const DISCRIMINATOR/.test(rust(f)))
    .filter((f) => /pub const N_PUBLIC/.test(rust(f)))
    .sort();
  assert.deepEqual(
    opFilesOnDisk,
    Object.values(OP_FILES).sort(),
    "SOLANA_OPS must cover exactly the op modules declaring a DISCRIMINATOR",
  );
  for (const [name, file] of Object.entries(OP_FILES) as [SolanaOpName, string][]) {
    const l = SOLANA_OPS[name];
    const rows: Record<string, number> = {
      DISCRIMINATOR: l.discriminator,
      N_PUBLIC: l.nPublic,
      CARRIED_PUBLICS: l.carried.length,
      KEM_CT_LEN, // each op module re-declares the FIPS 203 ct size
      KEM_CT_COUNT: l.kemCtCount,
    };
    if (l.stealthTailLen !== 0) rows.STEALTH_TAIL_LEN = l.stealthTailLen;
    if (l.enabled !== null && l.enabled.arity === 10) rows.ARITY = l.enabled.arity;
    if (name === "disburse256") rows.CIRCUIT_LOG_B = LOG_B_ENTERPRISE;
    pinAll(numericConsts(rust(file)), rows, file);
    // Rust PAYLOAD_LEN is an expression of the pinned factors; the table's
    // derived wire length is the same sum plus the discriminator byte.
    assert.equal(
      wireLenOf(l),
      1 + PROOF_LEN + 32 * l.carried.length + l.kemCtCount * KEM_CT_LEN + l.stealthTailLen,
    );
  }
});

interface OpFixture {
  proof: string;
  publicsFull: string[];
  publicsCarried: string[];
  kemCiphertexts: string[];
  nullifiers?: string[];
  nullifier?: string;
  outputCommitments?: string[];
  changeCommitment?: string;
  amount?: string;
  spentRoot?: string;
  disclosureHash?: string;
  subtreeRoot?: string;
  kemBinding?: string;
  batchEpoch?: number;
}

test("layout table reconciles with every committed conformance fixture field-for-field", () => {
  for (const [name, file] of Object.entries(FIXTURE_FILES) as [SolanaOpName, string][]) {
    const l = SOLANA_OPS[name];
    const fx = JSON.parse(readFileSync(join(CONFORMANCE, file), "utf8")) as OpFixture;
    const at = (i: number): string => fx.publicsFull[i];

    // The field map must partition the FULL vector exactly once — the
    // coverage assert for the table itself: a public added to N_PUBLIC
    // without a named home (or two fields claiming one index) fails here.
    const covered = Object.values(l.fields)
      .flat()
      .sort((a, b) => a - b);
    assert.deepEqual(
      covered,
      Array.from({ length: l.nPublic }, (_, i) => i),
      `${name}: field map must partition publics 0..${l.nPublic - 1}`,
    );

    assert.equal(fx.publicsFull.length, l.nPublic, `${name} publicsFull length`);
    assert.deepEqual(fx.publicsCarried, l.carried.map(at), `${name} carried composition`);
    assert.equal(fx.kemCiphertexts.length, l.kemCtCount, `${name} kem ct count`);
    for (const ct of fx.kemCiphertexts) {
      assert.equal((ct.length - 2) / 2, KEM_CT_LEN, `${name} kem ct length`);
    }
    assert.equal((fx.proof.length - 2) / 2, PROOF_LEN, `${name} proof length`);

    if (l.enabled !== null) {
      for (const i of Array(l.enabled.arity).keys()) {
        const want: bigint = l.enabled.constantOne
          ? 1n
          : BigInt(at(l.enabled.nullifiersAt + i)) === 0n
            ? 0n
            : 1n;
        assert.equal(BigInt(at(l.enabled.enabledAt + i)), want, `${name} enabled[${i}] derivation`);
      }
    }

    // Named anchors the fixture carries double-pin the field positions.
    const F: Partial<Record<string, readonly number[]>> = l.fields;
    if (fx.nullifiers) assert.deepEqual(fx.nullifiers, F.nullifiers!.map(at), `${name} nullifiers`);
    if (fx.nullifier) assert.equal(fx.nullifier, at(F.nullifiers![0]), `${name} nullifier`);
    if (fx.outputCommitments) {
      assert.deepEqual(fx.outputCommitments, F.outputCommitments!.map(at), `${name} outputCommitments`);
    }
    if (fx.changeCommitment) {
      assert.equal(fx.changeCommitment, at(F.changeCommitment![0]), `${name} changeCommitment`);
    }
    if (fx.amount) assert.equal(fx.amount, at(F.amount![0]), `${name} amount`);
    if (fx.spentRoot) assert.equal(fx.spentRoot, at(F.root![0]), `${name} spentRoot vs root field`);
    if (fx.disclosureHash) {
      assert.equal(fx.disclosureHash, at(F.disclosureHash![0]), `${name} disclosureHash`);
    }
    if (fx.subtreeRoot) assert.equal(fx.subtreeRoot, at(F.subtreeRoot![0]), `${name} subtreeRoot`);
    if (fx.kemBinding) assert.equal(fx.kemBinding, at(F.kemBinding![0]), `${name} kemBinding`);
    if (fx.batchEpoch !== undefined) {
      assert.equal(fx.batchEpoch, ARBITER_EPOCH_GENESIS, `${name} batchEpoch`);
    }
  }
});
