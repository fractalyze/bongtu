// The ONE home for the Solana rail's chain facts — the Solana sibling of
// chain/network.ts (the EVM/live-pool facts module). Everything here MIRRORS
// a constant declared in the Rust program (chains/solana/program/src), which
// stays hand-written by design (the independent second implementation), so
// the owner of each truth is the Rust source: test/solana.test.ts holds this
// module to it field-for-field by parsing the Rust text, and its coverage
// assert makes a NEW Rust constant fail until it gets a pin row + a mirror
// here — a transcription slip fails in milliseconds instead of at ledger
// decode time.
//
// NEVER update a value here by pattern-matching an old one or another rail's
// copy: transcribe from the Rust constant BY NAME (the network.ts rule).
//
// DATA-ONLY by design: no chain-library import, no node:fs — browser-safe
// plain data plus the dependency-free base58 codec below, so the indexer and
// the future client-solana package import the same facts. The one import is
// the sibling network.ts (H): the IMT height is protocol-wide and network.ts
// stays its declared owner.
//
// BYTE-ENCODING RULE (state.rs module doc; SOLR §4.1 one-endianness rule):
// every FIELD ELEMENT crosses the wire as 32-byte BIG-ENDIAN — the Groth16
// public-input encoding, one canonical byte form across verifier, tree,
// events and PDA seed values. COUNTERS are LITTLE-endian: next_leaf_index /
// start_leaf_index / epoch are u64 LE, the config batch B is u32 LE — and
// the DisburseBatch PDA seed value is its start_leaf_index u64 LE (a
// counter, not a field element; every other value seed is 32-byte BE).

import { H } from "./network.js";

/** The pool program id (lib.rs `declare_id!`; the harness PROGRAM_ID_STR and
 *  the indexer's SOLANA_PROGRAM env default resolve to the same id). Base58,
 *  the operator-facing convention — `base58ToHex` converts once at an app's
 *  edge so one 0x-hex byte convention exists inside services. */
export const PROGRAM_ID_BASE58 = "HGVVfVfRnHauJoQwUttgUoy6ucG47LAXj8e6YBbZkoCj";

/** IMT height — protocol-wide, OWNED by network.ts H (SPEC §4 / SOLR §4.1):
 *  the Solana TreeState is the same 32-level single-frontier IMT as the EVM
 *  pool, so this is a reference to the one owner, not a second literal (the
 *  generated zeros.rs TREE_HEIGHT is pinned equal by the test). */
export const TREE_HEIGHT = H;

/** Consumer fixture-profile batch B (gen_consumer_realproofs.ts seeds
 *  ImtTree(32, 16); the P2P family never batch-attaches, so B only labels
 *  the profile) and its log2. */
export const BATCH_B_CONSUMER = 16;
export const LOG_B_CONSUMER = 4;

/** Enterprise-profile batch B — the production disburse arity (disburse256
 *  folds exactly 256 leaves in-circuit; the Rust CIRCUIT_LOG_B pins the
 *  attach level) — and its log2. Equals network.ts B because the circuits
 *  are shared verbatim across rails (SOLR §4.1); the test asserts it. */
export const BATCH_B_ENTERPRISE = 256;
export const LOG_B_ENTERPRISE = 8;

// --- PDA seed prefixes (state.rs SEED_*) ------------------------------------
// Seed VALUES follow the byte rule above: 32-byte BE field elements, except
// the DisburseBatch seed (start_leaf_index u64 LE).

export const SEED_NULLIFIER = "nf";
export const SEED_KNOWN_ROOT = "root";
export const SEED_EVENT_AUTHORITY = "__event_authority";
export const SEED_DISBURSE_BATCH = "batch";
export const SEED_VAULT_AUTHORITY = "authority";
export const SEED_CONFIG = "config";
export const SEED_TREE = "tree";

// --- account layouts (state.rs: plain fixed-offset byte layouts, no serde) --

/** Account-type tags (first data byte). */
export const TAG_POOL_CONFIG = 1;
export const TAG_TREE_STATE = 2;
export const TAG_DISBURSE_BATCH = 3;

/** PoolConfig: tag(1) version(1) family_flags(u16 LE) admin(32) mint(32)
 *  vault(32) batch B(u32 LE) arbiter bjj key(2×32 BE) arbiter KEM pk
 *  hash(32). */
export const POOL_CONFIG_LEN = 200;
export const CONFIG_OFF_FLAGS = 2;
export const CONFIG_OFF_MINT = 36;
export const CONFIG_OFF_VAULT = 68;
export const CONFIG_OFF_BATCH_B = 100;
export const CONFIG_OFF_ARBITER_X = 104;
export const CONFIG_OFF_ARBITER_Y = 136;
export const CONFIG_OFF_KEM_PK_HASH = 168;

/** TreeState (zero-copy single-frontier IMT): tag(1) version(1) config(32)
 *  next_leaf_index(u64 LE) current_root(32 BE) filled_subtrees[32]
 *  (32 BE each). */
export const TREE_STATE_LEN = 1098;
export const TREE_OFF_CONFIG = 2;
export const TREE_OFF_NEXT = 34;
export const TREE_OFF_ROOT = 42;
export const TREE_OFF_FRONTIER = 74;

/** DisburseBatch (the durable per-batch audit anchor, SOLR §3.3.1): tag(1)
 *  version(1) start_leaf_index(u64 LE) disclosure_hash(32 BE)
 *  kem_binding(32 BE) epoch(u64 LE). */
export const DISBURSE_BATCH_LEN = 82;
export const BATCH_OFF_START = 2;
export const BATCH_OFF_DISCLOSURE_HASH = 10;
export const BATCH_OFF_KEM_BINDING = 42;
export const BATCH_OFF_EPOCH = 74;

// --- wire scalars -----------------------------------------------------------

/** Arbiter epoch on this rail, pinned at genesis (state.rs): `rotateArbiter`
 *  is not yet a Solana instruction (dated deviation in SOLR §3.3.1), so every
 *  batch records epoch 0 and ledger data cannot describe any other epoch. */
export const ARBITER_EPOCH_GENESIS = 0;

/** Groth16 proof wire bytes (groth16.rs): A(64) || B(128, EVM/EIP-197 limb
 *  order — the alt_bn128 syscall encoding) || C(64). */
export const PROOF_LEN = 256;

/** ML-KEM-768 ciphertext bytes (FIPS 203 pins the ct size; per-op count is a
 *  layout fact in solanaOps.ts). */
export const KEM_CT_LEN = 1088;

/** `initialize` (discriminator 0, initialize.rs) — the one-shot deploy
 *  instruction. Wire after the discriminator: family_flags (u16 LE) ||
 *  batch B (u32 LE) || arbiter bjj key x,y (32 B BE each) || arbiter KEM pk
 *  hash (32 B). Not an op: no proof, no publics, no event. */
export const INITIALIZE_DISCRIMINATOR = 0;
export const INITIALIZE_PAYLOAD_LEN = 102;

/** Self-CPI event instruction discriminator (event.rs). */
export const EVENT_DISCRIMINATOR = 0xf0;

// --- base58 (dependency-free codec) -----------------------------------------
// Moved from apps/indexer/src/solana/rpc.ts so the indexer and the client
// packages share ONE codec: ids stay base58 at operator-facing edges, bytes
// and 0x-hex inside services.

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58ToBytes(s: string): Uint8Array {
  const digits: number[] = [];
  for (const ch of s) {
    const v = BASE58_ALPHABET.indexOf(ch);
    if (v < 0) throw new Error(`base58: invalid character "${ch}"`);
    const carry = digits.reduce((c, _, i) => {
      const x = digits[i] * 58 + c;
      digits[i] = x & 0xff;
      return x >> 8;
    }, v);
    const push = (c: number): void => {
      if (c > 0) {
        digits.push(c & 0xff);
        push(c >> 8);
      }
    };
    push(carry);
  }
  const firstNonOne = [...s].findIndex((c) => c !== "1");
  const zeros = firstNonOne === -1 ? s.length : firstNonOne;
  return new Uint8Array([...Array.from({ length: zeros }, () => 0), ...digits.reverse()]);
}

export function bytesToBase58(bytes: Uint8Array): string {
  const digits: number[] = [];
  for (const byte of bytes) {
    const carry = digits.reduce((c, _, i) => {
      const x = digits[i] * 256 + c;
      digits[i] = x % 58;
      return Math.floor(x / 58);
    }, byte);
    const push = (c: number): void => {
      if (c > 0) {
        digits.push(c % 58);
        push(Math.floor(c / 58));
      }
    };
    push(carry);
  }
  const firstNonZero = [...bytes].findIndex((b) => b !== 0);
  const zeros = firstNonZero === -1 ? bytes.length : firstNonZero;
  return "1".repeat(zeros) + digits.reverse().map((d) => BASE58_ALPHABET[d]).join("");
}

export function base58ToHex(s: string): string {
  return "0x" + Array.from(base58ToBytes(s), (b) => b.toString(16).padStart(2, "0")).join("");
}
