// The Solana half of the key-derivation migration belt, mirroring
// client-evm/test/deriveDeterminism.test.ts: the spending key is a pure
// function of the signMessage payload + the signing account, so this file
// pins (1) the exact payload TEXT (the frozen consensus bytes — the OPEN-2
// template), (2) that the REAL signing path turns a fixed 64-byte ed25519
// signature into the pinned bjj identity, and (3) the stricter Solana
// determinism guard: double-sign on every unbound first derivation, hard
// refusal of a wallet whose two signatures differ, hard refusal of a changed
// key — with nothing written on either refusal.
//
// ── HOW TO READ A FAILURE HERE ─────────────────────────────────────────────
// PIN_PAYLOAD is NOT a snapshot to refresh. Only two things move it: (a) a
// CODE change to the template — the bug the pin exists to catch (every user
// on the same deployment would silently derive a different key); revert the
// change, do not touch the pin. (b) a deliberate domain change (program id /
// key version / payload format) — a USER-VISIBLE IDENTITY BREAK, re-pinned
// only together with that decision. The genesis hash here is devnet's, used
// as a FIXED test constant (a local validator mints a fresh genesis per
// ledger reset, so determinism tests never touch a validator — the OPEN-2
// record). PIN_SCALAR/PIN_COMPRESSED never move on a deployment change: the
// KDF hashes the SIGNATURE, not the payload.

import { test } from "node:test";
import assert from "node:assert/strict";

import { ed25519 } from "@noble/curves/ed25519.js";
import { PROGRAM_ID_BASE58 } from "@bongtu/core/solana";
import { deriveIdentityFromSignature, scalarFromSignature } from "@bongtu/client/derive";
import {
  KEY_CHANGED_MESSAGE,
  NONDETERMINISTIC_WALLET_MESSAGE,
} from "@bongtu/client/login";
import {
  SOLANA_KEY_VERSION,
  keyDerivationPayload,
  keyDerivationPayloadText,
  solanaKeyDerivation,
} from "@bongtu/client-solana/derive";
import {
  deriveSolanaLoginIdentity,
  runSolanaLogin,
  solanaLoginNeedsDeterminismCheck,
} from "@bongtu/client-solana/identity";
import type { SolanaConnection } from "@bongtu/client-solana/connection";

// --- pinned derivation facts -------------------------------------------------

/** A fixed cluster for the payload pin: the devnet genesis hash as a CONSTANT
 *  (never fetched — see the module doc). */
const GENESIS = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

/** The exact template bytes for (devnet genesis, the pool program, key
 *  version "1") — the OPEN-2 payload, frozen. 329 bytes, all format-0 ASCII. */
const PIN_PAYLOAD =
  "bongtu key derivation v1\n" +
  `cluster: ${GENESIS}\n` +
  "program: HGVVfVfRnHauJoQwUttgUoy6ucG47LAXj8e6YBbZkoCj\n" +
  "key-version: 1\n" +
  "\n" +
  "Derive my bongtu BabyJubJub spending key for this pool.\n" +
  "WARNING: Signing this reveals your bongtu spending key to whoever requested it. " +
  "Only sign inside the official bongtu wallet.";

/** A fixed stand-in for a wallet's deterministic 64-byte ed25519 signature. */
const FIXED_SIG = ("0x" + "a1".repeat(32) + "b2".repeat(32)) as string;

/** deriveIdentityFromSignature(FIXED_SIG) — captured at authoring time
 *  (2026-09-05) through the UNCHANGED rail-agnostic KDF. These do not move on
 *  a deployment change; a failure here is always a real KDF regression. */
const PIN_SCALAR = 2332322152663468266269715951562183249488406818071254559182815272691157759663n;
const PIN_COMPRESSED = "0x1a9904c9dc0d22ca4a2d6699f707507f63cb7f19d7673edb947c803665d6ae81";
const PIN_VIEW_COMPRESSED = "0x8d73cc8a540f2d4975deaffbe3bc4e30ac29bca82d5e12eb3a213c59e225399a";

/** The full signing-path vector: a fixed ed25519 key (seed 0x11×32, RFC 8032
 *  — the deterministic wallet class) signing PIN_PAYLOAD, and the identity
 *  that signature derives. */
const SIGNER_SEED = new Uint8Array(32).fill(0x11);
const PIN_SIGNED_SIG =
  "0x056cb96b68939537a1cb096bd3344b0201177a314c7565216c3b340f37af2702" +
  "bf38c7dc27f16d9db2d6d7cbafa6b3f9ee372f9aec4eacb5eb866c28acae6704";
const PIN_SIGNED_COMPRESSED = "0xdfae12697323886820d71a6db8a6437f1379904430511990f4b47914b71a50a4";

const KDF = solanaKeyDerivation(GENESIS);

/** A SolanaConnection over a local RFC 8032 signer — the fake models the
 *  WALLET, so the whole client stack in between is the code under test. */
function signerConnection(signedPayloads: Uint8Array[], seed: Uint8Array = SIGNER_SEED): SolanaConnection {
  return {
    address: "9fYLFVoVqwH37C3dyPi6cpeobfbQ2jtLpN5HgAYDDdkm",
    transport: "injected",
    rpcUrl: "http://127.0.0.1:1",
    signMessage: async (bytes) => {
      signedPayloads.push(bytes);
      return ed25519.sign(bytes, seed);
    },
    signAndSendTransaction: () => Promise.reject(new Error("not under test")),
  };
}

// --- (1) the frozen payload bytes -------------------------------------------

test("the payload template still renders the pinned OPEN-2 bytes", () => {
  assert.equal(keyDerivationPayloadText(KDF), PIN_PAYLOAD);
  const bytes = keyDerivationPayload(KDF);
  assert.equal(bytes.length, 329, "the ~330 B Ledger-format-0 size claim");
  assert.deepEqual(bytes, new TextEncoder().encode(PIN_PAYLOAD));
});

test("the domain wiring: program id from the rail facts module, key version pinned", () => {
  assert.equal(KDF.programId, PROGRAM_ID_BASE58);
  assert.equal(KDF.keyVersion, SOLANA_KEY_VERSION);
  assert.equal(SOLANA_KEY_VERSION, "1");
});

test("format-0 rule: LF-only, restricted printable ASCII, no trailing newline", () => {
  assert.ok(!PIN_PAYLOAD.includes("\r"));
  assert.ok(!PIN_PAYLOAD.endsWith("\n"));
  for (const b of keyDerivationPayload(KDF)) {
    assert.ok(b === 0x0a || (b >= 0x20 && b <= 0x7e), `byte 0x${b.toString(16)} violates format 0`);
  }
  // A non-ASCII domain value must be refused, not silently signed.
  assert.throws(() => keyDerivationPayloadText({ ...KDF, genesisHash: "é" }), /format-0/);
});

// --- (2) the KDF vectors -----------------------------------------------------

test("a fixed 64-byte signature derives the pinned identity (the rail-agnostic KDF unchanged)", () => {
  assert.equal(scalarFromSignature(FIXED_SIG), PIN_SCALAR);
  const id = deriveIdentityFromSignature(FIXED_SIG);
  assert.equal(id.compressedPubkey, PIN_COMPRESSED);
  assert.equal(id.compressedViewPubkey, PIN_VIEW_COMPRESSED);
});

test("the REAL signing path: payload in, pinned signature out, pinned identity derived", async () => {
  const payloads: Uint8Array[] = [];
  const id = await deriveSolanaLoginIdentity(signerConnection(payloads), { doubleSign: false }, KDF);
  assert.equal(payloads.length, 1);
  assert.deepEqual(payloads[0], new TextEncoder().encode(PIN_PAYLOAD), "the wallet was asked to sign the pin");
  assert.equal(
    "0x" + Buffer.from(ed25519.sign(payloads[0], SIGNER_SEED)).toString("hex"),
    PIN_SIGNED_SIG,
    "RFC 8032 signature over the pinned payload",
  );
  assert.equal(id.compressedPubkey, PIN_SIGNED_COMPRESSED);
});

// --- (3) the stricter determinism guard --------------------------------------

test("the Solana rule ignores transport: doubleSign iff no stored binding", () => {
  assert.equal(solanaLoginNeedsDeterminismCheck(null), true);
  assert.equal(solanaLoginNeedsDeterminismCheck(PIN_COMPRESSED), false);
});

test("doubleSign asks twice and accepts a deterministic wallet", async () => {
  const payloads: Uint8Array[] = [];
  const id = await deriveSolanaLoginIdentity(signerConnection(payloads), { doubleSign: true }, KDF);
  assert.equal(payloads.length, 2, "two popups on the determinism check");
  assert.equal(id.compressedPubkey, PIN_SIGNED_COMPRESSED);
});

test("an MPC-class wallet (two different signatures) is refused with the engine's message", async () => {
  const seeds = [new Uint8Array(32).fill(0x22), new Uint8Array(32).fill(0x33)];
  const drawn: { n: number } = { n: 0 };
  const nondeterministic: SolanaConnection = {
    ...signerConnection([]),
    signMessage: async (bytes) => {
      const seed = seeds[drawn.n];
      drawn.n += 1;
      return ed25519.sign(bytes, seed);
    },
  };
  await assert.rejects(
    deriveSolanaLoginIdentity(nondeterministic, { doubleSign: true }, KDF),
    new Error(NONDETERMINISTIC_WALLET_MESSAGE),
  );
});

test("runSolanaLogin: two signatures on a first login, one thereafter, refusal writes nothing", async () => {
  const bindings = new Map<string, string>();
  const sessions: unknown[] = [];
  const payloads: Uint8Array[] = [];
  const deps = {
    openConnection: async () => signerConnection(payloads),
    kdf: KDF,
    loadKeyBinding: (a: string) => bindings.get(a) ?? null,
    saveKeyBinding: (a: string, k: string) => void bindings.set(a, k),
    saveSession: (s: unknown) => void sessions.push(s),
    ensureChain: async () => {},
  };
  const first = await runSolanaLogin({ indexerUrl: "http://127.0.0.1:1" }, deps);
  assert.equal(payloads.length, 2, "unbound first login pays the double signature");
  assert.equal(first.identity.compressedPubkey, PIN_SIGNED_COMPRESSED);
  assert.equal(first.tokenless, true, "the consumer login never obtains a view token");
  assert.equal(bindings.get(first.connection.address), PIN_SIGNED_COMPRESSED, "binding recorded");

  const second = await runSolanaLogin({ indexerUrl: "http://127.0.0.1:1" }, deps);
  assert.equal(payloads.length, 3, "bound login is one signature against the stored binding");
  assert.equal(second.identity.compressedPubkey, PIN_SIGNED_COMPRESSED);

  // A wallet now deriving a DIFFERENT key: hard refusal, binding untouched.
  bindings.set(first.connection.address, PIN_COMPRESSED);
  await assert.rejects(
    runSolanaLogin({ indexerUrl: "http://127.0.0.1:1" }, deps),
    new Error(KEY_CHANGED_MESSAGE),
  );
  assert.equal(bindings.get(first.connection.address), PIN_COMPRESSED, "refusal overwrote nothing");
});
