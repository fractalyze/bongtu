// The Solana key-derivation seed — the ONE module holding the signMessage
// payload template (the OPEN-2 decision, .dev/solana-rail-design.md SOLR §4.2;
// user veto on the decision stays open, which is WHY the template is isolated
// here). The signature this payload produces IS the seed of every derived key,
// exactly as @bongtu/client-evm/derive keyDerivationTypedData is on the EVM
// rail, so the exact bytes are consensus-critical: changing one byte rotates
// every user's key. The KDF that turns the signature into the bjj/view/KEM
// identity stays rail-agnostic in @bongtu/client/derive; the signing edge that
// submits this payload is @bongtu/client-solana/connection signKeyDerivation.
//
// ── The exact signMessage payload (OPEN-2, quoted) ──────────────────────────
// The wallet signs the UTF-8 bytes (all-ASCII by construction) of this
// template. LF (0x0a) line separators, exactly one blank line between the
// domain block and the statement block, NO trailing newline, no CR, no BOM:
//
//   bongtu key derivation v1
//   cluster: {GENESIS_HASH_BASE58}
//   program: {PROGRAM_ID_BASE58}
//   key-version: {KEY_VERSION}
//
//   Derive my bongtu BabyJubJub spending key for this pool.
//   WARNING: Signing this reveals your bongtu spending key to whoever requested it. Only sign inside the official bongtu wallet.
//
// Byte-level rules (each falsifiable by test/derivePayload.test.ts):
//  1. Encoding: new TextEncoder().encode(template); the template is restricted
//     printable ASCII (0x20..0x7e plus 0x0a) — Solana's off-chain message
//     format 0 is the only format Ledger clear-signs, and base58 is an ASCII
//     subset so the two injected addresses cannot violate this. The builder
//     THROWS on any other byte rather than silently widening the domain.
//  2. Field order is fixed as shown; reordering rotates every key.
//  3. {GENESIS_HASH_BASE58}: the cluster genesis hash, base58, verbatim as
//     getGenesisHash returns it — the chainId analogue. PINNED per deployment
//     (never read from the RPC at derive time): the Solana ensureChain
//     analogue asserts the live getGenesisHash equals the pinned value BEFORE
//     the signing popup, so a lying RPC can only block login, never steer
//     which key is derived (the runLogin ordering rule).
//  4. {PROGRAM_ID_BASE58}: PROGRAM_ID_BASE58 from @bongtu/core/solana — the
//     verifyingContract analogue. Never hand-transcribed, never hex.
//  5. {KEY_VERSION}: "1" at ship (SOLANA_KEY_VERSION below) — the deliberate
//     rotate-everyone lever, same semantics as the EVM domain `version`.
//  6. Statement + warning: the EVM BongtuSpendingKey message fields with the
//     warning collapsed to one line. The header `bongtu key derivation v1`
//     plays the EIP-712 (name, format-version) role: a FORMAT change is also
//     a rotation and must bump the `v1`.
//  7. Size: ~330 B with real values — far under the 1,212 B off-chain-message
//     body limit, so Ledger format-0 clear-signing fits.
//
// Wallet envelopes: some signers (Ledger) sign the Solana off-chain-message
// wrapping (\xffsolana offchain preamble + our payload as body), not the raw
// bytes. That needs no code here — determinism is per-(account, wallet) and
// the KDF hashes whatever signature arrives — but it is why rule 1 is load-
// bearing: a non-format-0 payload gets Ledger users blind-sign prompts.
// MONITORED RISK (sRFC 38): a proposed v1 of that off-chain format would
// change the signed bytes for migrating wallets; the stored key binding then
// fails the login LOUDLY (KEY_CHANGED_MESSAGE) instead of showing an empty
// balance — the identity.ts guard is the runtime backstop.
//
// Rotation table (SOLR OPEN-2 record): program upgrade (same id) => keys
// STABLE; pool redeploy (new program id) => ROTATE; cluster change / local
// test-validator ledger reset => ROTATE (fresh chain, fresh pool); config
// account migration under the same program => STABLE by design (config is
// excluded from the domain so an admin migration cannot strand notes);
// key-version or format bump => the deliberate lever.

import { PROGRAM_ID_BASE58 } from "@bongtu/core/solana";

/** KDF domain version — part of the payload domain block, so bumping it
 *  rotates every derived key. Pinned per deployment; never silently changed
 *  (the KEY_DERIVATION.keyVersion pinning rule, @bongtu/client/identity). */
export const SOLANA_KEY_VERSION = "1";

/** The domain facts the Solana KDF signs over. Same values => same payload =>
 *  same derived key, so a deployment must pass identical values everywhere it
 *  derives — build them through solanaKeyDerivation below, never by hand. */
export interface SolanaKdfConfig {
  /** the cluster genesis hash, base58 — the chainId analogue (rule 3). */
  genesisHash: string;
  /** the pool program id, base58 — the verifyingContract analogue (rule 4). */
  programId: string;
  /** the rotate-everyone lever (rule 5). */
  keyVersion: string;
}

/**
 * THIS deployment's KDF domain facts for a given cluster: the program id comes
 * from the ONE rail facts module (@bongtu/core/solana) and the key version is
 * the pin above, so the only per-cluster input is the genesis hash — itself
 * pinned in the caller's deployment record, not read from the RPC (rule 3).
 */
export function solanaKeyDerivation(genesisHash: string): SolanaKdfConfig {
  return { genesisHash, programId: PROGRAM_ID_BASE58, keyVersion: SOLANA_KEY_VERSION };
}

/** Restricted printable ASCII (0x20..0x7e) plus LF — Solana off-chain message
 *  format 0, the Ledger clear-signing class (rule 1). */
function assertFormat0(text: string): void {
  for (const ch of text) {
    const c = ch.codePointAt(0) as number;
    if (c !== 0x0a && (c < 0x20 || c > 0x7e)) {
      throw new Error(
        `key-derivation payload contains a non-format-0 byte 0x${c.toString(16)} — ` +
          "the template must stay restricted printable ASCII (Ledger clear-signing, OPEN-2 rule 1)",
      );
    }
  }
}

/**
 * The exact payload TEXT the wallet is asked to sign (the template above with
 * the domain fields injected). Exported beside the byte form so tests and
 * wallet UIs render precisely what gets signed.
 */
export function keyDerivationPayloadText(cfg: SolanaKdfConfig): string {
  const text =
    "bongtu key derivation v1\n" +
    `cluster: ${cfg.genesisHash}\n` +
    `program: ${cfg.programId}\n` +
    `key-version: ${cfg.keyVersion}\n` +
    "\n" +
    "Derive my bongtu BabyJubJub spending key for this pool.\n" +
    "WARNING: Signing this reveals your bongtu spending key to whoever requested it. " +
    "Only sign inside the official bongtu wallet.";
  assertFormat0(text);
  return text;
}

/** The consensus-critical bytes: UTF-8 of the template (all-ASCII, rule 1). */
export function keyDerivationPayload(cfg: SolanaKdfConfig): Uint8Array {
  return new TextEncoder().encode(keyDerivationPayloadText(cfg));
}
