// When a login must sign TWICE, and when a login must be REFUSED.
//
// The whole wallet rests on one assumption (derive.ts): eth_signTypedData_v4 is
// DETERMINISTIC, so the same account signing the same struct always yields the same
// 65 bytes and therefore the same bjj spending key. MetaMask's ECDSA is RFC-6979, so
// that holds for the injected path and always has.
//
// WalletConnect breaks the assumption open: the signer is now whatever wallet app the
// user scanned with, and a wallet that adds randomness to its ECDSA nonce produces a
// DIFFERENT signature — hence a different key, hence an empty balance and notes that
// nothing can spend — on every single login. Nothing on the wire distinguishes that
// wallet from a good one, so the only way to find out is to look:
//
//   FIRST WalletConnect login on this browser (nothing remembered for the account):
//     ask for the same signature twice and require byte-equality. Two popups, once,
//     and only for a wallet we have never derived under.
//   ANY login where this browser already remembers a key for the account:
//     the freshly derived key must BE that key. One popup, and the check is free —
//     it is the same comparison, against a stronger reference.
//
// Both refusals are hard: the login stops and nothing stored is overwritten, because
// overwriting the remembered key is exactly how a user would lose sight of their notes.

/** How the browser is talking to the wallet: an injected extension, or WalletConnect. */
export type WalletTransport = "injected" | "walletconnect";

export const NONDETERMINISTIC_WALLET_MESSAGE =
  "This wallet signed the same message two different ways, so it can't produce a stable " +
  "bongtu key — every login would look like a different account. Connect with a wallet " +
  "that signs deterministically.";

export const KEY_CHANGED_MESSAGE =
  "This wallet produced a different signing key than last time — it may not support " +
  "deterministic signatures. Use the wallet you first connected with.";

/** Hex from two different wallets can differ in case and padding whitespace and still
 *  be the same bytes (the KDF hashes the decoded bytes, so case is not a difference). */
function sameHex(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/**
 * Whether this login has to spend the second signature: a WalletConnect wallet this
 * browser has never derived a key under. An injected wallet never does (MetaMask-class
 * determinism is established), and neither does any account we already remember a key
 * for — there the remembered key is the better reference.
 */
export function loginNeedsDeterminismCheck(
  transport: WalletTransport,
  knownPubkey: string | null,
): boolean {
  return transport === "walletconnect" && knownPubkey === null;
}

/** Refuse a wallet whose two signatures over the SAME struct differ. */
export function assertDeterministicSignatures(first: string, second: string): void {
  if (!sameHex(first, second)) throw new Error(NONDETERMINISTIC_WALLET_MESSAGE);
}

/**
 * Refuse a login that derived a different key than this browser last recorded for the
 * account. `knownPubkey === null` (a first login here) passes — there is nothing to
 * contradict yet.
 */
export function assertKeyUnchanged(derivedPubkey: string, knownPubkey: string | null): void {
  if (knownPubkey !== null && !sameHex(derivedPubkey, knownPubkey)) {
    throw new Error(KEY_CHANGED_MESSAGE);
  }
}
