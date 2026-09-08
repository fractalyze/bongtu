// Build-time facts the page renders and derives against.
//
// INDEXER_URL follows the other apps' relative-base convention ("/indexer" —
// Vite proxies it in dev, the vercel.json rewrite owns it in prod).
//
// PORTAL_PRIV_FACTORY + SWEEPER_INITCODE_HASH pin the CREATE2 mapping the page
// computes LOCALLY (create2Address over the browser-derived salt). They are
// deliberately build-time config, not a server read: the destination shown to
// the payer must be a pure function of public constants and the browser's own
// derivation, so a hostile indexer can at worst hide a payment, never redirect
// one — the announce response's server-recomputed destination is only
// PARITY-CHECKED against the local value, and a mismatch fails the page
// closed (src/lib/pay.ts). Values come from the Vercel project env (the
// deploy record's `portalPrivFactory` by field name + the committed parity
// vector's initcode hash); dev falls back to empty, which the page reports
// as unconfigured instead of deriving garbage.
export const INDEXER_URL: string = import.meta.env?.VITE_INDEXER_URL ?? "/indexer";
export const PORTAL_PRIV_FACTORY: string = import.meta.env?.VITE_PORTAL_PRIV_FACTORY ?? "";
export const SWEEPER_INITCODE_HASH: string = import.meta.env?.VITE_SWEEPER_INITCODE_HASH ?? "";

/** The payment coordinates the facts card shows: env-overridable so a
 * non-Maroo profile (the Sepolia USDC demo, spec payment-name R12) states
 * the right network and asset without a fork. */
export const CHAIN_NAME: string = import.meta.env?.VITE_CHAIN_NAME ?? "Maroo";
export const TOKEN_SYMBOL: string = import.meta.env?.VITE_TOKEN_SYMBOL ?? "kKRW";
