// PURE provider-brand detection for the connected-wallet card (framework-free,
// unit-tested headlessly). The EIP-1193 injected provider self-identifies via
// vendor flags — MetaMask sets `isMetaMask: true` — and the UI shows the matching
// brand mark (the fox) or falls back to a generic wallet icon.

export type WalletBrand = "metamask" | "unknown";

/**
 * Classify the raw injected EIP-1193 provider object (ethers v5 keeps it at
 * `web3Provider.provider`). Strictly `isMetaMask === true`: several non-MetaMask
 * wallets spoof the flag with truthy non-boolean values, and an absent/foreign
 * provider must degrade to the generic icon, never throw.
 */
export function walletBrand(injected: unknown): WalletBrand {
  if (typeof injected === "object" && injected !== null) {
    if ((injected as { isMetaMask?: unknown }).isMetaMask === true) return "metamask";
  }
  return "unknown";
}
