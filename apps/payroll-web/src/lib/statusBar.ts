// The status bar's PURE state selection (the full-width bar under the console
// header). Two states only, and one truthfulness rule worth pinning headlessly:
// a connected wallet whose balance has NOT been read yet stays `balance: null`
// (the view renders the loading treatment) — it is never coerced to zero, for
// the same reason sendReadiness treats null notes as its own verdict.

export type StatusBarState =
  | { kind: "disconnected" }
  | {
      kind: "connected";
      /** the connected eth account (0x…, shortened by the view). */
      ethAccount: string;
      /** the session's compressed bjj pubkey — the bongtu address. */
      bongtuAddress: string;
      /** unspent balance in wei, or null = not read yet (show loading, never 0). */
      balanceWei: bigint | null;
    };

export function statusBarState(
  wallet: { ethAccount: string; bongtuAddress: string } | null,
  balanceWei: bigint | null,
): StatusBarState {
  if (wallet === null) return { kind: "disconnected" };
  return {
    kind: "connected",
    ethAccount: wallet.ethAccount,
    bongtuAddress: wallet.bongtuAddress,
    balanceWei,
  };
}
