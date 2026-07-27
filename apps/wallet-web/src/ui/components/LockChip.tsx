// The spending lock, shown in the Home header next to the indexer chip.
//
// Locked means the wallet is not holding your spending permission: the next send,
// withdraw or deposit asks you to confirm once in the wallet you connected with.
// Unlocked means it is holding it, and those actions go straight to the transaction.
// The tooltip names that wallet as it detected it, never a brand. It says nothing
// about VIEWING — balance and activity read with the login token and work either
// way — so the copy talks about sending, never about keys.
//
// Fresh load, ten idle minutes, and signing out all show Locked.

import type { ReactNode } from "react";
import { NEUTRAL_WALLET_NAME } from "../../lib/walletBrand.js";
import { useWalletUnlocked } from "../hooks.js";
import { IconLock, IconUnlock } from "./icons.js";

export function LockChip({ walletName = NEUTRAL_WALLET_NAME }: { walletName?: string }): ReactNode {
  const unlocked = useWalletUnlocked();
  const word = unlocked ? "Unlocked" : "Locked";
  return (
    <span
      className="inline-flex items-center gap-1 text-xs text-muted"
      role="status"
      aria-label={`Wallet ${word.toLowerCase()}`}
      title={
        unlocked
          ? "Unlocked — you can send without confirming again for a while."
          : `Locked — you'll confirm once in ${walletName} the next time you send.`
      }
    >
      {unlocked ? <IconUnlock /> : <IconLock />}
      {/* The header already carries the brand, a testnet tag, the indexer chip and
          two buttons; below ~640px the padlock stands alone rather than squeeze
          the row (the label is still announced, and hoverable on desktop). */}
      <span className="hidden sm:inline">{word}</span>
    </span>
  );
}
