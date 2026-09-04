// The spending lock, shown in the nav as a padlock and nothing else.
//
// Closed and muted means the wallet is not holding your spending permission: the next
// send, withdraw or deposit asks you to confirm once in the wallet you connected with.
// Open and green means it is holding it, and those actions go straight to the
// transaction. The words live in the tooltip (and in the aria-label, so a screen
// reader gets them without a hover); the nav itself is icons only.
//
// The tooltip names the connected wallet as it detected it, never a brand. It says
// nothing about VIEWING — balance and activity read with the login token and work
// either way — so the copy talks about sending, never about keys.
//
// Logging in unlocks it (App.connectWallet seeds the lock with the identity the login
// signature already produced). Ten idle minutes, a reload, and signing out show Locked.

import type { ReactNode } from "react";
import { NEUTRAL_WALLET_NAME } from "../../lib/walletBrand.js";
import { useWalletUnlocked } from "../hooks.js";
import { IconLock, IconUnlock } from "./icons.js";

export function LockChip({ walletName = NEUTRAL_WALLET_NAME }: { walletName?: string }): ReactNode {
  const unlocked = useWalletUnlocked();
  return (
    <span
      className={`inline-flex items-center p-[5px] ${unlocked ? "text-pos" : "text-muted"}`}
      role="status"
      aria-label={unlocked ? "Wallet unlocked" : "Wallet locked"}
      title={
        unlocked
          ? "Unlocked. You can send without confirming again for a while."
          : `Locked. You'll confirm once in ${walletName} the next time you send.`
      }
    >
      {unlocked ? <IconUnlock size={17} /> : <IconLock size={17} />}
    </span>
  );
}
