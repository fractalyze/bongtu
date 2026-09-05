// The connected wallet's mark. Best available likeness, in order: the icon the wallet
// itself announced (EIP-6963, a data URI — no network fetch), our bundled MetaMask fox,
// or the generic wallet glyph. It must never show one wallet's brand for another, so
// the fox is drawn ONLY when the provider identified itself as MetaMask.

import type { ReactNode } from "react";
import type { WalletDescription } from "@bongtu/ui/walletBrand";
import { IconWallet, MetaMaskFox } from "./icons.js";

export function WalletMark({
  wallet,
  size = 18,
}: {
  wallet: WalletDescription;
  size?: number;
}): ReactNode {
  if (wallet.iconUrl) {
    return (
      <img
        src={wallet.iconUrl}
        alt=""
        width={size}
        height={size}
        className="rounded-[5px]"
        aria-hidden="true"
      />
    );
  }
  if (wallet.brand === "metamask") return <MetaMaskFox size={size} />;
  return <IconWallet size={size - 2} />;
}
