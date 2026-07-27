// #/receive kept as a deep-linkable route, but the Home modal is the primary path —
// both must show the exact same content, so this is just ReceivePanel under a header.

import type { ReactNode } from "react";
import { useWallet } from "../App.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { ReceivePanel } from "../components/ReceivePanel.js";

export function Receive(): ReactNode {
  const { identity } = useWallet();
  return (
    <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
      <ScreenHeader title="Receive" />
      <ReceivePanel pubkey={identity?.compressedPubkey ?? ""} />
    </div>
  );
}
