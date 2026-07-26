// #/receive kept as a deep-linkable route, but the Home modal is the primary path —
// both must show the exact same content, so this is just ReceivePanel under a header.

import type { ReactNode } from "react";
import { useWallet } from "../App.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { ReceivePanel } from "../components/ReceivePanel.js";

export function Receive(): ReactNode {
  const { identity } = useWallet();
  return (
    <div className="screen">
      <ScreenHeader title="Receive" />
      <ReceivePanel pubkey={identity?.compressedPubkey ?? ""} />
    </div>
  );
}
