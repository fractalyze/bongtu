// The receive modal opened by tapping the bongtu ID on Home — a thin wrapper: all
// dialog semantics (focus trap, Escape, backdrop-press-start dismissal) live in Modal.

import type { ReactNode } from "react";
import { Modal } from "./Modal.js";
import { ReceivePanel } from "./ReceivePanel.js";

export function ReceiveModal({ pubkey, onClose }: { pubkey: string; onClose: () => void }): ReactNode {
  return (
    <Modal title="Receive" onClose={onClose}>
      <ReceivePanel pubkey={pubkey} />
    </Modal>
  );
}
