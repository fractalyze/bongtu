// The receive modal opened by tapping the bongtu ID on Home. A fixed overlay (it
// must not disturb the mobile vertical frame): closes on the X icon, on a backdrop
// press, and on Escape. aria-modal promises assistive tech the background is inert,
// so the promise is kept manually: focus moves into the dialog on open, Tab cycles
// inside it, and focus returns to the opener on close. Backdrop dismissal keys off
// where the press STARTED — a text-selection drag out of the full-ID box must not
// close the modal mid-copy.

import { useEffect, useRef } from "react";
import type { ReactNode } from "react";
import { ReceivePanel } from "./ReceivePanel.js";
import { IconClose } from "./icons.js";

const FOCUSABLE = 'button, a[href], input, [tabindex]:not([tabindex="-1"])';

export function ReceiveModal({ pubkey, onClose }: { pubkey: string; onClose: () => void }): ReactNode {
  const cardRef = useRef<HTMLDivElement>(null);
  const downOnBackdrop = useRef(false);

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    const card = cardRef.current;
    (card?.querySelector<HTMLElement>(FOCUSABLE) ?? card)?.focus();
    document.body.style.overflow = "hidden";

    const on = (e: KeyboardEvent): void => {
      if (e.key === "Escape") {
        onClose();
        return;
      }
      if (e.key !== "Tab" || !card) return;
      const items = Array.from(card.querySelectorAll<HTMLElement>(FOCUSABLE));
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;
      if (e.shiftKey && (active === first || !card.contains(active))) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (active === last || !card.contains(active))) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", on);
    return () => {
      document.removeEventListener("keydown", on);
      document.body.style.overflow = "";
      opener?.focus();
    };
  }, [onClose]);

  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        downOnBackdrop.current = e.target === e.currentTarget;
      }}
      onMouseUp={(e) => {
        if (downOnBackdrop.current && e.target === e.currentTarget) onClose();
        downOnBackdrop.current = false;
      }}
    >
      <div ref={cardRef} className="modal-card" role="dialog" aria-modal="true" aria-label="Receive">
        <div className="modal-head">
          <h2 className="modal-title">Receive</h2>
          <button className="icon-btn" aria-label="Close" onClick={onClose}>
            <IconClose />
          </button>
        </div>
        <ReceivePanel pubkey={pubkey} />
      </div>
    </div>
  );
}
