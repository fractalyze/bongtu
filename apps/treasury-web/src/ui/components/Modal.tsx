// The one modal shell (extracted from ReceiveModal so every dialog keeps identical
// semantics). A fixed overlay (it must not disturb the mobile vertical frame): closes
// on the X icon, on a backdrop press, and on Escape. aria-modal promises assistive
// tech the background is inert, so the promise is kept manually: focus moves into the
// dialog on open, Tab cycles inside it, and focus returns to the opener on close.
// Backdrop dismissal keys off where the press STARTED — a text-selection drag out of
// the dialog (e.g. copying the full-ID box) must not close the modal mid-copy.

import { useEffect, useRef } from "react";
import type { ReactNode } from "react";
import { IconButton } from "./controls.js";
import { IconClose } from "./icons.js";

const FOCUSABLE = 'button, a[href], input, [tabindex]:not([tabindex="-1"])';

export function Modal({
  title,
  ariaLabel,
  onClose,
  children,
}: {
  title: ReactNode;
  /** Accessible dialog name; defaults to `title` when the title is a plain string. */
  ariaLabel?: string;
  onClose: () => void;
  children: ReactNode;
}): ReactNode {
  const cardRef = useRef<HTMLDivElement>(null);
  const downOnBackdrop = useRef(false);
  // The trap effect must run exactly once per OPEN. Keying it on [onClose]
  // re-runs it whenever a parent passes a fresh inline arrow (every parent
  // re-render — and the mint modal's parent re-renders on each download tick):
  // focus gets yanked back to the first focusable mid-typing, and `opener`
  // re-captures an element inside the dialog, breaking the close-time restore.
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    const card = cardRef.current;
    (card?.querySelector<HTMLElement>(FOCUSABLE) ?? card)?.focus();
    document.body.style.overflow = "hidden";

    const on = (e: KeyboardEvent): void => {
      if (e.key === "Escape") {
        onCloseRef.current();
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
  }, []);

  return (
    <div
      className="fixed inset-0 bg-backdrop flex items-center justify-center p-5 z-50"
      onMouseDown={(e) => {
        downOnBackdrop.current = e.target === e.currentTarget;
      }}
      onMouseUp={(e) => {
        if (downOnBackdrop.current && e.target === e.currentTarget) onClose();
        downOnBackdrop.current = false;
      }}
    >
      <div
        ref={cardRef}
        className="bg-surface rounded-2xl px-4.5 pt-4 pb-5 w-full max-w-[360px] max-h-[calc(100vh-40px)] overflow-y-auto flex flex-col gap-2.5 shadow-[0_18px_44px_-20px_rgba(17,24,39,0.45)]"
        role="dialog"
        aria-modal="true"
        aria-label={ariaLabel ?? (typeof title === "string" ? title : undefined)}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-[1.02rem] [font-weight:650]">{title}</h2>
          <IconButton aria-label="Close" onClick={onClose}>
            <IconClose />
          </IconButton>
        </div>
        {children}
      </div>
    </div>
  );
}
