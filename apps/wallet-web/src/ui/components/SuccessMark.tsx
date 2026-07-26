// SVG success checkmark shared by the Deposit/Send/Withdraw done states — the locked
// visual language bans glyph characters, so no checkmark char.

import type { ReactNode } from "react";

export function SuccessMark(): ReactNode {
  return (
    <div className="success-check" aria-hidden="true">
      <svg viewBox="0 0 24 24" width="26" height="26">
        <path
          d="M5 12.5 10 17.5 19 7"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </div>
  );
}
