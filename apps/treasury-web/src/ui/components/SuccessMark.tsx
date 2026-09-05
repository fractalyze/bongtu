// Success checkmark shared by the Deposit/Send/Withdraw done states — the locked
// visual language bans glyph characters, so the mark is the Remix check icon.

import type { ReactNode } from "react";
import { IconCheck } from "./icons.js";

export function SuccessMark(): ReactNode {
  return (
    <div
      className="w-[62px] h-[62px] rounded-full grid place-items-center bg-pos-bg border border-pos text-pos"
      aria-hidden="true"
    >
      <IconCheck size={30} />
    </div>
  );
}
