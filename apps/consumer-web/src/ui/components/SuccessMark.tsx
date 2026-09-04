// The Remix check icon, not a checkmark character: glyph chars are banned by the
// locked visual language.

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
