// Text "Back", not a chevron glyph: the locked visual language bans glyph characters
// in buttons (buttons are text-first).

import type { ReactNode } from "react";
import { navigate } from "../hooks.js";

export function ScreenHeader({
  title,
  right,
}: {
  title: string;
  right?: ReactNode;
}): ReactNode {
  return (
    <header className="screen-head">
      <button className="link-btn" onClick={() => navigate("home")}>
        Back
      </button>
      <h1 className="screen-title">{title}</h1>
      <div className="screen-head-right">{right}</div>
    </header>
  );
}
