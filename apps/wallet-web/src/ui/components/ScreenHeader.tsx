// Shared top bar for the secondary screens: a back chevron to Home, a centered
// title, and an optional right-side slot (e.g. the gear on Home).

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
      <button className="icon-btn" aria-label="Back" onClick={() => navigate("home")}>
        ‹
      </button>
      <h1 className="screen-title">{title}</h1>
      <div className="screen-head-right">{right}</div>
    </header>
  );
}
