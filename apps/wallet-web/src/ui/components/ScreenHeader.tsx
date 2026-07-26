import type { ReactNode } from "react";
import { navigate } from "../hooks.js";
import { IconBack } from "./icons.js";

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
        <IconBack />
      </button>
      <h1 className="screen-title">{title}</h1>
      <div className="screen-head-right">{right}</div>
    </header>
  );
}
