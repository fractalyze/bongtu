import type { ReactNode } from "react";
import { navigate } from "../hooks.js";
import { IconButton } from "./controls.js";
import { IconBack } from "./icons.js";

export function ScreenHeader({
  title,
  right,
  backDisabled = false,
}: {
  title: string;
  right?: ReactNode;
  /** a running op disables Back: a multi-leg chain keeps signing after the
   *  screen unmounts, and a remount would show a fresh form over the hidden
   *  run — the screen stays attached until the run resolves (ActionPanels). */
  backDisabled?: boolean;
}): ReactNode {
  return (
    <header className="grid grid-cols-[1fr_auto_1fr] items-center">
      <IconButton
        className="justify-self-start disabled:opacity-40 disabled:cursor-not-allowed"
        aria-label="Back"
        disabled={backDisabled}
        onClick={() => navigate("home")}
      >
        <IconBack />
      </IconButton>
      <h1 className="text-[1.05rem] [font-weight:650] text-center">{title}</h1>
      <div className="flex justify-end">{right}</div>
    </header>
  );
}
