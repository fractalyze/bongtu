import type { ReactNode } from "react";
import { navigate } from "../hooks.js";
import { IconButton } from "./controls.js";
import { IconBack } from "./icons.js";

export function ScreenHeader({
  title,
  right,
}: {
  title: string;
  right?: ReactNode;
}): ReactNode {
  return (
    <header className="grid grid-cols-[1fr_auto_1fr] items-center">
      <IconButton
        className="justify-self-start"
        aria-label="Back"
        onClick={() => navigate("home")}
      >
        <IconBack />
      </IconButton>
      <h1 className="text-[1.05rem] [font-weight:650] text-center">{title}</h1>
      <div className="flex justify-end">{right}</div>
    </header>
  );
}
