// The one "View on explorer" link. Always carries the external-link icon, so a link
// that leaves the wallet for the block explorer looks the same everywhere it appears.

import type { ReactNode } from "react";
import { IconExternalLink } from "./icons.js";

export function ExplorerLink({
  href,
  label = "View on explorer",
}: {
  href: string;
  label?: string;
}): ReactNode {
  return (
    <a
      className="text-primary no-underline text-[0.9rem] font-semibold inline-flex items-center gap-1.5"
      href={href}
      target="_blank"
      rel="noreferrer"
    >
      {label}
      <IconExternalLink size={14} />
    </a>
  );
}
