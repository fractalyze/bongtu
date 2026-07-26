// The single hand-drawn line-icon set (locked visual language): stroke-only SVGs on
// currentColor so icons inherit text color, one shared 24-viewBox frame so weights
// match everywhere. Text glyph characters and emoji stay banned — any pictograph the
// UI needs must come from here.

import type { ReactNode } from "react";

function Frame({
  size,
  strokeWidth = 1.6,
  className,
  children,
}: {
  size: number;
  strokeWidth?: number;
  className?: string;
  children: ReactNode;
}): ReactNode {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={className}
    >
      {children}
    </svg>
  );
}

/** The brand mark: an OPENED envelope (봉투) in minimal strokes — raised flap over a
 *  plain body. No interior fold: the top-anchored V is the CLOSED-envelope seal
 *  glyph, and at 20–28px it fused with the rect's top edge into a smudge. Slightly
 *  heavier stroke than the utility icons so it reads as a logo at small sizes. */
export function EnvelopeLogo({ size = 28, className }: { size?: number; className?: string }): ReactNode {
  return (
    <Frame size={size} strokeWidth={1.75} className={className}>
      <path d="M5.2 10.5 12 4.2l6.8 6.3" />
      <rect x="4" y="10.5" width="16" height="9.5" rx="1.8" />
    </Frame>
  );
}

export function IconGear({ size = 20 }: { size?: number }): ReactNode {
  return (
    <Frame size={size}>
      <circle cx="12" cy="12" r="6.4" />
      <circle cx="12" cy="12" r="2.5" />
      <path d="M12 3.2v2.4M12 18.4v2.4M3.2 12h2.4M18.4 12h2.4M5.8 5.8l1.7 1.7M16.5 16.5l1.7 1.7M18.2 5.8l-1.7 1.7M7.5 16.5l-1.7 1.7" />
    </Frame>
  );
}

export function IconLink({ size = 16 }: { size?: number }): ReactNode {
  return (
    <Frame size={size}>
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
    </Frame>
  );
}

export function IconWallet({ size = 16 }: { size?: number }): ReactNode {
  return (
    <Frame size={size}>
      <rect x="3" y="6" width="18" height="13" rx="2" />
      <path d="M16.5 6V4.8A1.3 1.3 0 0 0 15.2 3.5H6.5" />
      <path d="M21 12h-4a1.7 1.7 0 0 0 0 3.4h4" />
    </Frame>
  );
}

export function IconSend({ size = 18 }: { size?: number }): ReactNode {
  return (
    <Frame size={size}>
      <path d="M22 2 11 13" />
      <path d="M22 2l-7 20-4-9-9-4 20-7z" />
    </Frame>
  );
}

export function IconWithdraw({ size = 18 }: { size?: number }): ReactNode {
  return (
    <Frame size={size}>
      <path d="M12 4v10m0 0-4-4m4 4 4-4M5 19h14" />
    </Frame>
  );
}

export function IconDeposit({ size = 18 }: { size?: number }): ReactNode {
  return (
    <Frame size={size}>
      <path d="M12 5v14M5 12h14" />
    </Frame>
  );
}

export function IconCopy({ size = 16 }: { size?: number }): ReactNode {
  return (
    <Frame size={size}>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5 15h-.5A1.5 1.5 0 0 1 3 13.5v-9A1.5 1.5 0 0 1 4.5 3h9A1.5 1.5 0 0 1 15 4.5V5" />
    </Frame>
  );
}

export function IconCheck({ size = 16 }: { size?: number }): ReactNode {
  return (
    <Frame size={size}>
      <path d="M5 12.5l4.5 4.5L19 7.5" />
    </Frame>
  );
}

export function IconClose({ size = 18 }: { size?: number }): ReactNode {
  return (
    <Frame size={size}>
      <path d="M6 6l12 12M18 6 6 18" />
    </Frame>
  );
}
