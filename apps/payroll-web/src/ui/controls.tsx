// The repeated console control looks as React components (utilities-first
// Tailwind on the wallet's shared token palette: surface cards, ink text, ONE
// primary). Screen-specific layout stays inline in the view JSX.

import type { ButtonHTMLAttributes, ReactNode } from "react";

const BUTTON_CLS = {
  primary:
    "bg-primary text-primary-ink border-0 px-4 py-2 rounded-xl cursor-pointer font-semibold " +
    "hover:bg-primary-hover disabled:opacity-40 disabled:cursor-not-allowed transition-colors",
  secondary:
    "bg-surface text-ink border border-border px-3 py-1.5 rounded-xl cursor-pointer text-[13px] " +
    "font-medium hover:border-border-strong disabled:opacity-40 disabled:cursor-not-allowed transition-colors",
  ghost:
    "bg-transparent text-muted border-0 px-2 py-1 rounded-lg cursor-pointer text-[13px] " +
    "hover:text-ink disabled:opacity-40 transition-colors",
  // Secondary's shape in the warn palette: the session card's [Deposit] wears it
  // while the sheet is short, so the fix is visible where the money is, without a
  // second primary competing with [Send].
  warn:
    "bg-warn-bg text-warn border border-warn-border px-3 py-1.5 rounded-xl cursor-pointer text-[13px] " +
    "font-semibold hover:border-warn disabled:opacity-40 disabled:cursor-not-allowed transition-colors",
} as const;

export function Button({
  variant = "primary",
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: keyof typeof BUTTON_CLS }): ReactNode {
  return <button type="button" className={`${BUTTON_CLS[variant]} ${className}`.trim()} {...rest} />;
}

/** The busy indicator a button shows while its action runs (connect, generate,
 *  mint, the deposit's staged run). Drawn in `currentColor` so it stays visible on
 *  every variant — a white-inked spinner is invisible on the white secondary. */
export function Spinner(): ReactNode {
  return (
    <span
      aria-hidden
      className="inline-block w-3.5 h-3.5 mr-1.5 rounded-full border-2 border-current/40 border-t-current animate-spin align-[-2px]"
    />
  );
}

/** One worksheet/deposit text cell. `invalid` paints the error border the
 *  inline row message explains. */
export function CellInput({
  value,
  onChange,
  placeholder = "",
  invalid = false,
  mono = false,
  align = "left",
  ariaLabel,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  invalid?: boolean;
  mono?: boolean;
  align?: "left" | "right";
  ariaLabel?: string;
}): ReactNode {
  return (
    <input
      type="text"
      aria-label={ariaLabel}
      className={
        `w-full bg-surface border rounded-lg px-2.5 py-1.5 text-[13px] focus:outline-none ` +
        `${mono ? "font-mono " : ""}${align === "right" ? "text-right tabular-nums " : ""}` +
        `${invalid ? "border-err-border bg-err-bg" : "border-border focus:border-border-strong"}`
      }
      value={value}
      placeholder={placeholder}
      spellCheck={false}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}

export function Stat({ label, value, tone = "ink" }: { label: string; value: ReactNode; tone?: "ink" | "pos" | "err" }): ReactNode {
  const toneCls = tone === "pos" ? "text-pos" : tone === "err" ? "text-err" : "text-ink";
  return (
    <div className="flex flex-col gap-0.5 min-w-0">
      <span className="text-[11px] text-muted">{label}</span>
      <span className={`text-[15px] font-semibold tabular-nums truncate ${toneCls}`}>{value}</span>
    </div>
  );
}

/** The TESTNET badge pill — sits next to the brand on BOTH the login page and
 *  the console header: this whole console is a testnet tool, and the badge is
 *  how every screen says so. */
export function TestnetBadge(): ReactNode {
  return (
    <span className="text-[10px] font-semibold tracking-[0.08em] text-warn bg-warn-bg border border-warn-border rounded-full px-2 py-0.5 self-center">
      TESTNET
    </span>
  );
}

/** 0x1234…abcd — the header's pool/account short form. */
export function shortHex(v: string, head = 6, tail = 4): string {
  return v.length <= head + tail + 2 ? v : `${v.slice(0, head + 2)}…${v.slice(-tail)}`;
}
