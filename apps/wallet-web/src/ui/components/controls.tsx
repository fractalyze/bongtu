// The repeated control looks as React components (utilities-first Tailwind: variant
// props instead of a CSS class family). Everything screen-specific stays inline in
// the screen's JSX; only looks used across MANY files live here.

import type { ButtonHTMLAttributes, ReactNode } from "react";

type ButtonVariant = "primary" | "ghost" | "danger";
type ButtonSize = "md" | "lg" | "sm";

const BUTTON_BASE =
  "rounded-xl border border-transparent font-semibold cursor-pointer transition-colors " +
  "disabled:opacity-45 disabled:cursor-not-allowed";
const BUTTON_VARIANT: Record<ButtonVariant, string> = {
  primary: "bg-primary text-primary-ink enabled:hover:bg-primary-hover",
  ghost: "bg-surface border-border enabled:hover:border-border-strong",
  danger: "bg-surface border-err text-err",
};
const BUTTON_SIZE: Record<ButtonSize, string> = {
  md: "px-4 py-3 text-[0.95rem]",
  lg: "px-4.5 py-[15px] text-[1.02rem]",
  sm: "px-2.5 py-1.5 text-[0.82rem]",
};

export function Button({
  variant = "ghost",
  size = "md",
  block = false,
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  size?: ButtonSize;
  block?: boolean;
}): ReactNode {
  const cls = [BUTTON_BASE, BUTTON_VARIANT[variant], BUTTON_SIZE[size], block ? "w-full" : "", className]
    .filter(Boolean)
    .join(" ");
  return <button className={cls} {...rest} />;
}

/** Text-only action (Back, Settings, View all). */
export function LinkButton({
  small = false,
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { small?: boolean }): ReactNode {
  const cls = [
    "bg-transparent border-0 p-0 text-primary font-semibold cursor-pointer font-sans disabled:opacity-50 disabled:cursor-not-allowed",
    small ? "text-[0.78rem]" : "text-[0.88rem]",
    className,
  ]
    .filter(Boolean)
    .join(" ");
  return <button className={cls} {...rest} />;
}

/** Icon-only action (gear, copy, modal X) — padded hit area beyond the line icon. */
export function IconButton({
  ok = false,
  small = false,
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { ok?: boolean; small?: boolean }): ReactNode {
  const cls = [
    "bg-transparent border-0 cursor-pointer inline-flex items-center justify-center rounded-lg transition-colors hover:bg-surface-2",
    small ? "p-1" : "p-[5px]",
    ok ? "text-pos" : "text-primary",
    className,
  ]
    .filter(Boolean)
    .join(" ");
  return <button className={cls} {...rest} />;
}

export function TestnetTag({ className = "" }: { className?: string }): ReactNode {
  return (
    <span
      className={`text-[0.68rem] font-bold uppercase tracking-[0.06em] text-warn bg-warn-bg border border-warn-border rounded-full px-2 py-0.5 ${className}`.trim()}
    >
      Testnet
    </span>
  );
}
