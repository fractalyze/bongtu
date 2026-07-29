// The repeated control looks as React components (utilities-first Tailwind: variant
// props instead of a CSS class family). Everything screen-specific stays inline in
// the screen's JSX; only looks used across MANY files live here.

import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from "react";
import { DEFAULTS } from "../../config.js";
import { amountCaretIndex, groupAmountInput } from "@bongtu/client/money";

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

/** Text-only action (Back, Settings, View all). `subtle` drops the weight for
 *  side actions that must read lighter than the label they sit next to. */
export function LinkButton({
  small = false,
  subtle = false,
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { small?: boolean; subtle?: boolean }): ReactNode {
  const cls = [
    "bg-transparent border-0 p-0 text-primary cursor-pointer font-sans disabled:opacity-50 disabled:cursor-not-allowed",
    subtle ? "font-normal" : "font-semibold",
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

/**
 * A labeled form row: label line (with an optional right-aligned slot — e.g. a light
 * side action), the control itself, then an optional muted hint and/or error line.
 * The wrapper is a <div>, not a <label>: the right slot can hold a BUTTON, and a
 * button inside a label also activates the labeled control on click.
 */
export function Field({
  label,
  right,
  hint,
  error,
  children,
}: {
  label: string;
  right?: ReactNode;
  hint?: ReactNode;
  error?: string | null;
  children: ReactNode;
}): ReactNode {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="flex items-baseline justify-between gap-2">
        <span className="text-[0.82rem] text-muted font-semibold">{label}</span>
        {right}
      </span>
      {children}
      {hint && <span className="text-[0.78rem] text-muted">{hint}</span>}
      {error && <span className="text-[0.8rem] text-err">{error}</span>}
    </div>
  );
}

const INPUT_BASE =
  "bg-surface border border-border rounded-xl px-3.5 py-[13px] text-ink text-[0.98rem] w-full " +
  "tabular-nums focus:outline-none focus:border-primary focus:shadow-[0_0_0_3px_rgba(18,58,92,0.12)]";

/** The one text-input look; `mono` for addresses/keys. */
export function TextInput({
  mono = false,
  className = "",
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }): ReactNode {
  const cls = [INPUT_BASE, mono ? "font-mono" : "", className].filter(Boolean).join(" ");
  return <input className={cls} {...rest} />;
}

/**
 * Amount entry: decimal keypad, live thousands-grouping while typing
 * (groupAmountInput strips junk and keeps a single decimal point, so the value
 * always stays parseKkrw-clean on the comma rule).
 */
export function AmountInput({
  value,
  onValueChange,
  ...rest
}: Omit<InputHTMLAttributes<HTMLInputElement>, "value" | "onChange"> & {
  value: string;
  onValueChange: (value: string) => void;
}): ReactNode {
  return (
    <TextInput
      inputMode="decimal"
      placeholder="0.00"
      value={value}
      onChange={(e) => {
        const input = e.target;
        let raw = input.value;
        const sel = input.selectionStart ?? raw.length;
        // Caret bookkeeping in SIGNIFICANT chars (digits + dot): regrouping
        // moves commas around, so the DOM caret index is meaningless after the
        // controlled re-render — re-place it after the same significant count.
        let significant = raw.slice(0, sel).replace(/[^\d.]/g, "").length;
        let next = groupAmountInput(raw);
        // Backspacing a comma deletes only the separator, which regroups back
        // to the SAME string — a visual no-op. Treat it as deleting the digit
        // left of the separator, which is what the keystroke meant.
        if (next === value && raw.length < value.length && significant > 0) {
          raw = raw.slice(0, sel - 1) + raw.slice(sel);
          significant -= 1;
          next = groupAmountInput(raw);
        }
        onValueChange(next);
        requestAnimationFrame(() => {
          const i = amountCaretIndex(next, significant);
          input.setSelectionRange(i, i);
        });
      }}
      {...rest}
    />
  );
}

/**
 * The one error banner. A gas-shaped message additionally links the official
 * GIWA faucet (testnet posture only) so a stuck first-timer has a next step.
 */
export function ErrorBanner({ message }: { message: string }): ReactNode {
  return (
    <div className="rounded-xl px-3.5 py-3 text-[0.88rem] flex gap-2.5 items-center justify-between flex-wrap border border-err-border bg-err-bg text-err">
      {message}
      {DEFAULTS.testnet && /GIWA Sepolia ETH/.test(message) && (
        <a
          className="font-semibold underline text-err"
          href={DEFAULTS.gasFaucet}
          target="_blank"
          rel="noreferrer"
        >
          Get GIWA Sepolia ETH from the faucet
        </a>
      )}
    </div>
  );
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
