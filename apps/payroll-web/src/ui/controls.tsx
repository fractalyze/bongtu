// The repeated console control looks as React components (utilities-first
// Tailwind: variant props instead of CSS class families). Screen-specific
// layout stays inline in the view JSX.

import type { ButtonHTMLAttributes, ReactNode } from "react";

const BUTTON_CLS = {
  primary: "bg-accent text-white border-0 px-4 py-2 rounded-lg cursor-pointer font-semibold hover:brightness-110",
  small:
    "bg-panel2 text-fg border border-line px-2.5 py-1 rounded-lg cursor-pointer text-xs hover:border-accent",
} as const;

export function Button({
  variant = "primary",
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: keyof typeof BUTTON_CLS }): ReactNode {
  return <button className={`${BUTTON_CLS[variant]} ${className}`.trim()} {...rest} />;
}

// One padding per variant, chosen up front: two conflicting px-*/py-* utilities
// on one element resolve by generated-stylesheet order, not author order.
const CONTROL_CLS =
  "bg-panel2 text-fg border border-line rounded-lg px-2.5 py-2 text-[13px] font-mono w-full " +
  "focus:outline-none focus:border-accent";
const CONTROL_COMPACT_CLS =
  "bg-panel2 text-fg border border-line rounded-lg px-2 py-1 text-[13px] font-mono w-full " +
  "focus:outline-none focus:border-accent";

export function TextInput({
  value,
  onChange,
  placeholder = "",
  compact = false,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  compact?: boolean;
}): ReactNode {
  return (
    <input
      type="text"
      className={compact ? CONTROL_COMPACT_CLS : CONTROL_CLS}
      value={value}
      placeholder={placeholder}
      spellCheck={false}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}

export function TextArea({
  value,
  onChange,
  rows = 4,
  placeholder = "",
}: {
  value: string;
  onChange: (v: string) => void;
  rows?: number;
  placeholder?: string;
}): ReactNode {
  return (
    <textarea
      className={`${CONTROL_CLS} resize-y`}
      value={value}
      rows={rows}
      placeholder={placeholder}
      spellCheck={false}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}

export function Field({
  label,
  hint,
  className = "",
  children,
}: {
  label: string;
  hint?: string;
  className?: string;
  children: ReactNode;
}): ReactNode {
  return (
    <label className={`flex flex-col gap-1 my-2 ${className}`.trim()}>
      <span className="text-xs text-muted">{label}</span>
      {children}
      {hint && <span className="text-[11px] text-muted italic">{hint}</span>}
    </label>
  );
}

/** A one-line operation status; `link` renders the explorer anchor next to it. */
export interface StatusMsg {
  kind: "ok" | "err" | "info";
  text: string;
  link?: { href: string; label: string };
}

const STATUS_CLS: Record<StatusMsg["kind"], string> = {
  ok: "px-3 py-2 rounded-lg text-xs bg-ok/10 text-ok border border-ok/35",
  err: "px-3 py-2 rounded-lg text-xs bg-err/10 text-err border border-err/35",
  info: "px-3 py-2 rounded-lg text-xs bg-panel2 text-muted border border-line",
};

export function Status({ msg }: { msg: StatusMsg | null }): ReactNode {
  if (!msg) return null;
  return (
    <div className="my-2.5">
      <div className={STATUS_CLS[msg.kind]}>
        {msg.text}
        {msg.link && (
          <a className="text-accent ml-2.5" href={msg.link.href} target="_blank" rel="noreferrer">
            {msg.link.label}
          </a>
        )}
      </div>
    </div>
  );
}

export function Section({ title, children }: { title: string; children: ReactNode }): ReactNode {
  return (
    <section className="bg-panel border border-line rounded-xl p-4">
      <h3 className="mb-3 text-[15px] font-semibold">{title}</h3>
      {children}
    </section>
  );
}

export function H4({ children }: { children: ReactNode }): ReactNode {
  return (
    <h4 className="mt-4 mb-2 text-[13px] text-muted uppercase tracking-[0.04em] font-semibold">{children}</h4>
  );
}

export function Note({ children }: { children: ReactNode }): ReactNode {
  return <p className="text-xs text-muted my-2">{children}</p>;
}

export function JsonPane({ text }: { text: string }): ReactNode {
  return (
    <pre className="bg-pane border border-line rounded-lg p-3 font-mono text-[11px] max-h-[340px] overflow-auto whitespace-pre">
      {text}
    </pre>
  );
}

const CELL_CLS = "text-left px-2 py-1.5 border-b border-line align-top";

export function Table({ children }: { children: ReactNode }): ReactNode {
  return (
    <table className="border-collapse w-full text-xs">
      <tbody>{children}</tbody>
    </table>
  );
}

export function Th({ children }: { children?: ReactNode }): ReactNode {
  return <th className={`${CELL_CLS} text-muted font-semibold`}>{children}</th>;
}

export function Td({ cls = "", children }: { cls?: string; children?: ReactNode }): ReactNode {
  return <td className={`${CELL_CLS} ${cls}`.trim()}>{children}</td>;
}

/** key/value row: muted fixed-width key, mono break-all value. */
export function KvRow({ k, v }: { k: string; v: string }): ReactNode {
  return (
    <tr>
      <Td cls="text-muted w-[200px]">{k}</Td>
      <Td cls="font-mono break-all">{v}</Td>
    </tr>
  );
}

/** Human-readable message from wallet/RPC failures — MetaMask's ProviderRpcError
 *  and viem's layered errors are plain objects, so `String(e)` shows
 *  "[object Object]". */
export function errText(e: unknown): string {
  const o = e as {
    code?: number | string;
    reason?: string;
    message?: string;
    error?: { message?: string };
    data?: { message?: string };
  } | null;
  if (o?.code === 4001 || o?.code === "ACTION_REJECTED") return "Transaction rejected in your wallet.";
  const raw = o?.reason ?? o?.error?.message ?? o?.data?.message ?? o?.message;
  if (raw) return raw;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}
