// The service login — the console's only other screen. An id/password form
// whose credentials are REAL prover-service credentials (lib/serviceAuth.ts →
// GET /auth/check), not UI theater. The wallet is NOT connected here: MetaMask
// lives inside the Console, where the actions that need it are.
//
// Copy is deliberately minimal (LOCKED): brand + TESTNET badge + the two-line
// test-console tagline + the form.
// The hero is an inline SVG on the shared CSS tokens (no external assets): the
// brand envelope chip fanning out to many small notes — the product in one
// picture, one funding note privately paying a whole payroll. A hand-drawn
// "prettier" pay envelope was tried and rejected as clutter (2026-07-30): the
// source must be the SAME mark as the favicon/wordmark, nothing more.

import { useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { TestnetBadge } from "./controls.js";

/** The payroll hero: the brand envelope chip on the left, a fan of pay-flow
 *  lines to a column of recipient notes on the right. Token-driven colors only. */
function PayrollHero(): ReactNode {
  // Fan geometry precomputed so the JSX stays a plain list of paths.
  const targets = [26, 52, 78, 104, 130];
  return (
    <svg
      viewBox="0 0 360 156"
      role="img"
      aria-label="A pay envelope paying out to many recipients"
      className="w-full max-w-[360px] h-auto"
    >
      {/* the source: the brand mark itself (the favicon's rounded chip + Remix
          ri-mail-open-line), scaled 3x — a drawn "prettier" envelope kept
          reading as clutter here (user feedback), the icon is the identity */}
      <g transform="translate(30,48)">
        <rect width="72" height="72" rx="16.5" fill="var(--color-primary)" />
        <path
          transform="translate(9.3 9.3) scale(2.22)"
          fill="var(--color-primary-ink)"
          d="M2.24283 6.85435L11.4895 1.3086C11.8062 1.11865 12.2019 1.11872 12.5185 1.30878L21.7573 6.85433C21.9079 6.9447 22 7.10743 22 7.28303V20C22 20.5523 21.5523 21 21 21H3C2.44772 21 2 20.5523 2 20V7.28315C2 7.10748 2.09218 6.94471 2.24283 6.85435ZM4 8.13261V19H20V8.13214L12.0037 3.33237L4 8.13261ZM12.0597 13.6983L17.3556 9.23532L18.6444 10.7647L12.074 16.3017L5.36401 10.7717L6.63599 9.2283L12.0597 13.6983Z"
        />
      </g>
      {/* pay-flow fan: one source, many destinations */}
      {targets.map((y) => (
        <path
          key={y}
          d={`M104 84 C 170 84, 198 ${y}, 252 ${y}`}
          fill="none"
          stroke="var(--color-border-strong)"
          strokeWidth="1.6"
          strokeDasharray="4 5"
          strokeLinecap="round"
        />
      ))}
      {/* recipient notes (a ledger column) */}
      {targets.map((y, i) => (
        <g key={y} transform={`translate(252, ${y - 10})`}>
          <rect width="86" height="20" rx="6" fill="var(--color-surface)" stroke="var(--color-border)" strokeWidth="1.4" />
          <circle cx="12" cy="10" r="4.5" fill={i === 2 ? "var(--color-pos)" : "var(--color-primary)"} opacity={i === 2 ? 1 : 0.85} />
          <rect x="22" y="7" width={i % 2 ? 34 : 44} height="6" rx="3" fill="var(--color-surface-2)" />
        </g>
      ))}
    </svg>
  );
}

const FIELD_CLS =
  "w-full bg-surface border border-border rounded-xl px-3 py-2.5 text-[14px] " +
  "focus:outline-none focus:border-border-strong";

export function Login({
  onSignIn,
  busy,
  error,
}: {
  onSignIn: (id: string, password: string) => void;
  busy: boolean;
  error: string | null;
}): ReactNode {
  const [id, setId] = useState("");
  const [password, setPassword] = useState("");
  const submit = (e: FormEvent): void => {
    e.preventDefault();
    if (!busy) onSignIn(id, password);
  };
  return (
    <div className="min-h-full flex items-center justify-center p-6">
      <form
        onSubmit={submit}
        className="w-full max-w-[420px] bg-surface border border-border rounded-2xl p-8 flex flex-col items-center gap-5 text-center shadow-[0_8px_28px_-18px_rgba(17,24,39,0.18)]"
      >
        <div className="flex items-center gap-2">
          <span className="text-2xl font-bold text-primary">Bongtu</span>
          <span className="text-2xl font-bold">Payroll Tool</span>
          <TestnetBadge />
        </div>
        <div className="-mt-2">
          <p className="text-[15px] font-semibold">A test console for batch payroll</p>
          <p className="text-[13px] text-muted mt-0.5">
            Pay up to 255 recipients in a single private transaction.
          </p>
        </div>
        <PayrollHero />
        <label className="w-full flex flex-col gap-1 text-left">
          <span className="text-[11px] text-muted">ID</span>
          <input
            type="text"
            className={FIELD_CLS}
            autoComplete="username"
            autoFocus
            spellCheck={false}
            value={id}
            onChange={(e) => setId(e.target.value)}
          />
        </label>
        <label className="w-full flex flex-col gap-1 text-left">
          <span className="text-[11px] text-muted">Password</span>
          <input
            type="password"
            className={FIELD_CLS}
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <button
          type="submit"
          disabled={busy}
          className="w-full bg-primary text-primary-ink rounded-xl px-4 py-3 font-semibold cursor-pointer hover:bg-primary-hover disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
        {error && (
          <p role="alert" className="text-[13px] text-err bg-err-bg border border-err-border rounded-xl px-3 py-2 w-full">
            {error}
          </p>
        )}
      </form>
    </div>
  );
}
