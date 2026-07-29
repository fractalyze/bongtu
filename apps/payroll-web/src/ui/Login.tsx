// The service login — the console's only other screen. An id/password form
// whose credentials are REAL prover-service credentials (lib/serviceAuth.ts →
// GET /auth/check), not UI theater. The wallet is NOT connected here: MetaMask
// lives inside the Console, where the actions that need it are.
//
// Copy is deliberately minimal (LOCKED): brand + TESTNET badge + the two-line
// test-console tagline + the form.
// The hero is an inline SVG on the shared CSS tokens (no external assets):
// a shield-marked envelope fanning out to many small notes — the product in one
// picture, one funding note privately paying a whole payroll.

import { useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { TestnetBadge } from "./controls.js";

/** The payroll hero: envelope+shield on the left, a fan of pay-flow lines to a
 *  column of recipient notes on the right. Token-driven colors only. */
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
      {/* pay envelope (월급봉투): an upright open envelope with banknotes peeking
          out the top — not a mail letter. Bills first so the pocket overlaps them. */}
      <g>
        {/* banknotes sticking out, slightly fanned */}
        <g transform="translate(40,30) rotate(-8 22 13)">
          <rect width="44" height="26" rx="3.5" fill="var(--color-surface)" stroke="var(--color-pos)" strokeWidth="2" />
          <circle cx="22" cy="13" r="6.5" fill="none" stroke="var(--color-pos)" strokeWidth="1.6" />
        </g>
        <g transform="translate(54,24) rotate(5 22 13)">
          <rect width="44" height="26" rx="3.5" fill="var(--color-surface)" stroke="var(--color-pos)" strokeWidth="2" />
          <circle cx="22" cy="13" r="6.5" fill="none" stroke="var(--color-pos)" strokeWidth="1.6" />
          <text x="22" y="17.5" textAnchor="middle" fontSize="11" fontWeight="700" fill="var(--color-pos)">₩</text>
        </g>
        {/* envelope pocket: portrait, open mouth at the top */}
        <rect x="32" y="56" width="68" height="56" rx="7" fill="var(--color-surface)" stroke="var(--color-primary)" strokeWidth="2.5" />
        {/* open mouth: the inner back edge the bills rise from */}
        <path d="M36 58 H96" stroke="var(--color-border-strong)" strokeWidth="2" strokeLinecap="round" />
        {/* the pocket's front seam — the classic pay-envelope fold line */}
        <path d="M32 72 C 52 80, 80 80, 100 72" fill="none" stroke="var(--color-primary)" strokeWidth="2" strokeLinecap="round" opacity="0.55" />
        {/* shield badge on the envelope's corner */}
        <g transform="translate(84,96)">
          <path
            d="M16 2 L28 7 V16 C28 24.5 23 30.5 16 33 C9 30.5 4 24.5 4 16 V7 Z"
            fill="var(--color-primary)"
          />
          <path d="M10.5 16.5 L14.5 20.5 L22 12.5" fill="none" stroke="var(--color-primary-ink)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
        </g>
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
      {/* the "…and 250 more" ellipsis dots under the column */}
      {[0, 1, 2].map((i) => (
        <circle key={i} cx={285 + i * 10} cy={146} r="1.8" fill="var(--color-muted)" />
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
