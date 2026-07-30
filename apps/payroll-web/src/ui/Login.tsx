// The service login — the console's only other screen. An id/password form
// whose credentials are REAL prover-service credentials (lib/serviceAuth.ts →
// GET /auth/check), not UI theater. The wallet is NOT connected here: MetaMask
// lives inside the Console, where the actions that need it are.
//
// Copy is deliberately minimal (LOCKED, revised 2026-07-30): the text wordmark
// row is GONE — the envelope hero IS the brand on this screen (user decision);
// the TESTNET badge rides the tagline instead. The hero is an inline SVG on
// the shared CSS tokens (no external assets): a shield-marked pay envelope
// fanning out to many small notes — the product in one picture, one funding
// note privately paying a whole payroll.

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
      {/* pay envelope (월급봉투): an upright open pocket with banknotes rising
          out — not a mail letter. Draw order is depth order: shadow, inner
          back, bills, then the front pocket overlapping the bills' base. */}
      <g>
        {/* ground shadow so the envelope sits ON the card, not floats */}
        <ellipse cx="66" cy="118" rx="38" ry="5" fill="var(--color-ink)" opacity="0.07" />
        {/* the pocket's inner back wall, visible through the open mouth */}
        <rect x="34" y="48" width="64" height="30" rx="6" fill="var(--color-primary)" opacity="0.16" />
        {/* banknotes, fanned: back bill plain, front bill carries the ₩ seal */}
        <g transform="translate(38,26) rotate(-9 23 14)">
          <rect width="46" height="28" rx="4" fill="var(--color-pos-bg)" stroke="var(--color-pos)" strokeWidth="1.8" />
          <rect x="4" y="4" width="38" height="20" rx="2.5" fill="none" stroke="var(--color-pos)" strokeWidth="1" opacity="0.45" />
        </g>
        <g transform="translate(52,20) rotate(6 23 14)">
          <rect width="46" height="28" rx="4" fill="var(--color-surface)" stroke="var(--color-pos)" strokeWidth="1.8" />
          <rect x="4" y="4" width="38" height="20" rx="2.5" fill="none" stroke="var(--color-pos)" strokeWidth="1" opacity="0.45" />
          <circle cx="23" cy="14" r="7.5" fill="var(--color-pos-bg)" stroke="var(--color-pos)" strokeWidth="1.4" />
          <text x="23" y="18.5" textAnchor="middle" fontSize="11" fontWeight="700" fill="var(--color-pos)">₩</text>
        </g>
        {/* front pocket: two-tone — a filled body with a lighter top lip so the
            mouth reads as an opening, and the classic diagonal front folds */}
        <path
          d="M32 63 Q32 56 39 56 H93 Q100 56 100 63 V105 Q100 112 93 112 H39 Q32 112 32 105 Z"
          fill="var(--color-surface)"
          stroke="var(--color-primary)"
          strokeWidth="2.5"
        />
        {/* diagonal folds meeting at the seam — what makes it a pay envelope */}
        <path d="M33 62 L66 88 L99 62" fill="var(--color-primary)" opacity="0.08" />
        <path d="M33 62 L66 88 L99 62" fill="none" stroke="var(--color-primary)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" opacity="0.5" />
        {/* top lip highlight: the mouth's front edge */}
        <path d="M36 58.5 Q39 58 42 58 H90 Q95 58 96 58.5" fill="none" stroke="var(--color-border-strong)" strokeWidth="1.6" strokeLinecap="round" />
        {/* shield badge on the corner, ringed in surface so it pops off the fold */}
        <g transform="translate(82,92)">
          <path
            d="M17 1 L31 6.5 V17 C31 26.5 25.5 33.5 17 36.5 C8.5 33.5 3 26.5 3 17 V6.5 Z"
            fill="var(--color-primary)"
            stroke="var(--color-surface)"
            strokeWidth="2.5"
          />
          <path d="M11 18 L15.5 22.5 L23.5 13.5" fill="none" stroke="var(--color-primary-ink)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
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
        <PayrollHero />
        <div className="-mt-1">
          <p className="text-[15px] font-semibold inline-flex items-center gap-2">
            A test console for batch payroll <TestnetBadge />
          </p>
          <p className="text-[13px] text-muted mt-0.5">
            Pay up to 255 recipients in a single private transaction.
          </p>
        </div>
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
