// First run: a compact centered hero, three one-line steps, and a single Connect
// CTA. Connecting is ONE flow — MetaMask connect, the deterministic
// eth_signTypedData_v4 signature, and bjj key derivation happen back to back
// (App.connectWallet), so the user sees one button and lands on Home with a key.
// Copy is deliberately short and non-technical (locked after a diagram round —
// the user prefers text, one clause per step): never key/proof mechanics here.

import type { ReactNode } from "react";
import { useWallet } from "../App.js";
import { hasInjectedWallet, metamaskDeepLink } from "../../lib/metamask.js";
import { EnvelopeLogo, IconDeposit, IconSend, IconWallet } from "../components/icons.js";
import { Button, TestnetTag } from "../components/controls.js";

export function Onboarding(): ReactNode {
  const { connectWallet, connecting, connectError } = useWallet();
  return (
    <div className="px-5.5 py-6.5 flex flex-col justify-center gap-4 flex-1 bg-bg">
      <div className="text-center mb-2">
        <span className="inline-flex text-primary">
          <EnvelopeLogo size={52} />
        </span>
        <h1 className="text-[2rem] leading-tight font-bold mb-1 tracking-[-0.02em] text-primary">bongtu</h1>
        <p className="text-muted">The privacy wallet for kKRW on GIWA.</p>
        <TestnetTag className="inline-block mt-2" />
      </div>

      <ol className="list-none flex flex-col gap-3 p-3.5 bg-surface border border-border rounded-xl">
        <li className="flex gap-2.5 items-center text-[0.9rem] text-muted">
          <span className="inline-flex shrink-0 text-primary">
            <IconWallet size={18} />
          </span>
          <span>
            <strong className="text-ink">Get kKRW</strong> — mint free test kKRW here.
          </span>
        </li>
        <li className="flex gap-2.5 items-center text-[0.9rem] text-muted">
          <span className="inline-flex shrink-0 text-primary">
            <IconDeposit size={18} />
          </span>
          <span>
            <strong className="text-ink">Deposit</strong> — it becomes private kKRW.
          </span>
        </li>
        <li className="flex gap-2.5 items-center text-[0.9rem] text-muted">
          <span className="inline-flex shrink-0 text-primary">
            <IconSend size={18} />
          </span>
          <span>
            <strong className="text-ink">Send &amp; withdraw</strong> — nothing revealed.
          </span>
        </li>
      </ol>

      {connectError && (
        <div className="rounded-xl px-3.5 py-3 text-[0.88rem] flex gap-2.5 items-center justify-between flex-wrap border border-err-border bg-err-bg text-err">
          {connectError}
        </div>
      )}

      {hasInjectedWallet() ? (
        <Button variant="primary" size="lg" block onClick={connectWallet} disabled={connecting}>
          {connecting ? "Connecting…" : "Connect Wallet"}
        </Button>
      ) : (
        // No injected provider (plain mobile browser, or desktop without the
        // extension): the deep link reopens this page inside MetaMask Mobile's
        // dapp browser, where the normal connect flow works.
        <>
          <a
            className="block w-full rounded-xl border border-transparent bg-primary text-primary-ink px-4.5 py-[15px] text-[1.02rem] font-semibold cursor-pointer transition-colors hover:bg-primary-hover text-center no-underline"
            href={metamaskDeepLink()}
          >
            Open in MetaMask app
          </a>
          <p className="text-sm text-muted text-center">
            On mobile this opens the MetaMask app; on desktop, install the MetaMask extension
            and reload.
          </p>
        </>
      )}
      <p className="text-[0.8rem] text-muted text-center">
        Self-custody wallet. Your privacy, guaranteed by proofs.
      </p>
    </div>
  );
}
