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

export function Onboarding(): ReactNode {
  const { connectWallet, connecting, connectError } = useWallet();
  return (
    <div className="onboarding">
      <div className="onboarding-hero">
        <span className="onboarding-logo">
          <EnvelopeLogo size={52} />
        </span>
        <h1 className="onboarding-title">bongtu</h1>
        <p className="onboarding-tag">The privacy wallet for kKRW on GIWA.</p>
        <span className="testnet-tag onboarding-testnet">Testnet</span>
      </div>

      <ol className="onboarding-steps">
        <li className="onboarding-step">
          <span className="onboarding-step-icon">
            <IconWallet size={18} />
          </span>
          <span>
            <strong>Get kKRW</strong> — mint free test kKRW here.
          </span>
        </li>
        <li className="onboarding-step">
          <span className="onboarding-step-icon">
            <IconDeposit size={18} />
          </span>
          <span>
            <strong>Deposit</strong> — it becomes private kKRW.
          </span>
        </li>
        <li className="onboarding-step">
          <span className="onboarding-step-icon">
            <IconSend size={18} />
          </span>
          <span>
            <strong>Send &amp; withdraw</strong> — nothing revealed.
          </span>
        </li>
      </ol>

      {connectError && <div className="banner banner-err">{connectError}</div>}

      {hasInjectedWallet() ? (
        <button className="btn btn-primary btn-block btn-lg" onClick={connectWallet} disabled={connecting}>
          {connecting ? "Connecting…" : "Connect Wallet"}
        </button>
      ) : (
        // No injected provider (plain mobile browser, or desktop without the
        // extension): the deep link reopens this page inside MetaMask Mobile's
        // dapp browser, where the normal connect flow works.
        <>
          <a className="btn btn-primary btn-block btn-lg onboarding-deeplink" href={metamaskDeepLink()}>
            Open in MetaMask app
          </a>
          <p className="hint onboarding-nowallet">
            On mobile this opens the MetaMask app; on desktop, install the MetaMask extension
            and reload.
          </p>
        </>
      )}
      <p className="onboarding-fine">Self-custody wallet. Your privacy, guaranteed by proofs.</p>
    </div>
  );
}
