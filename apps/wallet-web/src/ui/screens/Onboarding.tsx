// First run: a compact centered hero, the three-step "how this wallet works"
// explainer, and a single Connect CTA. Connecting is ONE flow — MetaMask connect,
// the deterministic eth_signTypedData_v4 signature, and bjj key derivation happen
// back to back (App.connectWallet), so the user sees one button and lands on Home
// with a key. Copy stays non-technical: the explainer sells the kKRW → private
// kKRW mental model (2026-07-27 user ask — first-time visitors couldn't tell what
// to do), never key/proof mechanics.

import type { ReactNode } from "react";
import { useWallet } from "../App.js";
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
      </div>

      <ol className="onboarding-steps">
        <li className="onboarding-step">
          <span className="onboarding-step-icon">
            <IconWallet size={18} />
          </span>
          <span>
            <strong>Get kKRW.</strong> On testnet you can mint free test kKRW right from this
            wallet.
          </span>
        </li>
        <li className="onboarding-step">
          <span className="onboarding-step-icon">
            <IconDeposit size={18} />
          </span>
          <span>
            <strong>Deposit it.</strong> Depositing turns public kKRW into private kKRW only
            you control.
          </span>
        </li>
        <li className="onboarding-step">
          <span className="onboarding-step-icon">
            <IconSend size={18} />
          </span>
          <span>
            <strong>Use it freely.</strong> Send and withdraw privately — amounts and
            recipients stay hidden.
          </span>
        </li>
      </ol>

      {connectError && <div className="banner banner-err">{connectError}</div>}

      <button className="btn btn-primary btn-block btn-lg" onClick={connectWallet} disabled={connecting}>
        {connecting ? "Connecting…" : "Connect Wallet"}
      </button>
      <p className="onboarding-fine">Self-custody wallet. Your privacy, guaranteed by proofs.</p>
    </div>
  );
}
