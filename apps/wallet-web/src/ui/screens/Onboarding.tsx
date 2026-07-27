// First run: a compact centered hero, the ConceptFlow diagram (the whole pitch —
// no explainer paragraphs), and a single Connect CTA. Connecting is ONE flow —
// MetaMask connect, the deterministic eth_signTypedData_v4 signature, and bjj key
// derivation happen back to back (App.connectWallet), so the user sees one button
// and lands on Home with a key. Copy stays non-technical: never key/proof
// mechanics on this screen.

import type { ReactNode } from "react";
import { useWallet } from "../App.js";
import { EnvelopeLogo } from "../components/icons.js";
import { ConceptFlow } from "../components/ConceptFlow.js";

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

      <ConceptFlow />

      {connectError && <div className="banner banner-err">{connectError}</div>}

      <button className="btn btn-primary btn-block btn-lg" onClick={connectWallet} disabled={connecting}>
        {connecting ? "Connecting…" : "Connect Wallet"}
      </button>
      <p className="onboarding-fine">Self-custody wallet. Your privacy, guaranteed by proofs.</p>
    </div>
  );
}
