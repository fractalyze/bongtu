// First run: a single Connect CTA. Connecting is ONE flow — MetaMask connect, the
// deterministic eth_signTypedData_v4 signature, and bjj key derivation happen back to
// back (App.connectWallet), so the user sees one button and lands on Home with a key.
// Nothing is persisted: the spending key is re-derived from the signature each session.

import type { ReactNode } from "react";
import { useWallet } from "../App.js";

export function Onboarding(): ReactNode {
  const { connectWallet, connecting, connectError } = useWallet();
  return (
    <div className="onboarding">
      <div className="onboarding-hero">
        <div className="mark">◈</div>
        <h1 className="onboarding-title">bongtu</h1>
        <p className="onboarding-tag">Self-custody private kKRW on GIWA.</p>
      </div>

      <ul className="onboarding-points">
        <li>
          <span className="pt-glyph">🔑</span> Your spending key is derived from your wallet
          signature — never stored, never sent.
        </li>
        <li>
          <span className="pt-glyph">◈</span> Balances and amounts stay private on-chain.
        </li>
        <li>
          <span className="pt-glyph">⚡</span> Proofs are generated on your device.
        </li>
      </ul>

      {connectError && <div className="banner banner-err">{connectError}</div>}

      <button className="btn btn-primary btn-block btn-lg" onClick={connectWallet} disabled={connecting}>
        {connecting ? "Connecting…" : "Connect wallet"}
      </button>
      <p className="onboarding-fine">
        You'll be asked to sign a message to derive your spending key. Only sign inside the
        official bongtu wallet.
      </p>
    </div>
  );
}
