// First run: a compact centered hero, three one-line steps, and the ways in — the
// installed extension, named after itself (walletBrand.ts), and WalletConnect when
// this build carries a project id. Whichever is pressed, connecting is ONE flow — the
// wallet connect, the deterministic eth_signTypedData_v4 signature, and bjj key
// derivation happen back to back (loginFlow.runLogin), so the user presses once and
// lands on Home with a key.
// Copy is deliberately short and non-technical (locked after a diagram round —
// the user prefers text, one clause per step): never key/proof mechanics here.

import type { ReactNode } from "react";
import { DEFAULTS } from "../../config.js";
import { useWallet } from "../App.js";
import { hasInjectedWallet, metamaskDeepLink } from "../../lib/metamask.js";
import { walletConnectEnabled } from "../../lib/walletconnect.js";
import {
  EnvelopeLogo,
  IconDeposit,
  IconSend,
  IconWallet,
  WalletConnectMark,
} from "../components/icons.js";
import { Button, ErrorBanner, TestnetTag } from "../components/controls.js";

export function Onboarding(): ReactNode {
  const { wallet, connectWallet, connecting, connectError } = useWallet();
  const connectLabel = wallet.named ? `Connect ${wallet.name}` : "Connect Wallet";
  const injected = hasInjectedWallet();
  // Absent VITE_WC_PROJECT_ID this is false at build time and the button below never
  // exists — the extension is the only way in, exactly as before (walletconnect.ts).
  const remote = walletConnectEnabled();
  return (
    <div className="px-5.5 py-6.5 flex flex-col justify-center gap-4 flex-1 bg-bg">
      {/* flex-col, not inline flow: an inline logo span sits on the text baseline
          and leaves descender space under the icon no margin utility removes. */}
      <div className="text-center mb-2 flex flex-col items-center gap-0.5">
        <span className="inline-flex text-primary">
          <EnvelopeLogo size={52} />
        </span>
        <h1 className="text-[2rem] leading-tight font-bold mb-1 tracking-[-0.02em] text-primary">bongtu</h1>
        <p className="text-muted">The privacy wallet for kKRW on GIWA.</p>
        {DEFAULTS.testnet && <TestnetTag className="inline-block mt-2" />}
      </div>

      <ol className="list-none flex flex-col gap-3 p-3.5 bg-surface border border-border rounded-xl">
        <li className="flex gap-2.5 items-center text-[0.9rem] text-muted">
          <span className="inline-flex shrink-0 text-primary">
            <IconWallet size={18} />
          </span>
          <span>
            {DEFAULTS.testnet ? (
              <>
                <strong className="text-ink">Get kKRW</strong> — mint free test kKRW here.
              </>
            ) : (
              <>
                <strong className="text-ink">Get kKRW</strong> — fund your account with kKRW.
              </>
            )}
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

      {connectError && <ErrorBanner message={connectError} />}

      {injected && (
        <Button
          variant="primary"
          size="lg"
          block
          onClick={() => connectWallet("injected")}
          disabled={connecting !== null}
        >
          {connecting === "injected" ? "Connecting…" : connectLabel}
        </Button>
      )}

      {remote && (
        // Primary when there is no extension to be the primary — that is the whole
        // point of the option: a phone wallet, or a desktop wallet with no extension.
        <Button
          variant={injected ? "ghost" : "primary"}
          size="lg"
          block
          onClick={() => connectWallet("walletconnect")}
          disabled={connecting !== null}
          className="inline-flex items-center justify-center gap-2"
        >
          <WalletConnectMark size={20} />
          {connecting === "walletconnect" ? "Connecting…" : "WalletConnect"}
        </Button>
      )}

      {!injected && (
        // No injected provider (plain mobile browser, or desktop without the
        // extension): the deep link reopens this page inside MetaMask Mobile's
        // dapp browser, where the normal connect flow works.
        <>
          <a
            className={
              "block w-full rounded-xl border px-4.5 py-[15px] text-[1.02rem] font-semibold " +
              "cursor-pointer transition-colors text-center no-underline " +
              (remote
                ? "border-border bg-surface text-ink hover:border-border-strong"
                : "border-transparent bg-primary text-primary-ink hover:bg-primary-hover")
            }
            href={metamaskDeepLink()}
          >
            Open in MetaMask App
          </a>
          <p className="text-sm text-muted text-center">
            {remote
              ? "Or open this page inside the MetaMask app."
              : "On mobile this opens the MetaMask app; on desktop, install the MetaMask extension and reload."}
          </p>
        </>
      )}
      <p className="text-[0.8rem] text-muted text-center">
        Self-custody wallet. Your privacy, guaranteed by proofs.
      </p>
    </div>
  );
}
