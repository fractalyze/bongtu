// First run: a compact centered hero, three one-line steps, and ONE way in — the
// Connect button opens the RainbowKit modal, which lists every installed extension
// (EIP-6963) and, when the build carries a WalletConnect project id, the QR /
// deep-link path for phones. Whatever the modal connects, logging in is ONE flow —
// the deterministic eth_signTypedData_v4 signature and bjj key derivation run the
// moment the wallet is live (the effect below), so the user presses once and lands
// on Home with a key.
// Copy is deliberately short and non-technical (locked after a diagram round —
// the user prefers text, one clause per step): never key/proof mechanics here.

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { useAccount } from "wagmi";
import { useConnectModal } from "@rainbow-me/rainbowkit";
import { DEFAULTS } from "../../config.js";
import { useWallet } from "../App.js";
import { LOGIN_IDLE, loginPendingStep, startLoginPending } from "@bongtu/ui/loginPending";
import { hasInjectedWallet, metamaskDeepLink, walletConnectEnabled } from "@bongtu/ui/wagmi";
import { EnvelopeLogo, IconDeposit, IconSend, IconWallet } from "../components/icons.js";
import { Button, ErrorBanner, TestnetTag } from "../components/controls.js";
import { Banner } from "@bongtu/ui/Banner";

export function Onboarding(): ReactNode {
  const { connectWallet, connecting, connectError, dataError } = useWallet();
  const { isConnected } = useAccount();
  const { openConnectModal, connectModalOpen } = useConnectModal();
  // Armed when the user presses Connect while no wallet is live: the modal opens,
  // and the moment wagmi reports a connection the login runs — one press, one flow.
  // The transitions (fire on connect, DISARM on a dismissed modal — else the stale
  // flag would auto-fire a signature popup at the next unrelated connect) are the
  // pure machine in lib/loginPending.ts; this effect only feeds it and executes
  // its verdict.
  const [loginPending, setLoginPending] = useState(LOGIN_IDLE);

  useEffect(() => {
    const { state, effect } = loginPendingStep(loginPending, {
      modalOpen: connectModalOpen,
      connected: isConnected,
    });
    if (state !== loginPending) setLoginPending(state);
    if (effect === "login") void connectWallet();
  }, [loginPending, isConnected, connectModalOpen, connectWallet]);

  const onConnect = (): void => {
    if (isConnected) {
      // A wallet is already live (warm reconnect, or a previous modal round whose
      // login failed) — no modal needed, go straight to the signature.
      void connectWallet();
      return;
    }
    setLoginPending(startLoginPending());
    openConnectModal?.();
  };

  const injected = hasInjectedWallet();
  // Absent VITE_WC_PROJECT_ID this is false at build time: the modal lists only the
  // installed extensions, and the no-wallet fallback below stays the deep link.
  const remote = walletConnectEnabled();
  const busy = connecting || connectModalOpen;
  return (
    <div className="px-5.5 py-6.5 flex flex-col justify-center gap-4 flex-1 bg-bg">
      {/* flex-col, not inline flow: an inline logo span sits on the text baseline
          and leaves descender space under the icon no margin utility removes. */}
      <div className="text-center mb-2 flex flex-col items-center gap-0.5">
        <span className="inline-flex text-primary">
          <EnvelopeLogo size={52} />
        </span>
        <h1 className="text-[2rem] leading-tight font-bold mb-1 tracking-[-0.02em] text-primary">bongtu</h1>
        <p className="text-muted">The privacy wallet for kKRW on {DEFAULTS.chainName}.</p>
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
                <strong className="text-ink">Get kKRW</strong>: mint free test kKRW here.
              </>
            ) : (
              <>
                <strong className="text-ink">Get kKRW</strong>: fund your account with kKRW.
              </>
            )}
          </span>
        </li>
        <li className="flex gap-2.5 items-center text-[0.9rem] text-muted">
          <span className="inline-flex shrink-0 text-primary">
            <IconDeposit size={18} />
          </span>
          <span>
            <strong className="text-ink">Deposit</strong>: it becomes private kKRW.
          </span>
        </li>
        <li className="flex gap-2.5 items-center text-[0.9rem] text-muted">
          <span className="inline-flex shrink-0 text-primary">
            <IconSend size={18} />
          </span>
          <span>
            <strong className="text-ink">Send &amp; withdraw</strong>: nothing revealed.
          </span>
        </li>
      </ol>

      {connectError && <ErrorBanner message={connectError} />}
      {/* The session-fatal notice (class 3): why the app routed back here — an
          expired login, a wallet that ended its session. Calm info tone: nothing is
          wrong with what the user is about to do. A fresh visit has none. */}
      {!connectError && dataError && <Banner tone="info" message={dataError} />}

      {(injected || remote) && (
        <Button variant="primary" size="lg" block onClick={onConnect} disabled={busy}>
          {connecting ? "Connecting…" : "Connect Wallet"}
        </Button>
      )}

      {!injected && !remote && (
        // No injected provider AND no WalletConnect in this build (plain mobile
        // browser, or desktop without an extension): the deep link reopens this page
        // inside MetaMask Mobile's dapp browser, where the normal connect flow works.
        <>
          <a
            className={
              "block w-full rounded-xl border px-4.5 py-[15px] text-[1.02rem] font-semibold " +
              "cursor-pointer transition-colors text-center no-underline " +
              "border-transparent bg-primary text-primary-ink hover:bg-primary-hover"
            }
            href={metamaskDeepLink()}
          >
            Open in MetaMask App
          </a>
          <p className="text-sm text-muted text-center">
            On mobile this opens the MetaMask app; on desktop, install the MetaMask extension and
            reload.
          </p>
        </>
      )}
      <p className="text-[0.8rem] text-muted text-center">
        Self-custody wallet. Your privacy, guaranteed by proofs.
      </p>
    </div>
  );
}
