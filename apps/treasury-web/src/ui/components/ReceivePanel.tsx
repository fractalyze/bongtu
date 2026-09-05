// The receive content (QR + full bongtu ID + copy) as ONE shared panel: the Home
// modal is the primary path and the #/receive route must stay byte-equivalent, so
// both render this instead of drifting apart. QR is rendered client-side from the
// qrcode lib into a data URL — no network.
//
// Below the shielded address sits the ONE-TIME DEPOSIT ADDRESS surface (Slice ⑤
// portal deposits): issuance is name-keyed (POST /pay/{name}), so the section is
// enabled only once the session's registered payment name is known — detected
// through the payName.ts lookup seam (the wallet holds no name registry of its
// own). The stateful wiring lives in the OneTimeAddress container so BOTH
// callers (Home modal, #/receive route) stay byte-equivalent for free; the
// rendered surface is the pure PortalAddressSection, testable headlessly.

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import QRCode from "qrcode";
import { useCopyFeedback } from "../hooks.js";
import { useWallet } from "../App.js";
import { Button, LinkButton, TextInput } from "./controls.js";
import {
  detectPayName,
  issueOneTimeAddress,
  rememberPayName,
  verifyOwnName,
} from "../../lib/payName.js";

export function ReceivePanel({ pubkey }: { pubkey: string }): ReactNode {
  const [qr, setQr] = useState<string>("");
  const { copied, copy } = useCopyFeedback(pubkey);

  useEffect(() => {
    if (!pubkey) return;
    const alive = { current: true };
    void QRCode.toDataURL(pubkey, { margin: 1, width: 240, color: { dark: "#111827", light: "#ffffff" } })
      .then((url) => {
        if (alive.current) setQr(url);
      })
      .catch(() => {
        if (alive.current) setQr("");
      });
    return () => {
      alive.current = false;
    };
  }, [pubkey]);

  return (
    <div className="flex flex-col gap-4 items-center">
      <p className="text-muted text-[0.9rem] text-center mt-1">
        Share this address to receive privacy kKRW.
      </p>
      <div className="bg-surface border border-border p-3 rounded-2xl">
        {qr ? (
          <img className="block w-60 max-w-full h-auto" src={qr} alt="Your bongtu address QR" />
        ) : (
          <div className="w-60 h-60 bg-surface-2 rounded-lg animate-pulse-soft" />
        )}
      </div>
      <div className="w-full bg-surface-2 border border-border rounded-xl px-3.5 py-3 font-mono text-[0.8rem] text-muted [overflow-wrap:anywhere] text-center">
        {pubkey}
      </div>
      <Button variant="primary" block onClick={copy}>
        {copied ? "Copied" : "Copy Address"}
      </Button>
      <OneTimeAddress />
    </div>
  );
}

/** What the issuance surface is showing right now — one value, so the pure
 *  section renders every state without private hooks. */
export interface PortalIssueView {
  issuing: boolean;
  /** the issued CREATE2 destination (EIP-55, straight off the wire) or null. */
  destination: string | null;
  error: string | null;
}

/**
 * The pure one-time-address surface. `name === null` renders the disabled
 * state with the claim form (enter a registered payment name to link it);
 * with a name, the issue button is live and an issued destination renders as
 * a copyable address with the payer-facing explanation.
 */
export function PortalAddressSection({
  name,
  claimValue,
  claimBusy,
  claimError,
  onClaimChange,
  onClaimSubmit,
  issue,
  onIssue,
}: {
  name: string | null;
  claimValue: string;
  claimBusy: boolean;
  claimError: string | null;
  onClaimChange: (value: string) => void;
  onClaimSubmit: () => void;
  issue: PortalIssueView;
  onIssue: () => void;
}): ReactNode {
  const { copied, copy } = useCopyFeedback(issue.destination ?? "");
  return (
    <div className="w-full flex flex-col gap-2.5 border-t border-border pt-4 mt-1">
      <span className="text-[0.82rem] text-muted font-semibold">One-time deposit address</span>
      {name === null ? (
        <>
          <p className="text-muted text-[0.82rem]">
            Get a fresh address anyone can pay with a plain kKRW transfer — it needs your
            registered payment name. Enter it once to link it to this wallet.
          </p>
          <div className="flex gap-2 items-center">
            <TextInput
              value={claimValue}
              placeholder="your payment name"
              onChange={(e) => onClaimChange(e.target.value)}
              disabled={claimBusy}
            />
            <LinkButton onClick={onClaimSubmit} disabled={claimBusy || claimValue.trim() === ""}>
              {claimBusy ? "Checking…" : "Link"}
            </LinkButton>
          </div>
          {claimError && <span className="text-[0.8rem] text-err">{claimError}</span>}
          <Button block disabled>
            Get one-time address
          </Button>
        </>
      ) : (
        <>
          <p className="text-muted text-[0.82rem]">
            Pay this address with a plain kKRW transfer from any wallet or exchange — the
            deposit lands in your shielded balance automatically. Each address is issued
            fresh: use one per payer.
          </p>
          <Button block onClick={onIssue} disabled={issue.issuing}>
            {issue.issuing ? "Issuing…" : `Get one-time address for ${name}`}
          </Button>
          {issue.destination && (
            <>
              <div className="w-full bg-surface-2 border border-border rounded-xl px-3.5 py-3 font-mono text-[0.8rem] text-muted [overflow-wrap:anywhere] text-center">
                {issue.destination}
              </div>
              <Button variant="primary" block onClick={copy}>
                {copied ? "Copied" : "Copy Deposit Address"}
              </Button>
            </>
          )}
          {issue.error && <span className="text-[0.8rem] text-err">{issue.error}</span>}
        </>
      )}
    </div>
  );
}

/** The stateful container: name detection on mount (payName.ts seam), the claim
 *  form when no name is linked yet, and the issue call. Session-less renders
 *  (the deep-linked route before login) show the disabled state. */
function OneTimeAddress(): ReactNode {
  const { indexerUrl, session } = useWallet();
  const owner = session?.compressedPubkey ?? null;
  const [name, setName] = useState<string | null>(null);
  const [claimValue, setClaimValue] = useState("");
  const [claimBusy, setClaimBusy] = useState(false);
  const [claimError, setClaimError] = useState<string | null>(null);
  const [issue, setIssue] = useState<PortalIssueView>({ issuing: false, destination: null, error: null });

  // Re-verify the remembered claim per session owner; a claim that stopped
  // resolving to THIS owner leaves the surface disabled (see payName.ts).
  useEffect(() => {
    if (!owner) return;
    const alive = { current: true };
    void detectPayName(indexerUrl, owner)
      .then((found) => {
        if (alive.current) setName(found);
      })
      .catch(() => {
        // indexer unreachable — leave the surface disabled; the claim form
        // will surface the concrete error if the user tries to link.
        if (alive.current) setName(null);
      });
    return () => {
      alive.current = false;
    };
  }, [indexerUrl, owner]);

  async function handleClaim(): Promise<void> {
    if (!owner) return;
    setClaimBusy(true);
    setClaimError(null);
    try {
      const verified = await verifyOwnName(indexerUrl, claimValue, owner);
      if (verified === null) {
        setClaimError("That name isn't registered to this wallet.");
        return;
      }
      rememberPayName(owner, verified);
      setName(verified);
    } catch (e) {
      setClaimError(e instanceof Error ? e.message : String(e));
    } finally {
      setClaimBusy(false);
    }
  }

  async function handleIssue(): Promise<void> {
    if (name === null) return;
    setIssue({ issuing: true, destination: null, error: null });
    const outcome = await issueOneTimeAddress(indexerUrl, name);
    setIssue(
      outcome.ok
        ? { issuing: false, destination: outcome.destination, error: null }
        : { issuing: false, destination: null, error: outcome.message },
    );
  }

  return (
    <PortalAddressSection
      name={name}
      claimValue={claimValue}
      claimBusy={claimBusy}
      claimError={claimError}
      onClaimChange={setClaimValue}
      onClaimSubmit={() => void handleClaim()}
      issue={issue}
      onIssue={() => void handleIssue()}
    />
  );
}
