// Receive: show the wallet's compressed bjj pubkey as a QR + copyable text. This IS
// the receive identifier a payer types into Send (derive.ts: packPubkey(publicKey)).
// The QR is rendered client-side from the qrcode lib into a data URL — no network.

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import QRCode from "qrcode";
import { useWallet } from "../App.js";
import { ScreenHeader } from "../components/ScreenHeader.js";

export function Receive(): ReactNode {
  const { identity } = useWallet();
  const pubkey = identity?.compressedPubkey ?? "";
  const [qr, setQr] = useState<string>("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!pubkey) return;
    let alive = true;
    void QRCode.toDataURL(pubkey, { margin: 1, width: 240, color: { dark: "#0e1116", light: "#ffffff" } })
      .then((url) => {
        if (alive) setQr(url);
      })
      .catch(() => {
        if (alive) setQr("");
      });
    return () => {
      alive = false;
    };
  }, [pubkey]);

  async function copy(): Promise<void> {
    try {
      await navigator.clipboard.writeText(pubkey);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked — the text is on screen to copy manually */
    }
  }

  return (
    <div className="screen">
      <ScreenHeader title="Receive" />
      <div className="receive-body">
        <p className="receive-lead">Share this address to receive private kKRW.</p>
        <div className="qr-frame">{qr ? <img className="qr" src={qr} alt="Your address QR" /> : <div className="qr-skeleton" />}</div>
        <div className="pubkey-box mono">{pubkey}</div>
        <button className="btn btn-primary btn-block" onClick={copy}>
          {copied ? "Copied ✓" : "Copy address"}
        </button>
      </div>
    </div>
  );
}
