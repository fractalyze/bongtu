// The receive content (QR + full bongtu ID + copy) as ONE shared panel: the Home
// modal is the primary path and the #/receive route must stay byte-equivalent, so
// both render this instead of drifting apart. QR is rendered client-side from the
// qrcode lib into a data URL — no network.

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import QRCode from "qrcode";
import { useCopyFeedback } from "../hooks.js";

export function ReceivePanel({ pubkey }: { pubkey: string }): ReactNode {
  const [qr, setQr] = useState<string>("");
  const { copied, copy } = useCopyFeedback(pubkey);

  useEffect(() => {
    if (!pubkey) return;
    let alive = true;
    void QRCode.toDataURL(pubkey, { margin: 1, width: 240, color: { dark: "#111827", light: "#ffffff" } })
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

  return (
    <div className="receive-body">
      <p className="receive-lead">Share this address to receive privacy kKRW.</p>
      <div className="qr-frame">{qr ? <img className="qr" src={qr} alt="Your bongtu address QR" /> : <div className="qr-skeleton" />}</div>
      <div className="pubkey-box mono">{pubkey}</div>
      <button className="btn btn-primary btn-block" onClick={copy}>
        {copied ? "Copied" : "Copy address"}
      </button>
    </div>
  );
}
