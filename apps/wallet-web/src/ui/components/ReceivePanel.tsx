// The receive content (QR + full bongtu ID + copy) as ONE shared panel: the Home
// modal is the primary path and the #/receive route must stay byte-equivalent, so
// both render this instead of drifting apart. QR is rendered client-side from the
// qrcode lib into a data URL — no network.

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import QRCode from "qrcode";
import { useCopyFeedback } from "../hooks.js";
import { Button } from "./controls.js";

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
    </div>
  );
}
