// Tiny view hooks: hash-based routing (no router lib — the brief locks a single SPA),
// an elapsed-seconds counter for the proving stage, and copy-with-feedback.

import { useCallback, useEffect, useRef, useState } from "react";
import { copyText } from "../lib/clipboard.js";
import { subscribeCircuitDownload, type CircuitDownloadState } from "../lib/prove.js";

export type Route = "home" | "receive" | "send" | "withdraw" | "deposit" | "activity" | "settings";

const ROUTES: readonly Route[] = ["home", "receive", "send", "withdraw", "deposit", "activity", "settings"];

function parseHash(): Route {
  const h = window.location.hash.replace(/^#\/?/, "");
  return (ROUTES as readonly string[]).includes(h) ? (h as Route) : "home";
}

/** The current screen from `location.hash`, re-rendering on hashchange. */
export function useHashRoute(): Route {
  const [route, setRoute] = useState<Route>(parseHash);
  useEffect(() => {
    const on = (): void => setRoute(parseHash());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

/** Navigate to a screen (updates the hash; the hook above reacts). */
export function navigate(route: Route): void {
  window.location.hash = route === "home" ? "#/" : `#/${route}`;
}

/** Seconds since `active` became true; resets to 0 when inactive. Drives the
 *  "Generating ZK proof… N s" counter — the honest elapsed clock (never a promise). */
export function useElapsedSeconds(active: boolean): number {
  const [secs, setSecs] = useState(0);
  useEffect(() => {
    if (!active) {
      setSecs(0);
      return;
    }
    const start = Date.now();
    setSecs(0);
    const id = setInterval(() => setSecs(Math.floor((Date.now() - start) / 1000)), 250);
    return () => clearInterval(id);
  }, [active]);
  return secs;
}

/** What a screen renders for a circuit's proving-asset download. `active` also
 *  gates every proof-reaching button (disabled while the assets stream in). */
export interface CircuitDownloadView {
  active: boolean;
  received: number;
  /** Summed Content-Length across the circuit's assets; null when any is unsized
   *  (bar goes indeterminate, no ETA). */
  total: number | null;
  /** Whole seconds remaining at the observed rate; null until measurable. */
  etaSeconds: number | null;
}

const IDLE_DOWNLOAD: CircuitDownloadView = { active: false, received: 0, total: null, etaSeconds: null };

/**
 * Live download progress of `circuit`'s wasm+zkey (prove.ts registry — survives
 * remounts and StrictMode's coalesced prefetch). Updates are coalesced to ~4/s so
 * a fast stream doesn't re-render the screen per network chunk.
 */
export function useCircuitDownload(circuit: "transfer" | "withdraw" | "deposit"): CircuitDownloadView {
  const [view, setView] = useState<CircuitDownloadView>(IDLE_DOWNLOAD);
  const lastPaint = useRef(0);
  useEffect(() => {
    return subscribeCircuitDownload(circuit, (s: CircuitDownloadState | null) => {
      if (!s) {
        lastPaint.current = 0;
        setView(IDLE_DOWNLOAD);
        return;
      }
      const now = Date.now();
      if (now - lastPaint.current < 250) return; // coalesce chunk storms
      lastPaint.current = now;
      const assets = Object.values(s.assets);
      const received = assets.reduce((n, a) => n + a.received, 0);
      const total = assets.every((a) => a.total !== null)
        ? assets.reduce((n, a) => n + (a.total ?? 0), 0)
        : null;
      const elapsed = (now - s.startedAt) / 1000;
      const rate = elapsed > 0.5 ? received / elapsed : 0;
      const etaSeconds =
        total !== null && rate > 0 ? Math.max(1, Math.ceil((total - received) / rate)) : null;
      setView({ active: true, received, total, etaSeconds });
    });
  }, [circuit]);
  return view;
}

/** Copy `text` and flip a short-lived `copied` flag — only on a REAL clipboard write
 *  (copyText's boolean), so the UI never claims "Copied" when the browser refused.
 *  The timeout lives in an effect so unmount can't fire a setState on a dead tree. */
export function useCopyFeedback(text: string, resetMs = 1500): { copied: boolean; copy: () => void } {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const id = setTimeout(() => setCopied(false), resetMs);
    return () => clearTimeout(id);
  }, [copied, resetMs]);
  const copy = useCallback((): void => {
    void copyText(text).then((ok) => {
      if (ok) setCopied(true);
    });
  }, [text]);
  return { copied, copy };
}
