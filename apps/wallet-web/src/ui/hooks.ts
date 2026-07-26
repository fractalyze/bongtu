// Tiny view hooks: hash-based routing (no router lib — the brief locks a single SPA),
// an elapsed-seconds counter for the proving stage, and copy-with-feedback.

import { useCallback, useEffect, useState } from "react";
import { copyText } from "../lib/clipboard.js";

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
