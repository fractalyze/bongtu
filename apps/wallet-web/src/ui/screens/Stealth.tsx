// Stealth funds: the one-time addresses this identity's withdrawals landed on,
// and what still sits there. Discovery is on-demand (a button, not a login
// step) because it can cost up to two popups: the spending key signs the
// per-owner announcements read (the same read-auth /notes uses), and the
// stealth struct signature derives the meta keys that recompute each address
// locally — the indexer's word is never taken for which addresses are ours
// (stealthFunds.ts). An unlocked wallet reuses both from the lock, popup-free.
//
// Balances are plain chain reads per address. Spending FROM a one-time address
// needs gas there, so v1 hands out the address's private key (importable into
// any wallet) instead of pretending to sweep; the key is derived on click,
// shown once, and never stored.
//
// KEY-CUSTODY RULE: no StealthKeys in React state. Every action (scan, reveal)
// takes the stealth identity from the wallet's ONE lock (keyCache.unlockStealth),
// which holds it beside the spending key under the same idle wipe, account
// binding, and lock() — this screen holds only what it displays.

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { TOKEN_ADDRESS } from "@bongtu/core/network";
import {
  discoverStealthFunds,
  erc20BalanceReader,
  exportStealthFundKey,
  ownedAnnouncementsFetcher,
  type StealthDiscovery,
} from "@bongtu/client/stealthFunds";
import { walletErrorMessage } from "@bongtu/client/connection";
import { useWallet } from "../App.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { Button } from "../components/controls.js";
import { formatKkrw } from "@bongtu/client/money";
import { keyCache } from "../../lib/keyCache.js";

function shortAddr(a: string): string {
  return `${a.slice(0, 8)}…${a.slice(-4)}`;
}

export function Stealth(): ReactNode {
  const { connection, session, indexerUrl } = useWallet();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [found, setFound] = useState<StealthDiscovery | null>(null);
  const [revealed, setRevealed] = useState<Record<string, string>>({});

  // The revealed strings are a display of an on-click computation, not custody —
  // but they must not outlive the identity they belong to. Unmounting destroys
  // them for free (React state); a lock transition (accountsChanged fires
  // keyCache.lock(), so does the idle wipe and sign-out) and any session or
  // connection change blank them explicitly.
  useEffect(
    () =>
      keyCache.subscribe(() => {
        if (!keyCache.isUnlocked()) setRevealed({});
      }),
    [],
  );
  useEffect(() => {
    setRevealed({});
  }, [connection, session]);

  async function scan(): Promise<void> {
    if (!connection || !session) return;
    setBusy(true);
    setError(null);
    try {
      // Both identities come from the ONE lock: the spending key signs the
      // per-owner announcements read, the stealth keys recompute each address.
      // An unlocked wallet pays no popup for either; a switched account refuses
      // both through the lock's own checks.
      const identity = await keyCache.unlock(connection, session.compressedPubkey);
      const stealthKeys = await keyCache.unlockStealth(connection, session.compressedPubkey);
      const discovery = await discoverStealthFunds(stealthKeys, {
        fetchMine: ownedAnnouncementsFetcher(
          indexerUrl,
          session.compressedPubkey,
          identity.keypair.formattedPrivateKey,
        ),
        balanceOf: erc20BalanceReader(connection.publicClient, TOKEN_ADDRESS),
      });
      setFound(discovery);
      setRevealed({});
    } catch (e) {
      setError(walletErrorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function reveal(ephemeralPub: string): Promise<void> {
    if (!connection || !session) return;
    setError(null);
    try {
      // Per-action read from the lock: if the hold idled out since the scan this
      // re-derives (one popup) rather than trusting anything this screen kept.
      const stealthKeys = await keyCache.unlockStealth(connection, session.compressedPubkey);
      const { privateKey, address } = exportStealthFundKey(stealthKeys, ephemeralPub);
      setRevealed((r) => ({ ...r, [address]: privateKey }));
    } catch (e) {
      setError(walletErrorMessage(e));
    }
  }

  return (
    <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
      <ScreenHeader title="Stealth funds" />
      <p className="text-[12.5px] text-muted">
        One-time addresses your anonymous withdrawals paid out to. Scanning may ask for up
        to two signatures — one to read your own announcements, one to derive the keys that
        recognize (and can spend) these addresses; an unlocked wallet reuses both.
      </p>
      <Button variant="primary" block disabled={!connection || !session || busy} onClick={() => void scan()}>
        {busy ? "Scanning…" : found ? "Rescan" : "Scan for my stealth funds"}
      </Button>
      {error && <div className="text-[12.5px] text-danger">{error}</div>}

      {found && (
        <div className="flex flex-col gap-3">
          <div className="flex justify-between text-sm">
            <span className="text-muted">Total across {found.funds.length} address(es)</span>
            <span className="font-semibold">{formatKkrw(found.total)} kKRW</span>
          </div>
          {found.funds.length === 0 && (
            <div className="text-[12.5px] text-muted">
              No stealth payouts found for this identity yet.
            </div>
          )}
          {found.funds.map((f) => (
            <div key={f.address} className="bg-surface border border-border rounded-xl p-3 flex flex-col gap-2">
              <div className="flex justify-between items-center gap-2">
                <span className="font-mono text-[12.5px]" title={f.address}>{shortAddr(f.address)}</span>
                <span className="text-sm font-semibold">{formatKkrw(f.balance)} kKRW</span>
              </div>
              {revealed[f.address] ? (
                <div className="flex flex-col gap-1">
                  <span className="text-[11.5px] text-danger">
                    Private key — import into a wallet to spend; anyone who sees it controls this address.
                  </span>
                  <code className="font-mono text-[11px] break-all select-all">{revealed[f.address]}</code>
                </div>
              ) : (
                <Button variant="ghost" onClick={() => void reveal(f.ephemeralPub)}>
                  Reveal private key
                </Button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
