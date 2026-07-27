// The wallet shell: a mobile-width vertical frame centered on the page, holding all
// runtime state (connection, derived identity, indexer URL, balance/notes/history) in
// one React context and switching screens on the hash route. There is NO local-journal
// fallback (locked decision): balance + activity come only from the arbiter-mode
// indexer's signed /notes and /history.

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { DEFAULTS } from "../config.js";
import {
  keyDerivationTypedData,
  deriveIdentityFromSignature,
  type WalletIdentity,
} from "../lib/derive.js";
import { connect, signKeyDerivation, walletErrorMessage, type Connection } from "../lib/metamask.js";
import { balanceViaNotes } from "../lib/balance.js";
import {
  buildHistoryUrl,
  fetchHistory,
  type OwnerNote,
  type HistoryItem,
} from "../lib/indexerClient.js";
import { useHashRoute, navigate } from "./hooks.js";
import { Onboarding } from "./screens/Onboarding.js";
import { Home } from "./screens/Home.js";
import { Receive } from "./screens/Receive.js";
import { Deposit } from "./screens/Deposit.js";
import { SpendScreen } from "./components/SpendScreen.js";
import { Activity } from "./screens/Activity.js";
import { Settings } from "./screens/Settings.js";

// --- wallet context --------------------------------------------------------------

export interface WalletContextValue {
  connection: Connection | null;
  identity: WalletIdentity | null;
  indexerUrl: string;
  setIndexerUrl: (url: string) => void;

  // arbiter-indexer-derived state (null until first successful load)
  balance: bigint | null;
  notes: OwnerNote[];
  history: HistoryItem[];
  loading: boolean;
  /** friendly message when the indexer isn't arbiter-mode / is unreachable (else null). */
  dataError: string | null;

  connecting: boolean;
  connectError: string | null;
  connectWallet: () => Promise<void>;
  disconnect: () => void;
  refresh: () => Promise<void>;
}

const WalletContext = createContext<WalletContextValue | null>(null);

/** Access the wallet context (throws if used outside the provider — a wiring bug). */
export function useWallet(): WalletContextValue {
  const ctx = useContext(WalletContext);
  if (!ctx) throw new Error("useWallet used outside <App> provider");
  return ctx;
}

// A signed /notes or /history against a PUBLIC (non-arbiter) indexer 404s/401s; an
// unreachable one throws a network error. Both become a friendly, non-crashing state.
function friendlyIndexerError(err: unknown, indexerUrl: string): string {
  const msg = err instanceof Error ? err.message : String(err);
  if (/->\s*(404|401|403)/.test(msg)) {
    return `The indexer at ${indexerUrl} isn't serving your notes — connect an arbiter-mode indexer to see your balance and activity.`;
  }
  return `Couldn't reach the indexer at ${indexerUrl}. Check it's running and the URL in Settings. (${msg})`;
}

export function App(): ReactNode {
  const route = useHashRoute();

  const [connection, setConnection] = useState<Connection | null>(null);
  const [identity, setIdentity] = useState<WalletIdentity | null>(null);
  const [indexerUrl, setIndexerUrl] = useState<string>(DEFAULTS.indexerUrl);

  const [balance, setBalance] = useState<bigint | null>(null);
  const [notes, setNotes] = useState<OwnerNote[]>([]);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [dataError, setDataError] = useState<string | null>(null);

  const [connecting, setConnecting] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);

  const refresh = useCallback(async (): Promise<void> => {
    if (!identity) return;
    setLoading(true);
    setDataError(null);
    try {
      const { balance: bal, notes: ns } = await balanceViaNotes(indexerUrl, identity);
      setBalance(bal);
      setNotes(ns);
      // History is best-effort on top of a working /notes: if only /history is missing
      // (older indexer) keep the balance and just show an empty activity feed.
      try {
        const url = buildHistoryUrl(
          indexerUrl,
          identity.compressedPubkey,
          identity.keypair.formattedPrivateKey,
        );
        setHistory(await fetchHistory(url));
      } catch {
        setHistory([]);
      }
    } catch (e) {
      setBalance(null);
      setNotes([]);
      setHistory([]);
      setDataError(friendlyIndexerError(e, indexerUrl));
    } finally {
      setLoading(false);
    }
  }, [identity, indexerUrl]);

  // Auto-load whenever the identity or indexer changes (after connect, or a settings edit).
  useEffect(() => {
    if (identity) void refresh();
  }, [identity, indexerUrl, refresh]);

  const connectWallet = useCallback(async (): Promise<void> => {
    setConnecting(true);
    setConnectError(null);
    try {
      const conn = await connect();
      const typed = keyDerivationTypedData(DEFAULTS.chainId, DEFAULTS.pool, DEFAULTS.keyVersion);
      const sig = await signKeyDerivation(conn, typed);
      const id = deriveIdentityFromSignature(sig);
      setConnection(conn);
      setIdentity(id);
      navigate("home");
    } catch (e) {
      setConnectError(walletErrorMessage(e));
    } finally {
      setConnecting(false);
    }
  }, []);

  const disconnect = useCallback((): void => {
    setConnection(null);
    setIdentity(null);
    setBalance(null);
    setNotes([]);
    setHistory([]);
    setDataError(null);
    navigate("home");
  }, []);

  const value = useMemo<WalletContextValue>(
    () => ({
      connection,
      identity,
      indexerUrl,
      setIndexerUrl,
      balance,
      notes,
      history,
      loading,
      dataError,
      connecting,
      connectError,
      connectWallet,
      disconnect,
      refresh,
    }),
    [
      connection, identity, indexerUrl, balance, notes, history, loading, dataError,
      connecting, connectError, connectWallet, disconnect, refresh,
    ],
  );

  return (
    <WalletContext.Provider value={value}>
      <div className="min-h-full flex justify-center items-stretch p-[clamp(0px,3vw,28px)]">
        <div className="w-full max-w-[420px] bg-bg border border-border rounded-[clamp(0px,3vw,20px)] shadow-[0_8px_28px_-18px_rgba(17,24,39,0.18)] overflow-hidden flex flex-col min-h-[min(760px,calc(100vh-56px))]">
          {identity ? <Router route={route} /> : <Onboarding />}
        </div>
      </div>
    </WalletContext.Provider>
  );
}

function Router({ route }: { route: string }): ReactNode {
  switch (route) {
    case "receive":
      return <Receive />;
    case "send":
      // key by kind so switching send↔withdraw REMOUNTS (fresh form/phase state)
      // instead of React reusing the instance and leaking a half-typed spend across.
      return <SpendScreen key="transfer" kind="transfer" />;
    case "withdraw":
      return <SpendScreen key="withdraw" kind="withdraw" />;
    case "deposit":
      return <Deposit />;
    case "activity":
      return <Activity />;
    case "settings":
      return <Settings />;
    default:
      return <Home />;
  }
}
