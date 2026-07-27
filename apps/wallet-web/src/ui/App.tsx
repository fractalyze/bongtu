// The wallet shell: a mobile-width vertical frame centered on the page, holding all
// runtime state (connection, session, balance/notes/history) in one React context and
// switching screens on the hash route. There is NO local-journal fallback (locked
// decision): balance + activity come only from the arbiter-mode indexer's /notes and
// /history.
//
// KEY-CUSTODY RULE (user-mandated): the bjj private key NEVER enters React state or
// browser storage. Connect derives it (one signature), trades it for a VIEW-ONLY
// indexer token, and hands it to the wallet's in-memory lock (keyCache.ts) — so a
// fresh login lands on Home already unlocked, on the popup it just spent, and the
// lock's 10-minute idle wipe runs from that moment. The persisted record (session.ts)
// is only { eoa address, compressed pubkey, token, exp }. Actions take the key from
// that same lock, which this shell drops on sign-out and on an account switch in the
// connected wallet; a page load with no fresh login (a silently restored session)
// starts LOCKED, because nothing persists the key.
//
// A stored unexpired session restores SILENTLY on load: eth_accounts (no popup)
// must still report the same account, then balance+activity load via the token —
// no signature popup until the user actually deposits/sends/withdraws.

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { DEFAULTS } from "../config.js";
import { deriveTransientIdentity } from "../lib/identity.js";
import {
  connect,
  onAccountsChanged,
  reconnect,
  walletErrorMessage,
  type Connection,
} from "../lib/metamask.js";
import { keyCache } from "../lib/keyCache.js";
import { startWalletDiscovery } from "../lib/eip6963.js";
import { injectedFrom, type WalletDescription } from "../lib/walletBrand.js";
import { sumUnspent } from "../lib/balance.js";
import {
  buildNotesUrl,
  buildHistoryUrl,
  buildNotesTokenUrl,
  buildHistoryTokenUrl,
  obtainViewToken,
  fetchNotes,
  fetchHistory,
  type OwnerNote,
  type HistoryItem,
} from "../lib/indexerClient.js";
import { clearSession, loadSession, saveSession, type StoredSession } from "../lib/session.js";
import { markLockIntroSeen, shouldShowLockIntro } from "../lib/lockIntro.js";
import {
  classifyReadFailure,
  pollForAction,
  refreshPlan,
  type OwnerSnapshot,
} from "../lib/refresh.js";
import { useHashRoute, navigate, useWalletDescription } from "./hooks.js";
import { Onboarding } from "./screens/Onboarding.js";
import { LockIntro } from "./screens/LockIntro.js";
import { Home } from "./screens/Home.js";
import { Receive } from "./screens/Receive.js";
import { Deposit } from "./screens/Deposit.js";
import { SpendScreen } from "./components/SpendScreen.js";
import { Activity } from "./screens/Activity.js";
import { Settings } from "./screens/Settings.js";

// --- wallet context --------------------------------------------------------------

export interface WalletContextValue {
  connection: Connection | null;
  /** which wallet the user is on — brand, display name, icon. Detected live from the
   *  injected provider, so a silently-restored session identifies it too. */
  wallet: WalletDescription;
  /** the logged-in session: account, receive pubkey, view token. NO key material. */
  session: StoredSession | null;
  /** where every read goes. Fixed for the page (config/env — see INDEXER_URL). */
  indexerUrl: string;

  // arbiter-indexer-derived state (null until first successful load)
  balance: bigint | null;
  notes: OwnerNote[];
  history: HistoryItem[];
  loading: boolean;
  /** true while a post-action poll waits for the indexer to reflect the action. */
  syncing: boolean;
  /** friendly message when the indexer isn't arbiter-mode / is unreachable (else null). */
  dataError: string | null;
  /** calm, non-error note about the data on screen (e.g. a tokenless session that
   *  cannot refresh). Never clears the balance the way dataError does. */
  dataNotice: string | null;

  connecting: boolean;
  connectError: string | null;
  connectWallet: () => Promise<void>;
  disconnect: () => void;
  refresh: () => Promise<void>;
  /** post-action refresh: poll until `txHash` is reflected, then apply the data. */
  refreshAfterAction: (txHash: string) => Promise<void>;
}

const WalletContext = createContext<WalletContextValue | null>(null);

// The indexer every read goes to. Deployment-fixed, not user-editable: the runtime
// override in Settings was retired (U-W9) because a wrong URL there silently broke
// balance and activity with no way back. `VITE_INDEXER_URL` still points a dev build
// at another box (config.ts), and vite proxies the default relative `/indexer`.
const INDEXER_URL = DEFAULTS.indexerUrl;

/** Access the wallet context (throws if used outside the provider — a wiring bug). */
export function useWallet(): WalletContextValue {
  const ctx = useContext(WalletContext);
  if (!ctx) throw new Error("useWallet used outside <App> provider");
  return ctx;
}

export function App(): ReactNode {
  const route = useHashRoute();

  const [connection, setConnection] = useState<Connection | null>(null);
  const [session, setSession] = useState<StoredSession | null>(null);
  // The lock explainer stands in front of Home for the one login that earns it.
  const [lockIntro, setLockIntro] = useState(false);

  const [balance, setBalance] = useState<bigint | null>(null);
  const [notes, setNotes] = useState<OwnerNote[]>([]);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [dataError, setDataError] = useState<string | null>(null);
  const [dataNotice, setDataNotice] = useState<string | null>(null);

  const [connecting, setConnecting] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);

  // Ask every installed wallet to announce itself once, then describe the one in use.
  // Before a connection exists the page's injected wallet is the subject — that is
  // what Onboarding names its Connect button after.
  useEffect(startWalletDiscovery, []);
  const wallet = useWalletDescription(
    injectedFrom(connection, (globalThis as { ethereum?: unknown }).ethereum),
  );

  // One loader for every read path: /notes drives the balance; /history is
  // best-effort on top (an older indexer without it keeps the balance working).
  const loadOwnerData = useCallback(
    async (notesUrl: string, historyUrl: string): Promise<OwnerSnapshot> => {
      const ns = await fetchNotes(notesUrl);
      let hs: HistoryItem[] = [];
      try {
        hs = await fetchHistory(historyUrl);
      } catch {
        hs = [];
      }
      return { notes: ns, history: hs };
    },
    [],
  );

  const applySnapshot = useCallback((snap: OwnerSnapshot): void => {
    setBalance(sumUnspent(snap.notes));
    setNotes(snap.notes);
    setHistory(snap.history);
  }, []);

  // Drop the login and every owner-derived value. Used by the Disconnect button and
  // by a dead token (a 401 on the only auth these reads have).
  const endSession = useCallback((reason: string | null): void => {
    keyCache.lock(); // signing out drops the spending key too, not just the token
    clearSession();
    setConnection(null);
    setSession(null);
    setBalance(null);
    setNotes([]);
    setHistory([]);
    setDataError(reason);
    setDataNotice(null);
    navigate("home");
  }, []);

  const refresh = useCallback(async (): Promise<void> => {
    if (!session) return;
    const plan = refreshPlan(session);
    if (plan.kind === "notice") {
      // No token to read with: keep the snapshot already on screen (refresh.ts).
      setDataNotice(plan.message);
      setDataError(null);
      return;
    }
    setLoading(true);
    setDataError(null);
    setDataNotice(null);
    try {
      // Reads authenticate with the VIEW token only — no key, no signature popup.
      const snap = await loadOwnerData(
        buildNotesTokenUrl(INDEXER_URL, session.compressedPubkey, session.token),
        buildHistoryTokenUrl(INDEXER_URL, session.compressedPubkey, session.token),
      );
      applySnapshot(snap);
    } catch (e) {
      const failure = classifyReadFailure(e, INDEXER_URL);
      if (failure.kind === "expired") {
        endSession(failure.message); // back to onboarding — retrying can only 401 again
        return;
      }
      setBalance(null);
      setNotes([]);
      setHistory([]);
      setDataError(failure.message);
    } finally {
      setLoading(false);
    }
  }, [session, loadOwnerData, applySnapshot, endSession]);

  // Auto-load whenever the session changes (after a connect or a silent restore).
  useEffect(() => {
    if (session) void refresh();
  }, [session, refresh]);

  // A held spending key belongs to ONE wallet account, so a switch drops it at the
  // moment it happens — the flows re-check anyway, this just makes the header honest
  // (and re-locks a wallet whose owner walked away from the account).
  useEffect(() => onAccountsChanged(() => keyCache.lock()), []);

  // SILENT restore on first load: a stored unexpired session + the same authorised
  // account (eth_accounts, no popup) puts the user straight on Home; anything else
  // (expired token, account changed, storage empty) falls through to Onboarding.
  const restored = useRef(false);
  useEffect(() => {
    if (restored.current) return; // StrictMode double-mount guard
    restored.current = true;
    const stored = loadSession();
    if (!stored) return;
    void (async () => {
      const conn = await reconnect(stored.eoaAddress);
      if (!conn) {
        // account changed or no longer authorised — require a fresh connect.
        clearSession();
        return;
      }
      setConnection(conn);
      setSession(stored);
    })();
  }, []);

  const connectWallet = useCallback(async (): Promise<void> => {
    setConnecting(true);
    setConnectError(null);
    try {
      const conn = await connect();
      // ONE signature popup, through the module that owns the derivation (identity.ts)
      // — the same call the lock makes when it derives lazily, so a login-seeded key
      // and a lazily-derived one are the same key by construction, not by two copies
      // of the recipe agreeing. The identity (bjj keypair) never enters React state:
      // it signs the token handshake here, and the only reference that outlives this
      // function is the one keyCache.seed takes below (memory-only, idle-wiped).
      const id = await deriveTransientIdentity(conn);
      let sess: StoredSession;
      try {
        const vt = await obtainViewToken(INDEXER_URL, id.compressedPubkey, id.keypair.formattedPrivateKey);
        sess = { eoaAddress: conn.address, compressedPubkey: id.compressedPubkey, token: vt.token, exp: vt.exp };
        saveSession(sess); // the ONLY persisted record: address + pubkey + view token
      } catch {
        // Indexer without /auth (older build) or unreachable: log in for this page
        // only (tokenless sessions are never persisted — loadSession drops them),
        // and load the data ONCE with a key-signed query before the key drops.
        sess = { eoaAddress: conn.address, compressedPubkey: id.compressedPubkey, token: "", exp: 0 };
        try {
          applySnapshot(
            await loadOwnerData(
              buildNotesUrl(INDEXER_URL, id.compressedPubkey, id.keypair.formattedPrivateKey),
              buildHistoryUrl(INDEXER_URL, id.compressedPubkey, id.keypair.formattedPrivateKey),
            ),
          );
        } catch {
          // Nothing loaded and nothing left to load with — the tokenless refresh
          // notice is what the user will see once the session state lands.
        }
      }
      // The login popup already paid for the key — hold it (the seed re-checks it
      // against the session pubkey, exactly as unlock() does with a derived one) so
      // the first send/withdraw/deposit costs only its transaction popup.
      keyCache.seed(id, conn.address, sess.compressedPubkey);
      setConnection(conn);
      setSession(sess);
      // The lock explainer is a once-per-device screen, and ONLY a fresh login sees
      // it: a restored session is already past its first unlock (lockIntro.ts).
      setLockIntro(shouldShowLockIntro("connect"));
      navigate("home");
    } catch (e) {
      setConnectError(walletErrorMessage(e));
    } finally {
      setConnecting(false);
    }
  }, [loadOwnerData, applySnapshot]);

  const disconnect = useCallback((): void => endSession(null), [endSession]);

  // Post-action refresh: the indexer tails the chain on a poll, so the moment a tx
  // confirms /notes may still show the PRE-action state. Poll (3s, ≤30s) until the
  // action is reflected (its tx in /history, or the note set changed), applying the
  // freshest snapshot either way. `syncing` lets success screens say the balance is
  // still catching up.
  const refreshAfterAction = useCallback(
    async (txHash: string): Promise<void> => {
      if (refreshPlan(session).kind === "notice") {
        await refresh(); // tokenless (or logged out): nothing to poll with
        return;
      }
      if (!session) return;
      setSyncing(true);
      try {
        const load = (): Promise<OwnerSnapshot> =>
          loadOwnerData(
            buildNotesTokenUrl(INDEXER_URL, session.compressedPubkey, session.token),
            buildHistoryTokenUrl(INDEXER_URL, session.compressedPubkey, session.token),
          );
        const { last } = await pollForAction(load, { notes, history }, txHash);
        if (last) {
          applySnapshot(last);
          setDataError(null);
        } else {
          await refresh(); // every poll failed — fall back to the plain path + its error
        }
      } finally {
        setSyncing(false);
      }
    },
    [session, notes, history, loadOwnerData, applySnapshot, refresh],
  );

  const value = useMemo<WalletContextValue>(
    () => ({
      connection,
      wallet,
      session,
      indexerUrl: INDEXER_URL,
      balance,
      notes,
      history,
      loading,
      syncing,
      dataError,
      dataNotice,
      connecting,
      connectError,
      connectWallet,
      disconnect,
      refresh,
      refreshAfterAction,
    }),
    [
      connection, wallet, session, balance, notes, history, loading, syncing, dataError,
      dataNotice, connecting, connectError, connectWallet, disconnect, refresh, refreshAfterAction,
    ],
  );

  return (
    <WalletContext.Provider value={value}>
      <div className="min-h-full flex justify-center items-stretch p-[clamp(0px,3vw,28px)]">
        <div className="w-full max-w-[420px] bg-bg border border-border rounded-[clamp(0px,3vw,20px)] shadow-[0_8px_28px_-18px_rgba(17,24,39,0.18)] overflow-hidden flex flex-col min-h-[min(760px,calc(100vh-56px))]">
          {!session ? (
            <Onboarding />
          ) : lockIntro ? (
            <LockIntro
              onDone={() => {
                markLockIntroSeen();
                setLockIntro(false);
              }}
            />
          ) : (
            <Router route={route} />
          )}
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
