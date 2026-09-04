// The consumer wallet shell: apps/wallet-web's App forked (copy-and-trim is the
// recorded decision — the arch review rejected a shared UI package) and cut down to
// the profile that IS this product: every balance and activity fact on screen comes
// from the OPMOD §3.6 self-scan of the PUBLIC feed with the wallet's own keys,
// against a public-mode indexer. What deliberately does NOT exist here (issue #13's
// not-coming-along list): the enterprise view-token session (logins are tokenless
// BY CONSTRUCTION — the injected token dep refuses before any request, and the app
// persists its own tokenless record, lib/sessionStore.ts), owner-authed indexer
// reads, activity paging (the scan holds the whole history it can ever derive),
// the pool KEM-epoch guard, and the gas-sponsoring exit leg.
//
// KEY-CUSTODY RULE (user-mandated, unchanged from wallet-web): the bjj private key
// NEVER enters React state or browser storage. Connect derives it (one signature)
// and hands it to the in-memory lock (lib/keyCache.ts) — a fresh login lands on
// Home already unlocked and scanning; a silently restored session starts LOCKED
// and serves the last completed scan under the calm locked notice until the next
// unlock signature, because scanning needs the view keys and a background read
// must never pop a signature.

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { DEFAULTS } from "../config.js";
import { walletErrorMessage, type Connection } from "@bongtu/client/connection";
import {
  endWalletConnection,
  requireConnection,
  restoreConnection,
  warmReconnect,
  watchWallet,
} from "../lib/wagmi.js";
import { runTokenlessLogin } from "@bongtu/client/loginFlow";
import { KEY_DERIVATION, deriveLoginIdentity } from "@bongtu/client/identity";
import { keyCache } from "../lib/keyCache.js";
import type { WalletDescription } from "../lib/walletBrand.js";
import { sumUnspent } from "@bongtu/client/balance";
import {
  EMPTY_SCAN_STATE,
  isConsumerIdentity,
  runSelfScan,
  selfScanSnapshot,
  type ScanNote,
  type SelfScanState,
} from "@bongtu/client/selfscan";
import { clearScanState, loadScanState, saveScanState, scanNotice } from "../lib/scanStore.js";
import { accountGuard, forgetDevice } from "../lib/accountGuard.js";
import { autoTickAllowed } from "../lib/refreshGate.js";
import { IndexerClient, type OwnerNote, type HistoryItem } from "@bongtu/client/indexerClient";
import { SessionStore, type StoredSession } from "@bongtu/client/session";
import {
  clearConsumerSession,
  loadConsumerSession,
  saveConsumerSession,
} from "../lib/sessionStore.js";
import { markLockIntroSeen, shouldShowLockIntro } from "../lib/lockIntro.js";
import {
  skipBaseline,
  pollForAction,
  runRefresh,
  AUTO_REFRESH_MS,
  type OwnerSnapshot,
} from "@bongtu/client/refresh";
import { installGlobalErrorSurface, toastError, toasts } from "../lib/toasts.js";
import { ToastHost } from "@bongtu/ui/Toast";
import { useHashRoute, navigate, useWalletDescription } from "./hooks.js";
import { Onboarding } from "./screens/Onboarding.js";
import { LockIntro } from "./screens/LockIntro.js";
import { Home } from "./screens/Home.js";
import { Activity } from "./screens/Activity.js";
import { Settings } from "./screens/Settings.js";
import { Deposit } from "./screens/Deposit.js";
import { SpendScreen } from "./screens/SpendScreen.js";
import { Receive } from "./screens/Receive.js";

// The engine store is kept ONLY for the account→pubkey determinism bindings that
// runLogin's default deps write (loginGuard.ts) — the session record itself lives
// in the app-layer tokenless store (lib/sessionStore.ts), because the engine's
// loadSession drops tokenless records by contract.
const keyBindings = new SessionStore();

// --- wallet context --------------------------------------------------------------

export interface WalletContextValue {
  connection: Connection | null;
  /** which wallet the user is on — brand, display name, icon. Detected live from the
   *  injected provider, so a silently-restored session identifies it too. */
  wallet: WalletDescription;
  /** the logged-in session: account + receive pubkey. Tokenless by construction
   *  (token is always "" here) and NO key material, ever. */
  session: StoredSession | null;
  /** where every public read goes. Fixed for the page (config/env). */
  indexerUrl: string;

  // self-scan-derived state (null until the first scan lands)
  balance: bigint | null;
  notes: OwnerNote[];
  /** the same discovered notes in the SCAN shape (leafIndex + spent + seq) —
   *  what the consumer spend flows plan and prove over (ConsumerSpendContext
   *  is typed against ScanNote, not the arbiter OwnerNote view). */
  scanNotes: ScanNote[];
  /** activity derived from the scan (selfScanSnapshot) — the whole feed, unpaged:
   *  the scan holds every row it can ever derive, so there is nothing to page. */
  history: HistoryItem[];
  loading: boolean;
  /** friendly message when the indexer is unreachable / a scan failed (else null). */
  dataError: string | null;
  /** calm, non-error note about the data on screen (pending kem delivery, or a
   *  locked wallet serving its last scan). Never clears the balance the way
   *  dataError does. */
  dataNotice: string | null;
  /** the last completed scan's /head stamp — the sync dot's freshness reference.
   *  Null before a scan lands. */
  scannedNextLeafIndex: number | null;

  /** True while a login is running (the Connect button disables and says so). */
  connecting: boolean;
  connectError: string | null;
  /** Log in with whatever wallet wagmi has connected (the modal's pick). */
  connectWallet: () => Promise<void>;
  disconnect: () => void;
  /** `manual=true` marks a user-initiated refresh (sync dot, banner Retry): the one
   *  invocation allowed to toast on failure. Background callers omit it — their
   *  only failure surface is the dataError banner (never a toast). */
  refresh: (manual?: boolean) => Promise<void>;
  /** The between-legs read a spend chain waits on: a SELF-SCAN pass (consumer
   *  notes have no oracle to reload from). Applies what it reads so the balance
   *  on screen keeps up with a chain in flight. */
  reloadNotes: () => Promise<ScanNote[]>;
  /** Post-action refresh: the feed tails the chain on a poll, so the moment a
   *  tx confirms a scan may still see the PRE-action state — poll (3s, ≤30s)
   *  until the action is reflected, applying the freshest snapshot either way. */
  refreshAfterAction: (txHash: string) => Promise<void>;
}

const WalletContext = createContext<WalletContextValue | null>(null);

// The indexer every read goes to. Deployment-fixed, not user-editable (the U-W9
// verdict, kept): `VITE_INDEXER_URL` still points a dev build at another box
// (config.ts), and vite proxies the default relative `/indexer`.
const INDEXER_URL = DEFAULTS.indexerUrl;

// ONE bound client for the page — the self-scan's whole IO (events / nullifiers /
// head / path, all public) satisfies the engine's SelfScanIo seam structurally.
const indexer = new IndexerClient(INDEXER_URL);

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
  const [scanNotes, setScanNotes] = useState<ScanNote[]>([]);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [dataError, setDataError] = useState<string | null>(null);
  const [dataNotice, setDataNotice] = useState<string | null>(null);

  // The last completed scan (memory-first, localStorage-backed via scanStore)
  // plus its /head freshness stamp, and which owner the cached scan belongs to
  // (so sign-out can clear the right store row without making endSession depend
  // on session state).
  const scanRef = useRef<SelfScanState | null>(null);
  const scanOwnerRef = useRef<string | null>(null);
  const [scannedNextLeafIndex, setScannedNextLeafIndex] = useState<number | null>(null);

  const [connecting, setConnecting] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);

  // Which wallet the user is on — from the wagmi connector (its EIP-6963 metadata),
  // refined with vendor brand flags once the raw provider resolves (hooks.ts).
  const wallet = useWalletDescription();

  /** ONE read: an incremental §3.6 scan, resumed from the stored cursor, served in
   *  the OwnerSnapshot shape so everything downstream — applySnapshot,
   *  snapshotChanged, sumUnspent — is engine-blind. Scanning needs the view keys,
   *  and a background read must never pop a signature, so a LOCKED wallet serves
   *  its last completed scan unchanged under the calm notice. The notice verdict
   *  itself is the pure scanNotice fold (scanStore.ts): it lands after runRefresh's
   *  setNotice(null), so a successful read keeps it. */
  const loadSelfScan = useCallback(async (ownerCompressed: string): Promise<OwnerSnapshot> => {
    const prev = scanRef.current ?? loadScanState(ownerCompressed) ?? EMPTY_SCAN_STATE;
    const identity = keyCache.peek(ownerCompressed);
    const state =
      identity !== null && isConsumerIdentity(identity)
        ? await runSelfScan(indexer, identity, prev)
        : prev;
    scanRef.current = state;
    scanOwnerRef.current = ownerCompressed;
    saveScanState(ownerCompressed, state);
    setScannedNextLeafIndex(state.scannedNextLeafIndex);
    setScanNotes(state.notes);
    setDataNotice(scanNotice(state, identity !== null));
    return selfScanSnapshot(state, ownerCompressed);
  }, []);

  const applySnapshot = useCallback((snap: OwnerSnapshot): void => {
    setBalance(sumUnspent(snap.notes));
    setNotes(snap.notes);
    setHistory(snap.history);
  }, []);

  // Drop the login and every owner-derived value. `forget` separates an explicit
  // Disconnect (also ends the WalletConnect pairing, forgets which key this account
  // derives, and clears the stored scan — the user asked for a clean device) from a
  // forced sign-out, which must keep the determinism binding (loginGuard.ts).
  const endSession = useCallback((reason: string | null, forget = false): void => {
    keyCache.lock(); // signing out drops the spending key too
    toasts.clear(); // stale event toasts must not follow the user to onboarding
    clearConsumerSession();
    scanRef.current = null;
    setScannedNextLeafIndex(null);
    if (forget) {
      // The clean-device trio, sequenced as one pure plan (lib/accountGuard.ts
      // forgetDevice, gated headlessly): the determinism bindings, the stored
      // scan (a clean device keeps no decrypted amounts either — scanStore),
      // and the wagmi connector (for WalletConnect that ends the session, so
      // the wallet app stops showing bongtu as connected).
      forgetDevice({
        clearKeyBindings: () => keyBindings.clearKeyBindings(),
        clearStoredScan: () => {
          if (scanOwnerRef.current !== null) clearScanState(scanOwnerRef.current);
        },
        endWalletLink: () => void endWalletConnection(),
      });
    }
    // The owner stamp dies with the session: the forget sink above resolves
    // scanOwnerRef at call time, and a stamp that outlived its session once
    // let a later owner's Disconnect clear the PREVIOUS owner's stored row.
    scanOwnerRef.current = null;
    setConnection(null);
    setSession(null);
    setBalance(null);
    setNotes([]);
    setScanNotes([]);
    setHistory([]);
    setDataError(reason);
    setDataNotice(null);
    navigate("home");
  }, []);

  // ONE refresh path for every invocation. Reads are auth-free (the profile's
  // declaration to refreshPlan — the plan owns the read-or-notice decision), and
  // the surface routing itself is headless (refresh.ts runRefresh, tested); this
  // callback only wires the sinks to React state.
  const refresh = useCallback(
    async (manual = false, quiet = false): Promise<void> => {
      if (!session) return;
      if (!quiet) setLoading(true); // an auto tick must not flash loading UI every 3 s
      try {
        await runRefresh(session, (_token, owner) => loadSelfScan(owner), {
          applySnapshot,
          setBanner: setDataError,
          toast: toastError,
          signOut: (notice) => endSession(notice),
          setNotice: setDataNotice,
        }, {
          manual,
          indexerUrl: INDEXER_URL,
          authFree: true,
          // An unchanged read never touches the screen. `balance` is null until a
          // snapshot has actually landed, which is what tells the baseline apart
          // from an empty account reading back its empty self.
          skipUnchangedFrom: skipBaseline(balance !== null, {
            notes,
            history,
            historyNextBefore: null,
          }),
        });
      } finally {
        if (!quiet) setLoading(false);
      }
    },
    [session, loadSelfScan, applySnapshot, endSession, balance, notes, history],
  );

  // Auto-load whenever the session changes (after a connect or a silent restore).
  useEffect(() => {
    if (session) void refresh();
  }, [session, refresh]);

  // The chain advances without us, so re-scan on a cadence while the tab is
  // visible — money sent TO this account appears unprompted. Quiet: no loading
  // flash, no toast, failures move only the banner; a tick never overlaps itself.
  useEffect(() => {
    if (!session) return;
    const inflight = { current: false };
    const id = setInterval(() => {
      // The gate is pure (lib/refreshGate.ts): hidden tab → no pass, and a tick
      // never overlaps itself. The pass reads the lock with keyCache.peek only
      // (loadSelfScan) — a background read must never extend the idle deadline.
      if (!autoTickAllowed(document.visibilityState, inflight.current)) return;
      inflight.current = true;
      void refresh(false, true).finally(() => {
        inflight.current = false;
      });
    }, AUTO_REFRESH_MS);
    return () => clearInterval(id);
  }, [session, refresh]);

  // Class 5 (unexpected/bug): whatever still reaches the window's error and
  // unhandledrejection events was caught by NO deliberate surface — toast it with
  // Copy details.
  useEffect(() => installGlobalErrorSurface(), []);

  // The switch/disconnect sequences are fixed in lib/accountGuard.ts (pure,
  // gated): any accountsChanged locks the key AND detaches the in-memory scan
  // ref — the next pass resumes from the per-owner store, never from a ref
  // whose owner the live wallet no longer vouches for — while the screen keeps
  // its last snapshot under the calm locked notice; `disconnected` signs out
  // for WalletConnect only (there it is the phone ending the session; an
  // extension's disconnect can be a mere provider hiccup).
  useEffect(
    () =>
      watchWallet(
        accountGuard(
          {
            lock: () => keyCache.lock(),
            detachScan: () => {
              scanRef.current = null;
            },
            signOut: (notice) => endSession(notice),
          },
          () => connection?.transport ?? null,
        ),
      ),
    [connection, endSession],
  );

  // SILENT restore on first load: a stored login record + the same authorised
  // account (eth_accounts, no popup) puts the user straight on Home — LOCKED, on
  // the last completed scan; anything else falls through to Onboarding.
  const restored = useRef(false);
  useEffect(() => {
    if (restored.current) return; // StrictMode double-mount guard
    restored.current = true;
    const stored = loadConsumerSession();
    if (!stored) {
      // Nothing to restore — still warm wagmi's remembered connector (silent), so
      // the Connect button can skip the modal for a wallet that is already live.
      warmReconnect();
      return;
    }
    void (async () => {
      const conn = await restoreConnection(stored.eoaAddress);
      if (!conn) {
        // account changed or no longer authorised — require a fresh connect.
        clearConsumerSession();
        return;
      }
      setConnection(conn);
      setSession(stored);
    })();
  }, []);

  const connectWallet = useCallback(
    async (): Promise<void> => {
      setConnecting(true);
      setConnectError(null);
      try {
        // Everything security-relevant about a login — the derivation, the two
        // refusals, what gets persisted — lives in the flow (loginFlow.ts), gated
        // headlessly. The TOKENLESS variant refuses the view-token step inside the
        // engine — this app cannot even name the token machinery — so the flow
        // always returns its tokenless branch and the app persists its own
        // credential-free record instead. The identity never enters React state:
        // the only reference that outlives this function is the one keyCache.seed
        // takes below (memory-only, idle-wiped).
        const { connection: conn, identity: id, session: sess } = await runTokenlessLogin(
          { indexerUrl: INDEXER_URL },
          {
            openConnection: requireConnection,
            deriveIdentity: (c, plan) => deriveLoginIdentity(c, plan, KEY_DERIVATION),
          },
        );
        saveConsumerSession({
          eoaAddress: conn.address,
          compressedPubkey: sess.compressedPubkey,
          transport: conn.transport,
        });
        // The login popup already paid for the key — hold it so the first scan
        // runs now and the first action costs only its transaction popup.
        keyCache.seed(id, conn.address, sess.compressedPubkey);
        setConnection(conn);
        setSession(sess);
        // The lock explainer is a once-per-device screen, and ONLY a fresh login
        // sees it: a restored session is already past its first unlock.
        setLockIntro(shouldShowLockIntro("connect"));
        navigate("home");
      } catch (e) {
        setConnectError(walletErrorMessage(e));
      } finally {
        setConnecting(false);
      }
    },
    [],
  );

  const disconnect = useCallback((): void => endSession(null, true), [endSession]);

  // The between-legs read a spend chain waits on. It applies what it reads (so
  // the balance on screen keeps up with a chain in flight) but never clears
  // anything on failure — the chain's own bounded poll decides when the wait
  // has gone on too long.
  const reloadNotes = useCallback(async (): Promise<ScanNote[]> => {
    if (!session) throw new Error("Signed out mid-action. Reconnect and try again.");
    // Fail fast on a locked key: mid-chain the lock only closes when the S5
    // guard fired (account switch) or the key was wiped — a locked scan pass
    // would serve the stale store and make the chain's merge poll run its full
    // cap before blaming indexing lag, when the truth is the key is gone.
    if (keyCache.peek(session.compressedPubkey) === null) {
      throw new Error("The wallet key locked during this action. Start it again to continue.");
    }
    const snap = await loadSelfScan(session.compressedPubkey);
    applySnapshot(snap);
    return scanRef.current?.notes ?? [];
  }, [session, loadSelfScan, applySnapshot]);

  // Post-action refresh, polled rather than read once: the indexer tails the
  // chain, so the first scan after a confirmed tx can still see the PRE-action
  // state. The accept predicate is the shared actionReflected fold.
  const refreshAfterAction = useCallback(
    async (txHash: string): Promise<void> => {
      if (!session) return;
      const pre: OwnerSnapshot = { notes, history, historyNextBefore: null };
      const { last } = await pollForAction(() => loadSelfScan(session.compressedPubkey), pre, txHash);
      if (last) {
        applySnapshot(last);
        setDataError(null);
      } else {
        await refresh(); // every poll failed — fall back to the plain path + its error
      }
    },
    [session, notes, history, loadSelfScan, applySnapshot, refresh],
  );

  const value = useMemo<WalletContextValue>(
    () => ({
      connection,
      wallet,
      session,
      indexerUrl: INDEXER_URL,
      balance,
      notes,
      scanNotes,
      history,
      loading,
      dataError,
      dataNotice,
      scannedNextLeafIndex,
      connecting,
      connectError,
      connectWallet,
      disconnect,
      refresh,
      reloadNotes,
      refreshAfterAction,
    }),
    [
      connection, wallet, session, balance, notes, scanNotes, history, loading, dataError, dataNotice,
      scannedNextLeafIndex, connecting, connectError, connectWallet, disconnect, refresh,
      reloadNotes, refreshAfterAction,
    ],
  );

  return (
    <WalletContext.Provider value={value}>
      <div className="min-h-full flex justify-center items-stretch p-[clamp(0px,3vw,28px)]">
        {/* relative: the toast host floats over this frame's bottom edge. */}
        <div className="relative w-full max-w-[420px] bg-bg border border-border rounded-[clamp(0px,3vw,20px)] shadow-[0_8px_28px_-18px_rgba(17,24,39,0.18)] overflow-hidden flex flex-col min-h-[min(760px,calc(100vh-56px))]">
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
          <ToastHost queue={toasts} />
        </div>
      </div>
    </WalletContext.Provider>
  );
}

function Router({ route }: { route: string }): ReactNode {
  switch (route) {
    case "activity":
      return <Activity />;
    case "settings":
      return <Settings />;
    case "deposit":
      return <Deposit />;
    case "send":
      return <SpendScreen kind="transfer" />;
    case "withdraw":
      return <SpendScreen kind="withdraw" />;
    case "receive":
      return <Receive />;
    default:
      return <Home />;
  }
}
