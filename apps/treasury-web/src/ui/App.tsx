// The wallet shell: a mobile-width vertical frame centered on the page, holding all
// runtime state (connection, session, balance/notes/history) in one React context and
// switching screens on the hash route. There is NO local-journal fallback (locked
// decision): balance + activity come only from the configured discovery engine —
// the arbiter-mode indexer's /notes + /history, or (selfscan profile) the public
// feed via the §3.6 self-scan.
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
// A stored unexpired session restores SILENTLY on load, over whichever transport made
// it (injected eth_accounts, or a WalletConnect session the SDK still holds): the same
// account must still be reported, then balance+activity load via the token — no
// signature popup and no QR modal until the user actually deposits/sends/withdraws.

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { DEFAULTS, isSelfScan } from "../config.js";
import { ensureChain, type Connection } from "@bongtu/client-evm/connection";
import { treasuryErrorMessage } from "../lib/errors.js";
import {
  endWalletConnection,
  requireConnection,
  restoreConnection,
  warmReconnect,
  watchWallet,
} from "@bongtu/ui/wagmi";
import { runLogin } from "@bongtu/client/login";
import { SpendOps } from "@bongtu/client/spend";
import { KEY_DERIVATION } from "@bongtu/client/identity";
import { deriveLoginIdentity } from "@bongtu/client-evm/identity";
import { EVM_ENTERPRISE_IO } from "@bongtu/client-evm/ops";
import { keyCache } from "@bongtu/ui/keyCache";
import { proveInBrowser } from "../lib/prove.js";
import type { WalletDescription } from "@bongtu/ui/walletBrand";
import { sumUnspent } from "@bongtu/client/balance";
import { ScanSession } from "@bongtu/client/selfscan";
import { clearScanState, loadScanState, saveScanState } from "../lib/scanStore.js";
import { IndexerClient, type OwnerNote, type HistoryItem } from "@bongtu/core/indexerApi";
import { appendHistoryPage } from "@bongtu/client/activity";
import { SessionStore, type StoredSession } from "@bongtu/client/session";
import { markLockIntroSeen, shouldShowLockIntro } from "@bongtu/ui/lockIntro";
import {
  loadOwnerSnapshot,
  pollForAction,
  refreshPlan,
  skipBaseline,
  runRefresh,
  AUTO_REFRESH_MS,
  RECONNECT_NOTICE,
  type OwnerSnapshot,
} from "@bongtu/client/refresh";
import { installGlobalErrorSurface, toastError, toasts } from "@bongtu/ui/toasts";
import { ToastHost } from "@bongtu/ui/Toast";
import { useHashRoute, navigate, useWalletDescription } from "./hooks.js";
import { Onboarding } from "./screens/Onboarding.js";
import { LockIntro } from "./screens/LockIntro.js";
import { Home } from "./screens/Home.js";
import { Receive } from "./screens/Receive.js";
import { Deposit } from "./screens/Deposit.js";
import { SpendScreen } from "./screens/SpendScreen.js";
import { Activity } from "./screens/Activity.js";
import { Settings } from "./screens/Settings.js";

// ONE store over the browser's real localStorage — the receiver every session
// read/write in this shell goes through (loginFlow's default deps construct their
// own over the same localStorage; the storage IS the state, so they agree).
const sessionStore = new SessionStore();

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
  /** the activity pages loaded so far, newest-first: one page after a load or a
   *  refresh, plus whatever `loadMoreHistory` has appended since. */
  history: HistoryItem[];
  /** cursor for the page after `history`, or null when the feed is exhausted —
   *  which is also what tells the Activity screen to stop offering "Load more". */
  historyNextBefore: number | null;
  /** true while the next page is in flight (the button's own spinner). */
  historyLoadingMore: boolean;
  loading: boolean;
  /** true while a post-action poll waits for the indexer to reflect the action. */
  syncing: boolean;
  /** friendly message when the indexer isn't arbiter-mode / is unreachable (else null). */
  dataError: string | null;
  /** calm, non-error note about the data on screen (e.g. a tokenless session that
   *  cannot refresh). Never clears the balance the way dataError does. */
  dataNotice: string | null;
  /** selfscan mode: the last completed scan's /head stamp — the sync dot's
   *  freshness reference. Null before a scan lands, and always null in
   *  arbiter mode. */
  scannedNextLeafIndex: number | null;

  /** True while a login is running (the Connect button disables and says so).
   *  Which wallet to use is the RainbowKit modal's business, not this state's. */
  connecting: boolean;
  connectError: string | null;
  /** Log in with whatever wallet wagmi has connected (the modal's pick). The
   *  Onboarding screen opens the modal first when nothing is connected yet. */
  connectWallet: () => Promise<void>;
  disconnect: () => void;
  /** `manual=true` marks a user-initiated refresh (sync dot, banner Retry): the one
   *  invocation allowed to toast on failure. Background callers omit it — their
   *  only failure surface is the dataError banner (never a toast). */
  refresh: (manual?: boolean) => Promise<void>;
  /** post-action refresh: poll until `txHash` is reflected, then apply the data. */
  refreshAfterAction: (txHash: string) => Promise<void>;
  /** append the next activity page. REJECTS on a failed read so the screen that
   *  asked can say so locally, instead of a page-load failure blanking the feed
   *  that is already on screen. No-op when there is no next page. */
  loadMoreHistory: () => Promise<void>;
  /** The bound op facade for this login (null until connected): deposit /
   *  spend / preview over the session's connection, lock, prover and note
   *  source — constructed ONCE per login (issue #34, the C1 bind-once
   *  precedent), so no screen re-threads engine inputs per call. */
  ops: SpendOps | null;
}

const WalletContext = createContext<WalletContextValue | null>(null);

// The indexer every read goes to. Deployment-fixed, not user-editable: the runtime
// override in Settings was retired (U-W9) because a wrong URL there silently broke
// balance and activity with no way back. `VITE_INDEXER_URL` still points a dev build
// at another box (config.ts), and vite proxies the default relative `/indexer`.
const INDEXER_URL = DEFAULTS.indexerUrl;

// ONE bound client for the page — every indexer read below (public selfscan IO,
// the token-mode session reads, and the transient key-mode binding) goes
// through it, so the base URL and auth wiring exist in one place.
const indexer = new IndexerClient(INDEXER_URL);

// The self-scan round-trip (resume, key peek, one §3.6 pass, store writeback,
// notice verdict) is the engine's ScanSession — module-scoped like the indexer
// client it reads through, because its state belongs to the page, not to a
// render (it replaces the old scanRef/scanOwnerRef pair).
const scanSession = new ScanSession(
  indexer,
  { load: loadScanState, save: saveScanState, clear: clearScanState },
  keyCache,
);

// Which discovery engine feeds balance/activity (config.ts discoveryFromEnv):
// "arbiter" = the token-authed /notes + /history reads below, byte-unchanged;
// "selfscan" = the OPMOD §3.6 public-feed scan — no /notes, no /auth
// requirement, no arbiter key anywhere in the balance path.
const SELFSCAN = isSelfScan(DEFAULTS.discovery);
// The shell states the mode to the refresh plan ONCE: selfscan reads are
// public (auth-free), and the plan itself (refresh.ts refreshPlan) owns the
// read-or-notice decision — no token shims, no scattered call-site gates.
const PLAN_OPTS = { authFree: SELFSCAN } as const;

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
  const [historyNextBefore, setHistoryNextBefore] = useState<number | null>(null);
  const [historyLoadingMore, setHistoryLoadingMore] = useState(false);
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [dataError, setDataError] = useState<string | null>(null);
  const [dataNotice, setDataNotice] = useState<string | null>(null);

  // selfscan mode: the /head freshness stamp of the last completed scan. The
  // scan state itself (memory-first, localStorage-backed) and its owner stamp
  // live in the module-level ScanSession, not in refs.
  const [scannedNextLeafIndex, setScannedNextLeafIndex] = useState<number | null>(null);

  const [connecting, setConnecting] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);

  // Which wallet the user is on — from the wagmi connector (its EIP-6963 metadata),
  // refined with vendor brand flags once the raw provider resolves (hooks.ts).
  const wallet = useWalletDescription();

  /** SELFSCAN read: one incremental §3.6 scan through the engine's ScanSession,
   *  which owns the whole round-trip — resume from the per-owner store, the
   *  keyCache peek + identity gate, the store writeback, and the notice
   *  verdict (scan/session.ts); this callback only wires the outcome to React
   *  state. Served in the arbiter snapshot's shape so everything downstream —
   *  applySnapshot, snapshotChanged, sumUnspent — is mode-blind. Scanning needs
   *  the view keys, and a background read must never pop a signature, so a
   *  LOCKED wallet serves its last completed scan unchanged under the calm
   *  notice — which lands after runRefresh's setNotice(null), so a successful
   *  read keeps it. */
  const loadSelfScan = useCallback(async (ownerCompressed: string): Promise<OwnerSnapshot> => {
    const scan = await scanSession.scan(ownerCompressed);
    setScannedNextLeafIndex(scan.scannedNextLeafIndex);
    setDataNotice(scan.notice);
    return scan.snapshot;
  }, []);

  /** Used by every read path except the tokenless one-shot below, which cannot
   *  page and so cannot share this. In selfscan mode the token is unused —
   *  every read is public. */
  const loadFirstPage = useCallback(
    (token: string, ownerCompressed: string): Promise<OwnerSnapshot> => {
      if (SELFSCAN) return loadSelfScan(ownerCompressed);
      // ONE token-mode binding for both reads (asOwner: token => paged history);
      // `notes` tears off safely and `historyPage()` still always sends `limit`
      // — the same URLs the hand-built branch hit.
      const reads = indexer.asOwner(ownerCompressed, { token });
      return loadOwnerSnapshot(reads.notes, () => reads.historyPage());
    },
    [loadSelfScan],
  );

  // The facade's note source reads THIS ref, not React state: a mid-chain pass
  // must see the freshest applied notes without waiting for a re-render.
  const notesRef = useRef<OwnerNote[]>([]);

  // Applying a snapshot RESETS the activity paging: the feed becomes the page that
  // was just read, and any pages "Load more" had appended are dropped. That is the
  // honest reset — the older pages were read against a feed that has since moved.
  const applySnapshot = useCallback((snap: OwnerSnapshot): void => {
    notesRef.current = snap.notes;
    setBalance(sumUnspent(snap.notes));
    setNotes(snap.notes);
    setHistory(snap.history);
    setHistoryNextBefore(snap.historyNextBefore);
  }, []);

  // Drop the login and every owner-derived value. Used by the Disconnect button and
  // by a dead token (a 401 on the only auth these reads have).
  //
  // `forget` separates those two: an explicit Disconnect also ends the WalletConnect
  // pairing and forgets which key this account derives, because the user asked for a
  // clean device. An expired token must NOT — the account still derives the same key,
  // and that record is what catches a wallet whose signatures drift (loginGuard.ts).
  const endSession = useCallback((reason: string | null, forget = false): void => {
    keyCache.lock(); // signing out drops the spending key too, not just the token
    toasts.clear(); // stale event toasts must not follow the user to onboarding
    sessionStore.clearSession();
    setScannedNextLeafIndex(null);
    if (forget) {
      sessionStore.clearKeyBindings();
      // A clean device keeps no decrypted amounts either: the session clears
      // the stamped owner's stored scan along with its in-memory state.
      scanSession.forgetOwner();
      // wagmi drops + forgets the connector (for WalletConnect that ends the
      // session, so the wallet app stops showing bongtu as connected).
      void endWalletConnection();
    } else {
      // A plain sign-out ends the in-memory scan and its owner stamp; the
      // stored row survives for this owner's next login.
      scanSession.end();
    }
    setConnection(null);
    setSession(null);
    setBalance(null);
    notesRef.current = [];
    setNotes([]);
    setHistory([]);
    setHistoryNextBefore(null);
    setDataError(reason);
    setDataNotice(null);
    navigate("home");
  }, []);

  // ONE refresh path for both invocations of it. `manual` marks the user-initiated
  // one-shot (the sync-dot tap, a banner Retry): only that may toast on failure
  // (class 1); the background invocations (session change, post-action fallback)
  // can only move the dataError BANNER — never a toast, and never a blanked screen:
  // the surface routing itself is headless (refresh.ts runRefresh, tested), this
  // callback only wires the sinks to React state.
  const refresh = useCallback(
    async (manual = false, quiet = false): Promise<void> => {
      if (!session) return;
      if (!quiet) setLoading(true); // an auto tick must not flash loading UI every 3 s
      try {
        // Arbiter reads authenticate with the VIEW token only — no key, no
        // signature popup. Selfscan reads are auth-free: PLAN_OPTS says so once
        // and the plan owns the read-or-notice decision (refresh.ts).
        await runRefresh(session, loadFirstPage, {
          applySnapshot,
          setBanner: setDataError,
          toast: toastError,
          signOut: (notice) => endSession(notice), // back to onboarding — retrying can only 401 again
          setNotice: setDataNotice,
        }, {
          manual,
          indexerUrl: INDEXER_URL,
          ...PLAN_OPTS,
          // An unchanged read never touches the screen: applying wholesale resets
          // activity paging, a pure loss when the data is identical. `balance` is
          // null until a snapshot has actually landed, which is what tells the
          // baseline apart from an empty account reading back its empty self.
          skipUnchangedFrom: skipBaseline(balance !== null, { notes, history, historyNextBefore }),
        });
      } finally {
        if (!quiet) setLoading(false);
      }
    },
    [session, loadFirstPage, applySnapshot, endSession, balance, notes, history, historyNextBefore],
  );

  // Auto-load whenever the session changes (after a connect or a silent restore).
  useEffect(() => {
    if (session) void refresh();
  }, [session, refresh]);

  // The indexer advances without us (its own ~3 s chain tail poll), so re-read it
  // on the same cadence while the tab is visible — money sent TO this account
  // appears unprompted, ~6 s worst case end to end. Quiet: no loading flash, no
  // toast, failures move only the banner; a tick never overlaps itself or a
  // post-action poll (`syncing`).
  useEffect(() => {
    if (!session) return;
    const inflight = { current: false };
    const id = setInterval(() => {
      if (document.visibilityState !== "visible" || inflight.current || syncing) return;
      inflight.current = true;
      void refresh(false, true).finally(() => {
        inflight.current = false;
      });
    }, AUTO_REFRESH_MS);
    return () => clearInterval(id);
  }, [session, refresh, syncing]);

  // Class 5 (unexpected/bug): whatever still reaches the window's error and
  // unhandledrejection events was caught by NO deliberate surface — toast it with
  // Copy details. Every intentional failure path below is caught before it gets
  // here, so background loops cannot reach this (they only move the banner).
  useEffect(() => installGlobalErrorSurface(), []);

  // A held spending key belongs to ONE wallet account, so a switch drops it at the
  // moment it happens — the flows re-check anyway, this just makes the header honest
  // (and re-locks a wallet whose owner walked away from the account).
  //
  // wagmi's account store is the one emitter for every connector, so this watches it
  // rather than any per-transport event surface. `disconnected` signs out for
  // WalletConnect ONLY — there it is the phone ending the session, while an
  // extension's disconnect can be a mere provider hiccup, which is no reason to sign
  // anyone out.
  useEffect(
    () =>
      watchWallet({
        accountsChanged: () => {
          // Lock the key AND detach the scan session (wallet-web's accountGuard
          // semantics): the owner stamp already prevents cross-owner resume,
          // but the previous owner's decrypted scan must not linger in memory.
          keyCache.lock();
          scanSession.detach();
        },
        disconnected: () => {
          if (connection?.transport === "walletconnect") {
            endSession("Your wallet ended the connection. Connect again to continue.");
          }
        },
      }),
    [connection, endSession],
  );

  // SILENT restore on first load: a stored unexpired session + the same authorised
  // account (eth_accounts, no popup) puts the user straight on Home; anything else
  // (expired token, account changed, storage empty) falls through to Onboarding.
  const restored = useRef(false);
  useEffect(() => {
    if (restored.current) return; // StrictMode double-mount guard
    restored.current = true;
    const stored = sessionStore.loadSession();
    if (!stored) {
      // Nothing to restore — still warm wagmi's remembered connector (silent), so
      // the Connect button can skip the modal for a wallet that is already live.
      warmReconnect();
      return;
    }
    void (async () => {
      // Reopen whatever connector the session was made over. Silent by construction:
      // wagmi re-opens its remembered connector via eth_accounts (never a prompt) or
      // the WalletConnect connector's own stored session (never a QR modal).
      const conn = await restoreConnection(stored.eoaAddress);
      if (!conn) {
        // account changed or no longer authorised — require a fresh connect.
        sessionStore.clearSession();
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
        // refusals, the token handshake, what gets persisted — lives in the flow
        // (loginFlow.ts), which is gated headlessly; it logs in with whatever wallet
        // the RainbowKit modal connected (connection.ts requireConnection). The
        // identity it returns never enters React state: the only reference that
        // outlives this function is the one keyCache.seed takes below (memory-only,
        // idle-wiped).
        const { connection: conn, identity: id, session: sess, tokenless } = await runLogin(
          { indexerUrl: INDEXER_URL },
          {
            // The wallet the RainbowKit modal just connected (wagmi.ts), deriving
            // under THIS deployment's KDF domain facts — the engine reads no config.
            openConnection: requireConnection,
            ensureChain,
            deriveIdentity: (c, plan) => deriveLoginIdentity(c, plan, KEY_DERIVATION),
          },
        );
        if (tokenless) {
          // No token to read with later, so load ONCE now with a key-signed query,
          // while the key is still in hand.
          try {
            // A key-mode binding is constructed TRANSIENTLY while the key
            // is in hand (the asOwner custody invariant) — same signed URLs.
            const reads = indexer.asOwner(id.compressedPubkey, { key: id.keypair.formattedPrivateKey });
            applySnapshot(
              await loadOwnerSnapshot(
                reads.notes,
                // Unpaged on purpose: there is no token to fetch a second page
                // with, so this one read must carry the whole feed. `nextBefore`
                // null is therefore the truth, not a shortcut.
                async () => ({ items: await reads.history(), nextBefore: null }),
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
        setConnectError(treasuryErrorMessage(e));
      } finally {
        setConnecting(false);
      }
    },
    [applySnapshot],
  );

  const disconnect = useCallback((): void => endSession(null, true), [endSession]);

  // Post-action refresh: the indexer tails the chain on a poll, so the moment a tx
  // confirms /notes may still show the PRE-action state. Poll (3s, ≤30s) until the
  // action is reflected (its tx in /history, or the note set changed), applying the
  // freshest snapshot either way. `syncing` lets success screens say the balance is
  // still catching up.
  const refreshAfterAction = useCallback(
    async (txHash: string): Promise<void> => {
      if (refreshPlan(session, PLAN_OPTS).kind === "notice") {
        await refresh(); // tokenless (or logged out): nothing to poll with
        return;
      }
      if (!session) return;
      setSyncing(true);
      try {
        const load = (): Promise<OwnerSnapshot> => loadFirstPage(session.token, session.compressedPubkey);
        const pre: OwnerSnapshot = { notes, history, historyNextBefore };
        const { last } = await pollForAction(load, pre, txHash);
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
    [session, notes, history, historyNextBefore, loadFirstPage, applySnapshot, refresh],
  );

  // "Load more" on the Activity screen: one page further down the SAME feed, over
  // the SAME token — a cursor into an already-authorised read, so paging costs no
  // extra signature. The append de-dups on seq (activity.ts), which is what keeps
  // a refresh landing mid-page from doubling rows.
  const loadMoreHistory = useCallback(async (): Promise<void> => {
    if (!session || historyNextBefore === null || historyLoadingMore) return;
    setHistoryLoadingMore(true);
    try {
      const page = await indexer.asOwner(session.compressedPubkey, { token: session.token }).historyPage({
        before: historyNextBefore,
      });
      setHistory((cur) => appendHistoryPage(cur, page.items));
      setHistoryNextBefore(page.nextBefore);
    } finally {
      setHistoryLoadingMore(false);
    }
  }, [session, historyNextBefore, historyLoadingMore]);

  // The between-legs read a spend chain waits on. It applies what it reads (so the
  // balance on screen keeps up with a chain in flight) but never clears anything on
  // failure — the chain's own bounded poll decides when the wait has gone on too long.
  const reloadNotes = useCallback(async (): Promise<OwnerNote[]> => {
    if (!session || refreshPlan(session, PLAN_OPTS).kind === "notice") {
      throw new Error(RECONNECT_NOTICE); // tokenless: no way to read, so no way to chain
    }
    const snap = await loadFirstPage(session.token, session.compressedPubkey);
    applySnapshot(snap);
    return snap.notes;
  }, [session, loadFirstPage, applySnapshot]);

  // ONE facade per login: the engine inputs every op screen used to re-thread —
  // connection, pool/token/explorer/relayer config, the lock, the in-browser
  // prover, the session pubkey — bind here, and the screens call methods. The
  // note source reads the notes REF (not React state) so a mid-chain pass
  // always plans over the freshest applied snapshot, and its reload is the
  // between-legs read above.
  const ops = useMemo<SpendOps | null>(
    () =>
      connection && session
        ? new SpendOps(
            {
              ...EVM_ENTERPRISE_IO,
              connection,
              indexerUrl: INDEXER_URL,
              pool: DEFAULTS.pool,
              token: DEFAULTS.token,
              explorer: DEFAULTS.explorer,
              // Empty config means "no relayer" — the flow's undefined default
              // (wallet self-submit); the flow itself relays only withdraw legs.
              relayerUrl: DEFAULTS.relayerUrl || undefined,
              keyCache,
              prove: (request) => proveInBrowser(request, DEFAULTS.circuitBaseUrl),
            },
            session,
            { notes: () => notesRef.current, reload: reloadNotes },
          )
        : null,
    [connection, session, reloadNotes],
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
      historyNextBefore,
      historyLoadingMore,
      loading,
      syncing,
      dataError,
      dataNotice,
      scannedNextLeafIndex,
      connecting,
      connectError,
      connectWallet,
      disconnect,
      refresh,
      refreshAfterAction,
      loadMoreHistory,
      ops,
    }),
    [
      connection, wallet, session, balance, notes, history, historyNextBefore, historyLoadingMore,
      loading, syncing, dataError, dataNotice, scannedNextLeafIndex, connecting, connectError,
      connectWallet, disconnect, refresh, refreshAfterAction, loadMoreHistory, ops,
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
