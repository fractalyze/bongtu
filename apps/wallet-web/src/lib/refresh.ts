// Refresh policy + post-action refresh.
//
// Post-action refresh: after a deposit/transfer/withdraw confirms on-chain, the
// arbiter indexer still has to POLL the chain before /notes and /history reflect
// it (its tail poll is seconds behind the tx receipt). A single fire-and-forget
// refresh() at that moment usually reads the PRE-action state and leaves the user
// staring at a stale balance — so instead we poll until the action is visibly
// reflected (bounded), then hand the fresh snapshot to the UI.
//
// Pure core + injected sleep/load so the loop is unit-tested in milliseconds
// (test/refresh.test.ts); App.tsx wires the real token-authed fetches.

import { classifyIndexerRead } from "@bongtu/core/errors";
import type { OwnerNote, HistoryItem, HistoryPage } from "./indexerClient.js";

/** One consistent read of the owner's indexer state. `history` is the FIRST page
 *  of the activity feed and `historyNextBefore` the cursor for the page after it
 *  (null = the whole feed fitted in one page). */
export interface OwnerSnapshot {
  notes: OwnerNote[];
  history: HistoryItem[];
  historyNextBefore: number | null;
}

/**
 * ONE read of the owner's state, from whichever pair of fetches the caller's auth
 * allows (token-authed page, or the tokenless one-shot's whole feed).
 *
 * `loadNotes` failing REJECTS — the balance is the screen, and a wrong balance is
 * worse than an error banner. The activity read is best-effort on top: an indexer
 * without /history (or one that failed only that call) still yields a usable
 * balance, with an empty feed and a null cursor, which is the honest report — the
 * app has nothing to page from.
 *
 * The returned snapshot is what the app applies WHOLESALE, so the feed it holds
 * afterwards is exactly this read: any pages "Load more" had appended are dropped,
 * because they were read against a feed that has since moved.
 */
export async function loadOwnerSnapshot(
  loadNotes: () => Promise<OwnerNote[]>,
  loadHistory: () => Promise<HistoryPage>,
): Promise<OwnerSnapshot> {
  const notes = await loadNotes();
  try {
    const page = await loadHistory();
    return { notes, history: page.items, historyNextBefore: page.nextBefore };
  } catch {
    return { notes, history: [], historyNextBefore: null };
  }
}

// --- refresh policy (what a refresh may do, and what a failed read means) ---------

/** What the app is allowed to do for a refresh right now. */
export type RefreshPlan =
  /** the session holds a view token: issue the token-authed reads. */
  | { kind: "read" }
  /** no token to read with: keep whatever is on screen and say so. */
  | { kind: "notice"; message: string };

export const RECONNECT_NOTICE = "Reconnect to refresh your balance.";

/**
 * A tokenless session (the indexer had no /auth, so connect fell back to a
 * one-shot key-signed load) has NOTHING to authenticate a later read with. Issuing
 * one anyway returns 400/401 and the error path would wipe the balance the fallback
 * just loaded — turning a working screen into an indexer-error screen on the first
 * auto-refresh. So a tokenless refresh does not fetch at all.
 */
export function refreshPlan(session: { token: string } | null): RefreshPlan {
  if (!session || session.token === "") return { kind: "notice", message: RECONNECT_NOTICE };
  return { kind: "read" };
}

/** Why a token-authed read failed, and therefore what the app should do. */
export type ReadFailure =
  /** the token is dead (rotated secret / early expiry): log out, back to onboarding. */
  | { kind: "expired"; message: string }
  /** anything else: keep the session, show a retryable error. */
  | { kind: "error"; message: string };

export const EXPIRED_MESSAGE = "Your login expired. Please reconnect.";

/**
 * Classify a failed owner read. Only a 401 is conclusive: the token path is the
 * only auth these reads use, so the server rejecting it means the token is no
 * longer valid — the app must return to onboarding rather than show a retry button
 * that can only fail again. A 404/403 is the wrong-indexer case (a public-mode
 * instance has no /notes at all) and anything else is a transport failure.
 *
 * The structural verdict (which the sdk's `"url -> status"` message contract feeds)
 * comes from the shared classifier in @bongtu/core/errors; only the wallet's own
 * words live here.
 */
export function classifyReadFailure(err: unknown, indexerUrl: string): ReadFailure {
  const verdict = classifyIndexerRead(err);
  switch (verdict.kind) {
    case "unauthorized":
      return { kind: "expired", message: EXPIRED_MESSAGE };
    case "wrong_endpoint":
      return { kind: "error", message: "Can't load your balance right now. Check the indexer connection and retry." };
    case "unreachable":
      return {
        kind: "error",
        message: `Couldn't reach the indexer at ${indexerUrl}. Check it's running and the URL in Settings. (${verdict.detail})`,
      };
  }
}

// --- the refresh orchestration (which error surface a failed read gets) -----------

/** What a refresh failure toasts for a MANUAL refresh. The banner already names the
 *  holding condition in detail; the toast only announces the event the user's tap
 *  produced (toast = event, banner = state — .dev/error-surface-design.md). */
export const REFRESH_FAILED_TOAST = "Refresh failed. Showing the last loaded data.";

/**
 * The side effects one refresh may produce, as injectable sinks so the whole
 * surface policy is testable without React (App.tsx wires its setState calls in):
 *
 *   applySnapshot — a successful read, applied wholesale;
 *   setBanner     — the ONE degraded-state slot (App's `dataError`): set on a
 *                   failed read, cleared (null) by the next success. Deliberately
 *                   the only failure sink for background reads — there is no sink
 *                   that blanks on-screen data, because a failed background read
 *                   must never blank it (locked rule);
 *   toast         — fired ONLY for a manual refresh (class-1 event);
 *   signOut       — the 401 route: back to onboarding, carrying the notice;
 *   setNotice     — the calm tokenless-session strip (never an error).
 */
export interface RefreshSinks {
  applySnapshot(snap: OwnerSnapshot): void;
  setBanner(message: string | null): void;
  toast(message: string): void;
  signOut(notice: string): void;
  setNotice(message: string | null): void;
}

/**
 * ONE refresh, start to finish: plan (tokenless sessions never issue a doomed
 * read), load, then route the outcome to exactly one surface. `manual` says the
 * user asked for this refresh right now — the only case that may toast; the
 * background loop and the post-action fallback run with manual=false and can only
 * move the banner.
 */
export async function runRefresh(
  session: { token: string; compressedPubkey: string } | null,
  load: (token: string, owner: string) => Promise<OwnerSnapshot>,
  sinks: RefreshSinks,
  opts: { manual?: boolean; indexerUrl: string },
): Promise<void> {
  const plan = refreshPlan(session);
  if (plan.kind === "notice" || !session) {
    // No token to read with: keep the snapshot already on screen and say so.
    sinks.setNotice(plan.kind === "notice" ? plan.message : RECONNECT_NOTICE);
    sinks.setBanner(null);
    return;
  }
  sinks.setNotice(null);
  try {
    sinks.applySnapshot(await load(session.token, session.compressedPubkey));
    sinks.setBanner(null); // recovery clears the state banner
  } catch (e) {
    const failure = classifyReadFailure(e, opts.indexerUrl);
    if (failure.kind === "expired") {
      sinks.signOut(failure.message); // retrying can only 401 again
      return;
    }
    sinks.setBanner(failure.message);
    if (opts.manual) sinks.toast(REFRESH_FAILED_TOAST);
  }
}

/**
 * Whether `cur` shows the action that produced `txHash`, relative to the
 * pre-action `pre`. PURE. Three sufficient signals, any one accepts:
 *   - the tx itself appears in the history feed (the precise signal — every op
 *     kind lands a history item for its owner);
 *   - the history feed grew past its pre-action length (covers a feed that
 *     surfaces the op under a different hash, e.g. a multicall wrapper). Both
 *     sides are ONE page, so this signal goes quiet once an account's feed fills
 *     a page — the other two carry it from there, and a new op is always on the
 *     first page anyway, the feed being newest-first;
 *   - the note set changed (a note created, spent, or removed) — the balance
 *     consequence of the action, even if history lags.
 */
export function actionReflected(pre: OwnerSnapshot, cur: OwnerSnapshot, txHash: string): boolean {
  const wanted = txHash.toLowerCase();
  if (cur.history.some((h) => h.txHash.toLowerCase() === wanted)) return true;
  if (cur.history.length > pre.history.length) return true;
  if (cur.notes.length !== pre.notes.length) return true;
  const preKeys = new Set(pre.notes.map((n) => `${n.commitment}:${n.spent}`));
  return cur.notes.some((n) => !preKeys.has(`${n.commitment}:${n.spent}`));
}

export interface PollForActionOptions {
  /** between polls (task-fixed 2–4s band; default 3s). */
  intervalMs?: number;
  /** total budget; polling stops after this even if never reflected (default 30s). */
  capMs?: number;
  /** injectable for tests (defaults to a real setTimeout sleep). */
  sleep?: (ms: number) => Promise<void>;
}

export interface PollForActionResult {
  /** true when a snapshot showed the action inside the budget. */
  landed: boolean;
  /** the freshest successful snapshot (null when every poll errored). */
  last: OwnerSnapshot | null;
}

const realSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** What a bounded poll ended up with: whether `accept` ever said yes, and the last
 *  value that loaded at all (null when every attempt threw). */
export interface PollResult<T> {
  landed: boolean;
  last: T | null;
}

/**
 * The wallet's ONE bounded-poll policy, over any read: call `load` every
 * `intervalMs` until `accept` accepts a value or `capMs` runs out. A failing load
 * (indexer hiccup) is skipped, not fatal — the next tick retries — and the last
 * value that DID load comes back either way, so a cap-out can still render
 * something fresh.
 *
 * Two callers, both waiting on the same lag: pollForAction below (the post-action
 * balance refresh) and the spend chain, which cannot build its next leg until the
 * indexer has recorded the note the previous leg created (spendFlow.ts).
 */
export async function pollUntil<T>(
  load: () => Promise<T>,
  accept: (value: T) => boolean,
  opts: PollForActionOptions = {},
): Promise<PollResult<T>> {
  const intervalMs = opts.intervalMs ?? 3000;
  const capMs = opts.capMs ?? 30000;
  const sleep = opts.sleep ?? realSleep;
  let last: T | null = null;
  for (let elapsed = 0; elapsed < capMs; elapsed += intervalMs) {
    await sleep(intervalMs);
    try {
      const cur = await load();
      last = cur;
      if (accept(cur)) return { landed: true, last };
    } catch {
      // transient indexer failure — keep polling until the cap
    }
  }
  return { landed: false, last };
}

/**
 * Poll `load` until `actionReflected(pre, snapshot, txHash)` or the cap runs out.
 */
export async function pollForAction(
  load: () => Promise<OwnerSnapshot>,
  pre: OwnerSnapshot,
  txHash: string,
  opts: PollForActionOptions = {},
): Promise<PollForActionResult> {
  return pollUntil(load, (cur) => actionReflected(pre, cur, txHash), opts);
}
