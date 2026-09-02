// The error-surface standard's headless half (.dev/error-surface-design.md): the
// AppError taxonomy — five consequence classes, discriminated by what the user can
// do NEXT, never by which subsystem raised the error — plus the three boundary
// classifiers every app shares (indexer HTTP reads, chain/provider submissions,
// in-browser proving). React-free by design: the classifiers are pure functions
// over thrown values, so every row of their decision tables gates under node:test.
//
// Copy placement rule (locked): only app-AGNOSTIC strings live here (there are
// none today — the classifiers return structured verdicts). Each app maps a
// verdict to its own words (wallet-web: connection.ts walletErrorMessage,
// refresh.ts classifyReadFailure), because "plain words, no jargon" is per-app
// voice, not shared mechanics.

// ================================ AppError =======================================

/**
 * One error, classed by consequence (.dev/error-surface-design.md table):
 *   retryable — transient failure of something the user just did → toast (or the
 *               flow's nearer inline slot);
 *   flow      — in-flow, user-recoverable → inline in the flow, never a toast;
 *   fatal     — session-fatal (dead token, wrong chain) → route change + notice;
 *   degraded  — background degradation (auto-refresh loop) → banner, never a toast;
 *   bug       — unexpected/invariant violation → toast + "Copy details".
 */
export type AppError =
  | { kind: "retryable"; message: string }
  | { kind: "flow"; message: string }
  | { kind: "fatal"; message: string }
  | { kind: "degraded"; message: string }
  | { kind: "bug"; message: string; details: string };

/** The five discriminants, for exhaustiveness checks and tests. */
export type AppErrorKind = AppError["kind"];

/**
 * Wrap an unknown thrown value as the class-5 (bug) AppError: a generic headline the
 * app words itself, plus the full details for the "Copy details" affordance. The
 * details NEVER leave the device except by the user's own paste — there is no error
 * telemetry in this product (privacy stance, locked).
 */
export function bugError(message: string, thrown: unknown): AppError & { kind: "bug" } {
  return { kind: "bug", message, details: describeThrown(thrown) };
}

/** Render any thrown value readably (message + stack + bounded cause chain) for the
 *  Copy-details payload. Never throws. */
export function describeThrown(thrown: unknown): string {
  const parts: string[] = [];
  const walk = (cur: unknown, depth: number): void => {
    if (cur === null || cur === undefined || depth >= 8) return;
    if (cur instanceof Error) {
      parts.push(depth === 0 ? cur.stack ?? `${cur.name}: ${cur.message}` : `caused by: ${cur.name}: ${cur.message}`);
      walk(cur.cause, depth + 1);
      return;
    }
    const text = (() => {
      try {
        return typeof cur === "string" ? cur : JSON.stringify(cur);
      } catch {
        return String(cur);
      }
    })();
    parts.push(depth === 0 ? text : `caused by: ${text}`);
  };
  walk(thrown, 0);
  return parts.length > 0 ? parts.join("\n") : String(thrown);
}

// =========================== (a) indexer HTTP reads ==============================

/**
 * What a failed indexer read means, structurally. The sdk's fetch wrappers
 * (indexerApi.ts) throw `"<url> -> <status>: <body>"` for any non-2xx response —
 * that message shape is the contract this classifier parses (and the reason it
 * lives beside those wrappers in core).
 *
 *   unauthorized — the ONE conclusive verdict: these reads have exactly one auth
 *                  (the view token), so a 401 means the token is dead and retrying
 *                  can only 401 again. Session-fatal for the caller.
 *   wrong_endpoint — 403/404: the indexer answers but has no such read (a
 *                  public-mode instance has no /notes at all).
 *   unreachable  — no parsable status: transport failure (or a non-HTTP throw).
 */
export type IndexerReadFailure =
  | { kind: "unauthorized"; status: 401 }
  | { kind: "wrong_endpoint"; status: 403 | 404 }
  | { kind: "unreachable"; status: number | null; detail: string };

/** Classify a failed indexer read from its thrown value. Total: any input yields a
 *  verdict (non-Error throws land in `unreachable` with their string form). */
export function classifyIndexerRead(err: unknown): IndexerReadFailure {
  const msg = err instanceof Error ? err.message : String(err);
  const m = /->\s*(\d{3})\b/.exec(msg);
  const status = m ? Number(m[1]) : null;
  if (status === 401) return { kind: "unauthorized", status: 401 };
  if (status === 403 || status === 404) return { kind: "wrong_endpoint", status };
  return { kind: "unreachable", status, detail: msg };
}

// ========================= (b) chain / provider errors ===========================

/** Walk an error and its `cause` chain (viem nests the actionable failure several
 *  levels deep); bounded so a cyclic cause cannot spin. */
export function causeChain(e: unknown): Record<string, unknown>[] {
  const chain: Record<string, unknown>[] = [];
  const walk = (cur: unknown): void => {
    if (cur === null || typeof cur !== "object" || chain.length >= 8) return;
    chain.push(cur as Record<string, unknown>);
    walk((cur as { cause?: unknown }).cause);
  };
  walk(e);
  return chain;
}

/** The first conventional `code` field anywhere in the cause chain (EIP-1193
 *  ProviderRpcError codes, ethers-style string codes). */
export function errorCode(e: unknown): number | string | undefined {
  for (const o of causeChain(e)) {
    if (typeof o.code === "number" || typeof o.code === "string") return o.code;
  }
  return undefined;
}

/** Every human-readable text field in the cause chain, most-specific first — the
 *  conventional spots providers and viem write their message into. */
export function errorTexts(e: unknown): string[] {
  return causeChain(e).flatMap((o) =>
    [
      o.reason,
      (o.error as { message?: string } | undefined)?.message,
      (o.data as { message?: string } | undefined)?.message,
      o.shortMessage,
      o.details,
      o.message,
    ].filter((t): t is string => typeof t === "string"),
  );
}

/**
 * What a failed wallet/RPC interaction means, structurally. `text` is the best
 * human-readable line found in the cause chain (null when there is none — the app
 * falls back to stringifying), so an app can keep surfacing viem's own short
 * message for the shapes it has no better words for.
 *
 *   user_rejected    — EIP-1193 code 4001 / ethers ACTION_REJECTED / viem's typed
 *                      UserRejectedRequestError / a "user rejected|denied" text.
 *                      In-flow and fully recoverable: the user pressed Cancel.
 *   insufficient_gas — the account cannot pay L2 gas ("insufficient funds").
 *   chain_switch     — the wallet would not move to (or add) the target chain:
 *                      viem's SwitchChainError / ChainNotConfiguredError, or the
 *                      EIP-3085/3326 error surfaces. `rejected` says whether the
 *                      user declined it (vs the wallet simply failing).
 *   timeout          — the request timed out (viem TimeoutError or a timeout text).
 *   transport        — the RPC/relay could not be reached at all (viem
 *                      HttpRequestError/WebSocketRequestError, fetch failures).
 *   other            — everything else (contract reverts included): show `text`.
 */
export type ChainFailure =
  | { kind: "user_rejected"; text: string | null }
  | { kind: "insufficient_gas"; text: string | null }
  | { kind: "chain_switch"; rejected: boolean; text: string | null }
  | { kind: "timeout"; text: string | null }
  | { kind: "transport"; text: string | null }
  | { kind: "other"; text: string | null };

const REJECTED_CODES = new Set<number | string>([4001, "ACTION_REJECTED"]);

function chainHasName(e: unknown, names: readonly string[]): boolean {
  return causeChain(e).some((o) => typeof o.name === "string" && names.includes(o.name));
}

/** Classify a failed wallet/RPC interaction from its thrown value. Total. */
export function classifyChainFailure(e: unknown): ChainFailure {
  const texts = errorTexts(e);
  const text = texts.length > 0 ? texts[0] : null;
  const rejected =
    causeChain(e).some((o) => (typeof o.code === "number" || typeof o.code === "string") && REJECTED_CODES.has(o.code)) ||
    chainHasName(e, ["UserRejectedRequestError"]) ||
    texts.some((t) => /user rejected|user denied/i.test(t));
  // A refused/failed chain switch is its own consequence (the app must say which
  // network to select) — checked before the plain rejection so a declined switch
  // is not misread as a declined transaction.
  if (chainHasName(e, ["SwitchChainError", "ChainNotConfiguredError"]) || texts.some((t) => /switch(ing)? (the )?chain|wallet_switchEthereumChain/i.test(t))) {
    return { kind: "chain_switch", rejected, text };
  }
  if (rejected) return { kind: "user_rejected", text };
  if (texts.some((t) => /insufficient funds/i.test(t))) return { kind: "insufficient_gas", text };
  if (chainHasName(e, ["TimeoutError"]) || texts.some((t) => /timed? ?out/i.test(t))) {
    return { kind: "timeout", text };
  }
  if (
    chainHasName(e, ["HttpRequestError", "WebSocketRequestError", "SocketClosedError", "RpcRequestError"]) ||
    texts.some((t) => /failed to fetch|network ?error|ECONNREFUSED/i.test(t))
  ) {
    return { kind: "transport", text };
  }
  return { kind: "other", text };
}

// ============================ (c) proving worker =================================

/**
 * What a failed in-browser proof means, structurally.
 *
 *   assets  — the one-time wasm/zkey download failed (network or a missing asset):
 *             transient, retry re-fetches.
 *   witness — the witness calculator rejected the inputs (circom "Assert Failed",
 *             unset signals): NOT retryable with the same inputs — either the
 *             wallet's note view is stale (reload and retry) or it is a bug.
 *   memory  — the browser could not give snarkjs its working set: retryable after
 *             closing tabs, but the same tab will likely fail again.
 *   other   — everything else.
 */
export type ProvingFailure =
  | { kind: "assets"; detail: string }
  | { kind: "witness"; detail: string }
  | { kind: "memory"; detail: string }
  | { kind: "other"; detail: string };

/** Classify a failed proving attempt from its thrown value. Total. */
export function classifyProvingFailure(e: unknown): ProvingFailure {
  const detail = e instanceof Error ? e.message : String(e);
  if (/\.(wasm|zkey)\b/i.test(detail) || /failed to fetch|network ?error/i.test(detail)) {
    return { kind: "assets", detail };
  }
  if (/assert failed|not all inputs|too many signals|invalid signal|scalar size/i.test(detail)) {
    return { kind: "witness", detail };
  }
  if (/out of memory|memory access out of bounds|allocation failed|table index is out of bounds/i.test(detail)) {
    return { kind: "memory", detail };
  }
  return { kind: "other", detail };
}
