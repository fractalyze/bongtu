// The SERVICE session — the first stage of the two-stage login: an id/password
// pair the operator types on the login page, validated against the prover
// service's GET /auth/check and then attached — as the same HTTP Basic value —
// to EVERY prover request. These are REAL server-side credentials
// (prover PROVER_AUTH_SHA256), not UI theater: the prover refuses a /prove
// without them, so the console cannot pretend its way past this stage.
//
// Custody: sessionStorage, on purpose. Unlike the bjj SPENDING key (memory-only,
// lib/keyCache.ts — moving money), this value only authorizes talking to the
// employer's own prover box, and a login that evaporated on every refresh would
// push operators toward weak passwords. sessionStorage means a refresh keeps the
// service session and closing the browser ends it. The WALLET session stays
// exactly as strict as before — the second stage (MetaMask connect, in the
// Console) is untouched by this module.

/** sessionStorage key for the held Basic value. */
export const SERVICE_AUTH_KEY = "bongtu.payroll.serviceAuth.v1";

/** id + password -> the HTTP Basic header value the prover validates:
 *  "Basic " + base64(utf8(id + ":" + password)). */
export function basicAuthValue(id: string, password: string): string {
  const bytes = new TextEncoder().encode(`${id}:${password}`);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return `Basic ${btoa(bin)}`;
}

// Fallback holder for storage-less runtimes (node tests, the deploy e2e driver,
// a browser that blocks sessionStorage): process-lifetime memory.
let memoryHeld: string | null = null;
const listeners = new Set<() => void>();

function storage(): Storage | null {
  return typeof sessionStorage === "undefined" ? null : sessionStorage;
}

function notify(): void {
  for (const fn of [...listeners]) fn();
}

/** The one holder of the service session. App subscribes; the prover adapter
 *  reads `header()` per request and calls `drop()` on a 401. */
export const serviceAuth = {
  /** The held Basic value, or null = no service session (show the login page). */
  header(): string | null {
    const s = storage();
    if (!s) return memoryHeld;
    try {
      return s.getItem(SERVICE_AUTH_KEY);
    } catch {
      return memoryHeld;
    }
  },

  /** Start the service session (after /auth/check accepted the pair). */
  set(header: string): void {
    memoryHeld = header;
    try {
      storage()?.setItem(SERVICE_AUTH_KEY, header);
    } catch {
      // blocked storage — the memory fallback still carries this page session
    }
    notify();
  },

  /** End the service session: the Sign out button, and the adapter's 401 path
   *  (the prover said this credential is no longer valid — pretending otherwise
   *  would just fail the next request too). */
  drop(): void {
    memoryHeld = null;
    try {
      storage()?.removeItem(SERVICE_AUTH_KEY);
    } catch {
      // nothing to clean if storage is unreachable
    }
    notify();
  },

  /** Subscribe to session start/end (App's render gate). */
  subscribe(listener: () => void): () => void {
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  },
};

/** What a sign-in attempt can come back with. A thrown fetch (service
 *  unreachable) is NOT mapped here — the caller words that separately, because
 *  "wrong password" and "no prover" need different fixes. */
export type SignInResult = { ok: true } | { ok: false; error: string };

/**
 * Validate `id`/`password` against GET {proverBase}/auth/check and, on 200,
 * hold the Basic value as the service session. 401 = the pair is wrong (the
 * login form's inline error). With PROVER_AUTH_SHA256 unset on the service
 * (local dev) the check answers 200 for anything — sign-in stays free there.
 */
export async function signInToProver(
  baseUrl: string,
  id: string,
  password: string,
): Promise<SignInResult> {
  const header = basicAuthValue(id, password);
  const res = await fetch(`${baseUrl.replace(/\/$/, "")}/auth/check`, {
    headers: { authorization: header },
  });
  if (res.status === 401) return { ok: false, error: "Wrong ID or password." };
  if (!res.ok) return { ok: false, error: `The prover service answered ${res.status}. Try again.` };
  serviceAuth.set(header);
  return { ok: true };
}
