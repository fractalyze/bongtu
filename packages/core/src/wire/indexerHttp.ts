// wire/indexerHttp.ts — the shared JSON transport helpers + per-call options bag
// (split from indexerApi.ts). Exported for the sibling wire parts; the frozen
// `<url> -> <status>: <body-slice>` error shape lives here.
// --- thin typed client ----------------------------------------------------------

export async function getJson<T>(url: string, fetchFn: typeof fetch = fetch, signal?: AbortSignal): Promise<T> {
  const res = await fetchFn(url, signal === undefined ? undefined : { signal });
  const text = await res.text();
  if (!res.ok) throw new Error(`${url} -> ${res.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text) as T;
}

/** getJson for a JSON POST — same transport and the same thrown-message shape
 *  (`<url> -> <status>: <body-slice>`), which errors.ts classifyIndexerRead
 *  parses for the status code, so POSTs classify identically to reads. */
export async function postJson<T>(url: string, body: unknown, fetchFn: typeof fetch = fetch): Promise<T> {
  const res = await fetchFn(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${url} -> ${res.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text) as T;
}

/** getJson, except a 404 resolves to null — for lookups where absence is an
 *  answer, not a failure. Every other error keeps getJson's message shape. */
export async function getJsonOr404<T>(url: string, fetchFn: typeof fetch = fetch): Promise<T | null> {
  const res = await fetchFn(url);
  if (res.status === 404) return null;
  const text = await res.text();
  if (!res.ok) throw new Error(`${url} -> ${res.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text) as T;
}

export const trim = (u: string): string => u.replace(/\/$/, "");

/** Per-call transport options for the reads that predate fetch injection: the
 *  test seam (`fetchFn`) plus cancellation (`signal`) for polling consumers —
 *  a trailing optional bag, so every existing call keeps its exact shape. */
export interface IndexerFetchOpts {
  fetchFn?: typeof fetch;
  signal?: AbortSignal;
}
