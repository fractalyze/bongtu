// Thin fetch wrappers over the indexer read API (SPEC §6b). Employer-mode uses
// /head + /path to build the input-note membership witness from chain state;
// auditor-mode uses /events + /alarms.

import type { FeedEvent } from "./ledger.js";

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  const text = await res.text();
  if (!res.ok) throw new Error(`${url} -> ${res.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text) as T;
}

export interface Head {
  root: string;
  nextLeafIndex: number;
}
export interface PathResult {
  leafIndex: number;
  siblings: string[];
  pathIndices: number[];
  root: string;
}

export function getHead(indexerUrl: string): Promise<Head> {
  return getJson<Head>(`${indexerUrl.replace(/\/$/, "")}/head`);
}

/** Merkle path of a leaf against the current root (422 for a within-batch leaf in
 *  public mode — the caller surfaces that to the user). */
export function getPath(indexerUrl: string, leafIndex: number): Promise<PathResult> {
  return getJson<PathResult>(`${indexerUrl.replace(/\/$/, "")}/path/${leafIndex}`);
}

export function getEvents(indexerUrl: string, limit = 5000): Promise<FeedEvent[]> {
  return getJson<FeedEvent[]>(`${indexerUrl.replace(/\/$/, "")}/events?limit=${limit}`);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function getAlarms(indexerUrl: string): Promise<any[]> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return getJson<any[]>(`${indexerUrl.replace(/\/$/, "")}/alarms`);
}
