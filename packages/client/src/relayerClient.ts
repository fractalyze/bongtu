// The wallet's client for the gas-sponsoring withdraw relayer (apps/relayer).
// Its own module rather than connection.ts because connection.ts is, by its own
// header, "everything that operates ON a live [Connection] over viem" — and a
// relayed submit is the one submit with NO Connection in it: no wallet client,
// no signature, no gas popup, just an HTTP POST of the already-proven calldata.
// It is SAFE to hand that calldata to an untrusted third party because the
// withdraw circuit binds the payout address into the proof (pub[26]): the
// relayer can pay the gas or refuse to — it cannot redirect a wei.
//
// Only WITHDRAW has a relayed submit. Transfers and deposits carry no
// proof-bound recipient, so the relayer offers nothing for them (apps/relayer
// src/relay.ts owns the full argument); spendFlow.ts routes only the terminal
// withdraw leg here.

import type { Calldata } from "@bongtu/core/proving";
import { explorerTxUrl } from "@bongtu/core/network";
import type { StealthDerivation } from "@bongtu/core/stealth";
import type { SubmitResult } from "./connection.js";

/**
 * Submit a proven withdraw THROUGH the relayer: POST /relay, map { txHash }
 * into the same SubmitResult shape submitWithdraw returns, so spendFlow and the
 * success screen cannot tell the two apart. A stealth run's announcement half
 * rides in the body; omitted, the relayer submits the plain-withdraw sentinel
 * (ZERO_EPHEMERAL / viewTag 0) exactly like a wallet-submitted plain withdraw.
 *
 * NO SILENT FALLBACK to wallet submit — deliberately. A relayer that is
 * configured but failing must surface its error (thrown as a readable message,
 * walletErrorMessage conventions): silently re-submitting from the user's own
 * account would pay gas from the very wallet the relayer promised to spare,
 * which is the exact promise being broken. The user (or the app's config)
 * decides what to do with a dead relayer; this function never decides for them.
 */
export async function submitWithdrawRelayed(
  relayerUrl: string,
  calldata: Calldata,
  kemCiphertext: string,
  explorerBase: string,
  stealth?: StealthDerivation,
  fetchFn: typeof fetch = fetch,
): Promise<SubmitResult> {
  const url = `${relayerUrl.replace(/\/+$/, "")}/relay`;
  const response = await (async () => {
    try {
      return await fetchFn(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          calldata,
          kemCiphertext,
          // Announcement half only when a stealth derivation rides along — the
          // relayer's own default IS the plain sentinel, so absence == plain.
          ...(stealth ? { ephemeralPub: stealth.ephemeralPub, viewTag: stealth.viewTag } : {}),
        }),
      });
    } catch (e) {
      throw new Error(
        `The gas-sponsoring relayer could not be reached (${e instanceof Error ? e.message : String(e)}). Your withdrawal was not sent.`,
      );
    }
  })();
  if (!response.ok) {
    // The relayer's error bodies are already human-readable ({ error }): the
    // 422 carries the simulation revert reason, the 400/502 name their cause.
    const detail = await (async () => {
      try {
        const parsed = (await response.json()) as { error?: string };
        return parsed.error ?? `HTTP ${response.status}`;
      } catch {
        return `HTTP ${response.status}`;
      }
    })();
    throw new Error(`The gas-sponsoring relayer rejected the withdrawal: ${detail}`);
  }
  const body = (await response.json()) as { txHash?: string };
  if (typeof body.txHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(body.txHash)) {
    throw new Error("The gas-sponsoring relayer answered without a transaction hash.");
  }
  return { txHash: body.txHash, explorerUrl: explorerTxUrl(body.txHash, explorerBase) };
}
