// The wallet's OWN payment name: where the Receive screen learns which name to
// show. The directory has no owner-to-name reverse read (names resolve forward
// only), so the app remembers the name IT registered — a localStorage pointer,
// per owner pubkey, holding nothing but the label — and re-verifies it against
// the live directory on screen open (ownNameStatus below). The record is a
// HINT, never an authority: the resolve decides what renders, so a name
// re-registered from another device, taken over, or stripped of its consumer
// pair can never be shown as "yours" on this one.
//
// Every storage access is try/caught (the scanStore rule): a browser that
// blocks storage just means the Receive screen starts on the register form.

import type { NameRecord } from "@bongtu/core/indexerApi";
import { consumerRecipientOf } from "@bongtu/client/consumerBuild";

const key = (ownerCompressed: string): string => `bongtu.consumer.payname.${ownerCompressed}`;

/** The name this device last registered for `ownerCompressed`, or null. */
export function loadOwnPayName(ownerCompressed: string): string | null {
  try {
    return localStorage.getItem(key(ownerCompressed));
  } catch {
    return null;
  }
}

/** Remember a registration this device just made (best-effort). */
export function saveOwnPayName(ownerCompressed: string, name: string): void {
  try {
    localStorage.setItem(key(ownerCompressed), name);
  } catch {
    // storage blocked: the next visit re-registers or re-types the name
  }
}

/** Drop the pointer — the resolve said the name is no longer this wallet's. */
export function clearOwnPayName(ownerCompressed: string): void {
  try {
    localStorage.removeItem(key(ownerCompressed));
  } catch {
    // nothing to clear where nothing could be stored
  }
}

/**
 * What the live directory says about the name this device remembers:
 *   unregistered — no record: the name is free (or was never registered).
 *   not-ours     — registered to a DIFFERENT owner key: the local hint is
 *                  stale and must be cleared, never rendered as identity.
 *   needs-update — ours, but without a payable consumer pair (a v1-only or
 *                  cleared record): senders following the registry-name-only
 *                  rule cannot pay it until it is re-registered v2.
 *   registered   — ours and payable: the identity panel's happy state.
 */
export type OwnNameStatus = "unregistered" | "not-ours" | "needs-update" | "registered";

export function ownNameStatus(record: NameRecord | null, ownerCompressed: string): OwnNameStatus {
  if (record === null) return "unregistered";
  if (record.owner !== ownerCompressed) return "not-ours";
  const payable = ((): boolean => {
    try {
      consumerRecipientOf(record);
      return true;
    } catch {
      // consumerRecipientOf throws exactly for "no consumer identity" — the
      // v1-only / cleared class the Send screen refuses to pay.
      return false;
    }
  })();
  return payable ? "registered" : "needs-update";
}
