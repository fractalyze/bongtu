// Build a signed GET /notes URL (SPEC §6b v2 read-auth). The /notes auth binds to
// the OWNER key: the signature must verify against the queried pubkey, so the caller
// must hold that owner's private scalar. This is the wallet's own-notes lookup; in
// auditor-mode it is offered as a helper for a recipient checking their holdings via
// the arbiter indexer (or an auditor with a cooperating recipient's key). The
// auditor's general "who received what" view comes from the /events decrypt
// (ledger.ts), which needs only the arbiter key.

import { signNotesAuth, notesAuthMessage, packSignature } from "../../../../sdk/src/eddsa.js";
import { unpackPubkey } from "../../../../sdk/src/pubkey.js";

export function buildNotesUrl(indexerUrl: string, ownerCompressed: string, ownerPrivateKey: string): string {
  const pub = unpackPubkey(ownerCompressed.trim()); // validates the compressed pubkey
  const ts = Math.floor(Date.now() / 1000);
  const msg = notesAuthMessage(pub, ts);
  const sig = signNotesAuth(BigInt(ownerPrivateKey), msg);
  const base = indexerUrl.replace(/\/$/, "");
  return `${base}/notes?owner=${encodeURIComponent(ownerCompressed.trim())}&ts=${ts}&sig=${packSignature(sig)}`;
}

export async function fetchNotes(url: string): Promise<unknown> {
  const res = await fetch(url);
  const text = await res.text();
  if (!res.ok) throw new Error(`${res.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text);
}
