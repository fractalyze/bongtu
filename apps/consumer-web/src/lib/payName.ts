// Pay-by-name for the consumer family: the ONE resolve seam the Send screen
// (S6) confirms a recipient through. Names live in the indexer's public /names
// directory, and a consumer payment must seal to the payee's REGISTERED v2
// consumer triple (spend pubkey owner + note-layer view pubkey + ML-KEM ek) —
// so the triple is REQUIRED on resolve, not a soft preference: sealing to a
// missing or cleared key would mint notes the recipient could never discover
// by self-scan (funds land, discovery never does). The refusal itself lives in
// @bongtu/client/consumerBuild consumerRecipientOf (legacy v1 record and the
// signed zero-sentinel clear both refuse); this file owns only the wallet's
// words for each outcome.

import { normalizeName, resolveName } from "@bongtu/core/indexerApi";
import { consumerRecipientOf, type ConsumerRecipient } from "@bongtu/client/consumerBuild";

/** The name does not normalize or is not in the directory — a typo-or-unregistered
 *  answer, never a network answer (failures propagate, see below). */
export const RECIPIENT_NOT_REGISTERED_MESSAGE =
  "That name isn't registered. Check the spelling with the recipient.";

/** The name resolves but its record has no consumer triple (a legacy v1-only
 *  registration, or one whose consumer identity was cleared): the money could be
 *  sent but never found, so the wallet refuses with the plain reason. */
export const RECIPIENT_V1_ONLY_MESSAGE =
  "This recipient can’t receive private payments yet. Ask them to register their payment name from their own consumer wallet first.";

export type RecipientResolution =
  | { ok: true; name: string; recipient: ConsumerRecipient }
  | { ok: false; message: string };

/**
 * Resolve a typed recipient name to a payable consumer triple, or the exact
 * words for why it cannot be paid. Network failures PROPAGATE (the wallet-web
 * payName rule, kept): "the indexer is down" must not read as "that name
 * doesn't exist".
 */
export async function resolveConsumerRecipient(
  indexerUrl: string,
  name: string,
  resolve: typeof resolveName = resolveName,
): Promise<RecipientResolution> {
  const canonical = normalizeName(name);
  if (!canonical) return { ok: false, message: RECIPIENT_NOT_REGISTERED_MESSAGE };
  const record = await resolve(indexerUrl, canonical);
  if (!record) return { ok: false, message: RECIPIENT_NOT_REGISTERED_MESSAGE };
  const recipient = ((): ConsumerRecipient | null => {
    try {
      return consumerRecipientOf(record);
    } catch {
      // consumerRecipientOf throws exactly for "no consumer identity" — the
      // v1-only class; every other failure mode above already returned.
      return null;
    }
  })();
  if (recipient === null) return { ok: false, message: RECIPIENT_V1_ONLY_MESSAGE };
  return { ok: true, name: canonical, recipient };
}
