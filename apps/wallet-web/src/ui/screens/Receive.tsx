// Receive = identity. Sends are registry-name-only in v1, so what a person
// shares to get paid is their NAME — never the raw triple (~1.2 KB of keys no
// one could read back), and no longer a bare address (nothing accepts one).
// This screen is the identity panel: the registered name with QR/copy when the
// directory vouches for it, and the register/update flow when it doesn't.
//
// Registration is buildNameRegistrationV2 ONLY: the v2 payload binds the
// stealth meta pair AND the consumer pair (noteViewPub + kemEk) under one owner
// signature — required together, because a name registered without the consumer
// pair is exactly the record the Send screen refuses to pay (lib/payName.ts).
// The directory has no reverse read, so "which name is ours" starts from the
// device's own pointer (lib/payNameStore.ts); the pointer is a hint, and the
// live record decides what renders as identity.

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import QRCode from "qrcode";
import { normalizeName, registerName, resolveName } from "@bongtu/core/indexerApi";
import { buildNameRegistrationV2 } from "@bongtu/core/indexerApi";
import { isConsumerIdentity } from "@bongtu/client/selfscan";
import { selfConsumerRecipient } from "@bongtu/client/consumer";
import { keyCache } from "@bongtu/ui/keyCache";
import { consumerErrorMessage } from "../../lib/errors.js";
import { opGate, OP_IN_FLIGHT_MESSAGE } from "../actionMachine.js";
import {
  clearOwnPayName,
  loadOwnPayName,
  ownNameStatus,
  saveOwnPayName,
  type OwnNameStatus,
} from "../../lib/payNameStore.js";
import { useWallet } from "../App.js";
import { useCopyFeedback } from "../hooks.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { Button, ErrorBanner, Field, TextInput } from "../components/controls.js";

/** The name grammar, in the words a person can act on (the actual judge is the
 *  shared normalizeName — one grammar for form, registry and resolver). */
export const NAME_RULES_HINT = "3 to 32 characters: lowercase letters, numbers, and hyphens.";

/** Rejected before any signature: a name that cannot normalize can never register. */
export const NAME_INVALID_MESSAGE = `That name can't be registered. ${NAME_RULES_HINT}`;

/** The identity panel's one instruction. */
export const RECEIVE_SHARE_LINE = "People pay you by this name. Share the name, nothing else.";

/** An own record without the payment keys: exactly what senders refuse to pay. */
export const NAME_NEEDS_UPDATE_NOTICE =
  "This name doesn't carry your payment keys yet. Update it so people can pay you privately.";

/** The QR of the NAME — small payload, so a roomy quiet zone renders cleanly. */
function NameQr({ name }: { name: string }): ReactNode {
  const [qr, setQr] = useState<string>("");
  useEffect(() => {
    if (!name) return;
    const alive = { current: true };
    void QRCode.toDataURL(name, { margin: 1, width: 240, color: { dark: "#111827", light: "#ffffff" } })
      .then((url) => {
        if (alive.current) setQr(url);
      })
      .catch(() => {
        if (alive.current) setQr("");
      });
    return () => {
      alive.current = false;
    };
  }, [name]);
  return (
    <div className="bg-surface border border-border p-3 rounded-2xl">
      {qr ? (
        <img className="block w-60 max-w-full h-auto" src={qr} alt={`Payment name ${name} QR`} />
      ) : (
        <div className="w-60 h-60 bg-surface-2 rounded-lg animate-pulse-soft" />
      )}
    </div>
  );
}

export function Receive(): ReactNode {
  const { session, connection, indexerUrl } = useWallet();

  // "checking" only while a stored pointer is being re-judged against the live
  // directory; a device with no pointer starts straight on the form.
  const [status, setStatus] = useState<OwnNameStatus | "checking">("checking");
  const [ownName, setOwnName] = useState<string | null>(null);
  const [nameInput, setNameInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { copied, copy } = useCopyFeedback(ownName ?? "");

  const owner = session?.compressedPubkey ?? null;

  useEffect(() => {
    if (!owner) return;
    const stored = loadOwnPayName(owner);
    if (!stored) {
      setStatus("unregistered");
      return;
    }
    const alive = { current: true };
    void (async () => {
      try {
        const record = await resolveName(indexerUrl, stored);
        if (!alive.current) return;
        const verdict = ownNameStatus(record, owner);
        if (verdict === "not-ours") {
          // The directory outranks the device pointer: a name another wallet
          // now owns must never render as this one's identity.
          clearOwnPayName(owner);
          setStatus("unregistered");
          return;
        }
        setOwnName(verdict === "unregistered" ? null : stored);
        setNameInput(stored);
        setStatus(verdict);
      } catch (e) {
        if (!alive.current) return;
        // A network failure is not "unregistered" — say what happened (in the
        // classified words) and keep the form usable (registering re-checks
        // against the live server).
        setStatus("unregistered");
        setError(consumerErrorMessage(e));
      }
    })();
    return () => {
      alive.current = false;
    };
  }, [owner, indexerUrl]);

  async function register(): Promise<void> {
    if (!connection || !session) return;
    const canonical = normalizeName(nameInput);
    if (!canonical) {
      setError(NAME_INVALID_MESSAGE);
      return;
    }
    // Registration is a directory write, not a chain op, so it runs no flow —
    // but its unlock/unlockStealth popups still contend for the user's wallet,
    // so it takes the page's one-op slot like any op: never two signature
    // trains interleaving over one lock.
    const opToken = Symbol("register");
    if (!opGate.tryAcquire(opToken)) {
      setError(OP_IN_FLIGHT_MESSAGE);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      // The registration signs with the OWNER key and binds the stealth meta,
      // so both derivations go through the one lock (its account/session/idle
      // checks included) — never a key held by this component.
      const identity = await keyCache.unlock(connection, session.compressedPubkey);
      if (!isConsumerIdentity(identity)) {
        throw new Error("This session's key has no payment identity. Sign out and log in again.");
      }
      const stealth = await keyCache.unlockStealth(connection, session.compressedPubkey);
      const self = selfConsumerRecipient(identity);
      const reg = buildNameRegistrationV2(
        canonical,
        identity.compressedPubkey,
        identity.keypair.formattedPrivateKey,
        stealth.meta,
        // The v2 pair, REQUIRED together: registering either half alone would
        // mint a name that resolves but cannot be paid.
        { noteViewPub: self.noteViewPub, kemEk: self.kemEk },
      );
      const record = await registerName(indexerUrl, reg);
      saveOwnPayName(session.compressedPubkey, record.name);
      setOwnName(record.name);
      setNameInput(record.name);
      setStatus("registered");
    } catch (e) {
      setError(consumerErrorMessage(e));
    } finally {
      opGate.release(opToken);
      setBusy(false);
    }
  }

  const registered = status === "registered" && ownName !== null;

  return (
    <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
      <ScreenHeader title="Receive" />

      {registered ? (
        <div className="flex flex-col gap-4 items-center">
          <p className="text-muted text-[0.9rem] text-center mt-1">{RECEIVE_SHARE_LINE}</p>
          <NameQr name={ownName} />
          <div className="w-full bg-surface-2 border border-border rounded-xl px-3.5 py-3 text-center text-[1.2rem] [font-weight:700]">
            {ownName}
          </div>
          <Button variant="primary" block onClick={copy}>
            {copied ? "Copied" : "Copy Name"}
          </Button>
          {error && <ErrorBanner message={error} />}
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          <p className="text-sm text-muted">
            Pick a payment name. People send to the <strong>name</strong> — your keys travel with
            it, your address never does.
          </p>
          {status === "needs-update" && <p className="text-sm text-warn">{NAME_NEEDS_UPDATE_NOTICE}</p>}
          <Field label="Payment name" hint={NAME_RULES_HINT}>
            <TextInput
              placeholder="e.g. alice"
              value={nameInput}
              onChange={(e) => {
                setNameInput(e.target.value);
                setError(null);
              }}
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
            />
          </Field>
          {error && <ErrorBanner message={error} />}
          <Button
            variant="primary"
            block
            disabled={busy || status === "checking" || !connection || normalizeName(nameInput) === null}
            onClick={() => void register()}
          >
            {busy
              ? "Registering…"
              : status === "needs-update"
                ? "Update Payment Name"
                : "Register Payment Name"}
          </Button>
        </div>
      )}
    </div>
  );
}
