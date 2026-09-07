// The pay page's whole issuance decision, pure of the DOM (main.ts renders,
// this module decides) so the ordering and failure paths gate headlessly.
//
// The flow per page load (spec R2, in this exact order):
//   1. resolve the label's directory record and VALIDATE it (v2 consumer pair
//      present — a legacy record cannot receive consumer notes, fail closed);
//   2. derive a FRESH stealth destination in the browser: local ephemeral
//      scalar + the record's PUBLIC keys (@bongtu/core/stealth) — no server
//      secret participates, and the scalar dies with this call;
//   3. ANNOUNCE — POST the public derivation to the indexer BEFORE the address
//      is ever displayed (first write wins server-side, so an observer of the
//      displayed address can never front-run the honest record);
//   4. PARITY-CHECK the server's recomputed destination against the local
//      CREATE2 mapping — a mismatch means a misconfigured page or a hostile
//      indexer trying to show the payer a different address: fail closed.
// Only after all four does the caller get something to display.

import {
  announcePortal,
  resolveName,
  type NameRecord,
  type PortalPublicRecord,
} from "@bongtu/core/indexerApi";
import { KEM_EK_ZERO, NOTE_VIEW_PUB_ZERO } from "@bongtu/core/eddsa";
import {
  create2Address,
  deriveStealthAddress,
  portalSalt,
  randomEphemeralScalar,
} from "@bongtu/core/stealth";

/** What the page renders after a successful issuance. */
export interface IssuedPayment {
  /** the CREATE2 destination the payer funds (EIP-55) — QR + copy target. */
  destination: string;
  label: string;
  /** the announcement half, rendered nowhere but kept for debugging surface. */
  ephemeralPub: string;
  viewTag: number;
  stealthAddr: string;
}

/** Everything one issuance consumes, injectable for the headless tests. */
export interface PayDeps {
  indexerUrl: string;
  portalPrivFactory: string;
  sweeperInitCodeHash: string;
  fetchFn?: typeof fetch;
  drawScalar?: () => bigint;
}

/**
 * A record can receive only when it carries BOTH halves: the stealth meta
 * (viewPub/spendPub — the address derivation) and the v2 consumer pair
 * (noteViewPub/kemEk — what the sweep seals the notes to). The zero-sentinel
 * clear counts as absent. Returns the human-facing (Korean) reason, or null
 * when payable — the page's fail-closed gate.
 */
export function recordProblem(record: NameRecord | null): string | null {
  if (!record) return "등록되지 않은 주소예요";
  if (!record.viewPub || !record.spendPub) return "이 이름은 아직 받을 준비가 되지 않았어요";
  if (
    !record.noteViewPub ||
    !record.kemEk ||
    record.noteViewPub === NOTE_VIEW_PUB_ZERO ||
    record.kemEk === KEM_EK_ZERO
  ) {
    return "이 이름은 아직 받을 준비가 되지 않았어요";
  }
  return null;
}

/**
 * One issuance, start to finish (the four steps above). Throws with a
 * human-readable message on every failure path — the caller renders the
 * message and NOTHING else (no address ever shows without a recorded
 * announcement and a passed parity check).
 */
export async function issuePayment(label: string, deps: PayDeps): Promise<IssuedPayment> {
  if (!deps.portalPrivFactory || !deps.sweeperInitCodeHash) {
    throw new Error("이 페이지가 아직 설정되지 않았어요 (portalPriv factory unconfigured)");
  }
  const fetchFn = deps.fetchFn ?? fetch;
  const record = await resolveName(deps.indexerUrl, label, fetchFn);
  const problem = recordProblem(record);
  if (problem !== null) throw new Error(problem);
  const { viewPub, spendPub } = record as NameRecord;

  const derived = deriveStealthAddress(
    { viewPub, spendPub },
    (deps.drawScalar ?? randomEphemeralScalar)(),
  );
  const destination = create2Address(
    deps.portalPrivFactory,
    portalSalt(derived.address),
    deps.sweeperInitCodeHash,
  );

  // Announce BEFORE display — the server records first-write-wins, recomputes
  // the destination itself, and hands it back for the parity check.
  const recorded: PortalPublicRecord = await announcePortal(
    deps.indexerUrl,
    {
      label,
      ephemeralPub: derived.ephemeralPub,
      viewTag: derived.viewTag,
      stealthAddr: derived.address,
    },
    fetchFn,
  );
  if (recorded.destination.toLowerCase() !== destination.toLowerCase()) {
    throw new Error(
      "주소 확인에 실패했어요. 페이지를 새로고침해 주세요 (destination parity check failed)",
    );
  }

  return {
    destination,
    label,
    ephemeralPub: derived.ephemeralPub,
    viewTag: derived.viewTag,
    stealthAddr: derived.address,
  };
}

/** "0x7f3A…9c4E" — the address chip's shortened form. */
export function shortAddress(addr: string): string {
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

/** The /p/{label} route parse; null for any other path. */
export function labelFromPath(pathname: string): string | null {
  const m = /^\/p\/([A-Za-z0-9-]{1,64})$/.exec(pathname);
  return m ? m[1] : null;
}
