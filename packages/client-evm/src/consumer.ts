// The consumer-family SUBMIT layer: one thin wrapper per module op, each riding
// the ONE submit discipline (connection.ts submitPoolWrite — gas pinned at the
// node's floor quote x3, nonce from the chain's pending view, resolve only after
// the receipt). What differs from the enterprise submits is only the TARGET and
// the ciphertext shape: writes go to each op's MODULE address (@bongtu/core
// CONSUMER_MODULES — the pool stays the escrow/approval target and holds the
// verify-side state; modules hold no funds, docs/consumer.md), and the hybrid
// receiver ciphertexts are a PER-OUTPUT `bytes[]` of raw ML-KEM-768
// encapsulations (2 for the two-output ops, 1 for withdraw's change note)
// instead of the pool ops' single authority `bytes kemCiphertext` — there is no
// authority envelope in this family. Arg shapes mirror deploy/gates/
// consumer_leg.ts byte-for-byte; the fragment parse (CONSUMER_MODULE_ABI_FRAGMENTS)
// is the shared contract both sides encode against.

import { parseAbi } from "viem";
import type { Calldata } from "@bongtu/core/proving";
import { asProofArgs } from "./connection/index.js";
import {
  CONSUMER_MODULES,
  CONSUMER_MODULE_ABI_FRAGMENTS,
  explorerTxUrl,
} from "@bongtu/core/network";
import { ZERO_EPHEMERAL } from "@bongtu/core/stealth";
import {
  submitPoolWrite,
  type Connection,
  type SubmitResult,
} from "./connection/index.js";

const CONSUMER_MODULE_ABI = parseAbi([
  CONSUMER_MODULE_ABI_FRAGMENTS.depositPriv,
  CONSUMER_MODULE_ABI_FRAGMENTS.transferPriv,
  CONSUMER_MODULE_ABI_FRAGMENTS.transfer10x2Priv,
  CONSUMER_MODULE_ABI_FRAGMENTS.withdrawPriv,
]);

// Every entry is a raw ML-KEM-768 encapsulation (1088 B, FIPS 203) and the
// module length-checks both the count (one per output) and each entry;
// pre-checking here turns that revert into a readable client error — the same
// belt the enterprise submit wears for its single authority ct.
import { KEM_CIPHERTEXT_BYTES } from "@bongtu/core/kem";
function assertKemCiphertexts(kemCiphertexts: string[], outputs: number, op: string): void {
  if (kemCiphertexts.length !== outputs) {
    throw new Error(
      `${op} carries one kem ciphertext per output: expected ${outputs}, got ${kemCiphertexts.length}`,
    );
  }
  for (const [i, ct] of kemCiphertexts.entries()) {
    if (!/^0x[0-9a-fA-F]+$/.test(ct) || (ct.length - 2) / 2 !== KEM_CIPHERTEXT_BYTES) {
      throw new Error(
        `kemCiphertexts[${i}] must be ${KEM_CIPHERTEXT_BYTES} bytes of 0x-hex (got ${ct.length} chars)`,
      );
    }
  }
}

async function submitModule(
  connection: Connection,
  op: keyof typeof CONSUMER_MODULES,
  calldata: Calldata,
  kemCiphertexts: string[],
  explorerBase: string,
  tail: readonly unknown[] = [],
  moduleAddress?: string,
): Promise<SubmitResult> {
  assertKemCiphertexts(kemCiphertexts, op === "withdrawPriv" ? 1 : 2, op);
  const { a, b, c, pub } = asProofArgs(calldata);
  const hash = await submitPoolWrite(connection, {
    // Default: the canonical record constants (the live pool is canonical per
    // CLAUDE.md). The explicit moduleAddress exists for ONE caller class: a
    // fresh-stack gate (deploy/gates/consumer_leg.ts) that must drive its own
    // anvil deploy through this byte-identical encode path, which is what makes
    // a fragment/witness drift revert on-chain in CI. App flows never pass it.
    address: moduleAddress ?? CONSUMER_MODULES[op].module,
    abi: CONSUMER_MODULE_ABI,
    functionName: op,
    args: [a, b, c, pub, kemCiphertexts, ...tail],
  });
  return { txHash: hash, explorerUrl: explorerTxUrl(hash, explorerBase) };
}

/** Submit a proven depositPriv: the 0-in/2-out consumer mint (third-party
 *  recipients legal — each output seals to ITS recipient's registered triple).
 *  The pool pulls the value total (pub-bound) from the sender's prior ERC-20
 *  approve — which targets the POOL, never this module. */
export function submitDepositPriv(
  connection: Connection,
  calldata: Calldata,
  kemCiphertexts: string[],
  explorerBase: string,
  moduleAddress?: string,
): Promise<SubmitResult> {
  return submitModule(connection, "depositPriv", calldata, kemCiphertexts, explorerBase, [], moduleAddress);
}

/** Submit a proven transferPriv (2-in/2-out consumer spend). */
export function submitTransferPriv(
  connection: Connection,
  calldata: Calldata,
  kemCiphertexts: string[],
  explorerBase: string,
  moduleAddress?: string,
): Promise<SubmitResult> {
  return submitModule(connection, "transferPriv", calldata, kemCiphertexts, explorerBase, [], moduleAddress);
}

/** Submit a proven transfer10x2Priv: the 3–10-note consumer spend and every
 *  consumer merge leg (a chain's transfer10x2-to-self, same as enterprise). */
export function submitTransfer10x2Priv(
  connection: Connection,
  calldata: Calldata,
  kemCiphertexts: string[],
  explorerBase: string,
  moduleAddress?: string,
): Promise<SubmitResult> {
  return submitModule(connection, "transfer10x2Priv", calldata, kemCiphertexts, explorerBase, [], moduleAddress);
}

/** withdrawPriv public index the module range-checks as the payout address
 *  (WithdrawPrivModule.sol: pub[15]). */
const WITHDRAW_RECIPIENT_PUB = 15;

/** Submit a proven withdrawPriv (2-in / 1-out change + proof-bound payout).
 *
 *  The trailing (bytes32 stealthEphemeralPub, uint8 viewTag) pair is the
 *  enterprise withdraw's stealth-announcement slot, kept on the module so a
 *  future relayed/stealth consumer exit needs no ABI change. Consumer v1
 *  SELF-SUBMITS to a recipient the user chose and already knows, so there is
 *  nothing to announce: the wrapper pins the "no announcement" sentinel
 *  (zero32/0 — byte-identical to deploy/gates/consumer_leg.ts) rather than
 *  exposing a parameter nothing may set yet. */
export async function submitWithdrawPriv(
  connection: Connection,
  calldata: Calldata,
  kemCiphertexts: string[],
  explorerBase: string,
  moduleAddress?: string,
): Promise<SubmitResult> {
  // The recipient belt, re-worn client-side: the shared builder admits the
  // widest value any rail can bind (nonzero under 2^253 — the Solana edge
  // truncates to 253 bits), but THIS rail's module range-checks uint160
  // on-chain, so an over-wide address would spend a full proof only to
  // revert InvalidRecipient. Fail it before the wallet sees anything.
  const recipient = BigInt(calldata.pub[WITHDRAW_RECIPIENT_PUB]);
  if (recipient === 0n || recipient >> 160n !== 0n) {
    throw new Error(
      `withdraw recipient must be a nonzero 20-byte EVM address (uint160), got ${recipient}`,
    );
  }
  return submitModule(
    connection,
    "withdrawPriv",
    calldata,
    kemCiphertexts,
    explorerBase,
    [ZERO_EPHEMERAL as `0x${string}`, 0],
    moduleAddress,
  );
}
