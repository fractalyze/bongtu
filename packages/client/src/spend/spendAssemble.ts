// spend/spendAssemble.ts — the family-shared input-side witness assembly
// (split from spend.ts).

import {
  commitment,
  nullifier,
} from "@bongtu/core/note";
import { H } from "@bongtu/core/network";
import { foldToRoot } from "@bongtu/core/imt";
import type { WalletIdentity } from "@bongtu/client/derive";
import type { MembershipWitness, WalletInputNote } from "./spendPlan.js";

// --- helpers -------------------------------------------------------------------

// The membership witness shared by every spending circuit: recompute each real
// input's commitment + nullifier from the wallet key, pad the remaining slots up to
// the circuit's arity with value-0 notes, and fold every real input to the shared
// root. Exported (not just used here) because the consumer builders
// (consumerBuild.ts) spend the SAME untyped notes — the input-side algebra is
// family-shared by construction, so reusing this function keeps it that way.
export interface AssembledInputs {
  nullifiers: bigint[];
  inputCommitments: bigint[];
  inputValues: bigint[];
  inputSalts: bigint[];
  enabled: bigint[];
  pathElements: bigint[][];
  leafIndices: bigint[];
  root: bigint;
  inputTotal: bigint;
  membershipOk: boolean;
}

export function assembleInputs(
  identity: WalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  padSalts: string[],
  arity: number,
): AssembledInputs {
  if (inputs.length < 1 || inputs.length > arity) {
    throw new Error(`this spend takes 1 to ${arity} input notes, got ${inputs.length}`);
  }
  if (memberships.length !== inputs.length) {
    throw new Error(`need one membership witness per input: ${memberships.length} != ${inputs.length}`);
  }
  const padCount = arity - inputs.length;
  if (padSalts.length < padCount) {
    throw new Error(`need ${padCount} pad salts for a ${inputs.length}-of-${arity} spend, got ${padSalts.length}`);
  }
  const self = identity.keypair;
  const zeros: bigint[] = new Array(H).fill(0n);

  // All real inputs must be proven against ONE root (the live root). Take it from the
  // first membership and require the rest agree.
  const root = BigInt(memberships[0].root);
  for (const m of memberships) {
    if (BigInt(m.root) !== root) throw new Error("all input memberships must share one root");
    if (m.pathElements.length !== H) {
      throw new Error(`pathElements must have length ${H}, got ${m.pathElements.length}`);
    }
  }

  const nullifiers: bigint[] = [];
  const inputCommitments: bigint[] = [];
  const inputValues: bigint[] = [];
  const inputSalts: bigint[] = [];
  const enabled: bigint[] = [];
  const pathElements: bigint[][] = [];
  const leafIndices: bigint[] = [];
  const { inputTotal, membershipOk } = inputs.reduce(
    (acc, note, i) => {
      const v = BigInt(note.value);
      const s = BigInt(note.salt);
      if (v < 0n) throw new Error(`input #${i + 1} value must be non-negative, got ${v}`);
      const c = commitment(v, s, self.publicKey);
      const nf = nullifier(v, s, self.formattedPrivateKey);
      const path = memberships[i].pathElements.map((x) => BigInt(x));
      const pathOk = foldToRoot(c, path, memberships[i].leafIndex) === root;
      nullifiers.push(nf);
      inputCommitments.push(c);
      inputValues.push(v);
      inputSalts.push(s);
      enabled.push(1n);
      pathElements.push(path);
      leafIndices.push(BigInt(memberships[i].leafIndex));
      return { inputTotal: acc.inputTotal + v, membershipOk: acc.membershipOk && pathOk };
    },
    { inputTotal: 0n, membershipOk: true },
  );

  // Pad the unused slots with value-0 notes owned by the wallet: nullifier 0,
  // enabled 0, zeros path (membership disabled; the value belt forces value 0 -> no
  // mint), each on its OWN salt so no two pads share a commitment. This is the
  // convention the committed circuits/fixtures/inputs/transfer10x2_merge.json (and
  // transfer10.json) fixtures carry.
  for (const i of Array(padCount).keys()) {
    const s = BigInt(padSalts[i]);
    nullifiers.push(0n);
    inputCommitments.push(commitment(0n, s, self.publicKey));
    inputValues.push(0n);
    inputSalts.push(s);
    enabled.push(0n);
    pathElements.push([...zeros]);
    leafIndices.push(0n);
  }

  return {
    nullifiers,
    inputCommitments,
    inputValues,
    inputSalts,
    enabled,
    pathElements,
    leafIndices,
    root,
    inputTotal,
    membershipOk,
  };
}
