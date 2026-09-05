// The spend op (@bongtu/client/spend), whole: plan/build stopping at the
// ProvingRequest boundary, the run layer that proves and submits, and the SpendOps
// facade (below) binding the login-time deps once. Parts: plan.ts (input shapes,
// note selection, circuit choice, chain planning), crypto.ts (per-tx randomness +
// KEM draws), assemble.ts (input-side witness assembly), builders.ts (the
// ProvingRequest builders), run.ts (the prove+submit orchestration).
//
// The plan/build layer is PURE wallet-side witness assembly for the CPU circuits the
// public app proves in the browser: transfer (2-in / 2-out), transfer10x2 (10-in /
// 2-out) and withdraw (2-in / 1-out), SPEC §4 / §7. Framework- and network-free so
// the exact code runs in the browser view AND the headless spend-witness gate. It
// imports the sdk crypto DIRECTLY, so every commitment / nullifier is byte-identical
// to what snarkjs proves and the contract verifies — the witness objects produced
// are EXACTLY the circom `main` inputs deploy/gates/e2e_orchestrator.ts assembles by
// hand, in ProvingRequest form (@bongtu/core/proving). The SPEC §6 boundary falls
// INSIDE this subpath now: the builders stop at "a valid ProvingRequest", and run.ts
// is the layer that proves (through the app-injected prover) and sends the tx
// (through the @bongtu/client-evm/connection edges).
//
// ARITY, and who picks it. Every circuit here takes a FIXED number of inputs — 2 for
// transfer/withdraw, 10 for transfer10x2 — so a spend that needs fewer pads the rest
// with {nullifier:0, value:0, enabled:0, path:zeros}: the contract-derived enabled=0
// disables that slot's membership and the §5.2 value-belt forces its value to 0 (no
// mint). The wallet PICKS the circuit from how many notes the payment needs
// (planSpendAction): ≤2 notes stay on the cheap 2×2 transfer, 3–10 go to transfer10x2,
// and a withdraw — which has no arity-10 circuit — stays at 2. All of them emit their
// ciphertext as circuit outputs (public signals), so — unlike disburse — the wallet
// assembles NO separate ciphertext blob; the tx is just (a, b, c, pub, kemCiphertext).
//
// WHEN THE ARITY IS NOT ENOUGH, the wallet does not stop and ask the user to go merge
// their notes first. planSpendChain plans the WHOLE way through: however many
// transfer10x2 self-sends it takes to fold the balance down to something the terminal
// circuit can spend, then the payment or withdrawal itself. One plan, run as one
// flow — see runSpendChain (run.ts).
//
// TRANSFER10 IS DEPRECATED (user decision 2026-07-28): the 10-in/10-OUT circuit
// stays deployed on chain, but the wallet never routes to it — every >2-input spend
// AND every merge leg proves transfer10x2 (10-in / 2-OUT), because an output is a
// depth-32 IMT append and transfer10 paid for eight zero-value pads every time.
// buildTransfer10Request below survives only for the committed transfer10 e2e
// driver; nothing reachable from the wallet UI produces a "transfer10" request.

// This barrel stitches the parts back into the ONE stable public subpath
// (@bongtu/client/spend): plan, crypto, assemble, builders and run, plus the
// SpendOps facade defined below.
export * from "./plan.js";
export * from "./crypto.js";
export * from "./assemble.js";
export * from "./builders.js";
export * from "./run.js";

// ================================ SpendOps ===================================

import type { OwnerNote } from "@bongtu/core/indexerApi";
import type { Calldata, ProvingRequest } from "@bongtu/core/proving";
import type { StealthDerivation } from "@bongtu/core/stealth";
import type { Connection } from "@bongtu/client/rail";
import type { KeyCacheLike } from "@bongtu/client/keyCache";
import {
  runDeposit,
  type DepositOutcome,
  type DepositStage,
  type RunDepositDeps,
} from "@bongtu/client/deposit";
import { previewSpend, type SpendKind, type SpendPreview } from "./plan.js";
import {
  runSpendChain,
  type OnSpendStage,
  type RunSpendDeps,
  type SpendOutcome,
} from "./run.js";

/** The owner-note source SpendOps plans and spends over: the CURRENT unspent set
 *  on demand, and the between-legs reload a chain waits on (treasury-web wraps its
 *  arbiter /notes read + screen state into `reload`). The seam owns the note
 *  supply, so the app stops threading the array into every call. */
export interface SpendNoteSource {
  notes(): OwnerNote[];
  reload(): Promise<OwnerNote[]>;
}

/** What a wallet session binds ONCE for the enterprise ops (the C1 IndexerClient
 *  precedent): the login-time inputs every runDeposit / runSpendChain call site
 *  was re-threading. Any extra RunSpendDeps / RunDepositDeps members ride along
 *  into the flows' io seam unchanged, so a headless suite constructs one facade
 *  over its fakes and every method provably hits the same free-fn path. */
export type SpendOpsDeps = {
  connection: Connection;
  indexerUrl: string;
  /** the pool address every leg proves against and submits to (app config). */
  pool: string;
  /** the wrapped kKRW ERC-20 the pool escrows (app config). */
  token: string;
  /** the explorer base URL the success link is built on (app config). */
  explorer: string;
  /** set => the terminal withdraw leg submits through the gas relayer. */
  relayerUrl?: string;
  /** the wallet's lock — the structural seam, so fakes need no class. */
  keyCache: KeyCacheLike;
  /** Turn a ProvingRequest into Groth16 calldata (the APP supplies this). */
  prove: (request: ProvingRequest) => Promise<Calldata>;
} & Pick<
  RunSpendDeps,
  | "ensureChain"
  | "assertPoolKemEpoch"
  | "submitTransfer"
  | "submitTransfer10x2"
  | "submitWithdraw"
  | "submitWithdrawRelayed"
> &
  // the rail io — spread @bongtu/client-evm/ops EVM_ENTERPRISE_IO at the
  // wiring site (the engine has no rail defaults since the split).
  Pick<RunDepositDeps, "readTokenState" | "approveToken" | "submitDeposit"> &
  Partial<RunSpendDeps> &
  Partial<RunDepositDeps>;

/**
 * Bind once at login/session time, call per action. The free functions above
 * STAY the primitive layer — every method DELEGATES to them, so the class can
 * never drift from what the headless flow suites pin (the C1 house bar: state +
 * injected IO, never a data bag). What it holds is exactly what every call site
 * repeated: the session's connection + config + lock + prover, the session
 * pubkey, and the note source.
 */
export class SpendOps {
  constructor(
    private readonly deps: SpendOpsDeps,
    private readonly session: { compressedPubkey: string },
    private readonly noteSource: SpendNoteSource,
  ) {}

  /** runDeposit over the bound session: approve (if needed) → prove → submit. */
  deposit(
    args: { amount: string },
    onStage: (stage: DepositStage) => void,
  ): Promise<DepositOutcome> {
    const { connection, pool, token, explorer } = this.deps;
    return runDeposit(
      { connection, pool, token, explorer, sessionPubkey: this.session.compressedPubkey },
      args,
      onStage,
      this.deps,
    );
  }

  /** runSpendChain over the bound session and note source. */
  spend(
    kind: SpendKind,
    args: { to?: string; amount: string; stealth?: StealthDerivation; withdrawTo?: string },
    onStage: OnSpendStage,
  ): Promise<SpendOutcome> {
    const { connection, indexerUrl, pool, explorer, relayerUrl } = this.deps;
    return runSpendChain(
      kind,
      {
        connection,
        indexerUrl,
        pool,
        explorer,
        relayerUrl,
        notes: this.noteSource.notes(),
        sessionPubkey: this.session.compressedPubkey,
        reloadNotes: () => this.noteSource.reload(),
      },
      args,
      onStage,
      this.deps,
    );
  }

  /** previewSpend over the note source: which circuit, how many transactions. */
  preview(kind: SpendKind, amount: string): SpendPreview {
    return previewSpend(kind, this.noteSource.notes(), amount);
  }
}
