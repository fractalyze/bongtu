// The four-phase machine every value-moving screen runs: form → confirm → running →
// done. Send, Withdraw and Deposit differ only in what they put ON the form and in
// which flow function they call; the phase order, the stage reporting, the unlock
// step, the error landing and the post-action refresh are the SAME behaviour, so it
// lives here once — the ONE home both apps bind (issue #46 shared-libs
// consolidation; the previous per-app copies differed only in their wording import).
//
// It is a plain store, not a pile of useState calls, for one reason: the phases used
// to sit behind component state that no headless render could reach, which left the
// wallet's largest surface gated only by scanning .tsx files as text. ActionMachine
// takes the flow as an argument, so each app's actionMachine tests drive every
// transition with a stub and assert what the screens will show. The React adapter
// (useActionMachine — useSyncExternalStore over the same object, plus the per-screen
// extras that are genuinely React: asset prefetch, download view, the elapsed clock)
// STAYS in each app's src/ui/actionMachine.ts, which also bakes in the app's own
// wording for a failed run via the machine's `describeError` parameter.

/** One step of the staged progress rail (label keyed by the flow's stage string).
 *  The rendering component (each app's StagedProgress) re-exports this type, so a
 *  screen's step lists and the machine agree on the shape by construction. */
export interface StagedStep {
  key: string;
  label: string;
}

/** The same steps with the wallet-unlock signature in front. Screens switch to this
 *  only when a flow actually reports the "unlock" stage — a run that reuses the key
 *  already held never shows a step the user isn't asked to do. */
export function withUnlock(steps: StagedStep[]): StagedStep[] {
  return [{ key: "unlock", label: "Unlocking" }, ...steps];
}

/** What a second op's Confirm says while one is already running. */
export const OP_IN_FLIGHT_MESSAGE =
  "Another action is still running. Let it finish before starting a new one.";

/**
 * The one-op-at-a-time gate. Every screen owns its own ActionMachine, so nothing
 * structural stops a Send chain and a Deposit from proving at once — two wallet
 * popups interleaving over one lock is exactly the confusion the S5 guard exists
 * to prevent. The gate is a single shared slot: submit() takes it for the whole
 * run and releases it in finally, so an abort (a mid-op account switch included)
 * can never strand the slot with a stage on screen.
 */
export class OpGate {
  private holder: symbol | null = null;

  tryAcquire(token: symbol): boolean {
    if (this.holder !== null && this.holder !== token) return false;
    this.holder = token;
    return true;
  }

  release(token: symbol): void {
    if (this.holder === token) this.holder = null;
  }

  busy(): boolean {
    return this.holder !== null;
  }
}

/** The page's one gate — every screen's machine defaults onto it. Each app bundle
 *  (page) instantiates its own copy of this module, so the slot is page-wide, never
 *  cross-app. */
export const opGate = new OpGate();

export type ActionPhase = "form" | "confirm" | "running" | "done";

/** What every flow returns: enough to link the transaction and to poll the indexer. */
export interface ActionResult {
  txHash: string;
  explorerUrl: string;
}

/** Which transaction of a multi-transaction run is reporting. A flow that takes one
 *  transaction (every deposit, most spends) never sends this and stays at leg 0 of 1. */
export interface ActionLeg {
  index: number;
  count: number;
}

/** One run of a flow, reporting its coarse stages as they begin. The stage strings are
 *  the flow's own (SpendStage / DepositStage); the machine only knows that "unlock"
 *  means the wallet asked for a signature, and that a run may take several
 *  transactions (spendFlow.runSpendChain), each with its own pass through the stages. */
export type ActionRun<O extends ActionResult> = (
  onStage: (stage: string, leg?: ActionLeg) => void,
) => Promise<O>;

export interface ActionSnapshot<O extends ActionResult> {
  phase: ActionPhase;
  /** the flow's current stage key — matched against the step list by StagedProgress. */
  stage: string;
  /** which transaction of the run is in flight, and how many it takes. A single-
   *  transaction run stays at 0 of 1, which is what every screen renders today. */
  legIndex: number;
  legCount: number;
  /** whether THIS run needs the unlock signature: the flow tells us by reporting
   *  "unlock" first, and the step list grows a step to match. */
  unlocking: boolean;
  error: string | null;
  outcome: O | null;
}

/** The steps a run actually shows. A run that reuses the key already held never shows
 *  a signature step the user isn't asked for. */
export function stepsForRun(steps: StagedStep[], unlocking: boolean): StagedStep[] {
  return unlocking ? withUnlock(steps) : steps;
}

export class ActionMachine<O extends ActionResult> {
  private snap: ActionSnapshot<O>;
  private readonly listeners = new Set<() => void>();
  private readonly opToken = Symbol("op");

  /** `firstStage` is the flow's own opening stage (spend "assemble", deposit
   *  "approve"), shown as active until the flow reports otherwise. `describeError`
   *  is the app's wording for a failed run (the ONE per-app delta the old copies
   *  carried: treasury's treasuryErrorMessage vs the consumer wallet's
   *  consumerErrorMessage) — each app's adapter bakes its own in. `gate` defaults
   *  to the page-wide one-op-at-a-time slot; tests pass their own. */
  constructor(
    private readonly firstStage: string,
    private readonly describeError: (e: unknown) => string,
    private readonly gate: OpGate = opGate,
  ) {
    this.snap = {
      phase: "form",
      stage: firstStage,
      legIndex: 0,
      legCount: 1,
      unlocking: false,
      error: null,
      outcome: null,
    };
  }

  snapshot = (): ActionSnapshot<O> => this.snap;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  // A NEW object every time: useSyncExternalStore repaints on identity, not on depth.
  private set(patch: Partial<ActionSnapshot<O>>): void {
    this.snap = { ...this.snap, ...patch };
    for (const listener of this.listeners) listener();
  }

  /** form → confirm (Continue). Drops the error a previous failed run left on screen. */
  review = (): void => this.set({ phase: "confirm", error: null });

  /** confirm → form (Cancel). */
  cancel = (): void => this.set({ phase: "form" });

  /**
   * Run the flow: confirm → running (stages as reported) → done, or back to the form
   * carrying the wallet's message. `afterAction` is the post-action refresh — polled,
   * not awaited, because the success screen is already correct without it (a single
   * refresh here would usually read the pre-action state).
   */
  submit = async (run: ActionRun<O>, afterAction: (txHash: string) => unknown): Promise<void> => {
    // The one-op-at-a-time invariant: a run that cannot take the shared slot
    // never starts — it lands back on the form with the plain refusal, exactly
    // where a failed run lands, so the screen needs no second error surface.
    if (!this.gate.tryAcquire(this.opToken)) {
      this.set({ phase: "form", error: OP_IN_FLIGHT_MESSAGE });
      return;
    }
    this.set({
      phase: "running",
      stage: this.firstStage,
      legIndex: 0,
      legCount: 1,
      unlocking: false,
      error: null,
    });
    try {
      const outcome = await run((stage, leg) => {
        // A flow that reports no leg is a one-transaction flow: it keeps 0 of 1.
        const at = leg ? { legIndex: leg.index, legCount: leg.count } : {};
        this.set(stage === "unlock" ? { stage, unlocking: true, ...at } : { stage, ...at });
      });
      this.set({ phase: "done", outcome });
      void afterAction(outcome.txHash);
    } catch (e) {
      // Every abort — a mid-op account switch included: the S5 guard locks the
      // key, the flow's next unlock refuses, and the run lands HERE — returns
      // the screen to the form. No stage is ever stranded on screen.
      this.set({ phase: "form", error: this.describeError(e) });
    } finally {
      this.gate.release(this.opToken);
    }
  };
}
