// React adapter over the shared four-phase action machine (@bongtu/ui/actionMachine,
// issue #46 shared-libs consolidation). What is genuinely THIS app's stays here: the
// consumer wording for a failed run (consumerErrorMessage) baked into the machine,
// and the React extras — asset prefetch, download view, the elapsed clock. Screens
// and tests keep importing the whole machine surface from this path.
import { useEffect, useState, useSyncExternalStore } from "react";
import {
  ActionMachine as SharedActionMachine,
  OpGate,
  stepsForRun,
  type ActionResult,
  type ActionRun,
  type ActionSnapshot,
  type StagedStep,
} from "@bongtu/ui/actionMachine";
import { DEFAULTS, type BrowserCircuit } from "../config.js";
import { ensureCircuitAssets, prewarmProver } from "../lib/prove.js";
import { consumerErrorMessage } from "../lib/errors.js";
import { useCircuitDownload, useElapsedSeconds, type CircuitDownloadView } from "./hooks.js";

export {
  OpGate,
  opGate,
  OP_IN_FLIGHT_MESSAGE,
  stepsForRun,
  type ActionLeg,
  type ActionPhase,
  type ActionResult,
  type ActionRun,
  type ActionSnapshot,
} from "@bongtu/ui/actionMachine";

/** The shared machine with this app's wording for a failed run baked in
 *  (consumerErrorMessage — the one per-app delta the old copies carried), keeping the
 *  `(firstStage, gate?)` construction surface the screens and tests always used. */
export class ActionMachine<O extends ActionResult> extends SharedActionMachine<O> {
  constructor(firstStage: string, gate?: OpGate) {
    super(firstStage, consumerErrorMessage, gate);
  }
}

/** What a screen reads and calls: the machine's state, the steps and progress views
 *  that go with it, and the three transitions. */
export interface ActionMachineView<O extends ActionResult> extends ActionSnapshot<O> {
  /** the step list for this run — with the unlock step only when it applies. */
  steps: StagedStep[];
  /** seconds inside the proof (honest clock, never a promise). */
  elapsed: number;
  /** the one-time proving-asset download; `active` also gates every proof-reaching button. */
  download: CircuitDownloadView;
  review: () => void;
  cancel: () => void;
  submit: (run: ActionRun<O>, afterAction: (txHash: string) => unknown) => Promise<void>;
}

/**
 * The machine, wired for a screen. It also PREFETCHES `circuit`'s wasm+zkey (the
 * one-time download) and pre-warms the bn128 curve, so the heavy I/O overlaps the
 * user typing the amount. Progress/disable state comes from the prove.ts registry —
 * not from that call's promise — so a remount mid-download stays honest.
 *
 * `circuit` may CHANGE while the form is open: Send starts on the 2×2 transfer and
 * switches to the 10-in/2-out form the moment the typed amount needs 3+ notes. Each
 * value is fetched at most once per session (prove.ts coalesces), so the switch adds
 * the arity-10 key without re-fetching the first — which is exactly why the ~95 MB
 * key is never pulled on screen open.
 */
export function useActionMachine<O extends ActionResult>({
  circuit,
  steps,
}: {
  circuit: BrowserCircuit;
  /** the flow's stages, in order; its first key is the opening stage. */
  steps: StagedStep[];
}): ActionMachineView<O> {
  const [machine] = useState(() => new ActionMachine<O>(steps[0].key));
  const snap = useSyncExternalStore(machine.subscribe, machine.snapshot, machine.snapshot);
  const elapsed = useElapsedSeconds(snap.phase === "running" && snap.stage === "prove");
  const download = useCircuitDownload(circuit);

  useEffect(() => {
    void ensureCircuitAssets(circuit, DEFAULTS.circuitBaseUrl).catch(() => {});
  }, [circuit]);
  // The bn128 curve is shared by every circuit, so warm it once per screen — not
  // again each time the auto-pick switches which key is being fetched.
  useEffect(() => {
    void prewarmProver();
  }, []);

  return {
    ...snap,
    steps: stepsForRun(steps, snap.unlocking),
    elapsed,
    download,
    review: machine.review,
    cancel: machine.cancel,
    submit: machine.submit,
  };
}
