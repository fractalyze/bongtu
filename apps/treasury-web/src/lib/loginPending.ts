// Onboarding's connect-then-login handoff, as a pure state machine. The Connect
// button (no wallet live yet) opens the RainbowKit modal and arms `pending`; the
// moment wagmi reports a connection the login must fire — but a modal DISMISSED
// without connecting must disarm it, or the stale flag auto-fires a signature
// popup at the next unrelated connect (wave-1 review finding). RainbowKit exposes
// no dismiss callback, only `connectModalOpen`, and the modal opens ASYNC after the
// press — so "dismissed" is observable only as open→closed with no connection,
// which is exactly the transition this machine tracks (`modalSeen`).
//
// Pure on purpose: Onboarding feeds it (modalOpen, connected) on every change and
// executes the returned effect; every branch gates headlessly in
// test/loginPending.test.ts.

export interface LoginPendingState {
  /** a Connect press is waiting for the modal round to produce a connection. */
  pending: boolean;
  /** the modal has been seen OPEN during this round (so closed now = dismissed). */
  modalSeen: boolean;
}

export const LOGIN_IDLE: LoginPendingState = { pending: false, modalSeen: false };

/** The Connect press that opens the modal: arm a fresh round. */
export function startLoginPending(): LoginPendingState {
  return { pending: true, modalSeen: false };
}

export type LoginPendingEffect =
  /** nothing to do (idle, or the modal round is still in flight). */
  | "none"
  /** a wallet connected during the round: run the login now. */
  | "login"
  /** the modal closed with nothing connected: the user dismissed it — disarm. */
  | "dismissed";

/**
 * Advance the machine on an environment change. Connection wins over dismissal
 * (both can arrive in one step: RainbowKit closes its modal as the connect lands).
 */
export function loginPendingStep(
  state: LoginPendingState,
  env: { modalOpen: boolean; connected: boolean },
): { state: LoginPendingState; effect: LoginPendingEffect } {
  if (!state.pending) return { state, effect: "none" };
  if (env.connected) return { state: LOGIN_IDLE, effect: "login" };
  const modalSeen = state.modalSeen || env.modalOpen;
  if (modalSeen && !env.modalOpen) return { state: LOGIN_IDLE, effect: "dismissed" };
  // Same reference when nothing changed — the React effect feeding this compares by
  // identity, and a fresh-but-equal object would re-render forever.
  return { state: modalSeen === state.modalSeen ? state : { pending: true, modalSeen }, effect: "none" };
}
