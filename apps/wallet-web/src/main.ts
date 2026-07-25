// bongtu public wallet — self-custody entry (SPEC §7 public app). A single flow:
//   1. Connect MetaMask, sign the domain-separated struct, DERIVE the bjj spending
//      key (deterministic) and show the compressed pubkey (the RECEIVE address).
//   2. Load balance from the arbiter indexer's signed /notes (unspent sum).
//   3. transfer (2×2) / withdraw (2×1): assemble the witness, prove in-browser with
//      snarkjs, submit via MetaMask.
//
// All security-critical logic (derive/balance/witness) lives in the PURE, unit-tested
// lib modules; this file is the browser wiring around them. MetaMask + live circuit
// assets are not present in the build env, so the connect/prove/submit path is the
// documented un-tested edge (README "gate reality").

import "./styles.css";
import { el, field, input, button, clear, statusLine } from "./lib/dom.js";
import { DEFAULTS } from "./config.js";
import {
  keyDerivationTypedData,
  deriveIdentityFromSignature,
  type WalletIdentity,
} from "./lib/derive.js";
import { connect, signKeyDerivation, submitTransfer, submitWithdraw, type Connection } from "./lib/metamask.js";
import { balanceViaNotes } from "./lib/balance.js";
import type { OwnerNote } from "./lib/indexerClient.js";
import { getHead, getPath } from "./lib/indexerClient.js";
import {
  buildTransferRequest,
  buildWithdrawRequest,
  selectInputNotes,
  freshSpendCrypto,
  type WalletInputNote,
  type MembershipWitness,
} from "./lib/spend.js";
import { proveInBrowser } from "./lib/prove.js";

// --- runtime state --------------------------------------------------------------

interface State {
  connection: Connection | null;
  identity: WalletIdentity | null;
  notes: OwnerNote[];
}
const state: State = { connection: null, identity: null, notes: [] };

// Fresh per-tx field randomness (browser only; the pure test modules never call this).
// A shared ephemeral ECDH key + nonce across outputs of ONE tx is fine; reuse ACROSS
// txs is a two-time pad, so we draw fresh values every spend.
function randField(): string {
  const b = new Uint8Array(31); // < 2^248, safely under the field prime
  crypto.getRandomValues(b);
  let x = 0n;
  for (const byte of b) x = (x << 8n) | BigInt(byte);
  return (x === 0n ? 1n : x).toString();
}

// --- app shell ------------------------------------------------------------------

const appRoot = document.getElementById("app");
if (!appRoot) throw new Error("no #app root in index.html");

const indexerInput = input(DEFAULTS.indexerUrl, "http://localhost:8600");

const identityBox = el("div", { class: "panel-body" });
const balanceBox = el("div", { class: "panel-body" });
const transferBox = el("div", { class: "panel-body" });
const withdrawBox = el("div", { class: "panel-body" });

function panel(title: string, subtitle: string, bodyEl: HTMLElement): HTMLElement {
  return el(
    "section",
    { class: "panel" },
    el("div", { class: "panel-head" },
      el("span", { class: "panel-title", textContent: title }),
      el("span", { class: "panel-sub", textContent: subtitle }),
    ),
    bodyEl,
  );
}

// --- 1. connect + derive --------------------------------------------------------

function renderIdentity(): void {
  clear(identityBox);
  if (!state.identity || !state.connection) {
    identityBox.append(
      el("p", { class: "muted", textContent:
        "Connect MetaMask and sign the bongtu key-derivation message. The same account always derives the same spending key — no seed to store." }),
      button("Connect MetaMask & derive key", onConnect),
    );
    return;
  }
  const recv = state.identity.compressedPubkey;
  identityBox.append(
    el("div", { class: "kv" }, el("span", { class: "k", textContent: "ETH account" }), el("code", { class: "v", textContent: state.connection.address })),
    el("div", { class: "kv" }, el("span", { class: "k", textContent: "Receive address (bjj pubkey)" }), el("code", { class: "v mono-wrap", textContent: recv })),
    el("p", { class: "hint", textContent: "Share the receive address so others can pay you. It is deterministic: reconnecting the same MetaMask account regenerates the same key." }),
    button("Copy receive address", () => navigator.clipboard?.writeText(recv), "btn ghost"),
  );
}

async function onConnect(): Promise<void> {
  const st = el("div");
  identityBox.append(st);
  try {
    statusLine(st, "Requesting MetaMask connection…");
    const connection = await connect();
    statusLine(st, "Sign the key-derivation message in MetaMask…");
    const typed = keyDerivationTypedData(DEFAULTS.chainId, DEFAULTS.pool, DEFAULTS.keyVersion);
    const sig = await signKeyDerivation(connection, typed);
    const identity = deriveIdentityFromSignature(sig);
    state.connection = connection;
    state.identity = identity;
    renderIdentity();
    renderAll();
  } catch (e) {
    statusLine(st, (e as Error).message, "err");
  }
}

// --- 2. balance -----------------------------------------------------------------

function renderBalance(): void {
  clear(balanceBox);
  if (!state.identity) {
    balanceBox.append(el("p", { class: "muted", textContent: "Derive your key first." }));
    return;
  }
  const st = el("div");
  const list = el("div", { class: "note-list" });
  balanceBox.append(
    field("Arbiter indexer URL", indexerInput, "Signed GET /notes — balance requires a reachable arbiter-mode indexer."),
    button("Load balance", async () => {
      try {
        statusLine(st, "Fetching your notes (signed /notes)…");
        const { balance, notes } = await balanceViaNotes(indexerInput.value.trim(), state.identity!);
        state.notes = notes;
        statusLine(st, `Balance: ${balance.toString()} (unspent over ${notes.length} note(s))`, "ok");
        renderNoteList(list, notes);
        renderSpend();
      } catch (e) {
        statusLine(st, `Could not load notes: ${(e as Error).message}. Balance needs the arbiter indexer's /notes route — check the URL and that the indexer is running in arbiter mode.`, "err");
      }
    }),
    st,
    list,
  );
}

function renderNoteList(list: HTMLElement, notes: OwnerNote[]): void {
  clear(list);
  if (notes.length === 0) {
    list.append(el("p", { class: "muted", textContent: "No notes yet — ask an employer to disburse to your receive address." }));
    return;
  }
  for (const n of notes) {
    list.append(
      el("div", { class: `note ${n.spent ? "spent" : "unspent"}` },
        el("span", { class: "note-val", textContent: `${n.value}` }),
        el("span", { class: "note-idx", textContent: `leaf #${n.leafIndex}` }),
        el("span", { class: "note-flag", textContent: n.spent ? "spent" : "spendable" }),
      ),
    );
  }
}

// --- 3. transfer / withdraw -----------------------------------------------------

// Amount-aware note selection is PURE + unit-tested (spend.ts selectInputNotes);
// this wiring only fetches the live membership witnesses for the selected leaves.
async function selectSpendInputs(indexerUrl: string, amount: string): Promise<{ inputs: WalletInputNote[]; memberships: MembershipWitness[] }> {
  const inputs = selectInputNotes(state.notes, amount);
  const head = await getHead(indexerUrl);
  const memberships: MembershipWitness[] = [];
  for (const n of inputs) {
    const p = await getPath(indexerUrl, n.leafIndex); // 422 for a within-batch leaf in public mode
    memberships.push({ root: head.root, pathElements: p.siblings, leafIndex: n.leafIndex });
  }
  return { inputs, memberships };
}

function renderSpend(): void {
  renderTransfer();
  renderWithdraw();
}

function renderTransfer(): void {
  clear(transferBox);
  if (!state.identity) {
    transferBox.append(el("p", { class: "muted", textContent: "Derive your key + load balance first." }));
    return;
  }
  const to = input("", "recipient receive address (0x…32-byte bjj pubkey)");
  const amt = input("", "amount");
  const st = el("div");
  transferBox.append(
    field("Pay to (receive address)", to),
    field("Amount", amt),
    button("Prove & send transfer", () => runSpend("transfer", st, { to: to.value.trim(), amount: amt.value.trim() })),
    st,
  );
}

function renderWithdraw(): void {
  clear(withdrawBox);
  if (!state.identity) {
    withdrawBox.append(el("p", { class: "muted", textContent: "Derive your key + load balance first." }));
    return;
  }
  const amt = input("", "amount to withdraw to ERC-20");
  const st = el("div");
  withdrawBox.append(
    field("Withdraw amount", amt, "Pushes the underlying kKRW to your ETH account; the remainder stays a shielded change note."),
    button("Prove & send withdraw", () => runSpend("withdraw", st, { amount: amt.value.trim() })),
    st,
  );
}

async function runSpend(kind: "transfer" | "withdraw", st: HTMLElement, args: { to?: string; amount: string }): Promise<void> {
  try {
    if (!state.identity || !state.connection) throw new Error("connect + derive first");
    const indexerUrl = indexerInput.value.trim();
    statusLine(st, "Selecting notes + fetching membership paths…");
    const { inputs, memberships } = await selectSpendInputs(indexerUrl, args.amount);
    const crypto = freshSpendCrypto(randField);

    statusLine(st, "Assembling witness…");
    const built =
      kind === "transfer"
        ? buildTransferRequest(state.identity, inputs, memberships, args.to ?? "", args.amount, crypto)
        : buildWithdrawRequest(state.identity, inputs, memberships, args.amount, crypto);
    if (!built.meta.membershipOk) throw new Error("membership witness does not fold to the live root — reload balance");

    statusLine(st, "Proving in-browser (snarkjs, one-time zkey download)…");
    const calldata = await proveInBrowser(built.request, DEFAULTS.circuitBaseUrl);

    statusLine(st, "Submitting via MetaMask…");
    const res =
      kind === "transfer"
        ? await submitTransfer(state.connection, DEFAULTS.pool, calldata, DEFAULTS.explorer)
        : await submitWithdraw(state.connection, DEFAULTS.pool, calldata, DEFAULTS.explorer);
    clear(st);
    st.append(el("div", { class: "status status-ok" },
      el("span", { textContent: `${kind} sent — change ${built.meta.changeValue}. ` }),
      el("a", { href: res.explorerUrl, target: "_blank", textContent: "view tx", class: "link" }),
    ));
  } catch (e) {
    statusLine(st, (e as Error).message, "err");
  }
}

// --- render all -----------------------------------------------------------------

function renderAll(): void {
  renderIdentity();
  renderBalance();
  renderSpend();
}

appRoot.append(
  el("header", { class: "app-header" },
    el("div", { class: "brand" }, el("span", { class: "logo", textContent: "봉투" }), el("span", { class: "title", textContent: "bongtu wallet" })),
    el("div", { class: "chain-badge", textContent: `GIWA Sepolia · chain ${DEFAULTS.chainId} · pool ${DEFAULTS.pool.slice(0, 10)}…` }),
  ),
  el("main", { class: "wallet" },
    panel("1 · Identity", "derive spending key from MetaMask", identityBox),
    panel("2 · Balance", "unspent notes from the arbiter indexer", balanceBox),
    panel("3 · Transfer", "private 2-in / 2-out payment", transferBox),
    panel("4 · Withdraw", "2-in / 1-out to ERC-20", withdrawBox),
  ),
);

renderAll();
