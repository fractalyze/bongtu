// AUDITOR-MODE view (SPEC §7). The ONLY mode with the arbiter key. It fetches the
// PUBLIC /events feed + /alarms from an arbiter-mode indexer URL and decrypts each
// transfer/disburse authority envelope LOCALLY with the arbiter private key
// (ledger.ts) into "who received what / spent status" — the independent regulator
// seat. Also offers the signed GET /notes lookup (auth binds to the owner key).

import { el, field, input, button, clear, statusLine } from "../lib/dom.js";
import { DEFAULTS } from "../config.js";
import { getEvents, getAlarms } from "../lib/indexerClient.js";
import { buildAuditorLedger, type AuditorLedger, type LedgerNote } from "../lib/ledger.js";
import { buildNotesUrl, fetchNotes } from "../lib/notesAuth.js";

export function auditorView(): HTMLElement {
  const root = el("div", { class: "view" });

  const idxUrl = input(DEFAULTS.indexerUrl, "arbiter-mode indexer URL");
  const arbPriv = input("", "arbiter PRIVATE key (bjj scalar) — auditor only");
  const batchSize = input(String(DEFAULTS.batchSize), "batch size B");

  const status = el("div", { class: "status-box" });
  const summaryPane = el("div", { class: "meta-pane" });
  const alarmsPane = el("div", { class: "alarms-pane" });
  const opsPane = el("div", { class: "ops-pane" });
  const ledgerPane = el("div", { class: "ledger-pane" });

  async function loadLedger(): Promise<void> {
    try {
      if (arbPriv.value.trim() === "") throw new Error("enter the arbiter private key");
      statusLine(status, "fetching /events + /alarms and decrypting authority envelopes…", "info");
      const [events, alarms] = await Promise.all([getEvents(idxUrl.value.trim()), getAlarms(idxUrl.value.trim()).catch(() => [])]);
      const ledger = buildAuditorLedger(events, arbPriv.value.trim(), Number(batchSize.value) || 256);
      renderSummary(ledger, events.length, alarms.length);
      renderAlarms(alarms);
      renderOps(ledger);
      renderLedger(ledger);
      const decoded = ledger.ops.filter((o) => o.decoded).length;
      statusLine(status, `decoded ${decoded}/${ledger.ops.length} ops; ${ledger.notes.length} notes across ${ledger.byOwner.size} owners; ${alarms.length} alarms`, "ok");
    } catch (e) {
      clear(summaryPane);
      clear(alarmsPane);
      clear(opsPane);
      clear(ledgerPane);
      statusLine(status, `load failed: ${(e as Error).message}`, "err");
    }
  }

  function renderSummary(l: AuditorLedger, eventCount: number, alarmCount: number): void {
    clear(summaryPane);
    const spent = l.notes.filter((n) => n.spent).length;
    const value = l.notes.reduce((a, n) => a + BigInt(n.value), 0n);
    const rows: [string, string][] = [
      ["events fetched", String(eventCount)],
      ["ops decoded", `${l.ops.filter((o) => o.decoded).length} / ${l.ops.length}`],
      ["notes recovered", String(l.notes.length)],
      ["distinct owners", String(l.byOwner.size)],
      ["notes spent", String(spent)],
      ["total value seen", value.toString()],
      ["alarms", String(alarmCount)],
    ];
    const t = el("table", { class: "kv" });
    for (const [k, v] of rows) t.append(el("tr", {}, el("td", { class: "k", textContent: k }), el("td", { class: "v", textContent: v })));
    summaryPane.append(el("h4", { textContent: "auditor ledger summary" }), t);
  }

  function renderAlarms(alarms: unknown[]): void {
    clear(alarmsPane);
    alarmsPane.append(el("h4", { textContent: `disclosure alarms (${alarms.length})` }));
    if (alarms.length === 0) {
      alarmsPane.append(el("p", { class: "note", textContent: "no non-passing disclosures" }));
      return;
    }
    const pre = el("pre", { class: "json-pane", textContent: JSON.stringify(alarms, null, 2) });
    alarmsPane.append(pre);
  }

  function renderOps(l: AuditorLedger): void {
    clear(opsPane);
    const t = el("table", { class: "ledger" });
    t.append(el("tr", {}, el("th", { textContent: "seq" }), el("th", { textContent: "kind" }), el("th", { textContent: "tx" }), el("th", { textContent: "disclosure" }), el("th", { textContent: "outputs (real/total)" }), el("th", { textContent: "note" })));
    for (const o of l.ops) {
      t.append(
        el("tr", {},
          el("td", { textContent: String(o.seq) }),
          el("td", { textContent: o.kind }),
          el("td", { class: "mono", textContent: o.txHash.slice(0, 14) + "…" }),
          el("td", { textContent: o.disclosure ?? "—" }),
          el("td", { textContent: o.decoded ? `${o.realOutputs}/${o.totalOutputs}` : "—" }),
          el("td", { class: "small", textContent: o.decoded ? (o.spentInputs ? `${o.spentInputs} input(s) marked spent` : "") : (o.reason ?? "") }),
        ),
      );
    }
    opsPane.append(el("h4", { textContent: "operations feed (chain order)" }), t);
  }

  function renderLedger(l: AuditorLedger): void {
    clear(ledgerPane);
    ledgerPane.append(el("h4", { textContent: "decrypted ledger — who received what" }));
    if (l.byOwner.size === 0) {
      ledgerPane.append(el("p", { class: "note", textContent: "no decryptable notes (deposit/withdraw authority envelopes are not in the public feed — use an arbiter indexer's /notes for those)" }));
      return;
    }
    for (const [owner, notes] of l.byOwner) {
      const real = notes.filter((n) => BigInt(n.value) > 0n);
      if (real.length === 0) continue; // skip padding-only owners
      const bal = real.filter((n) => !n.spent).reduce((a, n) => a + BigInt(n.value), 0n);
      const t = el("table", { class: "ledger" });
      t.append(el("tr", {}, el("th", { textContent: "value" }), el("th", { textContent: "kind" }), el("th", { textContent: "leaf" }), el("th", { textContent: "tx" }), el("th", { textContent: "spent" })));
      for (const n of real) t.append(ownerNoteRow(n));
      ledgerPane.append(
        el("div", { class: "owner-block" },
          el("div", { class: "owner-head" }, el("span", { class: "mono owner-key", textContent: owner }), el("span", { class: "owner-bal", textContent: `unspent balance: ${bal}` })),
          t,
        ),
      );
    }
  }

  function ownerNoteRow(n: LedgerNote): HTMLElement {
    return el("tr", {},
      el("td", { textContent: n.value }),
      el("td", { textContent: n.kind }),
      el("td", { textContent: n.leafIndex == null ? "—" : String(n.leafIndex) }),
      el("td", { class: "mono", textContent: n.txHash.slice(0, 14) + "…" }),
      el("td", { textContent: n.spent ? "spent" : "unspent" }),
    );
  }

  // ---- /notes owner-lookup (signed-auth flow, binds to the OWNER key) -------
  const noteOwner = input("", "owner compressed pubkey (32-byte hex)");
  const notePriv = input("", "that owner's private scalar (auth binds to it)");
  const notesStatus = el("div", { class: "status-box" });
  const notesPane = el("pre", { class: "json-pane" });
  async function lookupNotes(): Promise<void> {
    try {
      statusLine(notesStatus, "signing + fetching /notes…", "info");
      const url = buildNotesUrl(idxUrl.value.trim(), noteOwner.value.trim(), notePriv.value.trim());
      const notes = await fetchNotes(url);
      notesPane.textContent = JSON.stringify(notes, null, 2);
      statusLine(notesStatus, "notes fetched (auth verified against the owner key)", "ok");
    } catch (e) {
      notesPane.textContent = "";
      statusLine(notesStatus, `/notes failed: ${(e as Error).message}`, "err");
    }
  }

  root.append(
    section("Arbiter connection", [
      el("p", { class: "note", textContent: "Auditor-mode is the only mode that holds the arbiter key. It never leaves this browser — it is used to decrypt the /events authority envelopes locally." }),
      field("indexer URL", idxUrl),
      field("arbiter private key", arbPriv, "bjj scalar — auditor secret"),
      field("batch size B", batchSize),
      button("Load ledger", () => void loadLedger(), "btn"),
      status,
    ]),
    section("Ledger", [summaryPane, ledgerPane]),
    section("Operations + alarms", [opsPane, alarmsPane]),
    section("GET /notes lookup (signed-auth demo)", [
      el("p", { class: "note", textContent: "The /notes auth binds to the OWNER key (the signature must verify against the queried pubkey), so this needs the owner's private scalar — it is the recipient's own-notes lookup via the arbiter indexer, not a general auditor browse. The auditor's full view above comes from decrypting /events." }),
      field("owner pubkey", noteOwner),
      field("owner private scalar", notePriv),
      button("Fetch /notes", () => void lookupNotes(), "btn-small"),
      notesStatus,
      notesPane,
    ]),
  );
  return root;
}

function section(title: string, children: HTMLElement[]): HTMLElement {
  return el("section", { class: "card" }, el("h3", { textContent: title }), ...children);
}
