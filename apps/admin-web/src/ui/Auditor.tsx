// AUDITOR-MODE view (SPEC §7). The ONLY mode with the arbiter key. It fetches the
// PUBLIC /events feed + /alarms from an arbiter-mode indexer URL and decrypts each
// transfer/disburse authority envelope LOCALLY with the arbiter private key
// (ledger.ts) into "who received what / spent status" — the independent regulator
// seat. Also offers the signed GET /notes lookup (auth binds to the owner key).

import { useState } from "react";
import type { ReactNode } from "react";
import { decodeAddress } from "@bongtu/core/pubkey";
import { DEFAULTS } from "../config.js";
import { getEvents, getAlarms, type Alarm } from "../lib/indexerClient.js";
import { buildAuditorLedger, type AuditorLedger, type LedgerNote } from "../lib/ledger.js";
import { buildNotesUrl, fetchNotes } from "../lib/notesAuth.js";
import {
  Button,
  Field,
  H4,
  JsonPane,
  KvRow,
  Note,
  Section,
  Status,
  Table,
  Td,
  TextInput,
  Th,
  errText,
  type StatusMsg,
} from "./controls.js";

export function Auditor(): ReactNode {
  const [idxUrl, setIdxUrl] = useState<string>(DEFAULTS.indexerUrl);
  const [arbPriv, setArbPriv] = useState("");
  const [batchSize, setBatchSize] = useState(String(DEFAULTS.batchSize));
  const [status, setStatus] = useState<StatusMsg | null>(null);
  const [ledger, setLedger] = useState<AuditorLedger | null>(null);
  const [alarms, setAlarms] = useState<Alarm[]>([]);
  const [eventCount, setEventCount] = useState(0);

  const [noteOwner, setNoteOwner] = useState("");
  const [notePriv, setNotePriv] = useState("");
  const [notesStatus, setNotesStatus] = useState<StatusMsg | null>(null);
  const [notesJson, setNotesJson] = useState("");

  async function loadLedger(): Promise<void> {
    try {
      if (arbPriv.trim() === "") throw new Error("enter the arbiter private key");
      setStatus({ kind: "info", text: "fetching /events + /alarms and decrypting authority envelopes…" });
      const [events, alarmList] = await Promise.all([
        getEvents(idxUrl.trim()),
        getAlarms(idxUrl.trim()).catch(() => []),
      ]);
      const l = buildAuditorLedger(events, arbPriv.trim(), Number(batchSize) || 256);
      setLedger(l);
      setAlarms(alarmList);
      setEventCount(events.length);
      const decoded = l.ops.filter((o) => o.decoded).length;
      setStatus({
        kind: "ok",
        text: `decoded ${decoded}/${l.ops.length} ops; ${l.notes.length} notes across ${l.byOwner.size} owners; ${alarmList.length} alarms`,
      });
    } catch (e) {
      setLedger(null);
      setAlarms([]);
      setStatus({ kind: "err", text: `load failed: ${errText(e)}` });
    }
  }

  async function lookupNotes(): Promise<void> {
    try {
      setNotesStatus({ kind: "info", text: "signing + fetching /notes…" });
      // The /notes wire param is canonical hex; the operator may paste either form.
      const url = buildNotesUrl(idxUrl.trim(), decodeAddress(noteOwner), notePriv.trim());
      const notes = await fetchNotes(url);
      setNotesJson(JSON.stringify(notes, null, 2));
      setNotesStatus({ kind: "ok", text: "notes fetched (auth verified against the owner key)" });
    } catch (e) {
      setNotesJson("");
      setNotesStatus({ kind: "err", text: `/notes failed: ${errText(e)}` });
    }
  }

  const nDisclosure = alarms.filter((a) => a.type === "disclosure").length;

  return (
    <div className="flex flex-col gap-4 pt-4">
      <Section title="Arbiter connection">
        <Note>
          Auditor-mode is the only mode that holds the arbiter key. It never leaves this browser — it is
          used to decrypt the /events authority envelopes locally.
        </Note>
        <Field label="indexer URL">
          <TextInput value={idxUrl} placeholder="arbiter-mode indexer URL" onChange={setIdxUrl} />
        </Field>
        <Field label="arbiter private key" hint="bjj scalar — auditor secret">
          <TextInput value={arbPriv} placeholder="arbiter PRIVATE key (bjj scalar) — auditor only" onChange={setArbPriv} />
        </Field>
        <Field label="batch size B">
          <TextInput value={batchSize} placeholder="batch size B" onChange={setBatchSize} />
        </Field>
        <Button onClick={() => void loadLedger()}>Load ledger</Button>
        <Status msg={status} />
      </Section>

      <Section title="Ledger">
        {ledger && (
          <>
            <H4>auditor ledger summary</H4>
            <Table>
              <KvRow k="events fetched" v={String(eventCount)} />
              <KvRow k="ops decoded" v={`${ledger.ops.filter((o) => o.decoded).length} / ${ledger.ops.length}`} />
              <KvRow k="notes recovered" v={String(ledger.notes.length)} />
              <KvRow k="distinct owners" v={String(ledger.byOwner.size)} />
              <KvRow k="notes spent" v={String(ledger.notes.filter((n) => n.spent).length)} />
              <KvRow k="total value seen" v={ledger.notes.reduce((a, n) => a + BigInt(n.value), 0n).toString()} />
              <KvRow k="alarms" v={String(alarms.length)} />
            </Table>
            <H4>decrypted ledger — who received what</H4>
            {ledger.byOwner.size === 0 ? (
              <Note>
                no decryptable notes (deposit/withdraw authority envelopes are not in the public feed — use
                an arbiter indexer's /notes for those)
              </Note>
            ) : (
              [...ledger.byOwner.entries()].map(([owner, notes]) => {
                const real = notes.filter((n) => BigInt(n.value) > 0n);
                if (real.length === 0) return null; // skip padding-only owners
                const bal = real.filter((n) => !n.spent).reduce((a, n) => a + BigInt(n.value), 0n);
                return (
                  <div key={owner} className="border border-line rounded-lg p-2.5 my-2.5">
                    <div className="flex justify-between gap-3 mb-1.5 flex-wrap">
                      <span className="font-mono break-all text-[11px]">{owner}</span>
                      <span className="text-ok text-xs whitespace-nowrap">unspent balance: {bal.toString()}</span>
                    </div>
                    <Table>
                      <tr>
                        <Th>value</Th>
                        <Th>kind</Th>
                        <Th>leaf</Th>
                        <Th>tx</Th>
                        <Th>spent</Th>
                      </tr>
                      {real.map((n, i) => (
                        <OwnerNoteRow key={i} n={n} />
                      ))}
                    </Table>
                  </div>
                );
              })
            )}
          </>
        )}
      </Section>

      <Section title="Operations + alarms">
        {ledger && (
          <>
            <H4>operations feed (chain order)</H4>
            <Table>
              <tr>
                <Th>seq</Th>
                <Th>kind</Th>
                <Th>tx</Th>
                <Th>disclosure</Th>
                <Th>outputs (real/total)</Th>
                <Th>note</Th>
              </tr>
              {ledger.ops.map((o) => (
                <tr key={o.seq}>
                  <Td>{o.seq}</Td>
                  <Td>{o.kind}</Td>
                  <Td cls="font-mono break-all">{o.txHash.slice(0, 14)}…</Td>
                  <Td>{o.disclosure ?? "—"}</Td>
                  <Td>{o.decoded ? `${o.realOutputs}/${o.totalOutputs}` : "—"}</Td>
                  <Td cls="text-[11px] text-muted">
                    {o.decoded ? (o.spentInputs ? `${o.spentInputs} input(s) marked spent` : "") : (o.reason ?? "")}
                  </Td>
                </tr>
              ))}
            </Table>
            {/* The /alarms feed is a discriminated union: disclosure alarms (published
                hash != recomputed) plus, in arbiter mode, envelope cross-check alarms
                (the publisher lied about note contents — SPEC §6b first-class). */}
            <H4>{`alarms (${alarms.length} — ${nDisclosure} disclosure · ${alarms.length - nDisclosure} envelope)`}</H4>
            {alarms.length === 0 ? <Note>no alarms</Note> : <JsonPane text={JSON.stringify(alarms, null, 2)} />}
          </>
        )}
      </Section>

      <Section title="GET /notes lookup (signed-auth demo)">
        <Note>
          The /notes auth binds to the OWNER key (the signature must verify against the queried pubkey), so
          this needs the owner's private scalar — it is the recipient's own-notes lookup via the arbiter
          indexer, not a general auditor browse. The auditor's full view above comes from decrypting
          /events.
        </Note>
        <Field label="owner pubkey">
          <TextInput value={noteOwner} placeholder="owner address (3… base58 or 32-byte hex)" onChange={setNoteOwner} />
        </Field>
        <Field label="owner private scalar">
          <TextInput value={notePriv} placeholder="that owner's private scalar (auth binds to it)" onChange={setNotePriv} />
        </Field>
        <Button variant="small" onClick={() => void lookupNotes()}>
          Fetch /notes
        </Button>
        <Status msg={notesStatus} />
        {notesJson && <JsonPane text={notesJson} />}
      </Section>
    </div>
  );
}

function OwnerNoteRow({ n }: { n: LedgerNote }): ReactNode {
  return (
    <tr>
      <Td>{n.value}</Td>
      <Td>{n.kind}</Td>
      <Td>{n.leafIndex == null ? "—" : String(n.leafIndex)}</Td>
      <Td cls="font-mono break-all">{n.txHash.slice(0, 14)}…</Td>
      <Td>{n.spent ? "spent" : "unspent"}</Td>
    </tr>
  );
}
