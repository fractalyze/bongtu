// EMPLOYER-MODE view (SPEC §7). Holds NO arbiter key. Flow:
//   recipients (form rows + optional CSV) + input note + membership witness
//     -> buildDisburseRequest (pure)   -> show the ProvingRequest + ciphertext + meta
//     -> prove on the prover service    -> get calldata
//     -> submit disburseWithCiphertexts via MetaMask
// The employer's ledger is its OWN authored recipients + change + receipts (no
// arbiter key needed — it authored the batch). Downloadable as CSV.

import { useRef, useState } from "react";
import type { ReactNode } from "react";
import { DEFAULTS } from "../config.js";
import {
  buildDisburseRequest,
  freshDisburseKem,
  type RecipientRow,
  type AssembleResult,
} from "../lib/disburse.js";
import { parseRecipientsCsv } from "../lib/csv.js";
import { getHead, getPath } from "../lib/indexerClient.js";
import { proveViaService } from "../lib/proverClient.js";
import { submitDisburse } from "../lib/chain.js";
import type { Calldata } from "@bongtu/core/proving";
import { deriveKeypair, commitment } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import { ImtTree } from "@bongtu/core/imt";
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
  TextArea,
  TextInput,
  Th,
  errText,
  type StatusMsg,
} from "./controls.js";

// Every demo-fillable text input in one bag: single-field updates stay one-line
// and the assemble call reads them in one place.
interface FormState {
  inValue: string;
  inSalt: string;
  inPriv: string;
  memRoot: string;
  memLeaf: string;
  memPath: string;
  idxUrl: string;
  ecdh: string;
  nonce: string;
  arbX: string;
  arbY: string;
  saltSeed: string;
  padSeed: string;
  csvPaste: string;
  proverUrl: string;
  poolAddr: string;
}

const INITIAL_FORM: FormState = {
  inValue: "",
  inSalt: "",
  inPriv: "",
  memRoot: "",
  memLeaf: "",
  memPath: "",
  idxUrl: DEFAULTS.indexerUrl,
  ecdh: "900000000000000000007",
  nonce: "424242424243",
  arbX: DEFAULTS.arbiterPubKey[0],
  arbY: DEFAULTS.arbiterPubKey[1],
  saltSeed: "9000000",
  padSeed: "50000000000",
  csvPaste: "",
  proverUrl: DEFAULTS.proverUrl,
  poolAddr: DEFAULTS.pool,
};

const TOOLBAR_CLS = "flex gap-2 flex-wrap mb-2.5 items-center";

export function Employer(): ReactNode {
  const [recipients, setRecipients] = useState<RecipientRow[]>([{ pubkey: "", amount: "" }]);
  const [form, setForm] = useState<FormState>(INITIAL_FORM);
  const [assembled, setAssembled] = useState<AssembleResult | null>(null);
  const [calldata, setCalldata] = useState<Calldata | null>(null);
  const [buildStatus, setBuildStatus] = useState<StatusMsg | null>(null);
  const [proveStatus, setProveStatus] = useState<StatusMsg | null>(null);
  const [submitStatus, setSubmitStatus] = useState<StatusMsg | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const set = (k: keyof FormState) => (v: string) => setForm((f) => ({ ...f, [k]: v }));

  function setRecipient(i: number, patch: Partial<RecipientRow>): void {
    setRecipients((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  }

  function removeRecipient(i: number): void {
    setRecipients((rs) => {
      const next = rs.filter((_, j) => j !== i);
      return next.length === 0 ? [{ pubkey: "", amount: "" }] : next;
    });
  }

  function loadCsv(text: string, source: string): void {
    try {
      const parsed = parseRecipientsCsv(text);
      if (parsed.length === 0) throw new Error("no rows parsed");
      setRecipients(parsed);
      setBuildStatus({ kind: "ok", text: `loaded ${parsed.length} recipients from ${source}` });
    } catch (e) {
      setBuildStatus({ kind: "err", text: `CSV error: ${errText(e)}` });
    }
  }

  function fillDemoRecipients(): void {
    setRecipients(
      Array.from({ length: 3 }, (_, i) => {
        const kp = deriveKeypair(4000000019n + BigInt(i) * 1000003n);
        return { pubkey: packPubkey(kp.publicKey), amount: String(100 + i) };
      }),
    );
    setBuildStatus({ kind: "info", text: "filled 3 demo recipients (derived bjj keys)" });
  }

  function fillDemoNote(): void {
    // A demo employer note big enough to cover the demo recipients + change.
    const kp = deriveKeypair(313131313131313131313131n);
    setForm((f) => ({
      ...f,
      inPriv: kp.formattedPrivateKey.toString(),
      inValue: "100000",
      inSalt: "777",
    }));
    setBuildStatus({
      kind: "info",
      text: `demo input note: value 100000, owner commitment ${commitment(100000n, 777n, kp.publicKey).toString().slice(0, 18)}…`,
    });
  }

  async function fetchWitness(): Promise<void> {
    try {
      const li = Number(form.memLeaf);
      if (!Number.isInteger(li) || li < 0) throw new Error("enter a valid leaf index first");
      setBuildStatus({ kind: "info", text: "fetching /head + /path…" });
      const [head, path] = await Promise.all([getHead(form.idxUrl), getPath(form.idxUrl, li)]);
      setForm((f) => ({ ...f, memRoot: head.root, memPath: JSON.stringify(path.siblings) }));
      setBuildStatus({
        kind: "ok",
        text: `fetched root ${head.root.slice(0, 16)}… + ${path.siblings.length}-sibling path for leaf ${li}`,
      });
    } catch (e) {
      setBuildStatus({ kind: "err", text: `indexer fetch failed: ${errText(e)}` });
    }
  }

  function buildLocalWitness(): void {
    // Reconstruct a tiny tree that ends with the input note, so the demo can produce
    // a real, verifiable membership witness without a running indexer.
    try {
      const kp = deriveKeypair(BigInt(form.inPriv));
      const tree = new ImtTree(32, 256);
      tree.appendLeaf(commitment(1n, 1n, kp.publicKey)); // leaf 0
      tree.appendLeaf(commitment(BigInt(form.inValue), BigInt(form.inSalt), kp.publicKey)); // leaf 1 = the input note
      const { siblings } = tree.merklePath(1);
      setForm((f) => ({
        ...f,
        memRoot: tree.getRoot().toString(),
        memLeaf: "1",
        memPath: JSON.stringify(siblings.map(String)),
      }));
      setBuildStatus({ kind: "ok", text: "built a local demo membership witness (input note at leaf 1)" });
    } catch (e) {
      setBuildStatus({ kind: "err", text: `fill the input note first: ${errText(e)}` });
    }
  }

  function buildBatch(): void {
    try {
      setAssembled(null);
      setCalldata(null);
      const rows = recipients.filter((r) => r.pubkey.trim() !== "" || r.amount.trim() !== "");
      // Fresh ML-KEM encapsulation per assembled batch (design doc §6: ct reuse
      // collapses the PQ compartment) — unlike the demo-friendly manual fields
      // above, this is machine-drawn: limbs feed the witness, the ct feeds the tx.
      const kem = freshDisburseKem();
      const res = buildDisburseRequest(
        { value: form.inValue.trim(), salt: form.inSalt.trim(), ownerPrivateKey: form.inPriv.trim() },
        {
          root: form.memRoot.trim(),
          pathElements: JSON.parse(form.memPath || "[]"),
          leafIndex: Number(form.memLeaf),
        },
        rows,
        {
          ecdhPrivateKey: form.ecdh.trim(),
          encryptionNonce: form.nonce.trim(),
          authorityPubKey: [form.arbX.trim(), form.arbY.trim()],
          kemSs: kem.kemSs,
          kemCiphertext: kem.kemCiphertext,
          saltSeed: form.saltSeed.trim(),
          padSeed: form.padSeed.trim(),
        },
      );
      setAssembled(res);
      setBuildStatus({
        kind: res.meta.membershipOk ? "ok" : "err",
        text: `assembled disburse: ${res.meta.realCount} recipients + ${res.meta.changeCount} change + ${res.meta.padCount} padding = 256 outputs; ciphertext ${res.meta.ciphertextLen} elements; membership ${res.meta.membershipOk ? "VERIFIED" : "NOT verified (root/path mismatch)"}`,
      });
    } catch (e) {
      setBuildStatus({ kind: "err", text: `assembly failed: ${errText(e)}` });
    }
  }

  async function proveBatch(): Promise<void> {
    if (!assembled) {
      setProveStatus({ kind: "err", text: "assemble a batch first" });
      return;
    }
    try {
      setProveStatus({
        kind: "info",
        text: "POSTing the request to the GPU prover service (compiled once at its boot; warm ~6s)…",
      });
      const cd = await proveViaService(form.proverUrl.trim(), assembled.request);
      setCalldata(cd);
      setProveStatus({ kind: "ok", text: `proof received: ${cd.pub.length} public signals; ready to submit` });
    } catch (e) {
      setCalldata(null);
      setProveStatus({ kind: "err", text: `proving failed: ${errText(e)}` });
    }
  }

  async function submitBatch(): Promise<void> {
    if (!assembled || !calldata) {
      setSubmitStatus({ kind: "err", text: "assemble + prove first" });
      return;
    }
    try {
      setSubmitStatus({ kind: "info", text: "connecting MetaMask + sending disburseWithCiphertexts…" });
      const r = await submitDisburse(
        form.poolAddr.trim(),
        calldata,
        assembled.ciphertext,
        assembled.kemCiphertext,
        DEFAULTS.explorer,
      );
      setSubmitStatus({
        kind: "ok",
        text: `submitted: ${r.txHash}`,
        link: { href: r.explorerUrl, label: "view on explorer" },
      });
    } catch (e) {
      setSubmitStatus({ kind: "err", text: `submit failed: ${errText(e)}` });
    }
  }

  function downloadReceipt(res: AssembleResult): void {
    const lines = ["pubkey,amount,kind", ...res.ledger.map((r) => `${r.pubkey},${r.amount},${r.kind}`)];
    const blob = new Blob([lines.join("\n") + "\n"], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "bongtu-disburse-receipt.csv";
    a.click();
  }

  return (
    <div className="flex flex-col gap-4 pt-4">
      <Section title="1 · Recipients">
        <div className={TOOLBAR_CLS}>
          <Button variant="small" onClick={() => setRecipients((rs) => [...rs, { pubkey: "", amount: "" }])}>
            + Add row
          </Button>
          <Button variant="small" onClick={fillDemoRecipients}>
            Fill 3 demo recipients
          </Button>
          <label className="inline-flex items-center gap-1.5 bg-panel2 border border-line rounded-lg px-2.5 py-1 cursor-pointer text-xs">
            <span>Upload CSV</span>
            <input
              ref={fileRef}
              type="file"
              accept=".csv,text/csv"
              className="hidden"
              onChange={async (e) => {
                const f = e.target.files?.[0];
                if (f) loadCsv(await f.text(), "CSV");
                if (fileRef.current) fileRef.current.value = "";
              }}
            />
          </label>
        </div>
        <table className="border-collapse w-full text-xs">
          <thead>
            <tr>
              <Th>#</Th>
              <Th>compressed pubkey</Th>
              <Th>amount</Th>
              <Th />
            </tr>
          </thead>
          <tbody>
            {recipients.map((r, i) => (
              <tr key={i}>
                <Td cls="w-[60px]">{i + 1}</Td>
                <Td>
                  <TextInput
                    compact
                    value={r.pubkey}
                    placeholder="0x… compressed bjj pubkey (32-byte hex)"
                    onChange={(v) => setRecipient(i, { pubkey: v })}
                  />
                </Td>
                <Td cls="w-[60px]">
                  <TextInput compact value={r.amount} placeholder="amount" onChange={(v) => setRecipient(i, { amount: v })} />
                </Td>
                <Td>
                  <Button variant="small" onClick={() => removeRecipient(i)}>
                    ✕
                  </Button>
                </Td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="flex gap-2 items-end my-2">
          <TextArea value={form.csvPaste} onChange={set("csvPaste")} rows={3} placeholder="# paste CSV: pubkey,amount per line" />
          <Button variant="small" onClick={() => loadCsv(form.csvPaste, "pasted CSV")}>
            Parse pasted CSV
          </Button>
        </div>
        <Note>
          A recipient is identified by a compressed bjj pubkey (sdk/pubkey.ts). Full ETH→bjj onboarding is
          out of scope for this PoC — recipients paste their compressed key.
        </Note>
      </Section>

      <Section title="2 · Employer input note">
        <div className={TOOLBAR_CLS}>
          <Button variant="small" onClick={fillDemoNote}>
            Derive a demo input note
          </Button>
        </div>
        <Field label="value">
          <TextInput value={form.inValue} placeholder="input note value (decimal)" onChange={set("inValue")} />
        </Field>
        <Field label="salt">
          <TextInput value={form.inSalt} placeholder="input note salt (decimal)" onChange={set("inSalt")} />
        </Field>
        <Field label="owner private scalar" hint="the employer's bjj spending key (pasted for the PoC)">
          <TextInput value={form.inPriv} placeholder="employer bjj private scalar (spending key)" onChange={set("inPriv")} />
        </Field>
      </Section>

      <Section title="3 · Membership witness (of the input note)">
        <div className={TOOLBAR_CLS}>
          <Button variant="small" onClick={buildLocalWitness}>
            Build a local membership witness (demo)
          </Button>
        </div>
        <Field label="root">
          <TextInput value={form.memRoot} placeholder="membership root (decimal)" onChange={set("memRoot")} />
        </Field>
        <Field label="leaf index">
          <TextInput value={form.memLeaf} placeholder="leaf index of the input note" onChange={set("memLeaf")} />
        </Field>
        <Field label="path (32 siblings, JSON)">
          <TextArea
            value={form.memPath}
            onChange={set("memPath")}
            placeholder="JSON array of 32 sibling values (decimal), or fetch from an indexer"
          />
        </Field>
        <div className="flex gap-2 items-end my-2">
          <Field label="indexer URL" className="flex-1 my-0">
            <TextInput value={form.idxUrl} placeholder="indexer URL" onChange={set("idxUrl")} />
          </Field>
          <Button variant="small" onClick={() => void fetchWitness()}>
            Fetch root + path from indexer
          </Button>
        </div>
      </Section>

      <Section title="4 · Crypto params (arbiter PUBLIC key — no secret here)">
        <div className="grid grid-cols-2 gap-y-2 gap-x-4">
          <Field label="ECDH private (ephemeral)">
            <TextInput value={form.ecdh} onChange={set("ecdh")} />
          </Field>
          <Field label="encryption nonce">
            <TextInput value={form.nonce} onChange={set("nonce")} />
          </Field>
          <Field label="arbiter pubkey X">
            <TextInput value={form.arbX} onChange={set("arbX")} />
          </Field>
          <Field label="arbiter pubkey Y">
            <TextInput value={form.arbY} onChange={set("arbY")} />
          </Field>
          <Field label="salt seed">
            <TextInput value={form.saltSeed} onChange={set("saltSeed")} />
          </Field>
          <Field label="padding seed">
            <TextInput value={form.padSeed} onChange={set("padSeed")} />
          </Field>
        </div>
      </Section>

      <Section title="5 · Build the disbursement">
        <Button onClick={buildBatch}>Build disbursement</Button>
        <Status msg={buildStatus} />
        {assembled && (
          <>
            <H4>assembled batch</H4>
            <Table>
              <KvRow k="input value" v={assembled.meta.inputValue} />
              <KvRow k="disbursed (recipients)" v={assembled.meta.disbursed} />
              <KvRow k="change to employer" v={assembled.meta.changeValue} />
              <KvRow
                k="outputs"
                v={`${assembled.meta.realCount} recipients + ${assembled.meta.changeCount} change + ${assembled.meta.padCount} padding = 256`}
              />
              <KvRow k="input commitment" v={assembled.meta.inputCommitment} />
              <KvRow k="nullifier" v={assembled.meta.nullifier} />
              <KvRow k="subtreeRoot" v={assembled.meta.subtreeRoot} />
              <KvRow k="disclosureHash" v={assembled.meta.disclosureHash} />
              <KvRow k="ciphertext length" v={`${assembled.meta.ciphertextLen}  (must be 2054)`} />
              <KvRow
                k="membership"
                v={assembled.meta.membershipOk ? "VERIFIED (path folds to root)" : "NOT verified"}
              />
            </Table>
          </>
        )}
        <details className="my-2.5">
          <summary className="cursor-pointer text-accent text-xs">
            ProvingRequest (POST body for the prover service)
          </summary>
          <JsonPane text={assembled ? JSON.stringify(assembled.request, null, 2) : ""} />
        </details>
        {assembled && (
          <>
            <H4>employer ledger (own CSV + receipts — no arbiter key)</H4>
            <Table>
              <tr>
                <Th>#</Th>
                <Th>recipient (compressed pubkey)</Th>
                <Th>amount</Th>
                <Th>kind</Th>
              </tr>
              {assembled.ledger.map((r, i) => (
                <tr key={i}>
                  <Td>{i + 1}</Td>
                  <Td cls="font-mono break-all text-[11px]">{r.pubkey}</Td>
                  <Td>{r.amount}</Td>
                  <Td>{r.kind}</Td>
                </tr>
              ))}
            </Table>
            <Button variant="small" onClick={() => downloadReceipt(assembled)}>
              Download receipt CSV
            </Button>
          </>
        )}
      </Section>

      <Section title="6 · Prove on the prover service">
        <Note>
          Browser GPU proving is infeasible (1.24GB zkey + rabbitsnark). The honest PoC path: POST the
          assembled request to the bongtu prover service (top-level prover/) on the employer's GPU box, get
          calldata, submit from here.
        </Note>
        <Field label="prover service URL">
          <TextInput value={form.proverUrl} placeholder="prover service URL" onChange={set("proverUrl")} />
        </Field>
        <Button onClick={() => void proveBatch()}>Prove via service</Button>
        <Status msg={proveStatus} />
        <details className="my-2.5">
          <summary className="cursor-pointer text-accent text-xs">calldata {"{a,b,c,pub}"}</summary>
          <JsonPane text={calldata ? JSON.stringify(calldata, null, 2) : ""} />
        </details>
      </Section>

      <Section title="7 · Submit to chain (MetaMask)">
        <Field label="pool address">
          <TextInput value={form.poolAddr} placeholder="BongtuPool address" onChange={set("poolAddr")} />
        </Field>
        <Button onClick={() => void submitBatch()}>Submit disburseWithCiphertexts</Button>
        <Status msg={submitStatus} />
      </Section>
    </div>
  );
}
