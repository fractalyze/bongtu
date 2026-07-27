// EMPLOYER-MODE view (SPEC §7). Holds NO arbiter key. Flow:
//   recipients (form rows + optional CSV) + input note + membership witness
//     -> buildDisburseRequest (pure)   -> show the ProvingRequest + ciphertext + meta
//     -> prove on the prover service    -> get calldata
//     -> submit disburseWithCiphertexts via MetaMask
// The employer's ledger is its OWN authored recipients + change + receipts (no
// arbiter key needed — it authored the batch). Downloadable as CSV.

import { el, field, input, textarea, button, clear, statusLine } from "../lib/dom.js";
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

export function employerView(): HTMLElement {
  const root = el("div", { class: "view" });

  // ---- module state --------------------------------------------------------
  const recipients: RecipientRow[] = [
    { pubkey: "", amount: "" },
  ];
  let assembled: AssembleResult | null = null;
  let calldata: Calldata | null = null;

  // ---- recipients editor ---------------------------------------------------
  const rowsBody = el("tbody");
  function renderRows(): void {
    clear(rowsBody);
    recipients.forEach((r, i) => {
      const pk = input(r.pubkey, "0x… compressed bjj pubkey (32-byte hex)");
      pk.oninput = () => (recipients[i].pubkey = pk.value);
      const amt = input(r.amount, "amount");
      amt.oninput = () => (recipients[i].amount = amt.value);
      const rm = button("✕", () => {
        recipients.splice(i, 1);
        if (recipients.length === 0) recipients.push({ pubkey: "", amount: "" });
        renderRows();
      }, "btn-small");
      rowsBody.append(
        el("tr", {},
          el("td", { class: "idx", textContent: String(i + 1) }),
          el("td", {}, pk),
          el("td", { class: "amt" }, amt),
          el("td", {}, rm),
        ),
      );
    });
  }
  renderRows();

  const csvFile = el("input", { type: "file", accept: ".csv,text/csv" });
  csvFile.onchange = async () => {
    const f = csvFile.files?.[0];
    if (!f) return;
    try {
      const parsed = parseRecipientsCsv(await f.text());
      if (parsed.length === 0) throw new Error("no rows parsed");
      recipients.splice(0, recipients.length, ...parsed);
      renderRows();
      statusLine(buildStatus, `loaded ${parsed.length} recipients from CSV`, "ok");
    } catch (e) {
      statusLine(buildStatus, `CSV error: ${(e as Error).message}`, "err");
    }
    csvFile.value = "";
  };

  const csvPaste = textarea("", 3, "# paste CSV: pubkey,amount per line");
  const csvPasteBtn = button("Parse pasted CSV", () => {
    try {
      const parsed = parseRecipientsCsv(csvPaste.value);
      if (parsed.length === 0) throw new Error("no rows parsed");
      recipients.splice(0, recipients.length, ...parsed);
      renderRows();
      statusLine(buildStatus, `loaded ${parsed.length} recipients from pasted CSV`, "ok");
    } catch (e) {
      statusLine(buildStatus, `CSV error: ${(e as Error).message}`, "err");
    }
  }, "btn-small");

  const demoBtn = button("Fill 3 demo recipients", () => {
    const demo: RecipientRow[] = Array.from({ length: 3 }, (_, i) => {
      const kp = deriveKeypair(4000000019n + BigInt(i) * 1000003n);
      return { pubkey: packPubkey(kp.publicKey), amount: String(100 + i) };
    });
    recipients.splice(0, recipients.length, ...demo);
    renderRows();
    statusLine(buildStatus, "filled 3 demo recipients (derived bjj keys)", "info");
  }, "btn-small");

  // ---- input note ----------------------------------------------------------
  const inValue = input("", "input note value (decimal)");
  const inSalt = input("", "input note salt (decimal)");
  const inPriv = input("", "employer bjj private scalar (spending key)");
  const demoNoteBtn = button("Derive a demo input note", () => {
    // A demo employer note big enough to cover the demo recipients + change.
    const kp = deriveKeypair(313131313131313131313131n);
    inPriv.value = kp.formattedPrivateKey.toString();
    inValue.value = "100000";
    inSalt.value = "777";
    statusLine(buildStatus, `demo input note: value 100000, owner commitment ${commitment(100000n, 777n, kp.publicKey).toString().slice(0, 18)}…`, "info");
  }, "btn-small");

  // ---- membership witness --------------------------------------------------
  const memRoot = input("", "membership root (decimal)");
  const memLeaf = input("", "leaf index of the input note");
  const memPath = textarea("", 4, "JSON array of 32 sibling values (decimal), or fetch from an indexer");
  const idxUrl = input(DEFAULTS.indexerUrl, "indexer URL");
  const fetchPathBtn = button("Fetch root + path from indexer", async () => {
    try {
      const li = Number(memLeaf.value);
      if (!Number.isInteger(li) || li < 0) throw new Error("enter a valid leaf index first");
      statusLine(buildStatus, "fetching /head + /path…", "info");
      const [head, path] = await Promise.all([getHead(idxUrl.value), getPath(idxUrl.value, li)]);
      memRoot.value = head.root;
      memPath.value = JSON.stringify(path.siblings);
      statusLine(buildStatus, `fetched root ${head.root.slice(0, 16)}… + ${path.siblings.length}-sibling path for leaf ${li}`, "ok");
    } catch (e) {
      statusLine(buildStatus, `indexer fetch failed: ${(e as Error).message}`, "err");
    }
  }, "btn-small");
  const localTreeBtn = button("Build a local membership witness (demo)", () => {
    // Reconstruct a tiny tree that ends with the input note, so the demo can produce
    // a real, verifiable membership witness without a running indexer.
    try {
      const priv = BigInt(inPriv.value);
      const v = BigInt(inValue.value);
      const s = BigInt(inSalt.value);
      const kp = deriveKeypair(priv);
      const tree = new ImtTree(32, 256);
      tree.appendLeaf(commitment(1n, 1n, kp.publicKey)); // leaf 0
      tree.appendLeaf(commitment(v, s, kp.publicKey)); // leaf 1 = the input note
      const { siblings } = tree.merklePath(1);
      memRoot.value = tree.getRoot().toString();
      memLeaf.value = "1";
      memPath.value = JSON.stringify(siblings.map(String));
      statusLine(buildStatus, "built a local demo membership witness (input note at leaf 1)", "ok");
    } catch (e) {
      statusLine(buildStatus, `fill the input note first: ${(e as Error).message}`, "err");
    }
  }, "btn-small");

  // ---- crypto params (arbiter PUBLIC key is safe here) ---------------------
  const ecdh = input("900000000000000000007", "ephemeral ECDH private scalar");
  const nonce = input("424242424243", "encryption nonce");
  const arbX = input(DEFAULTS.arbiterPubKey[0], "arbiter public key X");
  const arbY = input(DEFAULTS.arbiterPubKey[1], "arbiter public key Y");
  const saltSeed = input("9000000", "output salt seed");
  const padSeed = input("50000000000", "padding owner-key seed");

  // ---- actions -------------------------------------------------------------
  const buildStatus = el("div", { class: "status-box" });
  const requestPane = el("pre", { class: "json-pane" });
  const metaPane = el("div", { class: "meta-pane" });
  const ledgerPane = el("div", { class: "ledger-pane" });

  function buildBatch(): void {
    try {
      assembled = null;
      calldata = null;
      const rows = recipients.filter((r) => r.pubkey.trim() !== "" || r.amount.trim() !== "");
      // Fresh ML-KEM encapsulation per assembled batch (design doc §6: ct reuse
      // collapses the PQ compartment) — unlike the demo-friendly manual fields
      // above, this is machine-drawn: limbs feed the witness, the ct feeds the tx.
      const kem = freshDisburseKem();
      const res = buildDisburseRequest(
        { value: inValue.value.trim(), salt: inSalt.value.trim(), ownerPrivateKey: inPriv.value.trim() },
        { root: memRoot.value.trim(), pathElements: JSON.parse(memPath.value || "[]"), leafIndex: Number(memLeaf.value) },
        rows,
        {
          ecdhPrivateKey: ecdh.value.trim(),
          encryptionNonce: nonce.value.trim(),
          authorityPubKey: [arbX.value.trim(), arbY.value.trim()],
          kemSs: kem.kemSs,
          kemCiphertext: kem.kemCiphertext,
          saltSeed: saltSeed.value.trim(),
          padSeed: padSeed.value.trim(),
        },
      );
      assembled = res;
      requestPane.textContent = JSON.stringify(res.request, null, 2);
      renderMeta(res);
      renderLedger(res);
      statusLine(
        buildStatus,
        `assembled disburse: ${res.meta.realCount} recipients + ${res.meta.changeCount} change + ${res.meta.padCount} padding = 256 outputs; ciphertext ${res.meta.ciphertextLen} elements; membership ${res.meta.membershipOk ? "VERIFIED" : "NOT verified (root/path mismatch)"}`,
        res.meta.membershipOk ? "ok" : "err",
      );
    } catch (e) {
      requestPane.textContent = "";
      clear(metaPane);
      clear(ledgerPane);
      statusLine(buildStatus, `assembly failed: ${(e as Error).message}`, "err");
    }
  }

  function renderMeta(res: AssembleResult): void {
    clear(metaPane);
    const m = res.meta;
    const rows: [string, string][] = [
      ["input value", m.inputValue],
      ["disbursed (recipients)", m.disbursed],
      ["change to employer", m.changeValue],
      ["outputs", `${m.realCount} recipients + ${m.changeCount} change + ${m.padCount} padding = 256`],
      ["input commitment", m.inputCommitment],
      ["nullifier", m.nullifier],
      ["subtreeRoot", m.subtreeRoot],
      ["disclosureHash", m.disclosureHash],
      ["ciphertext length", `${m.ciphertextLen}  (must be 2054)`],
      ["membership", m.membershipOk ? "VERIFIED (path folds to root)" : "NOT verified"],
    ];
    const table = el("table", { class: "kv" });
    for (const [k, v] of rows) {
      table.append(el("tr", {}, el("td", { class: "k", textContent: k }), el("td", { class: "v", textContent: v })));
    }
    metaPane.append(el("h4", { textContent: "assembled batch" }), table);
  }

  function renderLedger(res: AssembleResult): void {
    clear(ledgerPane);
    const table = el("table", { class: "ledger" });
    table.append(el("tr", {}, el("th", { textContent: "#" }), el("th", { textContent: "recipient (compressed pubkey)" }), el("th", { textContent: "amount" }), el("th", { textContent: "kind" })));
    res.ledger.forEach((r, i) => {
      table.append(el("tr", {}, el("td", { textContent: String(i + 1) }), el("td", { class: "mono", textContent: r.pubkey }), el("td", { textContent: r.amount }), el("td", { textContent: r.kind })));
    });
    const dl = button("Download receipt CSV", () => {
      const lines = ["pubkey,amount,kind", ...res.ledger.map((r) => `${r.pubkey},${r.amount},${r.kind}`)];
      const blob = new Blob([lines.join("\n") + "\n"], { type: "text/csv" });
      const a = el("a", { href: URL.createObjectURL(blob), download: "bongtu-disburse-receipt.csv" });
      a.click();
    }, "btn-small");
    ledgerPane.append(el("h4", { textContent: "employer ledger (own CSV + receipts — no arbiter key)" }), table, dl);
  }

  const proveStatus = el("div", { class: "status-box" });
  const calldataPane = el("pre", { class: "json-pane" });
  const proverUrl = input(DEFAULTS.proverUrl, "prover service URL");
  async function proveBatch(): Promise<void> {
    if (!assembled) {
      statusLine(proveStatus, "assemble a batch first", "err");
      return;
    }
    try {
      statusLine(proveStatus, "POSTing the request to the GPU prover service (compiled once at its boot; warm ~6s)…", "info");
      calldata = await proveViaService(proverUrl.value.trim(), assembled.request);
      calldataPane.textContent = JSON.stringify(calldata, null, 2);
      statusLine(proveStatus, `proof received: ${calldata.pub.length} public signals; ready to submit`, "ok");
    } catch (e) {
      calldataPane.textContent = "";
      statusLine(proveStatus, `proving failed: ${(e as Error).message}`, "err");
    }
  }

  const submitStatus = el("div", { class: "status-box" });
  const poolAddr = input(DEFAULTS.pool, "BongtuPool address");
  async function submitBatch(): Promise<void> {
    if (!assembled || !calldata) {
      statusLine(submitStatus, "assemble + prove first", "err");
      return;
    }
    try {
      statusLine(submitStatus, "connecting MetaMask + sending disburseWithCiphertexts…", "info");
      const r = await submitDisburse(poolAddr.value.trim(), calldata, assembled.ciphertext, assembled.kemCiphertext, DEFAULTS.explorer);
      clear(submitStatus);
      submitStatus.append(
        el("div", { class: "status status-ok", textContent: `submitted: ${r.txHash}` }),
        el("a", { class: "link", href: r.explorerUrl, target: "_blank", textContent: "view on explorer" }),
      );
    } catch (e) {
      statusLine(submitStatus, `submit failed: ${(e as Error).message}`, "err");
    }
  }

  // ---- layout --------------------------------------------------------------
  root.append(
    section("1 · Recipients", [
      el("div", { class: "toolbar" }, button("+ Add row", () => { recipients.push({ pubkey: "", amount: "" }); renderRows(); }, "btn-small"), demoBtn, el("label", { class: "file-btn" }, el("span", { textContent: "Upload CSV" }), csvFile)),
      el("table", { class: "recips" }, el("thead", {}, el("tr", {}, el("th", { textContent: "#" }), el("th", { textContent: "compressed pubkey" }), el("th", { textContent: "amount" }), el("th", { textContent: "" }))), rowsBody),
      el("div", { class: "row" }, csvPaste, csvPasteBtn),
      el("p", { class: "note", textContent: "A recipient is identified by a compressed bjj pubkey (sdk/pubkey.ts). Full ETH→bjj onboarding is out of scope for this PoC — recipients paste their compressed key." }),
    ]),
    section("2 · Employer input note", [
      el("div", { class: "toolbar" }, demoNoteBtn),
      field("value", inValue),
      field("salt", inSalt),
      field("owner private scalar", inPriv, "the employer's bjj spending key (pasted for the PoC)"),
    ]),
    section("3 · Membership witness (of the input note)", [
      el("div", { class: "toolbar" }, localTreeBtn),
      field("root", memRoot),
      field("leaf index", memLeaf),
      field("path (32 siblings, JSON)", memPath),
      el("div", { class: "row" }, field("indexer URL", idxUrl), fetchPathBtn),
    ]),
    section("4 · Crypto params (arbiter PUBLIC key — no secret here)", [
      el("div", { class: "grid2" },
        field("ECDH private (ephemeral)", ecdh),
        field("encryption nonce", nonce),
        field("arbiter pubkey X", arbX),
        field("arbiter pubkey Y", arbY),
        field("salt seed", saltSeed),
        field("padding seed", padSeed),
      ),
    ]),
    section("5 · Build the disbursement", [
      button("Build disbursement", buildBatch, "btn"),
      buildStatus,
      metaPane,
      el("details", {}, el("summary", { textContent: "ProvingRequest (POST body for the prover service)" }), requestPane),
      ledgerPane,
    ]),
    section("6 · Prove on the prover service", [
      el("p", { class: "note", textContent: "Browser GPU proving is infeasible (1.24GB zkey + rabbitsnark). The honest PoC path: POST the assembled request to the bongtu prover service (top-level prover/) on the employer's GPU box, get calldata, submit from here." }),
      field("prover service URL", proverUrl),
      button("Prove via service", () => void proveBatch(), "btn"),
      proveStatus,
      el("details", {}, el("summary", { textContent: "calldata {a,b,c,pub}" }), calldataPane),
    ]),
    section("7 · Submit to chain (MetaMask)", [
      field("pool address", poolAddr),
      button("Submit disburseWithCiphertexts", () => void submitBatch(), "btn"),
      submitStatus,
    ]),
  );
  return root;
}

function section(title: string, children: HTMLElement[]): HTMLElement {
  return el("section", { class: "card" }, el("h3", { textContent: title }), ...children);
}
