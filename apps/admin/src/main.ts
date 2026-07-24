// bongtu admin — role-moded entry (SPEC §7 / Q10). Two modes in one app, switched
// by a tab: EMPLOYER (no arbiter key: assemble + prove + disburse) and AUDITOR
// (holds the arbiter key: decrypt the /events feed into a ledger). The two are kept
// as separate views so an employer instance never renders the arbiter-key inputs.

import "./styles.css";
import { el, clear } from "./lib/dom.js";
import { employerView } from "./views/employer.js";
import { auditorView } from "./views/auditor.js";
import { DEFAULTS } from "./config.js";

type Mode = "employer" | "auditor";

const appRoot = document.getElementById("app");
if (!appRoot) throw new Error("no #app root in index.html");

const body = el("div", { class: "mode-body" });

function render(mode: Mode): void {
  clear(body);
  body.append(mode === "employer" ? employerView() : auditorView());
  for (const b of document.querySelectorAll<HTMLButtonElement>(".mode-tab")) {
    b.classList.toggle("active", b.dataset.mode === mode);
  }
}

const employerTab = el("button", { class: "mode-tab active", textContent: "Employer mode" });
employerTab.dataset.mode = "employer";
employerTab.onclick = () => render("employer");
const auditorTab = el("button", { class: "mode-tab", textContent: "Auditor mode" });
auditorTab.dataset.mode = "auditor";
auditorTab.onclick = () => render("auditor");

appRoot.append(
  el("header", { class: "app-header" },
    el("div", { class: "brand" }, el("span", { class: "logo", textContent: "봉투" }), el("span", { class: "title", textContent: "bongtu admin" })),
    el("div", { class: "tabs" }, employerTab, auditorTab),
    el("div", { class: "chain-badge", textContent: `GIWA Sepolia · chain ${DEFAULTS.chainId} · pool ${DEFAULTS.pool.slice(0, 10)}…` }),
  ),
  body,
);

render("employer");
