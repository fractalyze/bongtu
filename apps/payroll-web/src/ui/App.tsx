// bongtu payroll — role-moded shell (SPEC §7 / Q10). Two modes in one app, switched
// by a tab: EMPLOYER (no arbiter key: assemble + prove + disburse) and AUDITOR
// (holds the arbiter key: decrypt the /events feed into a ledger). The two are kept
// as separate components so an employer instance never renders the arbiter-key
// inputs; switching modes REMOUNTS the other view (state intentionally dropped —
// an auditor tab must not keep a pasted arbiter key alive in the background).

import { useState } from "react";
import type { ReactNode } from "react";
import { DEFAULTS } from "../config.js";
import { Employer } from "./Employer.js";
import { Auditor } from "./Auditor.js";

type Mode = "employer" | "auditor";

const TAB_CLS = "bg-panel text-muted border border-line px-3.5 py-1.5 rounded-lg cursor-pointer";
const TAB_ACTIVE_CLS = "bg-panel2 text-fg border border-accent px-3.5 py-1.5 rounded-lg cursor-pointer";

export function App(): ReactNode {
  const [mode, setMode] = useState<Mode>("employer");
  return (
    <div className="max-w-[980px] mx-auto px-4 pb-16">
      <header className="flex items-center gap-4 flex-wrap py-4 border-b border-line sticky top-0 bg-bg z-[5]">
        <div className="flex items-center gap-2">
          <span className="text-xl font-bold text-accent">봉투</span>
          <span className="font-semibold">bongtu payroll</span>
        </div>
        <div className="flex gap-2">
          <button className={mode === "employer" ? TAB_ACTIVE_CLS : TAB_CLS} onClick={() => setMode("employer")}>
            Employer mode
          </button>
          <button className={mode === "auditor" ? TAB_ACTIVE_CLS : TAB_CLS} onClick={() => setMode("auditor")}>
            Auditor mode
          </button>
        </div>
        <div className="ml-auto font-mono text-[11px] text-muted">
          GIWA Sepolia · chain {DEFAULTS.chainId} · pool {DEFAULTS.pool.slice(0, 10)}…
        </div>
      </header>
      {mode === "employer" ? <Employer /> : <Auditor />}
    </div>
  );
}
