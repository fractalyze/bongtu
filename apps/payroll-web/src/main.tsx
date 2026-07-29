// React entry for the bongtu payroll tool. All chain/proving logic stays in
// the PURE lib modules (worksheet / disburse / randomRecipients / payRun /
// clients) and the shared @bongtu/client engine; this tree is the view wiring
// around them.

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { isMobileDevice } from "@bongtu/client/device";
import { App } from "./ui/App.js";
import "./styles.css";

/** The desktop-only door — a MetaMask-driven 255-row console breaks halfway
 *  on a phone (no injected provider in the system browser), so refuse at the
 *  root; device.ts owns the verdict. */
function DesktopOnly() {
  return (
    <div className="min-h-full flex items-center justify-center p-6">
      <div className="w-full max-w-[420px] bg-surface border border-border rounded-2xl p-8 flex flex-col gap-3 text-center">
        <div className="text-lg font-bold">
          <span className="text-primary">Bongtu</span> Payroll Tool
        </div>
        <div className="text-[14px] font-semibold">This tool is desktop-only.</div>
        <div className="text-[12.5px] text-muted">
          Please open this page on a PC to run a payroll.
        </div>
      </div>
    </div>
  );
}

const appRoot = document.getElementById("app");
if (!appRoot) throw new Error("no #app root in index.html");
createRoot(appRoot).render(
  <StrictMode>
    {isMobileDevice(navigator.userAgent, navigator.maxTouchPoints) ? <DesktopOnly /> : <App />}
  </StrictMode>,
);
