// React entry for the bongtu payroll console. All chain/proving logic stays in the
// PURE lib modules (disburse / csv / ledger / chain / clients); this tree is the
// view wiring around them. See src/ui/App.tsx for the mode shell.

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./ui/App.js";
import "./styles.css";

const appRoot = document.getElementById("app");
if (!appRoot) throw new Error("no #app root in index.html");
createRoot(appRoot).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
