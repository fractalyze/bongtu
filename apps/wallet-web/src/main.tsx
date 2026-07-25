// React entry for the bongtu public wallet (SPEC §7 public app). The whole UI is one
// React SPA mounted into #app; all security-critical logic still lives in the PURE,
// unit-tested lib modules (derive / spend / balance / prove-assets) — this tree is the
// browser wiring around them. See src/ui/App.tsx for the screen router + wallet state.

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./ui/App.js";
import "./styles.css";

const root = document.getElementById("app");
if (!root) throw new Error("no #app root in index.html");

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
