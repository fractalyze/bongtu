// The one-glance "what this wallet does" diagram: kKRW —Deposit→ private kKRW
// —→ send/withdraw. The icons carry the meaning so the screens that render it
// need no explainer paragraph.

import type { ReactNode } from "react";
import { EnvelopeLogo, IconArrowRight, IconCoin, IconSend } from "./icons.js";

export function ConceptFlow(): ReactNode {
  return (
    <div className="flowchart" role="img" aria-label="Deposit kKRW to get private kKRW, then send and withdraw freely">
      <div className="flowchart-node">
        <span className="flowchart-icon">
          <IconCoin size={22} />
        </span>
        <span className="flowchart-label">kKRW</span>
      </div>
      <div className="flowchart-arrow">
        <span className="flowchart-arrow-tag">Deposit</span>
        <IconArrowRight size={18} />
      </div>
      <div className="flowchart-node flowchart-node-primary">
        <span className="flowchart-icon">
          <EnvelopeLogo size={22} />
        </span>
        <span className="flowchart-label">Private kKRW</span>
      </div>
      <div className="flowchart-arrow">
        <IconArrowRight size={18} />
      </div>
      <div className="flowchart-node">
        <span className="flowchart-icon">
          <IconSend size={22} />
        </span>
        <span className="flowchart-label">Send freely</span>
      </div>
    </div>
  );
}
