// Settings: the deployment facts a user might actually want to check — which network,
// which pool, which token — and Disconnect. Nothing here is editable (U-W9): the
// indexer URL is deployment-fixed (App.INDEXER_URL), and the batch size, key version,
// arbiter key and own address were protocol trivia no user acts on. Disconnect is the
// logout: it clears the stored login record (view token only — the spending key is
// never in state or storage; session.ts).

import { useId } from "react";
import type { ReactNode } from "react";
import { DEFAULTS } from "../../config.js";
import { useWallet } from "../App.js";
import { IconExternalLink } from "../components/icons.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { Button } from "../components/controls.js";
import { shortenPubkey } from "../format.js";

const EXPLORER = DEFAULTS.explorer.replace(/\/+$/, "");

// One concrete row shape, three renderings:
//   value only        → plain text (Network)
//   full              → middle-shortened + custom tooltip revealing the full value
//                       (title= is unstylable and keyboard-dead — retired here)
//   full + href       → same, wrapped in an external explorer link with the shared icon
function Row({
  label,
  value,
  full,
  href,
  mono,
}: {
  label: string;
  /** Shown verbatim; ignored when `full` is given. */
  value?: string;
  /** Long value: rendered start8…end4 with a tooltip carrying the full string. */
  full?: string;
  /** External link target (new tab) for the value. */
  href?: string;
  mono?: boolean;
}): ReactNode {
  const tipId = useId();
  const row =
    "flex justify-between gap-3.5 py-[11px] border-b border-border last:border-b-0 text-[0.88rem]";
  const cls = `inline-flex items-center gap-1.5${mono ? " font-mono" : ""}`;
  if (!full) {
    return (
      <div className={row}>
        <span className="text-muted flex-none">{label}</span>
        <span className={cls}>{value}</span>
      </div>
    );
  }
  const short = shortenPubkey(full);
  return (
    <div className={row}>
      <span className="text-muted flex-none">{label}</span>
      <span className="relative inline-flex group">
        {href ? (
          <span className={cls}>
            <a
              className="text-inherit inline-flex items-center gap-1.5 no-underline hover:text-primary"
              href={href}
              target="_blank"
              rel="noreferrer"
              aria-label={`View ${label.toLowerCase()} ${short} on the explorer`}
              aria-describedby={tipId}
            >
              {short}
              <IconExternalLink size={14} />
            </a>
          </span>
        ) : (
          // tabIndex so keyboard users can reveal the tooltip (group-has-[:focus-visible])
          <span className={cls} tabIndex={0} aria-describedby={tipId}>
            {short}
          </span>
        )}
        {/* the value hugs the frame's right edge; a centered 250px tip would be clipped
            by the frame's overflow-hidden — anchor it to the right instead */}
        <span
          className="absolute bottom-[calc(100%+8px)] left-auto right-0 translate-x-0 bg-ink text-white font-mono text-[0.68rem] leading-[1.45] px-[9px] py-1.5 rounded-lg w-max max-w-[250px] [overflow-wrap:anywhere] text-center opacity-0 pointer-events-none transition-opacity z-30 group-hover:opacity-100 group-has-[:focus-visible]:opacity-100"
          role="tooltip"
          id={tipId}
        >
          {full}
        </span>
      </span>
    </div>
  );
}

export function Settings(): ReactNode {
  const { disconnect } = useWallet();

  return (
    <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
      <ScreenHeader title="Settings" />
      <div className="flex flex-col gap-3.5">
        <h2 className="text-xs uppercase tracking-[0.08em] text-muted [font-weight:650]">
          Deployment
        </h2>
        <div className="bg-surface border border-border rounded-xl px-3.5 py-1">
          <Row label="Network" value={`${DEFAULTS.chainName} · chain ${DEFAULTS.chainId}`} />
          <Row label="Pool" full={DEFAULTS.pool} href={`${EXPLORER}/address/${DEFAULTS.pool}`} mono />
          <Row
            label="Token (kKRW)"
            full={DEFAULTS.token}
            href={`${EXPLORER}/address/${DEFAULTS.token}`}
            mono
          />
        </div>

        <Button variant="danger" block onClick={disconnect}>
          Disconnect
        </Button>
        <p className="text-xs text-muted">
          Disconnecting signs you out and clears the saved login on this device. Reconnect
          anytime — your key is re-derived from your wallet signature.
        </p>
      </div>
    </div>
  );
}
