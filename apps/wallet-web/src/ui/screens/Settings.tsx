// Settings: read-only deployment facts (pool, token, chain, arbiter key version) plus
// the ONE editable knob — the indexer URL the balance/history/health reads point at —
// and Disconnect. Editing the indexer URL re-runs the balance load (App effect keys on
// indexerUrl). Disconnect drops the derived key from memory (it was never persisted).

import { useId, useState } from "react";
import type { ReactNode } from "react";
import { DEFAULTS } from "../../config.js";
import { useWallet } from "../App.js";
import { IconExternalLink } from "../components/icons.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { shortenPubkey } from "../format.js";

const EXPLORER = DEFAULTS.explorer.replace(/\/+$/, "");

// One concrete row shape, three renderings:
//   value only        → plain text (Network, Batch size, Key version)
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
  const cls = `settings-val${mono ? " mono" : ""}`;
  if (!full) {
    return (
      <div className="settings-row">
        <span className="settings-key">{label}</span>
        <span className={cls}>{value}</span>
      </div>
    );
  }
  const short = shortenPubkey(full);
  return (
    <div className="settings-row">
      <span className="settings-key">{label}</span>
      <span className="tip-wrap">
        {href ? (
          <span className={cls}>
            <a
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
          // tabIndex so keyboard users can reveal the tooltip (.tip-wrap:has(:focus-visible))
          <span className={cls} tabIndex={0} aria-describedby={tipId}>
            {short}
          </span>
        )}
        <span className="tip mono" role="tooltip" id={tipId}>
          {full}
        </span>
      </span>
    </div>
  );
}

export function Settings(): ReactNode {
  const { identity, indexerUrl, setIndexerUrl, disconnect } = useWallet();
  const [draft, setDraft] = useState(indexerUrl);
  const dirty = draft.trim() !== indexerUrl;

  return (
    <div className="screen">
      <ScreenHeader title="Settings" />
      <div className="settings-body">
        <h2 className="section-title">Indexer</h2>
        <label className="field">
          <span className="field-label">Arbiter indexer URL</span>
          <input
            className="input mono"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
          />
          <span className="field-hint">
            Balance and activity are read from this arbiter-mode indexer.
          </span>
        </label>
        <button
          className="btn btn-primary btn-block"
          disabled={!dirty || !draft.trim()}
          onClick={() => setIndexerUrl(draft.trim())}
        >
          Save indexer URL
        </button>

        <h2 className="section-title">Deployment</h2>
        <div className="settings-card">
          <Row label="Network" value={`GIWA · chain ${DEFAULTS.chainId}`} />
          <Row label="Pool" full={DEFAULTS.pool} href={`${EXPLORER}/address/${DEFAULTS.pool}`} mono />
          <Row label="Token" full={DEFAULTS.token} href={`${EXPLORER}/address/${DEFAULTS.token}`} mono />
          <Row label="Batch size" value={String(DEFAULTS.batchSize)} />
          <Row label="Key version" value={DEFAULTS.keyVersion} />
          <Row label="Arbiter key" full={DEFAULTS.arbiterPubKey[0]} mono />
          {identity && <Row label="Your address" full={identity.compressedPubkey} mono />}
        </div>

        <button className="btn btn-danger btn-block" onClick={disconnect}>
          Disconnect
        </button>
        <p className="settings-fine">
          Disconnecting clears your key from this device. Reconnect anytime — your key is
          re-derived from your wallet signature.
        </p>
      </div>
    </div>
  );
}
