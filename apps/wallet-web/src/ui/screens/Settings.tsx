// Settings: read-only deployment facts (pool, token, chain, arbiter key version) plus
// the ONE editable knob — the indexer URL the balance/history/health reads point at —
// and Disconnect. Editing the indexer URL re-runs the balance load (App effect keys on
// indexerUrl). Disconnect drops the derived key from memory (it was never persisted).

import { useState } from "react";
import type { ReactNode } from "react";
import { DEFAULTS } from "../../config.js";
import { useWallet } from "../App.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { shortenPubkey } from "../format.js";

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }): ReactNode {
  return (
    <div className="settings-row">
      <span className="settings-key">{label}</span>
      <span className={`settings-val${mono ? " mono" : ""}`} title={value}>
        {value}
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
          <Row label="Pool" value={DEFAULTS.pool} mono />
          <Row label="Token" value={DEFAULTS.token} mono />
          <Row label="Batch size" value={String(DEFAULTS.batchSize)} />
          <Row label="Key version" value={DEFAULTS.keyVersion} />
          <Row label="Arbiter key" value={shortenPubkey(DEFAULTS.arbiterPubKey[0])} mono />
          {identity && <Row label="Your address" value={identity.compressedPubkey} mono />}
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
