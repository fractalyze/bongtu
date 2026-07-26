// The full activity screen (hash route #/activity): the complete day-grouped feed the
// Home screen only shows the head of. Data comes from the same wallet context /history
// load — no extra fetch; a dataError renders the same calm retry banner as Home.

import type { ReactNode } from "react";
import { useWallet } from "../App.js";
import { DEFAULTS } from "../../config.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { ActivityList } from "../components/ActivityList.js";

export function Activity(): ReactNode {
  const { history, loading, dataError, refresh } = useWallet();
  return (
    <div className="screen">
      <ScreenHeader title="Activity" />
      {dataError ? (
        <div className="banner banner-warn">
          {dataError}
          <button className="btn btn-ghost btn-sm" onClick={() => void refresh()}>
            Retry
          </button>
        </div>
      ) : (
        <ActivityList
          history={history}
          loading={loading}
          explorerBase={DEFAULTS.explorer}
          heading={null}
        />
      )}
    </div>
  );
}
