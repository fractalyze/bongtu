// The full activity screen (hash route #/activity): the complete flat newest-first
// feed the Home screen only shows the head of. Data comes from the same wallet context /history
// load — no extra fetch; a dataError renders the same calm retry banner as Home.

import type { ReactNode } from "react";
import { useWallet } from "../App.js";
import { DEFAULTS } from "../../config.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { ActivityList } from "../components/ActivityList.js";
import { Button } from "../components/controls.js";

export function Activity(): ReactNode {
  const { history, loading, dataError, dataNotice, refresh } = useWallet();
  return (
    <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
      <ScreenHeader title="Activity" />
      {dataError ? (
        <div className="rounded-xl px-3.5 py-3 text-[0.88rem] flex gap-2.5 items-center justify-between flex-wrap border border-warn-border bg-warn-bg text-warn">
          {dataError}
          <Button variant="ghost" size="sm" onClick={() => void refresh()}>
            Retry
          </Button>
        </div>
      ) : (
        <>
          {/* Calm strip, not the warn banner: the feed below is real, just frozen. */}
          {dataNotice && <p className="text-muted text-[0.85rem] px-0.5">{dataNotice}</p>}
          <ActivityList
            history={history}
            loading={loading}
            explorerBase={DEFAULTS.explorer}
            heading={null}
          />
        </>
      )}
    </div>
  );
}
