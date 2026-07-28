// The full activity screen (hash route #/activity): the flat newest-first feed the
// Home screen only shows the head of. Data comes from the same wallet context
// /history load — no extra fetch for what is already loaded; a dataError renders
// the same calm retry banner as Home.
//
// The feed arrives ONE PAGE at a time, so this screen owns the only control that
// asks for more of it. A failed page is reported under the button and leaves the
// rows already on screen alone — the opposite of dataError, which means the whole
// read failed and there is nothing trustworthy to show.

import { useState, type ReactNode } from "react";
import { useWallet } from "../App.js";
import { DEFAULTS } from "../../config.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { ActivityList } from "../components/ActivityList.js";
import { Button } from "../components/controls.js";

export function Activity(): ReactNode {
  const { history, historyNextBefore, historyLoadingMore, loadMoreHistory, loading, dataError, dataNotice, refresh } =
    useWallet();
  const [moreError, setMoreError] = useState<string | null>(null);
  const onLoadMore = (): void => {
    setMoreError(null);
    void loadMoreHistory().catch(() => setMoreError("Couldn't load more activity. Try again."));
  };
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
          {historyNextBefore !== null && (
            <div className="flex flex-col gap-1.5 items-center">
              <Button onClick={onLoadMore} disabled={historyLoadingMore}>
                {historyLoadingMore ? "Loading…" : "Load more"}
              </Button>
              {moreError && <p className="text-err text-[0.82rem]">{moreError}</p>}
            </div>
          )}
        </>
      )}
    </div>
  );
}
