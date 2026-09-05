// The full activity screen (hash route #/activity): the flat newest-first feed the
// Home screen only shows the head of. Data comes from the same self-scan snapshot —
// no extra fetch, and deliberately NO pager: the scan derives the whole history it
// can ever know in one pass (selfScanSnapshot's historyNextBefore is null as the
// truth, not a shortcut), so a load-more control could only ever lie.

import type { ReactNode } from "react";
import { useWallet } from "../App.js";
import { DEFAULTS } from "../../config.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { ActivityList } from "../components/ActivityList.js";
import { Banner } from "@bongtu/ui/Banner";

export function Activity(): ReactNode {
  const { history, loading, dataError, dataNotice, refresh } = useWallet();
  return (
    <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
      <ScreenHeader title="Activity" />
      {/* The same state banner as Home (class 4): the scan failed, but the feed
          already on screen stays below it — stale beats blank. */}
      {dataError && <Banner message={dataError} onRetry={() => void refresh(true)} />}
      {/* Calm strip, not the warn banner: the feed below is real, just frozen. */}
      {!dataError && dataNotice && <p className="text-muted text-[0.85rem] px-0.5">{dataNotice}</p>}
      <ActivityList
        history={history}
        loading={loading}
        explorerBase={DEFAULTS.explorer}
        heading={null}
      />
    </div>
  );
}
