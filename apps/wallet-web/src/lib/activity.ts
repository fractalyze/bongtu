// PURE day-grouping for the activity feed (framework-free, unit-tested headlessly).
// The React card list renders whatever this returns; day boundaries are LOCAL time
// because "Today / Yesterday" is a human calendar concept, not a UTC one.

import type { HistoryItem } from "./indexerClient.js";

export interface DayGroup {
  /** "Today" | "Yesterday" | a locale date for older days. */
  label: string;
  /** Local-midnight epoch ms of the bucket — a stable React key and a test anchor. */
  dayStart: number;
  items: HistoryItem[];
}

function localMidnight(ms: number): number {
  const d = new Date(ms);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

/**
 * Bucket history items under local-day headers, newest day first and newest item
 * first within a day. `now` is injectable so the Today/Yesterday labels are
 * deterministic under test. An empty feed returns [].
 */
export function groupByDay(items: HistoryItem[], now: number = Date.now()): DayGroup[] {
  const sorted = [...items].sort(
    (a, b) => b.blockTimestamp - a.blockTimestamp || b.seq - a.seq,
  );
  const today = localMidnight(now);
  // setDate(-1) not (today - 86_400_000): a fixed-ms day breaks across DST shifts.
  const y = new Date(today);
  y.setDate(y.getDate() - 1);
  const yesterday = y.getTime();

  const groups: DayGroup[] = [];
  for (const it of sorted) {
    const dayStart = localMidnight(it.blockTimestamp * 1000);
    const last = groups[groups.length - 1];
    if (last && last.dayStart === dayStart) {
      last.items.push(it);
    } else {
      const label =
        // >= not ===: a block timestamp seconds ahead of local now (chain/clock
        // skew near midnight) must read "Today", not tomorrow's locale date.
        dayStart >= today
          ? "Today"
          : dayStart === yesterday
            ? "Yesterday"
            : new Date(dayStart).toLocaleDateString(undefined, {
                year: "numeric",
                month: "long",
                day: "numeric",
              });
      groups.push({ label, dayStart, items: [it] });
    }
  }
  return groups;
}
