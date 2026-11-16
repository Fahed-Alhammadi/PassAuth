/**
 * The popup's one search: every word of the query (ANDed) must appear in the item's name, user name, any of its
 * websites, its tags or its folder (or the second line of a card or identity). Results: logins for the current
 * page first, then items whose name or website starts with the query, then the rest in list order. Pure, unit-tested
 * (test/search.test.ts).
 */
import type { ItemSummary } from "../shared/types";

/** The query's words, in lower case. */
export const queryWords = (query: string) => query.toLowerCase().split(/\s+/).filter(Boolean);

const hostOf = (url: string) =>
  url
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, "")
    .replace(/^www\./i, "")
    .toLowerCase();

function fields(i: ItemSummary): string[] {
  const all = [i.name, i.username ?? "", i.subtitle, i.host, i.folder, ...(i.websites ?? []), ...(i.tags ?? [])];
  return all.filter(Boolean).map((s) => s.toLowerCase());
}

/** Whether `i` starts with the query: its name, a word of its name, or one of its websites' hosts. */
function startsWith(i: ItemSummary, query: string, first: string): boolean {
  const name = i.name.toLowerCase();
  if (name.startsWith(query)) return true;
  if (name.split(/[\s._@/-]+/).some((w) => w.startsWith(first))) return true;
  return [i.host, ...(i.websites ?? [])].some((u) => !!u && hostOf(u).startsWith(first));
}

/** Items matching `query`, best first (see above). `current`: ids of the logins for the page the user is on. */
export function searchItems<T extends ItemSummary>(items: readonly T[], query: string, current: ReadonlySet<string> = new Set()): T[] {
  const words = queryWords(query);
  if (!words.length) return [...items];
  const whole = words.join(" ");
  const first = words[0] ?? "";
  const hits: { item: T; rank: number; order: number }[] = [];
  items.forEach((item, order) => {
    const hay = fields(item);
    if (!words.every((w) => hay.some((h) => h.includes(w)))) return;
    const rank = (current.has(item.id) ? 0 : 2) + (startsWith(item, whole, first) ? 0 : 1);
    hits.push({ item, rank, order });
  });
  return hits.sort((a, b) => a.rank - b.rank || a.order - b.order).map((h) => h.item);
}
