/**
 * When the user last filled or copied each item, per account, so suggestions,
 * the right-click menu and the fill shortcut can put the last used first.
 * Only item ids and times are kept (chrome.storage.local, `lastUsed:<account>`),
 * never names, websites or secrets; at most MAX_ENTRIES per account.
 */

const MAX_ENTRIES = 500;
const key = (accountId: string) => `lastUsed:${accountId}`;

// Writes are serialized so two quick fills don't drop each other's time.
let queue: Promise<unknown> = Promise.resolve();

export function markUsed(accountId: string, itemId: string, at = Date.now()): Promise<void> {
  if (!accountId || !itemId) return Promise.resolve();
  const next = queue.then(async () => {
    const k = key(accountId);
    const stored = ((await chrome.storage.local.get(k))[k] ?? {}) as Record<string, number>;
    stored[itemId] = at;
    const entries = Object.entries(stored);
    const kept = entries.length > MAX_ENTRIES ? Object.fromEntries(entries.sort((a, b) => b[1] - a[1]).slice(0, MAX_ENTRIES)) : stored;
    await chrome.storage.local.set({ [k]: kept });
  });
  queue = next.catch(() => {});
  return next;
}

export async function lastUsedMap(accountId: string): Promise<Record<string, number>> {
  if (!accountId) return {};
  const k = key(accountId);
  return ((await chrome.storage.local.get(k))[k] ?? {}) as Record<string, number>;
}

/** Forget an account's history (sign-out, account removal). */
export async function forgetLastUsed(accountId: string): Promise<void> {
  if (accountId) await chrome.storage.local.remove(key(accountId));
}

/** Most recently used first; items never used keep their current order after them. */
export function byLastUsed<T extends { id: string }>(items: T[], used: Record<string, number>): T[] {
  return items
    .map((item, i) => ({ item, i, t: used[item.id] ?? 0 }))
    .sort((a, b) => b.t - a.t || a.i - b.i)
    .map((x) => x.item);
}
