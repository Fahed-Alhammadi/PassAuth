/**
 * Item rollback detection (ARCHITECTURE "Item edit counter"): every item carries an edit counter `rev` inside its
 * ciphertext, which the core raises on every write. This browser remembers, per account in its device memory
 * (device-memory.ts: kept when the offline copy goes at a sign-out or a "log out" timeout), the highest `rev` it has
 * seen for each item. A server that sends an item with a lower `rev` than that sends an older
 * version (an old password, say): the item is marked and shown with a warning, and when this browser still has the
 * newer copy, that copy is kept. The pure parts, unit-tested in item-revs.test.ts; vault.ts applies them where items
 * are decrypted.
 */

/** Marked items: "kept" = the newer copy this browser had is shown; "older" = none was here, the server's is shown. */
export type RolledBack = "kept" | "older";

export interface RevMemory {
  /** Item id → highest `rev` seen. */
  revs: Map<string, number>;
  /** Items the server sent in an older version than seen before. */
  rolledBack: Map<string, RolledBack>;
}

/** As it is stored (device-memory.ts; offline copies written before that kept it themselves). */
export interface StoredRevMemory {
  itemRevs?: Record<string, number>;
  rolledBack?: Record<string, RolledBack>;
}

export const ROLLBACK_ITEM_TEXT = "Your server sent an older version of this item.";
export const ROLLBACK_KEPT_TEXT = "Your server sent older versions of some items. PassAuth kept the newer copies it had.";
export const ROLLBACK_TEXT = "Your server sent older versions of some items.";

export const emptyRevMemory = (): RevMemory => ({ revs: new Map(), rolledBack: new Map() });

const count = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

/** An item's `rev` (0 when it has none: written before the counter existed, or not a number). */
export const itemRevOf = (item: unknown): number => {
  const r = (item as { rev?: unknown } | null)?.rev;
  return count(r) ? r : 0;
};

/** The memory as stored (anything malformed in it is left out). */
export function readRevMemory(v: { itemRevs?: unknown; rolledBack?: unknown } | null | undefined): RevMemory {
  const m = emptyRevMemory();
  const revs = v?.itemRevs;
  if (revs && typeof revs === "object" && !Array.isArray(revs)) for (const [id, r] of Object.entries(revs)) if (count(r)) m.revs.set(id, r);
  const marked = v?.rolledBack;
  if (marked && typeof marked === "object" && !Array.isArray(marked)) for (const [id, how] of Object.entries(marked)) if (how === "kept" || how === "older") m.rolledBack.set(id, how);
  return m;
}

/** The memory as it is stored. */
export function storedRevMemory(m: RevMemory): StoredRevMemory {
  return {
    ...(m.revs.size ? { itemRevs: Object.fromEntries(m.revs) } : {}),
    ...(m.rolledBack.size ? { rolledBack: Object.fromEntries(m.rolledBack) } : {}),
  };
}

/**
 * Apply the core's verdict (`itemRevCheck(remembered, served)`) for an item the server sent with `served` as its rev.
 * `changed`: the row differs from the one this browser showed before (false when the offline copy is read at unlock).
 * `newerCopy`: the rev of the copy this browser has (null when it has none it can open). Returns "keep" when that
 * copy must be shown (and kept) instead of the server's, else "show".
 * - new / newer: remembered, and a mark cleared (the server sends a newer version now);
 * - same: accepted (equal rev with other content = an edit by an app from before the counter); a changed row clears a
 *   mark (the server sends the remembered version again);
 * - rollback (and anything else): never remembered lower; marked; the newer copy kept when there is one.
 */
export function noteServed(m: RevMemory, id: string, served: number, verdict: string, changed: boolean, newerCopy: () => number | null): "show" | "keep" {
  if (verdict === "new" || verdict === "newer") {
    // Deleted first: the map's order is "least recently seen first" (`capRevMemory`).
    m.revs.delete(id);
    m.revs.set(id, served);
    m.rolledBack.delete(id);
    return "show";
  }
  if (verdict === "same") {
    const known = m.revs.get(id);
    if (known !== undefined) {
      m.revs.delete(id);
      m.revs.set(id, known);
    }
    if (changed) m.rolledBack.delete(id);
    return "show";
  }
  const mine = newerCopy();
  if (mine !== null && mine > served) {
    m.rolledBack.set(id, "kept");
    return "keep";
  }
  // Marked "kept" before and read again from the offline copy (unchanged): still the kept copy.
  if (!changed && m.rolledBack.get(id) === "kept") return "show";
  m.rolledBack.set(id, "older");
  return "show";
}

/** How many item edit counters are remembered at most. */
export const REV_MEMORY_CAP = 20_000;

/**
 * Forget an item: only when its absence is proven. Either this browser deleted it for good itself, or it is absent
 * from a vault whose manifest checked "ok" for that very answer. An item a server merely leaves out of an answer
 * keeps its counter: else the server could hide it once and then send an older version unnoticed.
 */
export function forgetRev(m: RevMemory, id: string): void {
  m.revs.delete(id);
  m.rolledBack.delete(id);
}

/**
 * Keep at most `cap` counters: the least recently seen go first, items this browser doesn't hold any more before
 * ones it holds (`present`). Marks of forgotten items go with them.
 */
export function capRevMemory(m: RevMemory, present: { has(id: string): boolean }, cap = REV_MEMORY_CAP): void {
  let over = m.revs.size - cap;
  if (over <= 0) return;
  for (const pass of [false, true]) {
    for (const id of [...m.revs.keys()]) {
      if (over <= 0) return;
      if (!pass && present.has(id)) continue;
      forgetRev(m, id);
      over--;
    }
  }
}

/** The vault-wide notice (with a key that changes with the set, for dismissing), or null when nothing is marked. */
export function rollbackNotice(m: RevMemory, shown: { has(id: string): boolean }): { text: string; key: string } | null {
  const ids = [...m.rolledBack.entries()].filter(([id]) => shown.has(id)).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  if (!ids.length) return null;
  const kept = ids.some(([, how]) => how === "kept");
  return { text: kept ? ROLLBACK_KEPT_TEXT : ROLLBACK_TEXT, key: JSON.stringify(ids) };
}
