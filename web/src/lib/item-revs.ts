/**
 * Item rollback detection: every item carries an edit counter `rev` inside its encryption (the core counts it up on
 * every encrypt), so a server can't change it, but it can serve an older ciphertext of an item. This device remembers,
 * per server and account, the highest `rev` it saw for each item id (local storage, like signed sharing's trust
 * memory: a new device starts empty and trusts what it sees first). A lower `rev` than remembered is a rollback: the
 * item is shown with a warning (keeping a newer copy this page still has), the remembered value is never lowered, and
 * the sync shows a notice. An equal `rev` with other content is accepted (an edit by an app from before the counter).
 * Ids of items no longer served at all (deleted for good, or in no vault this account has) are dropped.
 */
import * as core from "../wasm/passauth_core";
import type { KeyValueStore } from "./signing";
import type { Item } from "./types";

export const REVS_PREFIX = "pa.item-revs.";
export const revsKey = (scope: string) => `${REVS_PREFIX}${scope}`;

/** Shown on an item the server sent older than this device saw. */
export const ROLLBACK_ITEM = "Your server sent an older version of this item.";
/** Sync notice when every rolled-back item had a newer copy here, which is shown instead. */
export const ROLLBACK_KEPT = "Your server sent older versions of some items. PassAuth kept the newer copies it had.";
/** Sync notice when some rolled-back item is shown as the server sent it. */
export const ROLLBACK_SHOWN = "Your server sent older versions of some items.";

export type RevVerdict = "new" | "same" | "newer" | "rollback";

/** The item's edit counter (missing or malformed: 0, an item never counted). */
export function revOf(item: Pick<Item, "rev"> | null | undefined): number {
  const r = item?.rev;
  return typeof r === "number" && Number.isSafeInteger(r) && r >= 0 ? r : 0;
}

/** The core's rule (`itemRevCheck`): "new" (nothing remembered), "same", "newer" or "rollback". */
export function checkRev(remembered: number | undefined, served: number): RevVerdict {
  try {
    const v = core.itemRevCheck(remembered ?? null, served);
    return v === "new" || v === "newer" || v === "rollback" ? v : "same";
  } catch {
    // Not a counter the core takes: nothing is remembered from it.
    return "same";
  }
}

/** The remembered counters as stored (an unreadable value reads as nothing remembered). */
export function readRevs(store: KeyValueStore, scope: string): Map<string, number> {
  const out = new Map<string, number>();
  const text = store.get(revsKey(scope));
  if (text === null) return out;
  try {
    const v = JSON.parse(text) as unknown;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      for (const [id, rev] of Object.entries(v as Record<string, unknown>)) {
        if (typeof rev === "number" && Number.isSafeInteger(rev) && rev >= 0) out.set(id, rev);
      }
    }
  } catch {
    /* unreadable: start again */
  }
  return out;
}

/** One account's memory on this device, loaded once and written back after a sync changed it. */
export class RevMemory {
  readonly scope: string;
  private readonly store: KeyValueStore;
  private revs: Map<string, number>;
  private dropped = new Set<string>();
  private dirty = false;

  constructor(store: KeyValueStore, scope: string) {
    this.store = store;
    this.scope = scope;
    this.revs = readRevs(store, scope);
  }

  /** The remembered counter of `id` (undefined: none). */
  get(id: string): number | undefined {
    return this.revs.get(id);
  }

  /** Check a served item's counter; "new" and "newer" are remembered, a rollback never lowers what is remembered. */
  check(id: string, served: number): RevVerdict {
    const verdict = checkRev(this.revs.get(id), served);
    if (verdict === "new" || verdict === "newer") {
      this.revs.set(id, served);
      this.dropped.delete(id);
      this.dirty = true;
    }
    return verdict;
  }

  /** Forget every id not in `live` (the ids the server still serves in any form, trash included). */
  prune(live: ReadonlySet<string>) {
    for (const id of [...this.revs.keys()]) {
      if (live.has(id)) continue;
      this.revs.delete(id);
      this.dropped.add(id);
      this.dirty = true;
    }
  }

  /** Write back, merged with what another tab wrote meanwhile (the higher counter wins; ids dropped here stay dropped). */
  flush() {
    if (!this.dirty) return;
    const stored = readRevs(this.store, this.scope);
    for (const [id, rev] of stored) {
      if (this.dropped.has(id)) continue;
      const mine = this.revs.get(id);
      if (mine === undefined || rev > mine) this.revs.set(id, rev);
    }
    this.store.set(revsKey(this.scope), JSON.stringify(Object.fromEntries(this.revs)));
    this.dropped.clear();
    this.dirty = false;
  }
}
