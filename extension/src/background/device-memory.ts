/**
 * What this browser remembers per account to notice that a server went back in time, as one stored record
 * (storage.ts `deviceMemory`, its own IndexedDB key per server and account):
 * - the item edit counters and marks (item-revs.ts);
 * - per vault the version and link of the last manifest checked "ok", written or accepted here, and how often one was
 *   accepted with "Use the server's copy" (manifests.ts `MemoryEntry`);
 * - when each trashed item was first seen in the trash by this browser's clock (manifests.ts `TrashSeen`).
 * It is kept when the account's offline copy goes (a sign-out, a vault timeout with the "log out" action): else
 * every sign-in would be a first sight, and no rollback would ever be noticed across sessions. It goes only when the
 * account is removed from the browser. The pure parts, unit-tested in device-memory.test.ts.
 */
import { type RevMemory, readRevMemory, type StoredRevMemory, storedRevMemory } from "./item-revs";
import { type ManifestMemory, type MemoryEntry, mergeManifestMemory, readManifestMemory, readTrashSeen, storedManifestMemory, type TrashSeen } from "./manifests";

export const DEVICE_MEMORY_VERSION = 1;

export interface StoredDeviceMemory extends StoredRevMemory {
  v: typeof DEVICE_MEMORY_VERSION;
  manifests?: Record<string, MemoryEntry>;
  trashSeen?: Record<string, number>;
}

export interface DeviceMemory {
  revs: RevMemory;
  manifests: ManifestMemory;
  trashSeen: TrashSeen;
}

/**
 * The stored record read: "missing" when there is none (nothing remembered: a new browser for this account), the
 * memory when it is one, and "unreadable" for anything else (not a record of this version). Unreadable is never
 * "nothing remembered": the caller checks nothing against it and writes nothing over it.
 */
export function readDeviceMemory(stored: unknown): DeviceMemory | "missing" | "unreadable" {
  if (stored === undefined || stored === null) return "missing";
  const s = stored as Partial<StoredDeviceMemory>;
  if (typeof stored !== "object" || Array.isArray(stored) || s.v !== DEVICE_MEMORY_VERSION) return "unreadable";
  return { revs: readRevMemory(s), manifests: readManifestMemory(s.manifests), trashSeen: readTrashSeen(s.trashSeen) };
}

/**
 * The record to store for `mine`, given what is `stored` now (read in the same queued step): the manifest memory is
 * merged with the stored one (per vault the entry with more acceptances, then the higher version; a link is never
 * replaced at its version), so nothing stored is lowered except by an acceptance. The counters, marks and trash times
 * are this worker's own. A stored record that can't be read is returned as it is (never overwritten; the way out is
 * the reset in vault.ts `resetDeviceMemory`, which moves it aside).
 */
export function mergedDeviceMemory(stored: unknown, mine: DeviceMemory): unknown {
  const old = readDeviceMemory(stored);
  if (old === "unreadable") return stored;
  const manifests = old === "missing" ? mine.manifests : mergeManifestMemory(old.manifests, mine.manifests);
  const record: StoredDeviceMemory = {
    v: DEVICE_MEMORY_VERSION,
    ...storedRevMemory(mine.revs),
    ...(manifests.size ? { manifests: storedManifestMemory(manifests) } : {}),
    ...(mine.trashSeen.size ? { trashSeen: Object.fromEntries(mine.trashSeen) } : {}),
  };
  return record;
}
