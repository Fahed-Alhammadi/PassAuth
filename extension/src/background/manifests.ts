/**
 * Vault manifests (ARCHITECTURE "Vault manifests"): every vault can carry a small sealed record of its item set (a
 * version, how many items are live and in the trash, and a keyed sum over every item's id, state and ciphertext). The
 * core checks the rows this browser holds against it after every sync (`VaultKey.manifestVerify`), so a server that
 * hides a new item or a deletion, brings a deleted item back or sends an older copy of one is noticed, also for
 * changes this browser never saw. Every item write into such a vault carries the vault's next manifest
 * (`manifestNext`), which the server stores in the same transaction, only if nothing else was written meanwhile.
 *
 * This file holds the pure parts (unit-tested in manifests.test.ts): reading the new `/sync` fields, the rows as the
 * core counts them, what this browser remembers (the highest manifest version seen per vault, kept in the offline
 * copy next to the item edit counters), and the decisions "start a manifest?", "which trashed items are due?".
 * vault.ts applies them where answers are merged and items are written.
 */
import type { Snapshot } from "@web/lib/delta";
import type { SyncItemRow, SyncVaultRow } from "@web/lib/types";

/** `/api/config` feature: the server keeps manifests (and sends `manifest`, `manifest_seq`, `manifest_ok`, `data_sha256`). */
export const MANIFEST_FEATURE = "vault_manifest";

export const MANIFEST_WARNING_TEXT = "Your server's copy of this vault doesn't match its record of changes. Items may be missing, restored or out of date.";
/** Under the warning: the extension has no "Use the server's copy". */
export const MANIFEST_REVIEW_TEXT = "Open the web vault or the desktop app to review this vault.";
/** A write refused here because the vault's warning is unresolved. */
export const MANIFEST_HELD_TEXT = "This vault can't be changed until its warning is resolved.";
/** A write that met other writes into the vault three times. */
export const MANIFEST_BUSY_TEXT = "This vault changed on another device. Try again.";

/** Error codes of the two refusals above (shared/errors.ts style). */
export const MANIFEST_HELD = "manifest_held";
export const MANIFEST_BUSY = "manifest_busy";

/** A write gives up after this many tries in total (the first one included). */
export const MANIFEST_TRIES = 3;

/** Trashed items deleted in one request when the server names no limit (the web vault's import batch size). */
const PURGE_BATCH = 250;

/** The core's verdicts (`manifestVerify`). */
export type ManifestStatus = "none" | "ok" | "rollback" | "mismatch" | "incomplete";

/** Unresolved: the vault stays readable, shows the warning, and nothing is written into it. */
export const unresolved = (s: ManifestStatus | undefined): boolean => s === "rollback" || s === "mismatch";

type Rec = Record<string, unknown>;

const whole = (v: unknown): number | null => (typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : null);

/** A vault row's manifest version (0: the vault has none, also for anything that isn't a version). */
export const manifestSeqOf = (row: SyncVaultRow): number => whole((row as unknown as Rec).manifest_seq) ?? 0;

/** A vault row's sealed manifest, or null. */
export const manifestTextOf = (row: SyncVaultRow): string | null => {
  const m = (row as unknown as Rec).manifest;
  return typeof m === "string" && m ? m : null;
};

/** The server's gate: the vault's first manifest may be started now (only a strict `true` counts). */
export const manifestReady = (row: SyncVaultRow): boolean => (row as unknown as Rec).manifest_ok === true;

/** The key epoch the manifest is bound to (as the vault key was opened with: 0 when the row names none). */
export const epochOf = (row: SyncVaultRow): number => whole(row.key_epoch) ?? 0;

/**
 * An item row as the core counts it: its id, its trash state and its ciphertext, or where the row has none (a trash
 * summary) the server's `data_sha256`.
 */
export interface ManifestItem {
  id: string;
  deleted_at: unknown;
  data?: string;
  data_sha256?: string;
}

/**
 * The field a row carries when this browser kept its own newer copy of the item instead of the older version the
 * server sent (item-revs.ts "kept"): the hash of the data the server sent. The manifest is about the server's rows,
 * so that hash counts, never the kept copy's.
 */
export const SERVED_HASH = "served_sha256";

/** `row` for the core. Unknown shapes go through as they are: the core answers them ("incomplete", or an error). */
export function manifestItem(row: SyncItemRow): ManifestItem {
  const r = row as unknown as Rec;
  const base = { id: row.id, deleted_at: r.deleted_at ?? null };
  const served = r[SERVED_HASH];
  if (typeof served === "string") return { ...base, data_sha256: served };
  if (typeof r.data === "string") return { ...base, data: r.data };
  return typeof r.data_sha256 === "string" ? { ...base, data_sha256: r.data_sha256 } : base;
}

/** Every item row of the snapshot (live and trashed) by vault, as the core counts them. */
export function manifestItems(snap: Pick<Snapshot, "items">): Map<string, ManifestItem[]> {
  const out = new Map<string, ManifestItem[]>();
  for (const row of snap.items.values()) {
    const list = out.get(row.vault_id);
    if (list) list.push(manifestItem(row));
    else out.set(row.vault_id, [manifestItem(row)]);
  }
  return out;
}

/** What this browser remembers per vault: the highest manifest version it has seen checked (or written itself). */
export type ManifestMemory = Map<string, number>;

/** As the offline copy keeps it (sync-rules.ts `StoredSync`). */
export interface StoredManifestMemory {
  manifests?: Record<string, number>;
}

/** The memory an offline copy holds (anything malformed in it is left out). */
export function readManifestMemory(v: { manifests?: unknown } | null | undefined): ManifestMemory {
  const m: ManifestMemory = new Map();
  const stored = v?.manifests;
  if (stored && typeof stored === "object" && !Array.isArray(stored)) {
    for (const [id, version] of Object.entries(stored)) if (typeof version === "number" && Number.isSafeInteger(version) && version >= 1) m.set(id, version);
  }
  return m;
}

/** The memory as the offline copy keeps it. Vaults that are gone stay: ids are never reused, and a server could hide a vault and show it again. */
export function storedManifestMemory(m: ManifestMemory): StoredManifestMemory {
  return m.size ? { manifests: Object.fromEntries(m) } : {};
}

/** Remember `version` for the vault: raised, never lowered. */
export function rememberManifest(m: ManifestMemory, vaultId: string, version: number): void {
  if (!Number.isSafeInteger(version) || version < 1) return;
  if (version > (m.get(vaultId) ?? 0)) m.set(vaultId, version);
}

/** Two memories merged: each vault's higher version. */
export function mergeManifestMemory(a: ManifestMemory, b: ManifestMemory): ManifestMemory {
  const out: ManifestMemory = new Map(a);
  for (const [id, version] of b) rememberManifest(out, id, version);
  return out;
}

/** The part of the core's vault key this file calls. */
export interface ManifestKey {
  manifestVerify(vault_id: string, key_epoch: number, manifest_seq: number, sealed: string | null | undefined, remembered: number | null | undefined, items: unknown): unknown;
}

const STATUSES: readonly string[] = ["none", "ok", "rollback", "mismatch", "incomplete"];

/**
 * The core's verdict on one vault: its row against `items` (every row of the vault in the copy after the answer was
 * applied) and the version remembered. Anything thrown (rows the core can't read, an id listed twice) and any answer
 * that isn't a verdict is a mismatch. `version`: what to remember, for "ok" only.
 */
export function verifyVault(key: ManifestKey, row: SyncVaultRow, remembered: number | undefined, items: ManifestItem[]): { status: ManifestStatus; version: number } {
  try {
    const check = key.manifestVerify(row.id, epochOf(row), manifestSeqOf(row), manifestTextOf(row), remembered ?? null, items) as { status?: unknown; version?: unknown } | null;
    const status = check?.status;
    if (typeof status !== "string" || !STATUSES.includes(status)) return { status: "mismatch", version: 0 };
    return { status: status as ManifestStatus, version: whole(check?.version) ?? 0 };
  } catch {
    return { status: "mismatch", version: 0 };
  }
}

/** A manifest sent with a write: `manifests: [{vault_id, seq, sealed}]` in a body, `manifest_seq` + `manifest` in a query. */
export interface ManifestEntry {
  vault_id: string;
  seq: number;
  sealed: string;
}

/** What `manifestNext` answered, as an entry for `vaultId`; throws when it isn't one. */
export function entryOf(vaultId: string, next: unknown): ManifestEntry {
  const n = next as { seq?: unknown; sealed?: unknown } | null;
  const seq = whole(n?.seq);
  if (seq === null || seq < 1 || typeof n?.sealed !== "string" || !n.sealed) throw new Error("manifest");
  return { vault_id: vaultId, seq, sealed: n.sealed };
}

/** The query string of a request without a body (`revision` first, as before; then the manifest, both parts or neither). */
export function writeQuery(revision: number | undefined, entry: ManifestEntry | null): string {
  const parts: string[] = [];
  if (revision !== undefined) parts.push(`revision=${revision}`);
  if (entry) parts.push(`manifest_seq=${entry.seq}`, `manifest=${encodeURIComponent(entry.sealed)}`);
  return parts.length ? `?${parts.join("&")}` : "";
}

/** `snap` with the vault row's manifest set to the one this browser just had stored (`vaultSeq`: the vault's number after it, kept as an own write). */
export function withManifest(snap: Snapshot, entry: ManifestEntry, vaultSeq?: number): Snapshot {
  const vaults = snap.vaults.map((v) => (v.id === entry.vault_id ? ({ ...v, manifest: entry.sealed, manifest_seq: entry.seq, manifest_ok: true } as SyncVaultRow) : v));
  return { ...snap, vaults, ...(vaultSeq !== undefined ? { own: { ...snap.own, [entry.vault_id]: vaultSeq } } : {}) };
}

/** The server's clock and trash setting of a `/sync` answer (null: an older server, or not numbers). */
export interface Served {
  serverTime: number | null;
  trashDays: number | null;
}

export function readServed(answer: unknown): Served {
  const a = answer as { server_time?: unknown; trash_days?: unknown } | null;
  return { serverTime: whole(a?.server_time), trashDays: whole(a?.trash_days) };
}

/**
 * Whether this browser starts the vault's first manifest now: the server keeps manifests and says every member's apps
 * can (`manifest_ok`), the account may write, the vault has none and none was ever seen here, its verdict is "none",
 * and every row has its data or its hash. (The caller checks that the vault is open and passed signed sharing.)
 */
export function mayStart(o: { features: ReadonlySet<string>; row: SyncVaultRow; role: string; status: ManifestStatus | undefined; remembered: number | undefined; items: ManifestItem[] }): boolean {
  if (!o.features.has(MANIFEST_FEATURE) || o.status !== "none" || o.remembered !== undefined) return false;
  if (manifestSeqOf(o.row) !== 0 || !manifestReady(o.row) || typeof o.row.seq !== "number") return false;
  if (o.role !== "write" && o.role !== "admin" && o.role !== "owner") return false;
  return o.items.every((i) => typeof i.data === "string" || typeof i.data_sha256 === "string");
}

/**
 * The vault's trashed rows the server's trash setting says are due (deleted more than `trash_days` days before the
 * server's own clock in the same answer; a wrong clock here can't empty the trash). None when the setting is 0 (keep
 * forever) or the answer names no clock.
 */
export function dueTrash(rows: Iterable<SyncItemRow>, vaultId: string, served: Served): SyncItemRow[] {
  if (served.serverTime === null || !served.trashDays) return [];
  const before = served.serverTime - served.trashDays * 86400;
  const out: SyncItemRow[] = [];
  for (const r of rows) if (r.vault_id === vaultId && typeof r.deleted_at === "number" && r.deleted_at < before) out.push(r);
  return out;
}

/** How many trashed items one purge request may name: the server's `limits.max_import_items` (`/api/config`), else 250. */
export function purgeBatch(limits: unknown): number {
  const n = whole((limits as { max_import_items?: unknown } | null)?.max_import_items);
  return n && n >= 1 ? n : PURGE_BATCH;
}

/** The popup's notice: the warning with the vaults it is about (`key`: for dismissing; it changes with the set). */
export interface ManifestNotice {
  text: string;
  review: string;
  vaults: { id: string; name: string }[];
  key: string;
}

export function manifestNotice(vaults: { id: string; name: string }[], states: ReadonlyMap<string, ManifestStatus>): ManifestNotice | null {
  const list = vaults.filter((v) => unresolved(states.get(v.id))).map((v) => ({ id: v.id, name: v.name }));
  if (!list.length) return null;
  return { text: MANIFEST_WARNING_TEXT, review: MANIFEST_REVIEW_TEXT, vaults: list, key: JSON.stringify(list.map((v) => v.id).sort()) };
}
