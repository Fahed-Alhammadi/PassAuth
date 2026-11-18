/**
 * Vault manifests (servers with `vault_manifest`; protocol in docs/ARCHITECTURE.md, "Vault manifests"): each vault
 * carries a small sealed record of what it holds, made by the apps with a key from the vault key, so a server can't
 * serve an older copy of an item, hide a new one or a deletion, or bring back a deleted item unnoticed. This file holds
 * the rules the web vault and the desktop app follow, without network or state (`vault.ts` holds those):
 *
 * - `verifyVault`: after every applied /sync answer, each opened vault's complete item set is checked against the row's
 *   manifest and the highest version this device remembers (`ManifestMemory`, kept next to the item edit counters).
 * - `nextEntry` / `startSealed`: every write into a vault that has a manifest carries the next one.
 * - `mayStart`, `baselineSeq`, `dueTrash`: when a first manifest is started, the version of a new baseline ("Use the
 *   server's copy") and which trashed items an app deletes for the server (its sweeper leaves such vaults alone).
 *
 * The web vault never asks for `trash=summary`, so its rows always carry `data`.
 */
import type * as core from "../wasm/passauth_core";
import { hasErrorCode } from "./api";
import type { KeyValueStore } from "./signing";
import type { Role, SyncItemRow, SyncVaultRow } from "./types";

/** Shown on a vault whose items don't match its manifest, or whose manifest went back. */
export const VAULT_WARNING = "Your server's copy of this vault doesn't match its record of changes. Items may be missing, restored or out of date.";
/** Under the warning, for members who can't write. */
export const VAULT_WARNING_READER = "Someone who can edit this vault can review it.";
export const USE_SERVER_COPY = "Use the server's copy";
export const USE_SERVER_COPY_TITLE = "Use the server's copy?";
export const USE_SERVER_COPY_BODY =
  "PassAuth will accept this vault as the server has it now, including anything that is missing, restored or out of date. Do this only if you know why it changed, for example after the server was restored from a backup.";
/** A write refused here because the vault's warning is unresolved. */
export const MANIFEST_HELD = "This vault can't be changed until its warning is resolved.";
/** A write that met other writes three times in a row. */
export const MANIFEST_BUSY = "This vault changed on another device. Try again.";
/** A new baseline for a vault whose manifest is gone, while some member's app is too old to keep one. */
export const MANIFEST_NOT_READY = "This can't be done until every member's apps are up to date.";

/** Sends of one user action at most, when the vault keeps changing under it (409 `manifest_conflict`). */
export const MANIFEST_TRIES = 3;

/** The core's verdicts. "none": no manifest and none seen; the last three leave the vault unresolved. */
export type ManifestStatus = "none" | "ok" | "rollback" | "mismatch" | "incomplete";

export interface ManifestCheck {
  status: ManifestStatus;
  /** What to remember from now on (0: nothing). */
  version: number;
}

/** A vault's entry in a write's `manifests`: the manifest after the write, one version up. */
export interface ManifestEntry {
  vault_id: string;
  seq: number;
  sealed: string;
}

/** An item as a manifest counts it: its id, whether it is in the trash, and its `data` text exactly as stored. */
export interface ManifestRow {
  id: string;
  deleted_at: number | null;
  data?: string;
  data_sha256?: string;
}

/** Whether a vault with this verdict takes no writes (and shows the warning). */
export const unresolved = (s: ManifestStatus | undefined): boolean => s === "rollback" || s === "mismatch" || s === "incomplete";

/** The row's manifest version (0: none; anything but a whole number above 0 counts as none). */
export const manifestSeq = (row: Pick<SyncVaultRow, "manifest_seq"> | undefined): number =>
  typeof row?.manifest_seq === "number" && Number.isSafeInteger(row.manifest_seq) && row.manifest_seq > 0 ? row.manifest_seq : 0;

/** What the core needs of an item row. */
export const manifestRow = (row: Pick<SyncItemRow, "id" | "deleted_at" | "data" | "data_sha256">): ManifestRow => ({
  id: row.id,
  deleted_at: typeof row.deleted_at === "number" ? row.deleted_at : null,
  ...(typeof row.data === "string" ? { data: row.data } : typeof row.data_sha256 === "string" ? { data_sha256: row.data_sha256 } : {}),
});

/** 409 `manifest_conflict` or 400 `manifest_required` (this copy still said "no manifest"): sync, check, compute again. */
export const manifestRaced = (e: unknown): boolean => hasErrorCode(e, "manifest_conflict") || hasErrorCode(e, "manifest_required");

const STATUSES = new Set<string>(["none", "ok", "rollback", "mismatch", "incomplete"]);

/**
 * Whether a vault is checked at all: the server lists `vault_manifest`, or the row carries a manifest, or this device
 * remembers one for the vault. The last two keep a server from switching the check off by no longer listing the
 * feature (the remembered version then reads as a rollback).
 */
export function checkApplies(feature: boolean, row: Pick<SyncVaultRow, "manifest_seq" | "manifest">, remembered: number | undefined): boolean {
  return feature || manifestSeq(row) > 0 || (typeof row.manifest === "string" && row.manifest.length > 0) || remembered !== undefined;
}

/**
 * Check a vault against its manifest: `rows` are all of its item rows (trash included) as held after applying one
 * /sync answer, `remembered` the highest version this device saw. Anything the core refuses (a malformed row, an id
 * listed twice, a version that isn't a number) is a "mismatch".
 */
export function verifyVault(
  key: core.VaultKey,
  row: Pick<SyncVaultRow, "id" | "key_epoch" | "manifest" | "manifest_seq">,
  remembered: number | undefined,
  rows: readonly Pick<SyncItemRow, "id" | "deleted_at" | "data" | "data_sha256">[],
): ManifestCheck {
  const keep = remembered ?? 0;
  const seq = row.manifest_seq ?? 0;
  if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 0) return { status: "mismatch", version: keep };
  try {
    const r = key.manifestVerify(
      row.id,
      typeof row.key_epoch === "number" ? row.key_epoch : 0,
      seq,
      typeof row.manifest === "string" ? row.manifest : null,
      remembered ?? null,
      rows.map(manifestRow),
    ) as { status?: unknown; version?: unknown } | null;
    const status = typeof r?.status === "string" && STATUSES.has(r.status) ? (r.status as ManifestStatus) : "mismatch";
    const version = typeof r?.version === "number" && Number.isSafeInteger(r.version) && r.version >= 0 ? r.version : keep;
    return { status, version: status === "ok" ? Math.max(version, keep) : keep };
  } catch {
    return { status: "mismatch", version: keep };
  }
}

/**
 * The manifest entry for a write into the vault of `row` (its latest verdict "ok"): `removed` are the affected items as
 * they were before the write, `added` as they are after it. Null for a vault without a manifest (nothing is sent).
 */
export function nextEntry(key: core.VaultKey, row: SyncVaultRow, removed: readonly ManifestRow[], added: readonly ManifestRow[]): ManifestEntry | null {
  const seq = manifestSeq(row);
  if (!seq) return null;
  if (typeof row.manifest !== "string" || typeof row.key_epoch !== "number") throw new Error(MANIFEST_HELD);
  const m = key.manifestNext(row.id, row.key_epoch, seq, row.manifest, removed, added) as { seq?: unknown; sealed?: unknown } | null;
  if (typeof m?.seq !== "number" || typeof m.sealed !== "string" || m.seq !== seq + 1) throw new Error(MANIFEST_HELD);
  return { vault_id: row.id, seq: m.seq, sealed: m.sealed };
}

/** A whole manifest of `version` for exactly `rows`, sealed with `key` for `keyEpoch`: a first one, a baseline, a new key's. */
export function startSealed(key: core.VaultKey, vaultId: string, keyEpoch: number, version: number, rows: readonly ManifestRow[]): string {
  return key.manifestStart(vaultId, keyEpoch, version, rows);
}

/** The two query parameters of a write without a body (trash, restore, delete for good). */
export const manifestQuery = (m: ManifestEntry | null): string[] => (m ? [`manifest_seq=${m.seq}`, `manifest=${encodeURIComponent(m.sealed)}`] : []);

/** `path` with query parameters (none: unchanged). */
export const withQuery = (path: string, params: readonly string[]): string => (params.length ? `${path}?${params.join("&")}` : path);

const canWrite = (role: Role | string) => role === "write" || role === "admin" || role === "owner";

/**
 * Whether this app starts the vault's first manifest after a sync: the server lists the feature and says every member's
 * apps keep manifests (`manifest_ok`), the account may write, the vault has none and none was ever seen here, and the
 * vault has its number (`seq`) and key epoch from that answer. The caller adds: the vault's key opened, it passed the
 * signed sharing checks, and every row has its `data`.
 */
export function mayStart(feature: boolean, row: SyncVaultRow, status: ManifestStatus | undefined, remembered: number | undefined): boolean {
  return (
    feature &&
    status === "none" &&
    row.manifest_ok === true &&
    manifestSeq(row) === 0 &&
    remembered === undefined &&
    canWrite(row.role) &&
    typeof row.seq === "number" &&
    typeof row.key_epoch === "number"
  );
}

/** The version of a new baseline: above the server's and above what this device remembers. */
export const baselineSeq = (row: Pick<SyncVaultRow, "manifest_seq">, remembered: number | undefined): number => Math.max(manifestSeq(row), remembered ?? 0) + 1;

/**
 * The trashed items of a vault that are due (the server's sweeper rule, with the server's clock): in the trash for
 * longer than `trashDays`. None when the server keeps the trash forever (0) or didn't say.
 */
export function dueTrash(rows: readonly SyncItemRow[], serverTime: number | undefined, trashDays: number | undefined): SyncItemRow[] {
  if (typeof serverTime !== "number" || typeof trashDays !== "number" || !(trashDays > 0) || !(serverTime > 0)) return [];
  const before = serverTime - trashDays * 86400;
  return rows.filter((r) => typeof r.deleted_at === "number" && r.deleted_at < before);
}

/** Whether this app deletes a vault's due trash after a sync: the vault checked out, has a manifest, and the account may write. */
export const mayPurge = (row: SyncVaultRow, status: ManifestStatus | undefined): boolean => status === "ok" && manifestSeq(row) > 0 && canWrite(row.role);

// ------------------------------------------------------------ device memory

export const MANIFESTS_PREFIX = "pa.vault-manifests.";
export const manifestsKey = (scope: string) => `${MANIFESTS_PREFIX}${scope}`;

/** The remembered versions as stored (an unreadable value reads as nothing remembered). */
export function readManifestVersions(store: KeyValueStore, scope: string): Map<string, number> {
  const out = new Map<string, number>();
  const text = store.get(manifestsKey(scope));
  if (text === null) return out;
  try {
    const v = JSON.parse(text) as unknown;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      for (const [id, seq] of Object.entries(v as Record<string, unknown>)) {
        if (typeof seq === "number" && Number.isSafeInteger(seq) && seq >= 1) out.set(id, seq);
      }
    }
  } catch {
    /* unreadable: start again */
  }
  return out;
}

/**
 * Per server and account, the highest manifest version this device saw for each vault (same store and scope as the
 * item edit counters). Only ever raised; vaults that disappear keep their entry (vault ids are never reused, and a
 * server could hide a vault and show it again). Several tabs merge with the higher number.
 */
export class ManifestMemory {
  readonly scope: string;
  private readonly store: KeyValueStore;
  private seen: Map<string, number>;
  private dirty = false;

  constructor(store: KeyValueStore, scope: string) {
    this.store = store;
    this.scope = scope;
    this.seen = readManifestVersions(store, scope);
  }

  /** The remembered version of a vault (undefined: none). */
  get(vaultId: string): number | undefined {
    return this.seen.get(vaultId);
  }

  /** Remember `version` unless a higher one is remembered already. */
  raise(vaultId: string, version: number) {
    if (!Number.isSafeInteger(version) || version < 1) return;
    if ((this.seen.get(vaultId) ?? 0) >= version) return;
    this.seen.set(vaultId, version);
    this.dirty = true;
  }

  /** What another tab wrote meanwhile (the higher number wins), without writing. */
  refresh() {
    for (const [id, seq] of readManifestVersions(this.store, this.scope)) if (seq > (this.seen.get(id) ?? 0)) this.seen.set(id, seq);
  }

  /** Write back, merged with what another tab wrote meanwhile. */
  flush() {
    if (!this.dirty) return;
    this.refresh();
    this.store.set(manifestsKey(this.scope), JSON.stringify(Object.fromEntries(this.seen)));
    this.dirty = false;
  }
}
