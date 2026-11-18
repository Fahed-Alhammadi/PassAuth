/**
 * Vault manifests (servers with `vault_manifest`; protocol in docs/ARCHITECTURE.md, "Vault manifests"): each vault
 * carries a small sealed record of what it holds, made by the apps with a key from the vault key, so a server can't
 * serve an older copy of an item, hide a new one or a deletion, or bring back a deleted item unnoticed. This file holds
 * the rules the web vault and the desktop app follow, without network or state (`vault.ts` holds those):
 *
 * - `verifyVault`: before a /sync answer is taken over, each opened vault's complete item set is checked against the
 *   row's manifest and the manifest this device remembers (`ManifestMemory`, kept next to the item edit counters).
 * - `nextEntry` / `startEntry`: every write into a vault that has a manifest carries the next one, which names the one
 *   it replaces (`prev`); the device remembers the version and link of the last manifest it checked or wrote, so a
 *   server can't move it onto another history at the same or a later version (the vault's manifest log bridges jumps).
 * - `mayStart`, `baselineSeq`, `dueTrash`: when a first manifest is started, the version of a new baseline ("Use the
 *   server's copy") and which trashed items an app deletes for the server (its sweeper leaves such vaults alone).
 *
 * The web vault never asks for `trash=summary`, so its rows always carry `data`.
 */
import type * as core from "../wasm/passauth_core";
import { manifestLink as coreLink } from "../wasm/passauth_core";
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
/** A write into a vault whose check couldn't be finished (its record couldn't be fetched, or this device's memory can't be read). */
export const MANIFEST_UNCHECKED = "PassAuth couldn't check this vault with your server yet. Try again in a moment.";
/** "Use the server's copy" for a vault that holds an item its key can't open: a new record wouldn't change that. */
export const MANIFEST_HIDDEN = "This vault holds an item that its key can't open, so the server's copy can't be accepted. Restore the server from a backup.";
/** A write that met other writes three times in a row. */
export const MANIFEST_BUSY = "This vault changed on another device. Try again.";
/** A new baseline for a vault whose manifest is gone, while some member's app is too old to keep one. */
export const MANIFEST_NOT_READY = "This can't be done until every member's apps are up to date.";

/** Sends of one user action at most, when the vault keeps changing under it (409 `manifest_conflict`). */
export const MANIFEST_TRIES = 3;

/** The core's verdicts. "none": no manifest and none seen; the last three leave the vault unresolved. */
export type ManifestStatus = "none" | "ok" | "rollback" | "mismatch" | "incomplete";

/** What this device remembers of a vault: the version and link of the last manifest it checked "ok" or wrote itself. */
export interface Remembered {
  version: number;
  link: string;
}

export interface ManifestCheck {
  /**
   * "need_log": everything else checks out, but the manifest is more than one step ahead of the remembered one. Not a
   * verdict to show or store: the vault's manifest log is fetched and the check repeated with it (`verifyVault`'s `log`).
   */
  status: ManifestStatus | "need_log";
  /** What to remember from now on (0 / null: nothing): the row's version and link for "ok", else the remembered pair. */
  version: number;
  link: string | null;
}

/**
 * A vault's manifest after a write, one version up (or a whole new one): `seq`, `prev` and `sealed` go into the
 * request (`manifestsOf` / `manifestQuery`), `link` is what this device remembers once the server stored it.
 */
export interface ManifestEntry {
  vault_id: string;
  seq: number;
  /** The link of the manifest this one replaces (32 zero bytes for a vault's first). */
  prev: string;
  sealed: string;
  link: string;
}

/** An entry as a request carries it (the link stays on the device). */
export const wireEntry = (m: ManifestEntry) => ({ vault_id: m.vault_id, seq: m.seq, prev: m.prev, sealed: m.sealed });

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

/**
 * What the core needs of an item row, built from the row's own three fields and nothing else a server could add to it.
 * The web vault always asks for whole rows, so a row without its `data` is never counted by a hash the server sent
 * next to it (`data_sha256`): the core then says "incomplete", and after one full fetch the vault keeps its warning
 * (review 4: a live item can't be hidden behind a correct hash). `deleted_at` goes as it came: the core refuses
 * anything that is no time (0, a fraction), which makes the vault a "mismatch".
 */
export const manifestRow = (row: Pick<SyncItemRow, "id" | "deleted_at" | "data">): ManifestRow => ({
  id: row.id,
  deleted_at: row.deleted_at ?? null,
  ...(typeof row.data === "string" ? { data: row.data } : {}),
});

/** 409 `manifest_conflict` or 400 `manifest_required` (this copy still said "no manifest"): sync, check, compute again. */
export const manifestRaced = (e: unknown): boolean => hasErrorCode(e, "manifest_conflict") || hasErrorCode(e, "manifest_required");

const STATUSES = new Set<string>(["none", "ok", "rollback", "mismatch", "incomplete", "need_log"]);

/** A manifest link as it travels: base64url of 32 bytes. */
export const isLink = (v: unknown): v is string => typeof v === "string" && /^[A-Za-z0-9_-]{43}$/.test(v);

/** A whole number a version can be. */
const isVersion = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 1;

/** A remembered pair as stored; anything else (the first format's bare number, half a pair) is nothing remembered. */
export const asRemembered = (v: unknown): Remembered | undefined => {
  const r = v as { version?: unknown; link?: unknown } | null;
  return r && typeof r === "object" && isVersion(r.version) && isLink(r.link) ? { version: r.version, link: r.link } : undefined;
};

/**
 * Whether a vault is checked at all: the server lists `vault_manifest`, or the row carries a manifest, or this device
 * remembers one for the vault. The last two keep a server from switching the check off by no longer listing the
 * feature (the remembered version then reads as a rollback).
 */
export function checkApplies(feature: boolean, row: Pick<SyncVaultRow, "manifest_seq" | "manifest">, remembered: Remembered | undefined): boolean {
  return feature || manifestSeq(row) > 0 || (typeof row.manifest === "string" && row.manifest.length > 0) || remembered !== undefined;
}

/**
 * Check a vault against its manifest: `rows` are all of its item rows (trash included) as held after applying one
 * /sync answer, `remembered` the last manifest this device saw (version and link: the row must be it, or lead back to
 * it through `prev` links), `log` the vault's manifest log after a "need_log" (null: not fetched). Anything the core
 * refuses (a malformed row, an id listed twice, a version or a trash time that isn't one) is a "mismatch"; so is a
 * second "need_log" once a log was given.
 */
export function verifyVault(
  key: core.VaultKey,
  row: Pick<SyncVaultRow, "id" | "key_epoch" | "manifest" | "manifest_seq" | "manifest_prev">,
  remembered: Remembered | undefined,
  rows: readonly Pick<SyncItemRow, "id" | "deleted_at" | "data">[],
  log: readonly unknown[] | null = null,
): ManifestCheck {
  const keep = { version: remembered?.version ?? 0, link: remembered?.link ?? null };
  const seq = row.manifest_seq ?? 0;
  if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 0) return { status: "mismatch", ...keep };
  try {
    const r = key.manifestVerify(
      row.id,
      typeof row.key_epoch === "number" ? row.key_epoch : 0,
      seq,
      typeof row.manifest_prev === "string" ? row.manifest_prev : null,
      typeof row.manifest === "string" ? row.manifest : null,
      remembered?.version ?? null,
      remembered?.link ?? null,
      log ? [...log] : null,
      rows.map(manifestRow),
    ) as { status?: unknown; version?: unknown; link?: unknown } | null;
    let status = typeof r?.status === "string" && STATUSES.has(r.status) ? (r.status as ManifestCheck["status"]) : "mismatch";
    if (status === "need_log" && log) status = "mismatch";
    if (status !== "ok") return { status, ...keep };
    // "ok" names what to remember: the row's own version and link, never below what is remembered.
    if (!isVersion(r?.version) || !isLink(r.link) || r.version !== seq || r.version < keep.version) return { status: "mismatch", ...keep };
    return { status, version: r.version, link: r.link };
  } catch {
    return { status: "mismatch", ...keep };
  }
}

const readEntry = (vaultId: string, m: unknown, seq: number): ManifestEntry => {
  const e = m as { seq?: unknown; prev?: unknown; sealed?: unknown; link?: unknown } | null;
  if (e?.seq !== seq || !isLink(e.prev) || typeof e.sealed !== "string" || !e.sealed || !isLink(e.link)) throw new Error(MANIFEST_HELD);
  return { vault_id: vaultId, seq, prev: e.prev, sealed: e.sealed, link: e.link };
};

/**
 * The manifest entry for a write into the vault of `row` (its latest verdict "ok"): `removed` are the affected items as
 * they were before the write, `added` as they are after it. It names the row's manifest as the one it replaces. Null
 * for a vault without a manifest (nothing is sent).
 */
export function nextEntry(key: core.VaultKey, row: SyncVaultRow, removed: readonly ManifestRow[], added: readonly ManifestRow[]): ManifestEntry | null {
  const seq = manifestSeq(row);
  if (!seq) return null;
  if (typeof row.manifest !== "string" || !isLink(row.manifest_prev) || typeof row.key_epoch !== "number" || seq >= Number.MAX_SAFE_INTEGER) throw new Error(MANIFEST_HELD);
  return readEntry(row.id, key.manifestNext(row.id, row.key_epoch, seq, row.manifest_prev, row.manifest, removed, added), seq + 1);
}

/**
 * The link of the row's manifest, from its three fields (nothing is opened, so it needn't be one this device can
 * read): what a new baseline or a key replacement's manifest names as the one it replaces. Null for a vault without a
 * manifest; throws when the row's fields aren't a manifest's.
 */
export function rowLink(row: Pick<SyncVaultRow, "manifest" | "manifest_seq" | "manifest_prev">): string | null {
  const seq = manifestSeq(row);
  if (!seq) return null;
  if (typeof row.manifest !== "string" || !isLink(row.manifest_prev)) throw new Error("This vault's record of changes can't be read.");
  return coreLink(seq, row.manifest_prev, row.manifest);
}

/**
 * A whole manifest of `version` for exactly `rows`, sealed with `key` for `keyEpoch`, replacing the manifest whose link
 * is `prev` (null: a vault's first): a first one, a baseline, a new key's.
 */
export function startEntry(key: core.VaultKey, vaultId: string, keyEpoch: number, version: number, prev: string | null, rows: readonly ManifestRow[]): ManifestEntry {
  return readEntry(vaultId, key.manifestStart(vaultId, keyEpoch, version, prev, rows), version);
}

/** What a read-only view of someone else's vault (emergency access) found. */
export interface ViewCheck<T> {
  /** The vault doesn't match its manifest, or holds a row that can't be read or opened: `VAULT_WARNING` is shown. */
  warning: boolean;
  /** The vault has no manifest: nothing could be checked (`VIEW_UNCHECKED` is shown). */
  unchecked: boolean;
  /** The rows that opened, with what `open` made of them. */
  opened: { row: T; value: unknown }[];
  /** Rows that didn't open. */
  failed: number;
}

/** Shown in a read-only view for a vault that has no manifest to check it against. */
export const VIEW_UNCHECKED = "This vault has no record of changes yet, so PassAuth couldn't check that nothing is missing or out of date.";

/**
 * Check a vault shown read-only from one answer (the emergency access view): no device memory, no log, nothing
 * written, so first-sight trust only. The rows the core gets are built from parsed fields alone (id, trash time,
 * data), never the server's objects. A vault with a manifest gets the warning when the manifest doesn't check out,
 * when the answer held rows this app couldn't read (`malformed`), or when a row doesn't open with the vault's key
 * (review 4 / R5: an item can't be hidden behind a manifest that checks out).
 */
export function checkView<T extends { id: string; deletedAt: number | null; data: string }>(
  key: core.VaultKey,
  vault: { id: string; keyEpoch: number | null; manifest: string | null; manifestSeq: number; manifestPrev: string | null },
  rows: readonly T[],
  malformed: number,
  open: (row: T) => unknown,
): ViewCheck<T> {
  const opened: ViewCheck<T>["opened"] = [];
  let failed = 0;
  for (const row of rows) {
    try {
      opened.push({ row, value: open(row) });
    } catch {
      failed++;
    }
  }
  if (vault.manifestSeq === 0) return { warning: false, unchecked: true, opened, failed };
  const verdict = verifyVault(
    key,
    { id: vault.id, key_epoch: vault.keyEpoch ?? undefined, manifest: vault.manifest, manifest_seq: vault.manifestSeq, manifest_prev: vault.manifestPrev },
    undefined,
    rows.map((r) => ({ id: r.id, deleted_at: r.deletedAt, data: r.data })),
  );
  return { warning: malformed > 0 || failed > 0 || verdict.status !== "ok", unchecked: false, opened, failed };
}

/** The three query parameters of a write without a body (trash, restore, delete for good): all of them or none. */
export const manifestQuery = (m: ManifestEntry | null): string[] =>
  m ? [`manifest_seq=${m.seq}`, `manifest_prev=${encodeURIComponent(m.prev)}`, `manifest=${encodeURIComponent(m.sealed)}`] : [];

/** `path` with query parameters (none: unchanged). */
export const withQuery = (path: string, params: readonly string[]): string => (params.length ? `${path}?${params.join("&")}` : path);

const canWrite = (role: Role | string) => role === "write" || role === "admin" || role === "owner";

/**
 * Whether this app starts the vault's first manifest after a sync: the server lists the feature and says every member's
 * apps keep manifests (`manifest_ok`), the account may write, the vault has none and none was ever seen here, and the
 * vault has its number (`seq`) and key epoch from that answer. The caller adds: the vault's key opened, it passed the
 * signed sharing checks, and every row has its `data`.
 */
export function mayStart(feature: boolean, row: SyncVaultRow, status: ManifestStatus | undefined, remembered: Remembered | undefined): boolean {
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
export const baselineSeq = (row: Pick<SyncVaultRow, "manifest_seq">, remembered: Remembered | undefined): number => Math.max(manifestSeq(row), remembered?.version ?? 0) + 1;

/** The server's clock and this device's may differ by this much (seconds) for old trash to be deleted here. */
export const CLOCK_SLACK = 86400;

/**
 * Whether a row is in the trash: exactly when its `deleted_at` is not null (the one rule of every app and of the
 * core; a missing field reads as null).
 */
export const isTrashedRow = (row: Pick<SyncItemRow, "deleted_at">): boolean => (row.deleted_at ?? null) !== null;

/**
 * The trashed items of a vault that this device deletes for good. All of these hold (review 9: the server's word
 * alone never empties a trash):
 * - the server's rule, with its clock and retention: in the trash for longer than `trashDays` (at least 1; none when
 *   the server keeps the trash forever or didn't say);
 * - this device itself has seen the item in the trash for at least that long, by its own clock (`seen`: when it first
 *   saw each row trashed, `TrashSeen`);
 * - the two clocks agree within a day.
 */
export function dueTrash(
  rows: readonly SyncItemRow[],
  serverTime: number | undefined,
  trashDays: number | undefined,
  seen: (id: string) => number | undefined,
  now: number,
): SyncItemRow[] {
  const whole = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v > 0;
  if (!whole(serverTime) || !whole(trashDays) || !whole(now)) return [];
  const keep = trashDays * 86400;
  if (!Number.isSafeInteger(keep) || Math.abs(serverTime - now) > CLOCK_SLACK) return [];
  return rows.filter((r) => {
    const first = seen(r.id);
    return whole(r.deleted_at) && r.deleted_at < serverTime - keep && whole(first) && first <= now - keep;
  });
}

/** Whether this app deletes a vault's due trash after a sync: the vault checked out, has a manifest, and the account may write. */
export const mayPurge = (row: SyncVaultRow, status: ManifestStatus | undefined): boolean => status === "ok" && manifestSeq(row) > 0 && canWrite(row.role);

// ------------------------------------------------------------ device memory

export const MANIFESTS_PREFIX = "pa.vault-manifests.";
export const manifestsKey = (scope: string) => `${MANIFESTS_PREFIX}${scope}`;

/**
 * The remembered manifests as stored. Nothing stored is nothing remembered, and so is a single entry that isn't a
 * `{version, link}` pair (the first format kept a bare number). A stored value that can't be read at all is null: it is
 * neither checked against nor written over (`ManifestMemory.unreadable`).
 */
export function readManifestMemory(store: KeyValueStore, scope: string): Map<string, Remembered> | null {
  const out = new Map<string, Remembered>();
  const text = store.get(manifestsKey(scope));
  if (text === null) return out;
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return null;
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  for (const [id, entry] of Object.entries(v as Record<string, unknown>)) {
    const r = asRemembered(entry);
    if (r) out.set(id, r);
  }
  return out;
}

/**
 * Per server and account, the last manifest this device saw for each vault: its version and link (same store and
 * scope as the item edit counters). A version is only ever raised, and the link of a version is never replaced; vaults
 * that disappear keep their entry (vault ids are never reused, and a server could hide a vault and show it again).
 * Several tabs merge by the higher version.
 */
export class ManifestMemory {
  readonly scope: string;
  private readonly store: KeyValueStore;
  private seen: Map<string, Remembered>;
  private dirty = false;
  /** Something is stored that can't be read: nothing is checked against it and nothing is written over it. */
  unreadable: boolean;

  constructor(store: KeyValueStore, scope: string) {
    this.store = store;
    this.scope = scope;
    const stored = readManifestMemory(store, scope);
    this.unreadable = stored === null;
    this.seen = stored ?? new Map();
  }

  /** The remembered manifest of a vault (undefined: none). */
  get(vaultId: string): Remembered | undefined {
    return this.seen.get(vaultId);
  }

  /** Remember a manifest unless one of that version or a higher one is remembered already. */
  raise(vaultId: string, version: number, link: string | null) {
    if (this.unreadable || !isVersion(version) || !isLink(link)) return;
    if ((this.seen.get(vaultId)?.version ?? 0) >= version) return;
    this.seen.set(vaultId, { version, link });
    this.dirty = true;
  }

  /** What another tab wrote meanwhile (the higher version wins; at the same version the one held here stays), without writing. */
  refresh() {
    const stored = readManifestMemory(this.store, this.scope);
    if (stored === null) {
      this.unreadable = true;
      return;
    }
    if (this.unreadable) return;
    for (const [id, r] of stored) if (r.version > (this.seen.get(id)?.version ?? 0)) this.seen.set(id, r);
  }

  /** Write back, merged with what another tab wrote meanwhile. */
  flush() {
    if (!this.dirty || this.unreadable) return;
    this.refresh();
    if (this.unreadable) return;
    this.store.set(manifestsKey(this.scope), JSON.stringify(Object.fromEntries(this.seen)));
    this.dirty = false;
  }
}

export const TRASH_SEEN_PREFIX = "pa.trash-seen.";
export const trashSeenKey = (scope: string) => `${TRASH_SEEN_PREFIX}${scope}`;

/**
 * Per server and account, when this device first saw each trashed item in the trash (its own clock, Unix seconds):
 * old trash is deleted here only after the device itself watched it for the retention period (`dueTrash`). An entry
 * goes when its item is live again or no longer served; an unreadable store reads as nothing seen (nothing is deleted
 * until it was watched again).
 */
export class TrashSeen {
  readonly scope: string;
  private readonly store: KeyValueStore;
  private seen = new Map<string, number>();

  constructor(store: KeyValueStore, scope: string) {
    this.store = store;
    this.scope = scope;
    try {
      const v = JSON.parse(store.get(trashSeenKey(scope)) ?? "{}") as unknown;
      if (v && typeof v === "object" && !Array.isArray(v))
        for (const [id, at] of Object.entries(v as Record<string, unknown>)) if (typeof at === "number" && Number.isSafeInteger(at) && at > 0) this.seen.set(id, at);
    } catch {
      /* unreadable: nothing seen */
    }
  }

  get = (id: string): number | undefined => this.seen.get(id);

  /** After a copy was taken over: `rows` are all item rows held now. Rows first seen trashed get `now`; the rest is forgotten. */
  note(rows: Iterable<Pick<SyncItemRow, "id" | "deleted_at">>, now: number) {
    const next = new Map<string, number>();
    for (const r of rows) if (isTrashedRow(r)) next.set(r.id, Math.min(this.seen.get(r.id) ?? now, now));
    let changed = next.size !== this.seen.size;
    if (!changed) for (const [id, at] of next) if (this.seen.get(id) !== at) changed = true;
    this.seen = next;
    if (changed) this.store.set(trashSeenKey(this.scope), next.size ? JSON.stringify(Object.fromEntries(next)) : null);
  }
}
