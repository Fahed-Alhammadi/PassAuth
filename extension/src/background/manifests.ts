/**
 * Vault manifests (ARCHITECTURE "Vault manifests"): every vault can carry a small sealed record of its item set (a
 * version, how many items are live and in the trash, and a keyed sum over every item's id, state and ciphertext). The
 * core checks the rows this browser holds against it after every sync (`VaultKey.manifestVerify`), so a server that
 * hides a new item or a deletion, brings a deleted item back or sends an older copy of one is noticed, also for
 * changes this browser never saw. Every item write into such a vault carries the vault's next manifest
 * (`manifestNext`), which the server stores in the same transaction, only if nothing else was written meanwhile.
 *
 * This file holds the pure parts (unit-tested in manifests.test.ts): reading the new `/sync` fields, the rows as the
 * core counts them, what this browser remembers (per vault the version and the link of the last manifest it checked
 * or wrote, kept with the item edit counters in the account's device memory: device-memory.ts), and the decisions
 * "start a manifest?", "which trashed items are due?". vault.ts applies them where answers are merged and items are
 * written.
 *
 * The chain: every manifest names the one it replaces (`manifest_prev`, a hash link), and this browser remembers the
 * link of the last one it checked. A manifest more than one step ahead is checked against the vault's manifest log
 * (`GET /vaults/{id}/manifest-log`), so a server can't move this browser onto another history at the same or a higher
 * version ("fork then join").
 */
import type { Snapshot } from "@web/lib/delta";
import type { SyncItemRow, SyncVaultRow } from "@web/lib/types";

/** `/api/config` feature: the server keeps manifests (and sends `manifest`, `manifest_seq`, `manifest_prev`, `manifest_ok`, `data_sha256`). */
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

/** Trashed items deleted in one request, at most (the web vault's import batch size). */
const PURGE_BATCH = 250;

/**
 * A vault's state here. The core's verdicts (`manifestVerify`) "none", "ok", "rollback", "mismatch", "incomplete",
 * and "unchecked": the rows shown weren't checked as a server's answer yet (the offline copy at unlock didn't check
 * out, or what this browser remembers can't be read). An unchecked vault shows no warning; a write into it waits for
 * the sync that decides.
 */
export type ManifestStatus = "none" | "ok" | "rollback" | "mismatch" | "incomplete" | "unchecked";

/** What the core answers; "need_log": everything else checks out, but the vault's manifest log is needed to decide. */
export type ManifestVerdict = Exclude<ManifestStatus, "unchecked"> | "need_log";

/** Unresolved: the vault stays readable, shows the warning, and nothing is written into it. */
export const unresolved = (s: ManifestStatus | undefined): boolean => s === "rollback" || s === "mismatch";

/** Not settled: the next sync decides (rows incomplete for the manifest, or not checked as a server's answer yet). */
export const unsettled = (s: ManifestStatus | undefined): boolean => s === "incomplete" || s === "unchecked";

type Rec = Record<string, unknown>;

const whole = (v: unknown): number | null => (typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : null);

/** A vault row's manifest version (0: the vault has none, also for anything that isn't a version). */
export const manifestSeqOf = (row: SyncVaultRow): number => whole((row as unknown as Rec).manifest_seq) ?? 0;

/** A vault row's `manifest_prev` (the link of the manifest its manifest replaced), or null. Read here, not through the row's type. */
export const manifestPrevOf = (row: SyncVaultRow): string | null => {
  const p = (row as unknown as Rec).manifest_prev;
  return typeof p === "string" && p ? p : null;
};

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
 * The name of a field older builds of this version put on a row for which this browser kept its own newer copy. A
 * device-private marker must never be a row field (review: a server could send it and so choose the hash the check
 * counts): the hashes of what the server sent live in their own map now (`ServedHashes`), and this field is deleted
 * from every row that comes from the server or from an offline copy (`stripPrivate`).
 */
export const SERVED_HASH = "served_sha256";

/**
 * Item id → the hash of the data the server sent, for rows where this browser shows (and keeps in its copy) its own
 * newer copy instead (item-revs.ts "kept"). The manifest is about the server's rows, so that hash counts, never the
 * kept copy's. Only ever written by this browser (vault.ts `prepare`), kept in the offline copy next to the rows.
 */
export type ServedHashes = ReadonlyMap<string, string>;

/** Delete device-private fields from rows that came from outside (a server's answer, an offline copy). */
export function stripPrivate(rows: unknown): void {
  if (!Array.isArray(rows)) return;
  for (const r of rows) if (r && typeof r === "object" && SERVED_HASH in r) delete (r as Rec)[SERVED_HASH];
}

/** In the trash: exactly when the row's `deleted_at` is not null (the one predicate, everywhere; the core's too). */
export const isTrashed = (row: { deleted_at?: unknown }): boolean => row.deleted_at !== null && row.deleted_at !== undefined;

/**
 * `row` for the core. `served`: the hash of the server's data when the row holds this browser's kept newer copy (from
 * the `ServedHashes` map, never from the row). Unknown shapes go through as they are: the core answers them
 * ("incomplete", or an error).
 */
export function manifestItem(row: SyncItemRow, served?: string): ManifestItem {
  const r = row as unknown as Rec;
  const base = { id: row.id, deleted_at: r.deleted_at ?? null };
  if (typeof served === "string") return { ...base, data_sha256: served };
  if (typeof r.data === "string") return { ...base, data: r.data };
  return typeof r.data_sha256 === "string" ? { ...base, data_sha256: r.data_sha256 } : base;
}

/** Every item row of the snapshot (live and trashed) by vault, as the core counts them. */
export function manifestItems(snap: Pick<Snapshot, "items">, served?: ServedHashes): Map<string, ManifestItem[]> {
  const out = new Map<string, ManifestItem[]>();
  for (const row of snap.items.values()) {
    const item = manifestItem(row, served?.get(row.id));
    const list = out.get(row.vault_id);
    if (list) list.push(item);
    else out.set(row.vault_id, [item]);
  }
  return out;
}

/** What this browser remembers of one vault: the version and the link of the last manifest it checked "ok" or wrote itself. */
export interface Remembered {
  version: number;
  link: string;
}

export type ManifestMemory = Map<string, Remembered>;

const LINK = /^[A-Za-z0-9_-]{43}$/;

/** A link as it travels (base64url of 32 bytes). */
export const isLink = (v: unknown): v is string => typeof v === "string" && LINK.test(v);

const isRemembered = (v: unknown): v is Remembered => {
  const r = v as Partial<Remembered> | null;
  return !!r && typeof r === "object" && typeof r.version === "number" && Number.isSafeInteger(r.version) && r.version >= 1 && isLink(r.link);
};

/**
 * The memory as stored (`{vaultId: {version, link}}`). Anything that isn't an entry is left out: the first format's
 * bare number, half an entry, a link that isn't one. That is "nothing remembered" for the vault.
 */
export function readManifestMemory(stored: unknown): ManifestMemory {
  const m: ManifestMemory = new Map();
  if (stored && typeof stored === "object" && !Array.isArray(stored)) {
    for (const [id, entry] of Object.entries(stored)) if (isRemembered(entry)) m.set(id, { version: entry.version, link: entry.link });
  }
  return m;
}

/** The memory as it is stored. Vaults that are gone stay: ids are never reused, and a server could hide a vault and show it again. */
export function storedManifestMemory(m: ManifestMemory): Record<string, Remembered> {
  return Object.fromEntries(m);
}

/**
 * Remember `version` + `link` for the vault: the higher version wins; at the same version the entry already there
 * stays (a link is never replaced at its version: if the two differ, one of them is on another history, and the next
 * check says so). Half a memory is never stored.
 */
export function rememberManifest(m: ManifestMemory, vaultId: string, version: number, link: unknown): void {
  if (!Number.isSafeInteger(version) || version < 1 || !isLink(link)) return;
  if (version > (m.get(vaultId)?.version ?? 0)) m.set(vaultId, { version, link });
}

/** Two memories merged by that rule (`a`'s entries are the ones "already there"). */
export function mergeManifestMemory(a: ManifestMemory, b: ManifestMemory): ManifestMemory {
  const out: ManifestMemory = new Map(a);
  for (const [id, r] of b) rememberManifest(out, id, r.version, r.link);
  return out;
}

/** The part of the core's vault key this file calls. */
export interface ManifestKey {
  manifestVerify(
    vault_id: string,
    key_epoch: number,
    manifest_seq: number,
    prev: string | null | undefined,
    sealed: string | null | undefined,
    remembered_version: number | null | undefined,
    remembered_link: string | null | undefined,
    log: unknown,
    items: unknown,
  ): unknown;
}

const VERDICTS: readonly string[] = ["none", "ok", "rollback", "mismatch", "incomplete", "need_log"];

/** The core's answer on one vault: `version` + `link` are what to remember, for "ok" only. */
export interface Check {
  status: ManifestVerdict;
  version: number;
  link: string | null;
}

const MISMATCH: Check = { status: "mismatch", version: 0, link: null };

/**
 * The core's verdict on one vault: its row against `items` (every row of the vault in the copy after the answer was
 * applied), what this browser remembers of it and, after a "need_log", the vault's manifest log. Anything thrown (rows
 * the core can't read, an id listed twice, a `deleted_at` that is no time) and any answer that isn't a verdict is a
 * mismatch; so is "need_log" when a log was given (the core never says that, and nothing may ask for a log twice).
 */
export function verifyVault(key: ManifestKey, row: SyncVaultRow, remembered: Remembered | undefined, items: ManifestItem[], log?: unknown[] | null): Check {
  try {
    const mine = remembered && isRemembered(remembered) ? remembered : undefined;
    const check = key.manifestVerify(row.id, epochOf(row), manifestSeqOf(row), manifestPrevOf(row), manifestTextOf(row), mine?.version ?? null, mine?.link ?? null, log ?? null, items) as {
      status?: unknown;
      version?: unknown;
      link?: unknown;
    } | null;
    const status = check?.status;
    if (typeof status !== "string" || !VERDICTS.includes(status)) return MISMATCH;
    if (status === "need_log" && log) return MISMATCH;
    if (status === "ok" && !isLink(check?.link)) return MISMATCH;
    return { status: status as ManifestVerdict, version: whole(check?.version) ?? 0, link: isLink(check?.link) ? check.link : null };
  } catch {
    return MISMATCH;
  }
}

/** How many requests one check may spend on a vault's manifest log (a log with more pages doesn't connect). */
export const LOG_REQUESTS = 5;

/** The log couldn't be fetched (no answer, a 5xx, a 429…): the sync answer isn't checked and isn't used. */
export class LogUnavailable extends Error {}

/**
 * The vault's manifest log after `after`, page by page. `fetchPage(after)` resolves to the endpoint's answer, rejects
 * with `LogUnavailable` when there is none, and resolves to null for a 404 or 400 (an answer: the log doesn't exist
 * for this device). Resolves to the entries as sent (the core ignores what doesn't belong), or to null when the log
 * doesn't connect: no log, an answer that isn't one, or more pages than `LOG_REQUESTS`.
 */
export async function collectLog(after: number, fetchPage: (after: number) => Promise<unknown>): Promise<unknown[] | null> {
  const all: unknown[] = [];
  let from = after;
  for (let n = 0; n < LOG_REQUESTS; n++) {
    const page = (await fetchPage(from)) as { entries?: unknown; more?: unknown } | null;
    if (!page || typeof page !== "object" || !Array.isArray(page.entries)) return null;
    all.push(...page.entries);
    if (page.more !== true) return all;
    const last = whole((page.entries[page.entries.length - 1] as { seq?: unknown } | undefined)?.seq);
    // "More" without a higher place to go on from: it would ask the same page again.
    if (last === null || last <= from) return null;
    from = last;
  }
  return null;
}

/**
 * A manifest this browser built for a write (`manifestNext` / `manifestStart`): `seq`, `prev` and `sealed` are sent
 * (`manifests: [{vault_id, seq, prev, sealed}]` in a body; `manifest_seq`, `manifest_prev`, `manifest` in a query);
 * `link` is its own link, remembered with `seq` once the server stored it.
 */
export interface ManifestEntry {
  vault_id: string;
  seq: number;
  prev: string;
  sealed: string;
  link: string;
}

/** What the builder answered, as an entry for `vaultId`; throws when it isn't one. */
export function entryOf(vaultId: string, built: unknown): ManifestEntry {
  const n = built as { seq?: unknown; prev?: unknown; sealed?: unknown; link?: unknown } | null;
  const seq = whole(n?.seq);
  if (seq === null || seq < 1 || typeof n?.sealed !== "string" || !n.sealed || !isLink(n.prev) || !isLink(n.link)) throw new Error("manifest");
  return { vault_id: vaultId, seq, prev: n.prev, sealed: n.sealed, link: n.link };
}

/** The entry as a request body carries it (the link stays here). */
export const sentEntry = (e: ManifestEntry): { vault_id: string; seq: number; prev: string; sealed: string } => ({ vault_id: e.vault_id, seq: e.seq, prev: e.prev, sealed: e.sealed });

/** The query string of a request without a body (`revision` first, as before; then the manifest, all three parts or none). */
export function writeQuery(revision: number | undefined, entry: ManifestEntry | null): string {
  const parts: string[] = [];
  if (revision !== undefined) parts.push(`revision=${revision}`);
  if (entry) parts.push(`manifest_seq=${entry.seq}`, `manifest_prev=${encodeURIComponent(entry.prev)}`, `manifest=${encodeURIComponent(entry.sealed)}`);
  return parts.length ? `?${parts.join("&")}` : "";
}

/** `snap` with the vault row's manifest set to the one this browser just had stored (`vaultSeq`: the vault's number after it, kept as an own write). */
export function withManifest(snap: Snapshot, entry: ManifestEntry, vaultSeq?: number): Snapshot {
  const vaults = snap.vaults.map((v) => (v.id === entry.vault_id ? ({ ...v, manifest: entry.sealed, manifest_seq: entry.seq, manifest_prev: entry.prev, manifest_ok: true } as SyncVaultRow) : v));
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
 * every row has its data or its hash, and no row is a kept newer copy (`kept`: the server sent an older version of an
 * item of this vault; this browser never seals that into a first manifest). (The caller checks that the vault is open
 * and passed signed sharing, and that what this browser remembers could be read.)
 */
export function mayStart(o: {
  features: ReadonlySet<string>;
  row: SyncVaultRow;
  role: string;
  status: ManifestStatus | undefined;
  remembered: Remembered | undefined;
  items: ManifestItem[];
  kept?: boolean;
}): boolean {
  if (!o.features.has(MANIFEST_FEATURE) || o.status !== "none" || o.remembered !== undefined || o.kept) return false;
  if (manifestSeqOf(o.row) !== 0 || !manifestReady(o.row) || typeof o.row.seq !== "number") return false;
  if (o.role !== "write" && o.role !== "admin" && o.role !== "owner") return false;
  return o.items.every((i) => typeof i.data === "string" || typeof i.data_sha256 === "string");
}

const DAY = 86400;
/** The server's clock and this browser's may differ by this much (seconds) for old trash to be deleted from here. */
export const CLOCK_TOLERANCE = DAY;

/**
 * Item id → this browser's clock (Unix seconds) when it first saw the item in the trash. The server's word alone
 * (`server_time`, `trash_days`, `deleted_at`) never deletes anything from here: an item is deleted for good only
 * after this browser has itself seen it in the trash for the whole retention period.
 */
export type TrashSeen = Map<string, number>;

export function readTrashSeen(stored: unknown): TrashSeen {
  const m: TrashSeen = new Map();
  if (stored && typeof stored === "object" && !Array.isArray(stored)) for (const [id, at] of Object.entries(stored)) if (whole(at) !== null) m.set(id, at as number);
  return m;
}

/**
 * Bring the memory up to the rows this browser holds now (`now`: its clock, Unix seconds): a trashed row not seen
 * before is noted with `now`, one seen before keeps its time (also when the clock was set back since: the wait then
 * only gets longer), and rows that are live again or gone are forgotten (so a row that leaves the trash and comes
 * back starts again).
 */
export function noteTrash(seen: TrashSeen, rows: Iterable<SyncItemRow>, now: number): TrashSeen {
  if (!Number.isSafeInteger(now) || now < 0) return new Map(seen);
  const next: TrashSeen = new Map();
  for (const r of rows) if (isTrashed(r)) next.set(r.id, seen.get(r.id) ?? now);
  return next;
}

/**
 * The vault's trashed rows this browser deletes for good now. All of these must hold:
 * - the server's rule says the row is due: `trash_days >= 1` and `deleted_at + trash_days days <= server_time`, from
 *   the answer's own clock and setting (none when the answer names no clock);
 * - this browser has itself seen the row in the trash for at least `trash_days` days by its own clock (`seen`, `now`);
 * - the server's clock and this browser's agree within a day.
 * So a server that lies about its clock, its setting or a row's `deleted_at` can't have the trash emptied: at worst
 * it delays it. (Right after an update nothing is due until this browser has watched the trash for the period.)
 */
export function dueTrash(rows: Iterable<SyncItemRow>, vaultId: string, served: Served, seen: TrashSeen, now: number): SyncItemRow[] {
  const { serverTime, trashDays } = served;
  if (serverTime === null || trashDays === null || trashDays < 1 || !Number.isSafeInteger(now) || now < 0) return [];
  const keep = trashDays * DAY;
  if (!Number.isSafeInteger(keep) || Math.abs(serverTime - now) > CLOCK_TOLERANCE) return [];
  const out: SyncItemRow[] = [];
  for (const r of rows) {
    if (r.vault_id !== vaultId) continue;
    const at = whole(r.deleted_at);
    const first = seen.get(r.id);
    if (at === null || at < 1 || first === undefined) continue;
    // Subtractions only: nothing here can leave the whole numbers.
    if (serverTime - at >= keep && now - first >= keep) out.push(r);
  }
  return out;
}

/** How many trashed items one purge request names: 250, or the server's `limits.max_import_items` when that is less. */
export function purgeBatch(limits: unknown): number {
  const n = whole((limits as { max_import_items?: unknown } | null)?.max_import_items);
  return n && n >= 1 ? Math.min(n, PURGE_BATCH) : PURGE_BATCH;
}

/**
 * Whether a `/sync` answer's rows can be used at all: every vault row's `seq`, `manifest_seq` and `key_epoch` and
 * every item row's `deleted_at`, where present, is a whole number from 0 to 2^53 - 1 (anything else is an invalid
 * answer; nothing is computed with such numbers).
 */
export function validNumbers(answer: { vaults?: unknown; items?: unknown }): boolean {
  const opt = (v: unknown) => v === undefined || v === null || whole(v) !== null;
  if (Array.isArray(answer.vaults)) {
    for (const v of answer.vaults as Rec[]) if (v && typeof v === "object" && !(opt(v.seq) && opt(v.manifest_seq) && opt(v.key_epoch))) return false;
  }
  if (Array.isArray(answer.items)) {
    for (const r of answer.items as Rec[]) if (r && typeof r === "object" && !opt(r.deleted_at)) return false;
  }
  return true;
}

/**
 * Whether an answer is behind one of this browser's own writes already shown: a vault's number in it is below the
 * number after that write (`own`: the snapshot's `own`). Such an answer is asked for again before it is used.
 */
export function behindOwn(own: Readonly<Record<string, number>>, vaults: readonly SyncVaultRow[]): boolean {
  const seqs = new Map(vaults.map((v) => [v.id, v.seq]));
  return Object.entries(own).some(([id, mine]) => {
    const now = seqs.get(id);
    return typeof now === "number" && now < mine;
  });
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
