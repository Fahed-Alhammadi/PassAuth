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
/**
 * Under the warning, when the served copy can't be accepted as it is (its record doesn't describe the served items):
 * the extension writes no new record, so someone with write access reviews it in the web vault or the desktop app.
 */
export const MANIFEST_REVIEW_TEXT = "Open the web vault or the desktop app to review this vault.";
/** The same case for an account that can only read the vault. */
export const MANIFEST_READER_TEXT = "Someone who can edit this vault can review it.";
/** "Use the server's copy": the action (offered whenever the served copy checks out on its own), and its confirmation. */
export const MANIFEST_ACCEPT_ACTION = "Use the server's copy";
export const MANIFEST_ACCEPT_TITLE = "Use the server's copy?";
export const MANIFEST_ACCEPT_BODY =
  "PassAuth will accept this vault as the server has it now, including anything that is missing, restored or out of date. Do this only if you know why it changed, for example after the server was restored from a backup.";
/** The served copy still can't be accepted after a fresh fetch (it changed meanwhile, or never could). */
export const MANIFEST_NOT_ACCEPTABLE_TEXT = "The server's copy of this vault can't be accepted as it is.";
/**
 * "Use the server's copy" when the server shows no record for a vault that had one: accepting forgets what this browser
 * remembered, so the confirmation says what that means (the same text in every client).
 */
export const MANIFEST_FORGET_BODY =
  "Your server no longer shows a record of changes for this vault. If you continue, PassAuth stops checking this vault for missing, restored or out-of-date items until a new record is started.";
/** The quiet note such a vault carries afterwards, until it has a record again. */
export const MANIFEST_NOT_CHECKED_TEXT = "This vault isn't being checked for missing or restored items.";
/** The fresh fetch after the confirmation needs the other confirmation (a record where none was shown, or none where one was): nothing is accepted under a text that didn't say so. */
export const MANIFEST_CHANGED_TEXT = "The server's copy of this vault changed just now, so it wasn't accepted. Check what the popup shows now.";
/**
 * A vault that holds an item this account's keys don't open (the same text in every client; no instruction to delete:
 * the item may open on another device or in a newer version). Nothing is held for it: the vault's record itself
 * checked out.
 */
export const MANIFEST_ITEM_TEXT = "An item in this vault can't be opened.";
/** Under it, for an account with write access: where such an item can be deleted (the extension has no such delete). */
export const MANIFEST_ITEM_WHERE_TEXT = "It can be deleted for good in the web vault or the desktop app.";
/** The list's rows for items that aren't shown (the same texts in every client). */
export const ITEM_LOCKED_TITLE = "Item that can't be opened";
export const ITEM_NEWER_TITLE = "Item from a newer version of PassAuth";
export const ITEM_NEWER_NOTE = "Update PassAuth to see this item.";

/**
 * Why a row didn't open, from what the core threw: "newer" when the row decrypted (its key and data are authentic)
 * but its content isn't an item this version reads (an item type or format a later version added: the core's
 * `json: …` error, which only comes after the data was decrypted); "locked" for everything else (a key or data that
 * doesn't decrypt, or isn't there).
 */
export function openFailure(e: unknown): "newer" | "locked" {
  return e instanceof Error && e.message.startsWith("json: ") ? "newer" : "locked";
}
/** A write into a vault no server's answer was checked for yet. */
export const MANIFEST_UNCHECKED_TEXT = "PassAuth couldn't check this vault with your server yet. Try again in a moment.";
/** What this browser remembers can't be read (after three tries and a whole sync), with the way out. */
export const MEMORY_UNREADABLE_TEXT = "PassAuth can't read this device's record of your vaults.";
export const MEMORY_RESET_ACTION = "Reset on this device";
export const MEMORY_RESET_BODY = "PassAuth will trust what your server shows now and start a new record on this device.";
/** Reads that must fail in a row (with a whole sync among them) before the reset is offered. */
export const MEMORY_UNREAD_TRIES = 3;
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

/** What this browser remembers of one vault: the version and the link of the last manifest it checked "ok", wrote itself or accepted. */
export interface Remembered {
  version: number;
  link: string;
}

/**
 * A vault's entry in the memory: what is remembered (`version` + `link`, both or neither: neither is "nothing
 * remembered"), and `accepts`: how often the user replaced this vault's memory with "Use the server's copy" here
 * (left out while 0). The counter orders two copies of the memory before their versions do: an acceptance may lower
 * the version, and a copy from before it must not bring the old one back.
 */
export interface MemoryEntry {
  version?: number;
  link?: string;
  accepts?: number;
  /**
   * Only on an entry with nothing remembered: the user accepted "no record" for a vault that had one, so the vault
   * isn't checked until it has a record again (the popup says so). Gone with the next version remembered.
   */
  unchecked?: true;
}

export type ManifestMemory = Map<string, MemoryEntry>;

const LINK = /^[A-Za-z0-9_-]{43}$/;
/** The link of 32 zero bytes: what a first manifest names as its predecessor, never a manifest's own link. */
const ZERO_LINK = "A".repeat(43);

/** A link as it travels (base64url of 32 bytes). */
export const isLink = (v: unknown): v is string => typeof v === "string" && LINK.test(v);

const isRemembered = (v: unknown): v is Remembered => {
  const r = v as Partial<Remembered> | null;
  return !!r && typeof r === "object" && typeof r.version === "number" && Number.isSafeInteger(r.version) && r.version >= 1 && isLink(r.link) && r.link !== ZERO_LINK;
};

const acceptsOf = (v: unknown): number => {
  const n = (v as { accepts?: unknown } | null | undefined)?.accepts;
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 1 ? n : 0;
};

const entryWith = (r: Remembered | null, accepts: number, unchecked = false): MemoryEntry => ({
  ...(r ? { version: r.version, link: r.link } : {}),
  ...(accepts ? { accepts } : {}),
  ...(!r && unchecked ? { unchecked: true as const } : {}),
});

/** Whether the vault's entry says its check was given up with "Use the server's copy" (nothing remembered, marked). */
export const notChecked = (m: ManifestMemory, vaultId: string): boolean => {
  const e = m.get(vaultId);
  return !!e && !isRemembered(e) && e.unchecked === true;
};

/** What is remembered of the vault, or undefined: no entry, or one without a version and link (forgotten by an acceptance). */
export function rememberedOf(m: ManifestMemory, vaultId: string): Remembered | undefined {
  const e = m.get(vaultId);
  return isRemembered(e) ? { version: e.version, link: e.link } : undefined;
}

/**
 * The memory as stored (`{vaultId: {version, link, accepts}}`). An entry that isn't a version with a link (the first
 * format's bare number, half an entry, a link that isn't one or is all zero) is "nothing remembered" for the vault; its
 * `accepts`, if it has one, is kept.
 */
export function readManifestMemory(stored: unknown): ManifestMemory {
  const m: ManifestMemory = new Map();
  if (stored && typeof stored === "object" && !Array.isArray(stored)) {
    for (const [id, entry] of Object.entries(stored)) {
      const accepts = acceptsOf(entry);
      const unchecked = (entry as { unchecked?: unknown } | null)?.unchecked === true;
      if (isRemembered(entry)) m.set(id, entryWith(entry, accepts));
      else if (accepts || unchecked) m.set(id, entryWith(null, accepts, unchecked));
    }
  }
  return m;
}

/** The memory as it is stored. Vaults that are gone stay: ids are never reused, and a server could hide a vault and show it again. */
export function storedManifestMemory(m: ManifestMemory): Record<string, MemoryEntry> {
  return Object.fromEntries(m);
}

/**
 * Remember `version` + `link` for the vault (after an "ok", or an own write the server stored): only a higher version
 * than the one there; at the same version the entry already there stays (a link is never replaced at its version: if
 * the two differ, one of them is on another history, and the next check says so). `accepts` stays. Half a memory and
 * the all-zero link are never stored.
 */
export function rememberManifest(m: ManifestMemory, vaultId: string, version: number, link: unknown): void {
  if (!isRemembered({ version, link })) return;
  if (version > (rememberedOf(m, vaultId)?.version ?? 0)) m.set(vaultId, entryWith({ version, link: link as string }, acceptsOf(m.get(vaultId))));
}

/**
 * "Use the server's copy" (`acceptServerCopy` in vault.ts, nothing else): the vault's entry becomes the accepted
 * manifest's version and link, whatever was there (the version may go down), or nothing remembered (`accepted` null:
 * the server shows no manifest; the entry then carries the "not checked" marker), with `accepts` one above `floor`
 * (the higher of the stored and the loaded counter).
 */
export function acceptedEntry(accepted: Remembered | null, floor: number): MemoryEntry {
  return entryWith(accepted && isRemembered(accepted) ? accepted : null, floor + 1, true);
}

/** An entry's `accepts` (0 when it has none). */
export const acceptsIn = (m: ManifestMemory, vaultId: string): number => acceptsOf(m.get(vaultId));

/**
 * Two memories merged (`a`'s entries are the ones "already there", the stored ones), per vault: the entry with the
 * higher `accepts` wins; at the same `accepts` the higher version (nothing remembered counts as 0); at the same
 * version the one already there.
 */
export function mergeManifestMemory(a: ManifestMemory, b: ManifestMemory): ManifestMemory {
  const out: ManifestMemory = new Map(a);
  for (const [id, mine] of b) {
    const there = out.get(id);
    const [ta, ma] = [acceptsOf(there), acceptsOf(mine)];
    const [tv, mv] = [rememberedOf(out, id)?.version ?? 0, rememberedOf(b, id)?.version ?? 0];
    if (!there || ma > ta || (ma === ta && mv > tv)) out.set(id, mine);
  }
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
  /** `manifestVerify` with nothing remembered, under its own name: what "Use the server's copy" may accept. */
  manifestAccept(vault_id: string, key_epoch: number, manifest_seq: number, prev: string | null | undefined, sealed: string | null | undefined, items: unknown): unknown;
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
export function verifyVault(key: Pick<ManifestKey, "manifestVerify">, row: SyncVaultRow, remembered: Remembered | undefined, items: ManifestItem[], log?: unknown[] | null): Check {
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

/** What "Use the server's copy" finds: the served manifest describes the served rows ("ok"), the server shows none ("none"), or neither. */
export type Acceptance = { status: "ok"; version: number; link: string } | { status: "none" } | { status: "no" };

/**
 * Whether the vault's served copy can be accepted as it is, nothing remembered taken into account (the core's
 * `manifestAccept` on the row and every row of the vault). Anything thrown, "incomplete" and any answer that isn't
 * "ok" with a version and link, or "none", is "no": nothing may be remembered from it.
 */
export function acceptVault(key: Pick<ManifestKey, "manifestAccept">, row: SyncVaultRow, items: ManifestItem[]): Acceptance {
  try {
    const a = key.manifestAccept(row.id, epochOf(row), manifestSeqOf(row), manifestPrevOf(row), manifestTextOf(row), items) as { status?: unknown; version?: unknown; link?: unknown } | null;
    if (a?.status === "none") return { status: "none" };
    const version = whole(a?.version);
    if (a?.status === "ok" && isRemembered({ version, link: a.link })) return { status: "ok", version: version as number, link: a.link as string };
  } catch {
    /* not acceptable */
  }
  return { status: "no" };
}

/**
 * How many requests one check may spend on a vault's manifest log: 25 pages of up to 2000 entries each (a log with
 * more pages doesn't connect).
 */
export const LOG_REQUESTS = 25;

/** The log couldn't be fetched (no answer, a 5xx, a 429…): the sync answer isn't checked and isn't used. */
export class LogUnavailable extends Error {}

/**
 * The vault's manifest log after `after`, page by page. `fetchPage(after)` resolves to the endpoint's answer, rejects
 * with `LogUnavailable` when there is none, and resolves to null for a 404 or 400 (an answer: the log doesn't exist
 * for this device). Resolves to the well-typed entries, each exactly as the server sent it (`isLogEntry`: what the
 * core counts, and what the web vault passes on; anything else in a list is left out, never fatal), or to null when
 * the log doesn't connect: no log, an answer that isn't one, or more pages than `LOG_REQUESTS`.
 */
export async function collectLog(after: number, fetchPage: (after: number) => Promise<unknown>): Promise<unknown[] | null> {
  const all: unknown[] = [];
  let from = after;
  for (let n = 0; n < LOG_REQUESTS; n++) {
    const page = (await fetchPage(from)) as { entries?: unknown; more?: unknown } | null;
    if (!page || typeof page !== "object" || !Array.isArray(page.entries)) return null;
    const entries = page.entries.filter(isLogEntry);
    all.push(...entries);
    if (page.more !== true) return all;
    const last = entries.reduce((max, e) => Math.max(max, e.seq), 0);
    // "More" without a higher place to go on from: it would ask the same page again.
    if (last <= from) return null;
    from = last;
  }
  return null;
}

/**
 * An entry of a vault's manifest log as the core reads one: an object with a whole `seq` from 1 to 2^53 - 1 and the
 * texts `prev` and `digest`. Only such entries are passed to the core (the same in every client), as they came.
 */
export function isLogEntry(v: unknown): v is { seq: number; prev: string; digest: string } {
  const e = v as { seq?: unknown; prev?: unknown; digest?: unknown } | null;
  return !!e && typeof e === "object" && !Array.isArray(e) && typeof e.seq === "number" && Number.isSafeInteger(e.seq) && e.seq >= 1 && typeof e.prev === "string" && typeof e.digest === "string";
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
 * every row has its data or its hash, no row is a kept newer copy (`kept`: the server sent an older version of an
 * item of this vault; this browser never seals that into a first manifest), and no row of the vault fails to open
 * (`unopenable`: this browser can't vouch for a row it can't open; an item from a newer version of PassAuth, which
 * decrypts, doesn't count as one). (The caller checks that the vault is open and passed signed
 * sharing, and that what this browser remembers could be read.)
 */
export function mayStart(o: {
  features: ReadonlySet<string>;
  row: SyncVaultRow;
  role: string;
  status: ManifestStatus | undefined;
  remembered: Remembered | undefined;
  items: ManifestItem[];
  kept?: boolean;
  unopenable?: boolean;
}): boolean {
  if (!o.features.has(MANIFEST_FEATURE) || o.status !== "none" || o.remembered !== undefined || o.kept || o.unopenable) return false;
  if (manifestSeqOf(o.row) !== 0 || !manifestReady(o.row) || typeof o.row.seq !== "number") return false;
  if (o.role !== "write" && o.role !== "admin" && o.role !== "owner") return false;
  return o.items.every((i) => typeof i.data === "string" || typeof i.data_sha256 === "string");
}

const DAY = 86400;
/** The server's clock and this browser's may differ by this much (seconds) for old trash to be deleted from here. */
export const CLOCK_TOLERANCE = DAY;
/** An item is never deleted for good from here before this browser saw it in the trash for this many days. */
export const TRASH_FLOOR_DAYS = 7;

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
 * - the server's rule says the row is due: `trash_days >= 1` and `deleted_at < server_time - trash_days days`
 *   (strictly, as the server's own sweeper and every other client count), from the answer's own clock and setting
 *   (none when the answer names no clock);
 * - this browser has itself seen the row in the trash for at least max(`trash_days`, `TRASH_FLOOR_DAYS`) days by its
 *   own clock (`seen`, `now`): never less than a week, whatever setting the server names;
 * - the server's clock and this browser's agree within a day.
 * So a server that lies about its clock, its setting or a row's `deleted_at` can't have the trash emptied: at worst
 * it delays it. (Right after an update nothing is due until this browser has watched the trash for the period.)
 */
export function dueTrash(rows: Iterable<SyncItemRow>, vaultId: string, served: Served, seen: TrashSeen, now: number): SyncItemRow[] {
  const { serverTime, trashDays } = served;
  if (serverTime === null || trashDays === null || trashDays < 1 || !Number.isSafeInteger(now) || now < 0) return [];
  const keep = trashDays * DAY;
  const watched = Math.max(trashDays, TRASH_FLOOR_DAYS) * DAY;
  if (!Number.isSafeInteger(keep) || Math.abs(serverTime - now) > CLOCK_TOLERANCE) return [];
  const out: SyncItemRow[] = [];
  for (const r of rows) {
    if (r.vault_id !== vaultId) continue;
    const at = whole(r.deleted_at);
    const first = seen.get(r.id);
    if (at === null || at < 1 || first === undefined) continue;
    // Subtractions only: nothing here can leave the whole numbers.
    if (serverTime - at > keep && now - first >= watched) out.push(r);
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

/**
 * Why a vault shows its warning, which decides what the popup offers:
 * - "accept": the served record describes the served items (the core's `manifestAccept`: "ok"), so "Use the server's
 *   copy" can accept it here, whatever the account's role;
 * - "forget": the server shows no record at all for a vault that had one (`manifestAccept`: "none"): accepting forgets
 *   what was remembered, under a confirmation of its own that says the vault is no longer checked;
 * - "review": neither, so someone with write access has to write a new record in the web vault or the desktop app.
 * (An item that doesn't open is no cause: such a vault shows its own notice and takes writes.)
 */
export type WarningCause = "accept" | "forget" | "review";

/**
 * A vault's standing warning: the verdict, its cause and the vault row it was judged on (`stamp`: `rowStampOf`). Kept
 * with the offline copy, so the same answer isn't fetched in full again at every sync or worker start to find the
 * same verdict. Only ever a warning: "ok" is never read from here.
 */
export interface Standing {
  status: "rollback" | "mismatch";
  cause: WarningCause;
  stamp: string;
}

/** What a verdict on a vault row depends on, of the row itself: any write into the vault changes it (its `seq`). */
export function rowStampOf(row: SyncVaultRow): string {
  const r = row as unknown as Rec;
  return JSON.stringify([r.seq ?? null, r.manifest_seq ?? null, r.manifest_prev ?? null, r.manifest ?? null, r.key_epoch ?? null, r.wrapped_key ?? null]);
}

/** The standing warnings an offline copy holds (anything that isn't one is left out). */
export function readStanding(stored: unknown): Map<string, Standing> {
  const out = new Map<string, Standing>();
  if (stored && typeof stored === "object" && !Array.isArray(stored)) {
    for (const [id, v] of Object.entries(stored as Record<string, Partial<Standing> | null>)) {
      if (!v || typeof v !== "object" || typeof v.stamp !== "string") continue;
      if ((v.status === "rollback" || v.status === "mismatch") && (v.cause === "accept" || v.cause === "forget" || v.cause === "review"))
        out.set(id, { status: v.status, cause: v.cause, stamp: v.stamp });
    }
  }
  return out;
}

/** One vault of the popup's notice: what is wrong, what to do about it, and what the popup offers. */
export interface NoticeVault {
  id: string;
  name: string;
  /** The warning. */
  text: string;
  /** Under it: where it can be resolved when not here (none when "Use the server's copy" is offered). */
  hint?: string;
  /** "Use the server's copy" is offered (after the confirmation). */
  accept?: boolean;
  /** With `accept`: the server shows no record, so the confirmation is the one that says checking stops (`confirm.forgetBody`). */
  forget?: boolean;
  /** `hint` points to the web vault: its link is shown. */
  open?: boolean;
}

/**
 * The popup's notice: the vaults that show a warning, and the vaults that hold an item that can't be opened (`key`: it
 * changes with the set).
 */
export interface ManifestNotice {
  vaults: NoticeVault[];
  key: string;
  /** The confirmation of "Use the server's copy" (`forgetBody`: for a vault the server shows no record of). */
  confirm: { action: string; title: string; body: string; forgetBody: string };
}

type Shown = Omit<NoticeVault, "id" | "name">;

/** What one warned vault shows, by its cause and whether the account may write into it. */
export function warningOf(cause: WarningCause | undefined, canWrite: boolean): Shown {
  if (cause === "accept") return { text: MANIFEST_WARNING_TEXT, accept: true };
  if (cause === "forget") return { text: MANIFEST_WARNING_TEXT, accept: true, forget: true };
  return canWrite ? { text: MANIFEST_WARNING_TEXT, hint: MANIFEST_REVIEW_TEXT, open: true } : { text: MANIFEST_WARNING_TEXT, hint: MANIFEST_READER_TEXT };
}

/** What a vault with an item that can't be opened shows: the notice, and for an account that may write where the item can be deleted. */
export function itemNoticeOf(canWrite: boolean): Shown {
  return canWrite ? { text: MANIFEST_ITEM_TEXT, hint: MANIFEST_ITEM_WHERE_TEXT, open: true } : { text: MANIFEST_ITEM_TEXT };
}

/**
 * `unopenable`: the open vaults that hold an item that can't be opened. Such a vault shows its notice unless it shows
 * the warning (one line per vault; the item notice is there again once the warning is gone, while the row remains).
 */
export function manifestNotice(
  vaults: { id: string; name: string; role?: string }[],
  states: ReadonlyMap<string, ManifestStatus>,
  causes?: ReadonlyMap<string, { cause: WarningCause }>,
  unopenable?: ReadonlySet<string>,
): ManifestNotice | null {
  const list: NoticeVault[] = [];
  for (const v of vaults) {
    const canWrite = v.role !== undefined && v.role !== "read";
    if (unresolved(states.get(v.id))) list.push({ id: v.id, name: v.name, ...warningOf(causes?.get(v.id)?.cause, canWrite) });
    else if (unopenable?.has(v.id)) list.push({ id: v.id, name: v.name, ...itemNoticeOf(canWrite) });
  }
  if (!list.length) return null;
  return {
    vaults: list,
    key: JSON.stringify(list.map((v) => [v.id, v.accept ? (v.forget ? 2 : 1) : 0, v.text === MANIFEST_ITEM_TEXT ? 1 : 0]).sort()),
    confirm: { action: MANIFEST_ACCEPT_ACTION, title: MANIFEST_ACCEPT_TITLE, body: MANIFEST_ACCEPT_BODY, forgetBody: MANIFEST_FORGET_BODY },
  };
}

/** The quiet note: the vaults that aren't checked since "no record" was accepted for them (`key`: for dismissing), or null. */
export function notCheckedNotice(
  vaults: { id: string; name: string }[],
  states: ReadonlyMap<string, ManifestStatus>,
  memory: ManifestMemory,
): { text: string; vaults: { id: string; name: string }[]; key: string } | null {
  const list = vaults.filter((v) => states.get(v.id) === "none" && notChecked(memory, v.id)).map((v) => ({ id: v.id, name: v.name }));
  return list.length ? { text: MANIFEST_NOT_CHECKED_TEXT, vaults: list, key: JSON.stringify(list.map((v) => v.id).sort()) } : null;
}
