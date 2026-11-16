/**
 * Attachments (servers with the `attachments` feature): files encrypted on the device, each with a random key of its
 * own, and listed inside the encrypted item as `attachments: [{id, name, size, key}]` (`size` is the file's own size).
 * The server keeps the ciphertext under the attachment's id and a row (item, vault, encrypted size, pending or ready);
 * it never sees a file's name, key or contents.
 *
 * Adding one: a new key → `POST /items/{id}/attachments {id, size: encrypted size}` → `PUT /attachments/{id}` with the
 * encrypted file → save the item listing it (if that save fails for good, `DELETE` the attachment). Removing one: save
 * the item without it, then `DELETE`. Entries are changed one by one, so fields a newer app adds to an entry are kept.
 * Files aren't exported: `stripAttachments` drops the list from exported and imported items, so no file key leaves in
 * a file and no imported item points at another item's files.
 *
 * Pure (no WASM, no network, no React) and unit-tested in `attachments.test.ts`; `transfer.ts` moves the files and
 * `files.ts` connects both to the vault.
 */
import { stripInvisible } from "./text";
import type { Attachment, Item } from "./types";

export const MIB = 1024 * 1024;
/** Longest file name kept, in characters. */
const NAME_MAX = 255;
/** Attachment ids are UUIDs (the server refuses anything else). */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The raw list of an item (or version), whatever its entries hold. */
const rawList = (item: { attachments?: unknown } | null | undefined): unknown[] => (Array.isArray(item?.attachments) ? item.attachments : []);

/** An entry's id, lowercased for comparing (the server answers in lowercase); null when it isn't a UUID. */
const entryId = (v: unknown): string | null => {
  const id = v && typeof v === "object" ? (v as Record<string, unknown>).id : null;
  return typeof id === "string" && UUID.test(id) ? id.toLowerCase() : null;
};

/** Whether two attachment ids name the same attachment (UUIDs, in any letter case). */
export const sameId = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase();

/**
 * The files an item lists, for showing and opening them. Entries without an id or key, and repeated ids, are left out.
 * Ids are kept as written: the file's encryption is bound to them exactly. Names are cleaned (`cleanFileName`): another
 * member of a shared vault may have chosen one to look like something else.
 */
export function readAttachments(item: { attachments?: unknown } | null | undefined): Attachment[] {
  const seen = new Set<string>();
  const out: Attachment[] = [];
  for (const raw of rawList(item)) {
    const lower = entryId(raw);
    if (!lower || seen.has(lower)) continue;
    const v = raw as Record<string, unknown>;
    if (typeof v.key !== "string" || !v.key) continue;
    seen.add(lower);
    out.push({
      id: v.id as string,
      name: cleanFileName(typeof v.name === "string" ? v.name : ""),
      size: typeof v.size === "number" && Number.isFinite(v.size) && v.size >= 0 ? Math.floor(v.size) : 0,
      key: v.key,
    });
  }
  return out;
}

/** `item` listing exactly `list` (raw entries); an empty list removes the field, as for an item that never had files. */
export function setAttachments<T extends object>(item: T, list: unknown[]): T {
  const copy = { ...item } as T & { attachments?: unknown };
  if (list.length) copy.attachments = list;
  else delete copy.attachments;
  return copy;
}

/** `item` with `added` at the end of its list. */
export const addAttachments = (item: Item, added: Attachment[]): Item => setAttachments(item, [...rawList(item), ...added]);

/** `item` without the attachment `id`. */
export const removeAttachment = (item: Item, id: string): Item =>
  setAttachments(
    item,
    rawList(item).filter((a) => entryId(a) !== id.toLowerCase()),
  );

/** `item` (an edited draft) listing the files of `from` (the item as last synced): the editor never changes the list. */
export const withAttachmentsOf = (item: Item, from: Item | null | undefined): Item => setAttachments(item, rawList(from));

/**
 * Every entry of `first`, then those of `second` with other ids. Restoring an earlier version keeps the files of both:
 * none of the item's files is left without an item, and a file deleted since shows as missing.
 */
export function mergeAttachments(first: { attachments?: unknown } | null | undefined, second: { attachments?: unknown } | null | undefined): unknown[] {
  const seen = new Set<string>();
  const out: unknown[] = [];
  for (const raw of [...rawList(first), ...rawList(second)]) {
    const id = entryId(raw);
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push(raw);
  }
  return out;
}

/** An item for an export file or an import: without its file list (and so without the files' keys). */
export function stripAttachments<T extends object>(item: T): T {
  if (!("attachments" in item)) return item;
  const copy = { ...item } as T & { attachments?: unknown };
  delete copy.attachments;
  return copy;
}

/** Whether any of `items` lists a file (the export page then says files aren't included). */
export const anyAttachments = (items: { attachments?: unknown }[]): boolean => items.some((i) => readAttachments(i).length > 0);

// ------------------------------------------------------------------ sizes

/**
 * Whether a file of `plainSize` bytes is too large for the server: its limit (`max_attachment_mb`) applies to the
 * encrypted size, as the server counts it. Null `maxMb` (an older server that doesn't say) never refuses.
 */
export function tooLarge(plainSize: number, maxMb: number | null, encryptedSize: (plain: number) => number): boolean {
  if (maxMb === null || !(maxMb > 0)) return false;
  return encryptedSize(plainSize) > maxMb * MIB;
}

/** The server's attachment limit in MB from `/api/config` `limits`, or null when it doesn't say. */
export function attachmentLimitMb(limits: unknown): number | null {
  const v = limits && typeof limits === "object" ? (limits as Record<string, unknown>).max_attachment_mb : undefined;
  return typeof v === "number" && Number.isFinite(v) && v >= 1 ? Math.floor(v) : null;
}

// ------------------------------------------------------------------ names

/** Longest name a downloaded file is saved under, in characters. */
const SAVE_MAX = 200;
/** Characters a file name can't hold on some system (Windows' list covers the others), saved as "_". */
const NOT_IN_NAMES = /[\\/:*?"<>|]/g;
/**
 * Names Windows keeps for devices, also with any extension ("CON", "nul.txt", "COM1.tar.gz", "LPT¹"): a file can't be
 * saved under them.
 */
const DEVICE_NAME = /^(?:con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])\s*(?:\.|$)/i;

/**
 * What every shown or saved name goes through: no control or format characters (bidi overrides such as U+202E would
 * show "invoice", U+202E, "fdp.exe" as "invoiceexe.pdf"), one space for any run of white space (so spaces can't push the real
 * extension out of sight), and no dots or spaces at the end (Windows drops them: "report.exe." is "report.exe").
 */
const tidy = (name: string): string => stripInvisible(name).replace(/\s+/g, " ").trim().replace(/[.\s]+$/, "");

/** `name` cut to `max` characters, keeping a short extension at its end. */
function shorten(name: string, max: number): string {
  const chars = Array.from(name);
  if (chars.length <= max) return name;
  const dot = name.lastIndexOf(".");
  const ext = dot > 0 ? Array.from(name.slice(dot)) : [];
  const keep = ext.length > 1 && ext.length <= 16 ? ext : [];
  return chars.slice(0, max - keep.length).join("").replace(/[.\s]+$/, "") + keep.join("");
}

/**
 * The name kept and shown for a file: its own name without folders, control or format characters, runs of white
 * space or trailing dots and spaces, at most 255 characters; "Attachment" when nothing is left.
 */
export function cleanFileName(name: string): string {
  const base = stripInvisible(name).split(/[\\/]/).pop() ?? "";
  return shorten(tidy(base), NAME_MAX) || "Attachment";
}

/**
 * The name a downloaded file is saved under (and offered in a save dialog): the stored name cleaned as above, with "_"
 * for characters a file system would refuse, without leading dots (no hidden files), not a Windows device name, at most
 * 200 characters with its extension kept; "attachment" when nothing is left.
 */
export function downloadName(name: string): string {
  const clean = shorten(tidy(tidy(name).replace(NOT_IN_NAMES, "_").replace(/^[.\s]+/, "")), SAVE_MAX);
  if (!clean) return "attachment";
  return DEVICE_NAME.test(clean) ? `_${clean}` : clean;
}

// --------------------------------------------------------- server's list

/** An attachment as the server lists it (`GET /items/{id}/attachments`): never its name or key. */
export interface StoredAttachment {
  id: string;
  /** Bytes of the encrypted file. */
  size: number;
  state: "pending" | "ready";
  /** Unix seconds: when it was made, started uploading or became ready. */
  updatedAt: number;
}

/** The server's list for an item; malformed entries are left out. */
export function readStoredAttachments(value: unknown): StoredAttachment[] {
  const list = value && typeof value === "object" ? (value as Record<string, unknown>).attachments : null;
  if (!Array.isArray(list)) return [];
  const out: StoredAttachment[] = [];
  for (const raw of list) {
    const id = entryId(raw);
    if (!id) continue;
    const v = raw as Record<string, unknown>;
    if (v.state !== "pending" && v.state !== "ready") continue;
    out.push({
      id,
      size: typeof v.size === "number" && Number.isFinite(v.size) ? v.size : 0,
      state: v.state,
      updatedAt: typeof v.updated_at === "number" && Number.isFinite(v.updated_at) ? v.updated_at : 0,
    });
  }
  return out;
}

/** The listed files the server doesn't have (deleted since, e.g. listed again by restoring an earlier version). */
export function missingOnServer(list: Attachment[], stored: StoredAttachment[]): Set<string> {
  const ready = new Set(stored.filter((s) => s.state === "ready").map((s) => s.id));
  return new Set(list.filter((a) => !ready.has(a.id.toLowerCase())).map((a) => a.id));
}

/** Uploads whose item doesn't list them may still be on their way to the item for this long (seconds). */
export const LEFTOVER_AFTER = 15 * 60;

/**
 * Files on the server that the item doesn't list and that nobody is still attaching: an upload whose item was never
 * saved (the page closed in between). They count toward storage until deleted. Pending uploads are left to the server,
 * which deletes them after an hour.
 */
export function leftovers(item: Item | null | undefined, stored: StoredAttachment[], now: number): StoredAttachment[] {
  const listed = new Set(readAttachments(item).map((a) => a.id.toLowerCase()));
  return stored.filter((s) => s.state === "ready" && !listed.has(s.id) && now - s.updatedAt >= LEFTOVER_AFTER);
}
