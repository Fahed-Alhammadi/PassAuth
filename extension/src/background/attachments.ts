/**
 * Files attached to items (servers with `attachments`; docs/ARCHITECTURE.md "Attachments"), for the popup: which of
 * an item's files the server no longer has, and what downloading one needs. The popup downloads and decrypts the
 * file itself (popup/files.tsx, the core's `FileDecryptor`): the plaintext never crosses a message, and nothing of
 * it is released before the core has checked the whole file. Adding and removing files happens in the web vault; a
 * save from here keeps the item's file list as last synced (`keptFiles`), so it never drops a file attached
 * elsewhere (the web vault's `withAttachmentsOf` rule).
 */
import { missingOnServer, readAttachments, readStoredAttachments, sameId, stripAttachments, withAttachmentsOf } from "@web/lib/attachments";
import type { Item } from "@web/lib/types";
import { AppError, NOT_FOUND, signedOutError } from "../shared/errors";
import { log } from "../shared/log";
import type { FileAccess } from "../shared/types";
import { api, clientHeaders, renewAccess } from "./api";
import { activeId, local } from "./storage";
import type { Entry } from "./vault";
import * as vault from "./vault";

const itemOf = (id: string): Entry => {
  const e = vault.getEntry(id);
  if (!e) throw new AppError(NOT_FOUND, "This item isn't in your vault any more.");
  return e;
};

/**
 * The ids of the item's files that the server doesn't have (deleted since, e.g. listed again by restoring an earlier
 * version): `GET /items/{id}/attachments`. Null when the server can't say (offline, or a server without files).
 */
export async function missingFiles(itemId: string): Promise<string[] | null> {
  const list = readAttachments(itemOf(itemId).item);
  if (!list.length) return [];
  try {
    const stored = readStoredAttachments(await api<unknown>(`/items/${encodeURIComponent(itemId)}/attachments`));
    return [...missingOnServer(list, stored)];
  } catch (e) {
    log.debug("Listing an item's files failed:", e);
    return null;
  }
}

/**
 * What downloading one of the item's files needs: its address on the account's server, a current access token
 * (`renew`: a new one, after the last one was refused) and the app name every request carries. Only for a file the
 * item lists. The file's key is in the item the popup already has.
 */
export async function fileAccess(itemId: string, attachmentId: string, renew = false): Promise<FileAccess> {
  const att = readAttachments(itemOf(itemId).item).find((a) => sameId(a.id, attachmentId));
  if (!att) throw new AppError(NOT_FOUND, "This file isn't listed in the item any more.");
  const id = await activeId();
  if (renew) await renewAccess(id);
  const { data } = await local.account(id);
  if (!data?.server || !data.tokens) throw signedOutError();
  return { url: `${data.server}/api/attachments/${encodeURIComponent(att.id)}`, token: data.tokens.access, client: clientHeaders()["x-passauth-client"] ?? "" };
}

/**
 * An item saved from the popup's editor (or its star): with the file list of the item as last synced, never the
 * draft's. A file attached on another device while the editor was open stays listed; nothing can point an item at
 * another item's files.
 */
export const keptFiles = (draft: Item, synced: Item): Item => withAttachmentsOf(draft, synced);

/** A new item from the popup lists no files (the popup can't add any). */
export const withoutFiles = (draft: Item): Item => stripAttachments(draft);
