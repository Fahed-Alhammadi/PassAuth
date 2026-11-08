import { useSyncExternalStore } from "react";
import type { Item } from "./types";

/**
 * A change prepared outside the vault page, opened in the item editor for the user to review and save
 * (nothing is saved on its own). The desktop app uses it for verification codes from otpauth links;
 * the browser and the extension never open one.
 */
export interface ItemDraft {
  /** The route's item: an existing item's id, or `new-<kind>` for a new item. */
  itemId: string;
  /** Applied to the item (or the empty new item) the editor starts from. */
  apply(item: Item): Item;
  seq: number;
}

let draft: ItemDraft | null = null;
let seq = 0;
const listeners = new Set<() => void>();
const notify = () => listeners.forEach((fn) => fn());

/** Open `/vault/<filter>/<itemId>` too: the draft only shows while that item's route is open. */
export function openDraft(itemId: string, apply: (item: Item) => Item) {
  draft = { itemId, apply, seq: ++seq };
  notify();
}

export function clearDraft() {
  if (!draft) return;
  draft = null;
  notify();
}

export const getDraft = () => draft;

/** True while the vault page's item editor has unsaved changes (opening a draft would replace it). */
let editorDirty = false;
export const setEditorDirty = (dirty: boolean) => {
  editorDirty = dirty;
};
export const hasUnsavedEdit = () => editorDirty;

/** Drop the draft once its item's route (`/vault/<filter>/<itemId>`) is no longer open. */
export function keepDraftFor(pathname: string) {
  if (!draft) return;
  const parts = pathname.split("/");
  let itemId: string | undefined;
  try {
    itemId = parts[1] === "vault" && parts[3] ? decodeURIComponent(parts[3]) : undefined;
  } catch {
    itemId = undefined;
  }
  if (itemId !== draft.itemId) clearDraft();
}

export function useDraft() {
  return useSyncExternalStore(
    (fn) => {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    () => draft,
  );
}
