/**
 * Where the popup was: route, search, filters and the list's scroll position, kept in chrome.storage.session
 * (`popupView`) so reopening the popup within VIEW_KEEP_MS comes back to the same place, with an open editor's draft
 * (what was typed, not saved yet). The background removes it when PassAuth locks, signs out or switches accounts. A
 * page the background asked for (`popupRoute`: the right-click menu's "Add a login", the save prompt…) comes first
 * and is used once (without a draft).
 */
import type { Item, ItemKind } from "@web/lib/types";
import { POPUP_ROUTE_KEY, POPUP_VIEW_KEY, VIEW_KEEP_MS } from "../shared/storage-keys";
import type { PopupRouteRequest } from "../shared/types";
import type { Route } from "./ctx";

export interface ListFilter {
  query: string;
  kind: ItemKind | "";
  folder: string | null; // null = any, "" = no folder
  favorite: boolean;
  /** A vault id, or null for every vault. */
  vault: string | null;
}

export const NO_FILTER: ListFilter = { query: "", kind: "", folder: null, favorite: false, vault: null };
export const LIST: Route = { tab: "vault", page: "list" };

/** An open editor's unsaved draft. */
export interface Draft {
  /** Which editor: `editorKey(route)`. */
  key: string;
  item: Item;
  /** A new item's id (kept, so a save tried again after reopening can't add it twice). */
  newId?: string;
}

interface ViewState {
  account: string;
  at: number;
  route: Route;
  filter: ListFilter;
  scroll: number;
  draft?: Draft;
}

export interface Start {
  route: Route;
  filter: ListFilter;
  scroll: number;
  /** The draft of the editor the popup starts in. */
  draft?: Draft;
}

/**
 * A storage change that means the account's vault changed: the worker rewrites the match index (`index:<account>`,
 * session storage, which carries the vault's revision) after every sync that brought something, also from live sync
 * while the popup is open, and removes it when PassAuth locks.
 */
export function vaultChanged(changes: Record<string, unknown>, area: string, accountId: string): boolean {
  return area === "session" && !!accountId && `index:${accountId}` in changes;
}

/** Which editor a route opens ("edit:<id>", "new:<kind>"), or null for other pages. */
export function editorKey(route: Route): string | null {
  if (route.tab !== "vault") return null;
  if (route.page === "edit") return `edit:${route.id}`;
  if (route.page === "new") return `new:${route.kind}`;
  return null;
}

/** A draft larger than this isn't kept (a huge note): reopening shows the item as saved. */
const MAX_DRAFT_CHARS = 512 * 1024;

/** A stored draft that still has a known shape. */
function validDraft(d: unknown): Draft | null {
  const x = d as Partial<Draft> | null;
  if (!x || typeof x !== "object" || typeof x.key !== "string" || !x.item || typeof x.item !== "object" || typeof x.item.name !== "string") return null;
  return { key: x.key, item: x.item, ...(typeof x.newId === "string" && /^[0-9a-f-]{36}$/i.test(x.newId) ? { newId: x.newId } : {}) };
}

const KINDS = new Set<ItemKind>(["login", "note", "card", "identity", "ssh_key"]);
const str = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length < 200;

/** A stored route, if it still has a known shape. */
function validRoute(r: unknown): Route | null {
  const x = r as Partial<Record<string, unknown>> | null;
  if (!x || typeof x !== "object") return null;
  if (x.tab === "generator") return { tab: "generator" };
  if (x.tab === "settings") return { tab: "settings", ...(str(x.section) ? { section: x.section } : {}) };
  if (x.tab !== "vault") return null;
  if (x.page === "list") return LIST;
  if ((x.page === "item" || x.page === "edit" || x.page === "history") && str(x.id)) return { tab: "vault", page: x.page, id: x.id };
  if (x.page === "new" && KINDS.has(x.kind as ItemKind)) return { tab: "vault", page: "new", kind: x.kind as ItemKind };
  return null;
}

/** The page the background asked for (`PopupRouteRequest`), as a route. */
export function routeFor(ask: unknown): Route | null {
  const a = ask as Partial<PopupRouteRequest> | null;
  if (!a || typeof a !== "object") return null;
  if (a.page === "generator") return { tab: "generator" };
  if (a.page === "new" && (a.kind === "login" || a.kind === "card" || a.kind === "identity")) {
    const prefill = { ...(str(a.url) ? { url: a.url } : {}), ...(typeof a.username === "string" && a.username ? { username: a.username.slice(0, 1024) } : {}) };
    return { tab: "vault", page: "new", kind: a.kind, prefill };
  }
  return null;
}

/** Where the popup starts for `account`: a page the background asked for (used up), else where it was within VIEW_KEEP_MS, else the list. */
export async function takeStart(account: string): Promise<Start> {
  const got: Record<string, unknown> = await chrome.storage.session.get([POPUP_ROUTE_KEY, POPUP_VIEW_KEY]).catch(() => ({}));
  const asked = routeFor(got[POPUP_ROUTE_KEY]);
  if (got[POPUP_ROUTE_KEY] !== undefined) await chrome.storage.session.remove(POPUP_ROUTE_KEY).catch(() => {});
  const view = got[POPUP_VIEW_KEY] as Partial<ViewState> | undefined;
  const now = Date.now();
  const fresh = !!view && view.account === account && typeof view.at === "number" && now - view.at < VIEW_KEEP_MS && now >= view.at;
  const filter = fresh && view.filter ? { ...NO_FILTER, ...view.filter } : NO_FILTER;
  if (asked) return { route: asked, filter, scroll: 0 };
  const route = (fresh && validRoute(view.route)) || LIST;
  const draft = fresh ? validDraft(view.draft) : null;
  return {
    route,
    filter,
    scroll: fresh && typeof view.scroll === "number" ? view.scroll : 0,
    // Only for the editor it was typed in.
    ...(draft && draft.key === editorKey(route) ? { draft } : {}),
  };
}

/** The view to write (the last one saved), whether a write is due, and the open editor's draft. */
let last: Omit<ViewState, "at" | "draft"> | null = null;
let due = false;
let draft: Draft | null = null;
let timer: ReturnType<typeof setTimeout> | undefined;

function schedule() {
  due = true;
  clearTimeout(timer);
  timer = setTimeout(flushView, 300);
}

/** Remember where the popup is (written a moment later; `flushView` writes it now). */
export function saveView(v: Omit<ViewState, "at" | "draft">) {
  last = v;
  schedule();
}

/** Remember the open editor's draft with the view (null: the editor was left, saved or discarded). */
export function saveDraft(d: Draft | null) {
  if (d && JSON.stringify(d.item).length > MAX_DRAFT_CHARS) d = null;
  if (!d && !draft) return;
  draft = d;
  if (last) schedule();
}

export function flushView() {
  clearTimeout(timer);
  if (!due || !last) return;
  due = false;
  const v: ViewState = { ...last, ...(draft ? { draft } : {}), at: Date.now() };
  void chrome.storage.session.set({ [POPUP_VIEW_KEY]: v }).catch(() => {});
}

/** Forget a write that hasn't happened yet (the popup is leaving the unlocked screens: locked, signed out). */
export function dropPendingView() {
  clearTimeout(timer);
  due = false;
  last = null;
  draft = null;
}
