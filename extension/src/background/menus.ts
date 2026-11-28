/**
 * PassAuth's right-click menus: the page menu (root "PassAuth" on http/https pages) and the toolbar icon's menu.
 *
 * `menuModel` is pure: from the lock state, the logins for the active tab (the one used last first), the settings and
 * whether the site is hidden, it lists the entries. `refreshMenus` rebuilds chrome.contextMenus from it (debounced, and
 * only when the entries changed) on the triggers the badge uses (tab switch, page load, window focus, storage
 * changes, which also cover lock, unlock, sync and account switches; main.ts). Building it opens the vault only when
 * the page has logins: the match index answers "none" without decrypting anything.
 *
 * Titles name an item and its user name (cards: their name and last four digits), never a password or a code. Chrome
 * offers no "menu shown" event, so the menu can be a moment old: a click is checked again against the clicked frame's
 * address and the tab's current one before anything is filled or copied. Fill entries appear only in editable fields
 * and never on hidden sites. "Fill card ›" (https pages) and "Fill identity ›" list the account's cards and identities
 * (last used first) and fill through fill.ts like the inline menu. "Fill a strong password" shows in password fields
 * only: the page side says when the field the user is in is one (content/context-field.ts, `page:contextField`), and
 * the entry is shown or hidden at once (`chrome.contextMenus.update`), ahead of the menu.
 */
import { isSafari } from "../shared/browser";
import { AppError, CANT_FILL, NOT_FOR_SITE, NOT_FOUND } from "../shared/errors";
import { log, logged } from "../shared/log";
import { pageText } from "../shared/page-text";
import { POPUP_ROUTE_KEY } from "../shared/storage-keys";
import type { PopupRouteRequest, Settings } from "../shared/types";
import { touch } from "./activity";
import { copy } from "./clipboard";
import { copiedText, copyStrongPassword, failureText, fillAfterUnlock, openPopup, orderedMatches } from "./commands";
import { initCore } from "./core";
import { fill, fillItem } from "./fill";
import { noteFillProblem } from "./fill-problems";
import { cardLabel, fillStrongPassword, identityLabel } from "./inline-menu";
import { byLastUsed, lastUsedMap, markUsed } from "./last-used";
import { matchingIds } from "./match-index";
import { sameSiteAsTab } from "./senders";
import { baseDomain, matchesUrl, parse } from "./site";
import { webFrame } from "./sites";
import { activeId, getSettings, local, scratch } from "./storage";
import { notifyTab } from "./toast";
import * as vault from "./vault";

type Context = `${chrome.contextMenus.ContextType}`;

/** One menu entry, as handed to chrome.contextMenus.create. */
export interface MenuEntry {
  id: string;
  /** Absent for separators. */
  title?: string;
  parentId?: string;
  contexts: [Context, ...Context[]];
  enabled?: boolean;
  /** Present but not shown ("Fill a strong password" outside password fields; shown when the user moves into one). */
  visible?: false;
  separator?: true;
}

export type MenuStatus = "signed-out" | "locked" | "unlocked";

/** A login as the menu shows it: name and user name only. */
export interface MenuLogin {
  id: string;
  name: string;
  username: string;
  hasPassword: boolean;
  hasTotp: boolean;
}

export interface MenuState {
  status: MenuStatus;
  /** The active tab's host ("" for a page PassAuth doesn't work on). */
  host: string;
}

/** A card or identity as the menu shows it: its id and a title without secrets (cardLabel / identityLabel). */
export interface MenuItemRef {
  id: string;
  title: string;
}

/** What the unlocked menu offers besides the page's logins. */
export interface MenuExtras {
  /** The account's cards (listed on https pages only) and identities, the one used last first. */
  cards: MenuItemRef[];
  identities: MenuItemRef[];
  /** The page is https (cards are filled only there). */
  https: boolean;
  /** The field the user is in is a password field: "Fill a strong password" shows. */
  passwordField: boolean;
}

export const NO_EXTRAS: MenuExtras = { cards: [], identities: [], https: false, passwordField: false };

export const ROOT = "pa";
/** "Fill a strong password" (shown or hidden as the user moves between fields). */
export const STRONG_ID = `${ROOT}:strong`;
/** Logins, cards or identities listed in each submenu; more opens PassAuth. */
export const MAX_LISTED = 10;
const FILL: [Context, ...Context[]] = ["editable"];
const COPY: [Context, ...Context[]] = ["page", "editable", "selection", "link", "frame"];
const PAGES = ["http://*/*", "https://*/*"];

/**
 * The entries as this browser takes them. Safari has no menu on the toolbar icon ("action") and no "frame" context
 * (its "page" covers frames); an entry with a context it doesn't know isn't created at all.
 */
export function forBrowser(entries: MenuEntry[]): MenuEntry[] {
  if (!isSafari()) return entries;
  return entries.flatMap((e) => {
    const contexts = e.contexts.filter((c) => c !== "action" && c !== "frame");
    return contexts.length ? [{ ...e, contexts: contexts as [Context, ...Context[]] }] : [];
  });
}
const ACTION_PREFIX = "pa-action:";

/**
 * Text for a menu title. Chrome replaces "%s" with the selected text and reads "&" as a keyboard mnemonic, so both
 * are neutralised; long names are shortened.
 */
export function menuText(s: string, max = 60): string {
  const one = s.replace(/\s+/g, " ").trim();
  const short = one.length > max ? `${one.slice(0, max - 1)}…` : one;
  return short.replace(/&/g, "&&").replace(/%s/g, "%​s");
}

const label = (m: MenuLogin) => menuText(m.username ? `${m.name} · ${m.username}` : m.name);

type Field = "user" | "pass" | "code";
const FIELD_TITLES: Record<Field, string> = { user: "Copy user name", pass: "Copy password", code: "Copy verification code" };
const has: Record<Field, (m: MenuLogin) => boolean> = { user: (m) => !!m.username, pass: (m) => m.hasPassword, code: (m) => m.hasTotp };

/**
 * The page menu's entries (none when the setting is off). `matches`: the page's logins, the one used last first;
 * `extras`: the account's cards and identities and whether the user is in a password field (unlocked only).
 */
export function menuModel(state: MenuState, matches: MenuLogin[], settings: Pick<Settings, "contextMenu">, hidden: boolean, extras: MenuExtras = NO_EXTRAS): MenuEntry[] {
  if (!settings.contextMenu) return [];
  const out: MenuEntry[] = [{ id: ROOT, title: "PassAuth", contexts: COPY }];
  const add = (e: Omit<MenuEntry, "parentId">, parentId = ROOT) => out.push({ ...e, parentId });
  let seps = 0;
  const separator = (contexts = COPY) => add({ id: `${ROOT}:sep${++seps}`, contexts, separator: true });
  const unlocked = state.status === "unlocked";
  /** A submenu of items to fill (at most MAX_LISTED, then "More in PassAuth…"). */
  const fillList = (kind: "card" | "identity", title: string, items: MenuItemRef[]) => {
    if (!items.length) return;
    const parent = `${ROOT}:${kind}`;
    add({ id: parent, title, contexts: FILL });
    for (const i of items.slice(0, MAX_LISTED)) add({ id: `${parent}:${i.id}`, title: menuText(i.title), contexts: FILL }, parent);
    if (items.length > MAX_LISTED) {
      add({ id: `${parent}-sep`, contexts: FILL, separator: true }, parent);
      add({ id: `${ROOT}:more-${kind}`, title: "More in PassAuth…", contexts: FILL }, parent);
    }
  };
  /**
   * The entries every unlocked or locked menu ends with: unlocked, the cards and identities to fill and "Fill a
   * strong password" first. `after`: the contexts of what comes before (none: no separator).
   */
  const tail = (after: [Context, ...Context[]] | null = COPY) => {
    const cards = unlocked && !hidden && extras.https ? extras.cards : [];
    const identities = unlocked && !hidden ? extras.identities : [];
    if ((cards.length || identities.length) && after) separator(after);
    fillList("card", "Fill card", cards);
    fillList("identity", "Fill identity", identities);
    const filled = cards.length || identities.length ? FILL : after;
    if (filled) separator(filled);
    if (unlocked && !hidden && state.host) add({ id: STRONG_ID, title: "Fill a strong password", contexts: FILL, ...(extras.passwordField ? {} : { visible: false as const }) });
    add({ id: `${ROOT}:gen`, title: "Copy a strong password", contexts: COPY });
    separator();
    add({ id: `${ROOT}:open`, title: "Open PassAuth", contexts: COPY });
  };

  if (state.status === "signed-out") {
    add({ id: `${ROOT}:signin`, title: "Sign in to PassAuth…", contexts: COPY });
    return out;
  }
  if (state.status === "locked") {
    if (!hidden) add({ id: `${ROOT}:unlock`, title: "Unlock to fill…", contexts: FILL });
    tail(hidden ? null : FILL);
    return out;
  }
  const host = menuText(state.host);
  if (!matches.length) {
    if (!state.host) {
      tail(null);
      return out;
    }
    add({ id: `${ROOT}:none`, title: `No logins for ${host}`, contexts: COPY, enabled: false });
    add({ id: `${ROOT}:add`, title: `Add a login for ${host}…`, contexts: COPY });
    tail();
    return out;
  }
  const fillable = hidden ? [] : matches.filter((m) => m.hasPassword || m.username);
  const only = matches.length === 1 ? matches[0] : undefined;
  if (only) {
    if (fillable.length) add({ id: `${ROOT}:fill:${only.id}`, title: `Fill ${label(only)}`, contexts: FILL });
    const copies = (["user", "pass", "code"] as const).filter((f) => has[f](only));
    for (const f of copies) add({ id: `${ROOT}:${f}:${only.id}`, title: FIELD_TITLES[f], contexts: COPY });
    tail(copies.length ? COPY : fillable.length ? FILL : null);
    return out;
  }
  /** A submenu of logins (at most MAX_LISTED, then "More in PassAuth…"). */
  const list = (kind: "fill" | Field, title: string, logins: MenuLogin[], contexts: [Context, ...Context[]]) => {
    if (!logins.length) return;
    const parent = `${ROOT}:${kind}`;
    add({ id: parent, title, contexts });
    for (const m of logins.slice(0, MAX_LISTED)) add({ id: `${parent}:${m.id}`, title: label(m), contexts }, parent);
    if (logins.length > MAX_LISTED) {
      add({ id: `${parent}-sep`, contexts, separator: true }, parent);
      add({ id: `${ROOT}:more-${kind}`, title: "More in PassAuth…", contexts }, parent);
    }
  };
  list("fill", "Fill", fillable, FILL);
  for (const f of ["user", "pass", "code"] as const) list(f, FIELD_TITLES[f], matches.filter(has[f]), COPY);
  tail();
  return out;
}

/** The toolbar icon's menu (at most 6 entries: Chrome's limit for it). */
export function actionMenuModel(status: MenuStatus): MenuEntry[] {
  const entries: MenuEntry[] = [
    { id: `${ACTION_PREFIX}lock`, title: "Lock now", contexts: ["action"], enabled: status === "unlocked" },
    { id: `${ACTION_PREFIX}sync`, title: "Sync now", contexts: ["action"], enabled: status !== "signed-out" },
    { id: `${ACTION_PREFIX}generator`, title: "Generator", contexts: ["action"] },
    { id: `${ACTION_PREFIX}vault`, title: "Open web vault", contexts: ["action"], enabled: status !== "signed-out" },
  ];
  // Chrome shows at most 6 top-level entries in the toolbar icon's menu.
  return entries.slice(0, 6);
}

const toMenuLogin = (e: vault.Entry): MenuLogin => ({
  id: e.id,
  name: e.item.name || "Untitled",
  username: e.item.login?.username ?? "",
  hasPassword: !!e.item.login?.password,
  hasTotp: !!e.item.login?.totp,
});

/** A card's menu title: its name and the last four digits ("Visa •••• 4242 · 09/28" alone when it has no name). */
const cardTitle = (e: vault.Entry) => {
  const label = cardLabel(e.item.card!);
  return e.item.name && e.item.name !== label ? `${e.item.name} · ${label.split(" · ")[0]}` : label;
};

/** The account's cards and identities, the one used last first (the vault must be open). */
async function fillables(): Promise<Pick<MenuExtras, "cards" | "identities">> {
  const used = await lastUsedMap(await activeId());
  const all = vault.allEntries();
  return {
    cards: byLastUsed(
      all.filter((e) => e.item.card),
      used,
    ).map((e) => ({ id: e.id, title: cardTitle(e) })),
    identities: byLastUsed(
      all.filter((e) => e.item.identity),
      used,
    ).map((e) => ({ id: e.id, title: identityLabel(e.item.identity!, e.item.name) })),
  };
}

/** What the menus show for the active tab of the last focused window. */
async function snapshot(): Promise<{ state: MenuState; matches: MenuLogin[]; settings: Settings; hidden: boolean; extras: MenuExtras }> {
  const l = await local.get();
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  const page = tab?.url ? parse(tab.url) : null;
  const web = !!page && /^https?:$/.test(page.protocol);
  const host = web && page ? page.hostname : "";
  const hidden = !!host && l.hiddenSites.includes(baseDomain(host));
  const status = await vault.lockStatus();
  const https = page?.protocol === "https:";
  const extras: MenuExtras = { ...NO_EXTRAS, https, passwordField: tab?.id !== undefined && contextFields.get(tab.id) === true };
  const base = { settings: l.settings, hidden, extras };
  if (status !== "unlocked" || !web || !tab?.url || !l.settings.contextMenu) return { ...base, state: { status, host }, matches: [] };
  // No logins for the page and nothing else to list by the match index: no need to open (decrypt) the vault for the menu.
  const index = await vault.unlockedIndex().catch(() => null);
  const others = !hidden && ((https && (index?.cards ?? 1) > 0) || (index?.identities ?? 1) > 0);
  if (index && !others && !matchingIds(index, tab.url, l.settings.defaultMatch).length) return { ...base, state: { status, host }, matches: [] };
  if (!(await vault.ensureUnlocked().catch(() => false))) return { ...base, state: { status: "locked", host }, matches: [] };
  return { ...base, extras: { ...extras, ...(await fillables()) }, state: { status, host }, matches: (await orderedMatches(tab.url)).map(toMenuLogin) };
}

// A digest of the entries Chrome has now, so an unchanged menu isn't rebuilt. In session storage (menus outlive a
// worker restart); a digest, so no item names are kept there.
const BUILT_KEY = "menuBuilt";

async function digest(text: string): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return Array.from(hash, (b) => b.toString(16).padStart(2, "0")).join("");
}
let timer: ReturnType<typeof setTimeout> | undefined;
let chain: Promise<void> = Promise.resolve();

/** Rebuild the menus soon (changes come in bursts: one rebuild for all of them). `force`: Chrome's menus were cleared (install, update). */
export function refreshMenus(force = false) {
  if (force) void scratch.remove(BUILT_KEY).catch(logged("Resetting the menu state"));
  clearTimeout(timer);
  timer = setTimeout(() => void applyMenu(), 150);
}

/** Rebuild now, after any rebuild still running (refreshMenus debounces the calls). */
export function applyMenu(): Promise<void> {
  chain = chain.then(rebuild, rebuild);
  return chain;
}

async function rebuild() {
  // No right-click menu API (a browser without one).
  if (!chrome.contextMenus) return;
  try {
    await initCore();
    const s = await snapshot();
    const entries = forBrowser([...menuModel(s.state, s.matches, s.settings, s.hidden, s.extras), ...actionMenuModel(s.state.status)]);
    const key = await digest(JSON.stringify(entries));
    if ((await scratch.get<string>(BUILT_KEY)) === key) return;
    await chrome.contextMenus.removeAll();
    for (const e of entries) {
      const common = {
        id: e.id,
        contexts: e.contexts,
        ...(e.parentId ? { parentId: e.parentId } : {}),
        ...(e.enabled === false ? { enabled: false } : {}),
        ...(e.visible === false ? { visible: false } : {}),
      };
      const pages = e.contexts.includes("action") ? {} : { documentUrlPatterns: PAGES };
      // Errors (a duplicate id after a race) arrive in the callback; nothing else to do with them.
      const done = () => void chrome.runtime.lastError;
      if (e.separator) chrome.contextMenus.create({ ...common, ...pages, type: "separator" }, done);
      else chrome.contextMenus.create({ ...common, ...pages, title: e.title ?? "" }, done);
    }
    await scratch.set(BUILT_KEY, key);
  } catch (e) {
    log.warn("Updating the right-click menu failed:", e);
  }
}

// ------------------------------------------------------------ password fields

/** Per tab: whether the field the user is in is a password field on the tab's site (content/context-field.ts). */
const contextFields = new Map<number, boolean>();

/**
 * page:contextField: the user moved into a password field, or out of one. "Fill a strong password" is shown or hidden
 * at once for the active tab (the next rebuild draws it the same way).
 */
export function noteContextField(sender: chrome.runtime.MessageSender, password: boolean) {
  const tabId = sender.tab?.id;
  if (tabId === undefined) return;
  // Only a frame on the tab's site: the fill goes nowhere else.
  const value = password && sameSiteAsTab(webFrame(sender));
  if (contextFields.get(tabId) === value) return;
  contextFields.set(tabId, value);
  // Not in the menu right now (locked, hidden site, the setting off): an error to ignore.
  if (sender.tab?.active && chrome.contextMenus) chrome.contextMenus.update(STRONG_ID, { visible: value }, () => void chrome.runtime.lastError);
}

/** A tab closed. */
export function forgetContextField(tabId: number) {
  contextFields.delete(tabId);
}

// ------------------------------------------------------------------ clicks

export function onMenuClicked(info: chrome.contextMenus.OnClickData, tab?: chrome.tabs.Tab) {
  void menuClick(info, tab).catch(logged("A right-click menu action"));
}

/** The login `id`, if it still belongs to the clicked frame's address and the tab's current one (and the site isn't hidden for fills). */
async function checkedLogin(id: string, frameUrl: string, tabId: number, forFill: boolean): Promise<vault.Entry> {
  const entry = vault.getEntry(id);
  const login = entry?.item.login;
  if (!entry || !login) throw new AppError(NOT_FOUND, "This login is gone. Open PassAuth to check it.", true);
  const current = (await chrome.tabs.get(tabId)).url ?? "";
  const { defaultMatch } = await getSettings();
  const personal = vault.isPersonal(entry);
  const fits = (url: string) => /^https?:$/.test(parse(url)?.protocol ?? "") && login.urls.some((u) => matchesUrl(url, u, defaultMatch, personal));
  if (!fits(frameUrl) || !fits(current)) throw new AppError(NOT_FOR_SITE, "This login isn't saved for this site.");
  if (forFill) {
    const { hiddenSites } = await local.get();
    if (hiddenSites.includes(baseDomain(parse(current)?.hostname ?? "")))
      throw new AppError(CANT_FILL, "PassAuth's fill entries are hidden on this site. Show them again in PassAuth's settings.", true);
  }
  return entry;
}

/**
 * The clicked frame for a card, identity or strong-password fill, if it is still on the tab's current site (an
 * https page for cards) and the site isn't hidden. Returns the tab's site.
 */
async function checkedFrame(frameUrl: string, tabId: number, https: boolean): Promise<string> {
  const current = parse((await chrome.tabs.get(tabId)).url ?? "");
  const frame = parse(frameUrl);
  const web = (u: URL | null) => !!u && (https ? u.protocol === "https:" : /^https?:$/.test(u.protocol));
  if (!current || !frame || !web(current) || !web(frame) || baseDomain(frame.hostname) !== baseDomain(current.hostname)) {
    throw new AppError(CANT_FILL, https ? "PassAuth fills cards only on secure (https) pages of the site you're on." : "PassAuth can only fill on the site you're on.", true);
  }
  const site = baseDomain(current.hostname);
  const { hiddenSites } = await local.get();
  if (hiddenSites.includes(site)) throw new AppError(CANT_FILL, "PassAuth's fill entries are hidden on this site. Show them again in PassAuth's settings.", true);
  return site;
}

/** The card or identity `id`, if it still is one. */
function checkedItem(kind: "card" | "identity", id: string): vault.Entry {
  const entry = vault.getEntry(id);
  if (!entry || !(kind === "card" ? entry.item.card : entry.item.identity)) throw new AppError(NOT_FOUND, "This item is gone. Open PassAuth to check it.", true);
  return entry;
}

async function copyField(field: Field, id: string, frameUrl: string, tabId: number) {
  const entry = await checkedLogin(id, frameUrl, tabId, false);
  const login = entry.item.login;
  const value = field === "user" ? login?.username : field === "pass" ? login?.password : login?.totp ? vault.totp(login.totp).code : "";
  if (!value) throw new AppError(NOT_FOUND, "Nothing to copy.", true);
  await touch();
  await copy(value);
  void markUsed(await activeId(), id).catch(logged("Noting the login as used"));
  const { clearClipboard } = await getSettings();
  await notifyTab(tabId, copiedText(field === "user" ? "username" : field === "pass" ? "password" : "totp", clearClipboard));
}

async function addLogin(tab: chrome.tabs.Tab) {
  const page = parse(tab.url ?? "");
  const route: PopupRouteRequest = { page: "new", kind: "login", ...(page && /^https?:$/.test(page.protocol) ? { url: page.origin } : {}) };
  await scratch.set(POPUP_ROUTE_KEY, route);
  await openPopup();
}

/** One click on a PassAuth menu entry (exported for tests; `onMenuClicked` is the listener). */
export async function menuClick(info: chrome.contextMenus.OnClickData, tab?: chrome.tabs.Tab) {
  await initCore();
  const id = String(info.menuItemId);
  if (id.startsWith(ACTION_PREFIX)) return actionClick(id.slice(ACTION_PREFIX.length));
  if (!id.startsWith(`${ROOT}:`)) return;
  const [, action = "", itemId = ""] = id.split(":");
  const tabId = tab?.id;
  if (action === "open" || action === "signin" || action.startsWith("more-")) return openPopup();
  if (tabId === undefined || tabId < 0) return;
  const frameUrl = info.frameUrl ?? info.pageUrl ?? tab?.url ?? "";
  const frameId = info.frameId ?? 0;
  const waiting = { kind: "menu" as const, tabId, pageUrl: tab?.url ?? "", frameId, frameUrl };
  try {
    switch (action) {
      case "gen":
        return await copyStrongPassword(tabId);
      case "add":
        return await addLogin(tab!);
      case "unlock":
        return await fillAfterUnlock(waiting);
      case "fill": {
        // Locked since the menu was built: this login is filled right after the unlock (commands.ts afterUnlock).
        if (!(await vault.ensureUnlocked())) return await fillAfterUnlock({ ...waiting, itemId });
        await checkedLogin(itemId, frameUrl, tabId, true);
        await touch();
        // Into the frame that was right-clicked, at its focused field (fill.ts checks the frame again).
        return await fill(itemId, tabId, { frameId, url: frameUrl });
      }
      case "card":
      case "identity": {
        if (!(await vault.ensureUnlocked())) return await fillAfterUnlock({ ...waiting, itemId });
        checkedItem(action, itemId);
        await checkedFrame(frameUrl, tabId, action === "card");
        await touch();
        // Into the right-clicked frame at its focused field; fill.ts checks the frame's real origin again.
        return await fillItem(itemId, tabId, frameId);
      }
      case "strong": {
        if (!(await vault.ensureUnlocked())) return await openPopup();
        await checkedFrame(frameUrl, tabId, false);
        await touch();
        return await fillStrongPassword(tabId, { frameId, url: frameUrl }, "context");
      }
      case "user":
      case "pass":
      case "code":
        if (!(await vault.ensureUnlocked())) return await openPopup();
        return await copyField(action, itemId, frameUrl, tabId);
    }
  } catch (e) {
    log.debug("A right-click menu action failed:", e);
    if (action === "fill" || action === "card" || action === "identity" || action === "strong") await noteFillProblem(tabId, e).catch(logged("Keeping the fill problem"));
    await notifyTab(tabId, failureText(e, pageText`PassAuth couldn't do that on this page.`));
  }
}

async function actionClick(action: string) {
  if (action === "lock") return vault.lockAll();
  if (action === "sync") {
    if (await vault.ensureUnlocked()) return vault.sync();
    return openPopup();
  }
  if (action === "generator") {
    await scratch.set(POPUP_ROUTE_KEY, { page: "generator" } satisfies PopupRouteRequest);
    return openPopup();
  }
  if (action === "vault") {
    const { server } = await local.get();
    if (server) await chrome.tabs.create({ url: server });
  }
}
