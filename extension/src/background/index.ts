/** PassAuth extension service worker: message router, autofill, inline menu, save prompts, vault timeout. */
import type { ContentCommand, InlineInfo, InlineItems, Request, Reply, SaveAnswer, SaveOffer, SavePrompt, Settings } from "../shared/messages";
import type { LoginUrl } from "@web/lib/types";
import { copy } from "./clipboard";
import { getSettings, local, scratch } from "./storage";
import { cancelPasskey, decide, handlePasskey, pendingRequest } from "./passkey-handler";
import { applyToLogin, chosenTarget, NEW_LOGIN, planSave, type SaveTarget } from "./save-plan";
import { baseDomain, downgrade, matchesUrl, parse } from "./urls";
import { clampPromptHeight, promptHeight } from "../shared/save-layout";
import { openCentered, POPUP_WINDOW } from "../shared/windows";
import * as vault from "./vault";

// The service worker sleeps after ~30 s idle and loses everything in memory.
// State that must outlive that (inline-menu nonces, pending save prompts,
// popup activity) lives in chrome.storage.session, which only extension
// pages and this worker can read.

// ---------------------------------------------------------- vault timeout

/** Run the user's timeout action (lock, or sign out which also forgets the vault data). */
async function timeout() {
  const { settings } = await local.get();
  if (settings.timeoutAction === "logout") await vault.logoutAll();
  else await vault.lockAll();
}

let lastTouch = 0;
/** Activity in PassAuth restarts the inactivity timer (at most every 30 s unless `force`). */
async function touch(force = false) {
  if (!force && Date.now() - lastTouch < 30_000) return;
  lastTouch = Date.now();
  const { vaultTimeout } = await getSettings();
  if (typeof vaultTimeout === "number" && vaultTimeout > 0) await chrome.alarms.create("autolock", { delayInMinutes: vaultTimeout });
  else await chrome.alarms.clear("autolock");
}

chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === "autolock") void timeout();
});
chrome.idle.setDetectionInterval(60);
chrome.idle.onStateChanged.addListener(async (s) => {
  if (s === "locked" && (await getSettings()).vaultTimeout === "system-lock") await timeout();
});
// Keys in session storage are gone after a browser restart (locked); "sign out" also drops the session.
chrome.runtime.onStartup.addListener(async () => {
  const { vaultTimeout, timeoutAction } = await getSettings();
  if (vaultTimeout !== "never" && timeoutAction === "logout") await timeout();
});

// "Immediately": time out as soon as the last PassAuth window closes. The popup
// keeps a port open and sends a heartbeat (which also keeps this worker awake);
// if the worker was stopped anyway, the popup reconnects. As a backstop, the
// last heartbeat time is kept in session storage and checked before the vault
// is used (`lockCheck`).
const popupPorts = new Set<chrome.runtime.Port>();
const POPUP_SEEN = "popupSeen";

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "popup" || port.sender?.id !== chrome.runtime.id || !(port.sender.url ?? "").startsWith(chrome.runtime.getURL(""))) return;
  popupPorts.add(port);
  void scratch.set(POPUP_SEEN, Date.now());
  port.onMessage.addListener(() => void scratch.set(POPUP_SEEN, Date.now()));
  port.onDisconnect.addListener(async () => {
    popupPorts.delete(port);
    if (popupPorts.size) return;
    await scratch.set(POPUP_SEEN, 0);
    if ((await getSettings()).vaultTimeout === "immediately") await timeout();
  });
});

vault.setLockCheck(async () => {
  if (popupPorts.size || (await getSettings()).vaultTimeout !== "immediately") return;
  const seen = (await scratch.get<number>(POPUP_SEEN)) ?? 0;
  if (Date.now() - seen > 60_000 && (await vault.anyUnlocked())) await timeout();
});

// ------------------------------------------------------------ icon badge

/** Show how many saved logins match each window's active tab (nothing while locked). */
async function updateBadge() {
  const { settings } = await local.get();
  const unlocked = settings.badge && (await vault.ensureUnlocked().catch(() => false));
  for (const tab of await chrome.tabs.query({ active: true })) {
    if (tab.id === undefined) continue;
    const n = unlocked && tab.url?.startsWith("http") ? (await matching(tab.url)).length : 0;
    await chrome.action.setBadgeText({ tabId: tab.id, text: n ? String(Math.min(n, 99)) : "" }).catch(() => {});
  }
}

let badgeTimer: ReturnType<typeof setTimeout> | undefined;
const refreshBadge = () => {
  clearTimeout(badgeTimer);
  badgeTimer = setTimeout(() => void updateBadge(), 250);
};
chrome.action.setBadgeBackgroundColor({ color: "#0866ED" });
chrome.action.setBadgeTextColor?.({ color: "#FFFFFF" });
chrome.tabs.onActivated.addListener(refreshBadge);
chrome.tabs.onUpdated.addListener((_id, change) => (change.url || change.status === "complete") && refreshBadge());
chrome.windows.onFocusChanged.addListener(refreshBadge);
// Lock/unlock, account switches, syncs (item changes) and settings all touch local storage.
chrome.storage.onChanged.addListener((changes, area) => {
  // Session storage also holds short-lived state (heartbeats, prompts); only unlock changes matter there.
  if (area === "local" || Object.keys(changes).some((k) => k.startsWith("unlocked:"))) refreshBadge();
});
chrome.tabs.onRemoved.addListener((tabId) => void forgetTab(tabId));

async function matching(url: string) {
  const { defaultMatch } = await getSettings();
  return vault.allEntries().filter((e) => e.item.login?.urls.some((u) => matchesUrl(url, u, defaultMatch)));
}

// ------------------------------------------------------------- save prompts

interface PendingSave {
  /** The account that was active when this was typed: it is never saved into another account's vault. */
  accountId: string;
  url: string;
  username: string;
  password: string;
  /** Preselected under "Save in": the login to update, or `NEW_LOGIN`. */
  target: string;
  /** The logins the user may pick instead (their own ones for this site; see save-plan.ts). */
  targets: SaveTarget[];
  /** Ties the prompt the user sees to this pending save. */
  nonce: string;
  expires: number;
}
type Saves = Record<string, PendingSave>;
/** Username typed on the first step of an identifier-first login, per tab. */
type LastUsers = Record<string, { site: string; username: string; expires: number }>;

const SAVES = "pendingSaves";
const LAST_USERS = "lastUsers";

async function getSave(tabId: number) {
  const p = ((await scratch.get<Saves>(SAVES)) ?? {})[tabId];
  return p && p.expires > Date.now() ? p : undefined;
}
async function putSave(tabId: number, p: PendingSave | null) {
  const all = (await scratch.get<Saves>(SAVES)) ?? {};
  for (const [k, v] of Object.entries(all)) if (v.expires < Date.now()) delete all[k];
  if (p) all[tabId] = p;
  else delete all[tabId];
  await scratch.set(SAVES, all);
}
const closePrompt = (tabId: number) => chrome.tabs.sendMessage(tabId, { type: "save:close" } satisfies ContentCommand, { frameId: 0 }).catch(() => {});

/** Lock, sign-out, account switch: what was typed and not yet saved is forgotten, and open prompts close. */
async function dropSaves() {
  const all = (await scratch.get<Saves>(SAVES)) ?? {};
  await scratch.remove(SAVES);
  for (const tabId of Object.keys(all)) void closePrompt(Number(tabId));
}
vault.setKeysDroppedHandler(() => void dropSaves().catch(() => {}));

async function forgetTab(tabId: number) {
  await putSave(tabId, null);
  const users = (await scratch.get<LastUsers>(LAST_USERS)) ?? {};
  if (users[tabId]) {
    delete users[tabId];
    await scratch.set(LAST_USERS, users);
  }
}

/** The tab's top-level site, and whether `sender`'s frame is on it. */
function sameSiteAsTab(sender: chrome.runtime.MessageSender) {
  const top = parse(sender.tab?.url ?? "");
  const frame = parse(sender.url ?? "");
  return !!top && !!frame && /^https?:$/.test(top.protocol) && baseDomain(top.hostname) === baseDomain(frame.hostname);
}

async function rememberUser(sender: chrome.runtime.MessageSender, username: string) {
  const tabId = sender.tab?.id;
  const host = parse(sender.url ?? "")?.hostname;
  if (tabId === undefined || !host || !username || !sameSiteAsTab(sender)) return;
  const users = (await scratch.get<LastUsers>(LAST_USERS)) ?? {};
  users[tabId] = { site: baseDomain(host), username: username.slice(0, 256), expires: Date.now() + 10 * 60_000 };
  await scratch.set(LAST_USERS, users);
}

const MAX_SAVE_TARGETS = 12;

/** The default target and the "Save in" choices for what was typed (save-plan.ts), or null when there is nothing to offer. */
async function planFor(url: string, username: string, password: string): Promise<Pick<PendingSave, "target" | "targets"> | null> {
  const host = parse(url)?.hostname ?? "";
  const candidates = (await matching(url)).map((e) => ({
    id: e.id,
    name: (e.item.name || host).slice(0, 120),
    username: e.item.login!.username,
    password: e.item.login!.password,
    writable: vault.canWrite(e),
    personal: vault.isPersonal(e),
    vault: vault.vaultName(e.vaultId).slice(0, 60),
  }));
  const plan = planSave(candidates, username, password);
  if (plan.action === "none") return null;
  // The prompt lists a handful; the preselected login is always among them.
  const targets = [...plan.targets.filter((t) => t.id === plan.target), ...plan.targets.filter((t) => t.id !== plan.target)]
    .slice(0, MAX_SAVE_TARGETS)
    .map((t) => ({ ...t, username: t.username.slice(0, 256) }));
  return { target: plan.target, targets };
}

async function onSubmitted(sender: chrome.runtime.MessageSender, username: string, password: string): Promise<boolean> {
  const tabId = sender.tab?.id;
  const url = sender.url ?? "";
  if (tabId === undefined || !password || !sameSiteAsTab(sender) || !(await vault.ensureUnlocked().catch(() => false))) return false;
  const host = parse(url)?.hostname ?? "";
  const { neverSave, settings, activeId } = await local.get();
  if (!settings.askToSave || !host || neverSave.includes(baseDomain(host))) return false;
  if (!username) {
    // Identifier-first logins ask for the password on a second step without the username field.
    const last = ((await scratch.get<LastUsers>(LAST_USERS)) ?? {})[tabId];
    if (last && last.expires > Date.now() && last.site === baseDomain(host)) username = last.username;
  }
  username = username.trim().slice(0, 256);
  // Update a login the vault already has for this site instead of saving a second one.
  const plan = await planFor(url, username, password);
  if (!plan) return false;
  await putSave(tabId, { accountId: activeId, url, username, password, ...plan, nonce: crypto.randomUUID(), expires: Date.now() + 120_000 });
  return true;
}

/** What the page side gets: the nonce for the prompt frame and a first height for it. Nothing from the vault. */
const promptOf = (p: PendingSave): SavePrompt => ({ nonce: p.nonce, height: promptHeight(p.targets.length) });

/** What the prompt frame shows. */
async function offerOf(p: PendingSave): Promise<SaveOffer> {
  const { theme } = await getSettings();
  return { host: parse(p.url)?.hostname ?? "", username: p.username, targets: p.targets, selected: p.target, theme };
}

/**
 * The pending save of `sender`'s tab, if it belongs to the account that is
 * active now and the tab's top page is still on the site the login was typed on.
 */
async function saveForTab(sender: chrome.runtime.MessageSender): Promise<PendingSave | undefined> {
  const tabId = sender.tab?.id;
  if (tabId === undefined) return undefined;
  const p = await getSave(tabId);
  if (!p) return undefined;
  // Typed under another account (or stored by an older version of the extension): gone, not carried over.
  if (!p.accountId || p.accountId !== (await local.get()).activeId || !Array.isArray(p.targets) || typeof p.target !== "string") {
    await putSave(tabId, null);
    return undefined;
  }
  const top = parse(sender.tab?.url ?? "")?.hostname ?? "";
  return baseDomain(top) === baseDomain(parse(p.url)?.hostname ?? "") ? p : undefined;
}

/** The prompt is shown only in the top frame, on the same site as the login. */
async function pendingSaveFor(sender: chrome.runtime.MessageSender): Promise<SavePrompt | null> {
  if (sender.frameId !== 0) return null;
  const p = await saveForTab(sender);
  const here = parse(sender.url ?? "")?.hostname ?? "";
  return p && baseDomain(here) === baseDomain(parse(p.url)?.hostname ?? "") ? promptOf(p) : null;
}

/** Escape pressed in the page while the prompt is open: the one thing the page side may do to a pending save. */
async function dismissFromPage(sender: chrome.runtime.MessageSender, nonce: string) {
  const tabId = sender.tab?.id;
  if (tabId === undefined || sender.frameId !== 0) return null;
  const p = await saveForTab(sender);
  if (p && p.nonce === nonce) await putSave(tabId, null);
  return null;
}

/**
 * The save prompt is an extension page in a frame the content script places in
 * the top-right corner of the page (like the inline menu), so the website can
 * read neither the logins listed in it nor what the user picks. The pending
 * save's nonce ties the frame to the tab; the frame gets only these requests.
 */
async function handleSavePrompt(req: Request, sender: chrome.runtime.MessageSender): Promise<unknown> {
  const tabId = sender.tab?.id;
  // Only as a frame inside a tab's page, never opened as a page of its own.
  if (tabId === undefined || !sender.frameId) throw new Error("Not allowed.");
  if (req.type !== "save:offer" && req.type !== "save:answer" && req.type !== "save:resize") throw new Error("Not allowed.");
  const p = await saveForTab(sender);
  if (!p || p.nonce !== req.nonce) {
    await closePrompt(tabId);
    throw new Error("This prompt has expired.");
  }
  switch (req.type) {
    case "save:offer":
      return offerOf(p);
    case "save:resize":
      await chrome.tabs.sendMessage(tabId, { type: "save:size", height: clampPromptHeight(req.height) } satisfies ContentCommand, { frameId: 0 }).catch(() => {});
      return null;
    case "save:answer":
      return answerSave(tabId, p, req.accept, req.target);
  }
}

/** Saves being written right now, by nonce: a second click can't apply one twice. */
const applying = new Set<string>();

/**
 * The user's answer in the prompt. What is applied is the target the prompt
 * displayed (`target`, which must be one this pending save offered); the
 * pending save is removed on every way out except a failure the user can retry.
 */
async function answerSave(tabId: number, p: PendingSave, accept: "save" | "never" | "dismiss", target: unknown): Promise<SaveAnswer> {
  const host = (parse(p.url)?.hostname ?? "").replace(/^www\./, "");
  const finish = async (toast?: string): Promise<SaveAnswer> => {
    await putSave(tabId, null);
    await closePrompt(tabId);
    if (toast) await notifyTab(tabId, toast);
    return { done: true };
  };
  if (accept === "never") {
    const l = await local.get();
    await local.set({ neverSave: [...new Set([...l.neverSave, baseDomain(parse(p.url)?.hostname ?? "")])] });
    return finish();
  }
  if (accept !== "save") return finish();
  const choice = chosenTarget(p, target);
  if (choice === null) {
    await finish();
    throw new Error("Not allowed.");
  }
  if (applying.has(p.nonce)) return { error: "Saving…", retry: true };
  applying.add(p.nonce);
  try {
    if (!(await vault.ensureUnlocked().catch(() => false))) {
      await putSave(tabId, null);
      return { error: "PassAuth is locked, so the login wasn't saved. Unlock PassAuth, then sign in on the site again.", retry: false };
    }
    // Saving is the user at work in PassAuth: it restarts the vault timeout.
    await touch();
    if (choice !== NEW_LOGIN) {
      const existing = vault.getEntry(choice);
      if (!existing?.item.login || !vault.canWrite(existing)) {
        // The login the prompt showed was removed or became read-only (a sync in between). Never save
        // somewhere the user didn't see: work the choices out again and ask again.
        const next = await planFor(p.url, p.username, p.password);
        if (!next) return finish();
        const again: PendingSave = { ...p, ...next };
        await putSave(tabId, again);
        return { again: await offerOf(again), notice: "That login isn't in your vault any more. Check where to save, then try again." };
      }
      // updateItem moves the old password into the history; everything but the password (and a typed user name) stays.
      await vault.updateItem(existing, { ...existing.item, login: applyToLogin(existing.item.login, p.username, p.password) });
      // Inside the page the confirmation names the site, never the vault item.
      return finish(`Login updated for ${host}.`);
    }
    await vault.createItem({
      name: host,
      notes: "",
      favorite: false,
      folder: null,
      tags: [],
      login: { username: p.username, password: p.password, urls: [{ url: parse(p.url)!.origin, match: "default" }], totp: null, passkeys: [] },
      card: null,
      identity: null,
      ssh_key: null,
      fields: [],
      password_history: [],
      created_at: 0,
      updated_at: 0,
    });
    return finish(`Login saved for ${host}.`);
  } catch (e) {
    // The pending save stays, so the user can try again from the same prompt; the reason is shown in the prompt, not in the page.
    return { error: `PassAuth couldn't save this login. ${e instanceof Error ? e.message : String(e)}`, retry: true };
  } finally {
    applying.delete(p.nonce);
  }
}

// ------------------------------------------------------------------ fill

const describe = (u: LoginUrl) => (u.match === "regex" ? u.url : (parse(u.url)?.host ?? u.url));

/** An error whose text names vault data: fine in PassAuth's own pages, never shown inside a web page. */
class PrivateError extends Error {}

type FillCommand = Extract<ContentCommand, { type: "fill" }>;

/** Send the secrets to one frame only; true if it filled something. */
const sendFill = (tabId: number, frameId: number, cmd: FillCommand) =>
  chrome.tabs.sendMessage(tabId, cmd, { frameId }).then(
    (r) => !!(r as { filled?: boolean } | undefined)?.filled,
    () => null,
  );

// Login forms inside same-site iframes: frames are asked (without any secret)
// whether they have a matching login form; the first one to claim gets the fill.
const claims = new Map<string, { tabId: number; resolve: (frameId: number) => void }>();

function claimFrame(tabId: number, offer: Extract<ContentCommand, { type: "fill:offer" }>): Promise<number | undefined> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => done(undefined), 700);
    function done(frameId: number | undefined) {
      clearTimeout(timer);
      claims.delete(offer.token);
      resolve(frameId);
    }
    claims.set(offer.token, { tabId, resolve: done });
    chrome.tabs.sendMessage(tabId, offer).catch(() => {});
  });
}

/**
 * Fill a login into the page. `frameId`: the frame that asked (inline menu);
 * otherwise the top frame, then a same-site iframe that has a login form.
 */
async function fill(id: string, tabId: number, frameId?: number) {
  if (!(await vault.ensureUnlocked())) throw new Error("Unlock PassAuth first.");
  const entry = vault.getEntry(id);
  const login = entry?.item.login;
  if (!login) throw new Error("This item has no login to fill.");
  const settings = await getSettings();
  const tab = await chrome.tabs.get(tabId);
  const url = tab.url ?? "";
  const page = parse(url);
  if (!page || !/^https?:$/.test(page.protocol)) throw new Error("PassAuth can only fill on websites.");
  if (login.urls.length && !login.urls.some((u) => matchesUrl(url, u, settings.defaultMatch))) {
    throw new PrivateError(`This login is saved for ${login.urls.map(describe).join(", ")}, not for this site.`);
  }
  if (login.urls.some((u) => downgrade(url, u))) throw new Error("This page isn't secure (http). PassAuth won't fill a login saved for an https site here.");
  const code = login.totp ? vault.totp(login.totp).code : undefined;
  const site = baseDomain(page.hostname);
  // The frame checks the item's websites against its own URL again before filling.
  const cmd: FillCommand = {
    type: "fill",
    username: login.username,
    password: login.password,
    totp: code,
    site,
    urls: login.urls,
    defaultMatch: settings.defaultMatch,
    focused: frameId !== undefined,
  };
  let filled: boolean | null;
  if (frameId !== undefined) filled = await sendFill(tabId, frameId, cmd);
  else {
    filled = await sendFill(tabId, 0, cmd);
    if (filled === null) throw new Error("This page can't be filled. Reload it and try again.");
    if (!filled) {
      const token = crypto.randomUUID();
      const claimed = await claimFrame(tabId, { type: "fill:offer", token, site, urls: login.urls, defaultMatch: settings.defaultMatch });
      if (claimed !== undefined) filled = await sendFill(tabId, claimed, cmd);
    }
  }
  if (!filled) throw new Error("PassAuth couldn't find a login form on this page.");
  if (code && settings.autoCopyTotp) {
    await copy(code);
    await notifyTab(tabId, "Verification code copied. Paste it when the site asks.");
  }
}

async function notifyTab(tabId: number, text: string) {
  const { theme } = await getSettings();
  await chrome.tabs.sendMessage(tabId, { type: "toast", text, theme } satisfies ContentCommand, { frameId: 0 }).catch(() => {});
}

/** Keyboard shortcut / context menu: fill the single matching login, or open the popup. */
async function fillForActiveTab(tab?: chrome.tabs.Tab) {
  tab ??= (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
  if (!tab?.id || !tab.url) return;
  const tabId = tab.id;
  try {
    if (!(await vault.ensureUnlocked())) return void openPopup();
    await touch();
    const matches = await matching(tab.url);
    if (matches.length === 1) await fill(matches[0].id, tabId);
    else await openPopup();
  } catch (e) {
    await notifyTab(tabId, e instanceof PrivateError ? "This login isn't saved for this site. Open PassAuth to check its websites." : e instanceof Error ? e.message : String(e));
  }
}

chrome.commands.onCommand.addListener((cmd, tab) => {
  if (cmd === "autofill") void fillForActiveTab(tab);
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "passauth-fill", title: "Fill login with PassAuth", contexts: ["editable"] });
});
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "passauth-fill") void fillForActiveTab(tab);
});

async function openPopup() {
  try {
    await chrome.action.openPopup();
  } catch {
    // No toolbar to open from (e.g. no focused browser window): PassAuth in its own window, over the browser window.
    await openCentered(chrome.runtime.getURL("popup.html?popout=1"), POPUP_WINDOW);
  }
}

// ------------------------------------------------------------ inline menu

/**
 * The menu is an extension page in an iframe the content script places under
 * the field, so the website can't read the logins shown in it. A one-time
 * nonce ties each menu to the tab and frame that opened it.
 */
type InlineMenus = Record<string, { tabId: number; frameId: number; expires: number }>;
const INLINE_MENUS = "inlineMenus";

async function inlineInfo(sender: chrome.runtime.MessageSender): Promise<InlineInfo> {
  const { settings, tokens } = await local.get();
  const off: InlineInfo = { mode: "off", status: "locked", count: 0 };
  const top = parse(sender.tab?.url ?? "");
  if (settings.inlineMenu === "off" || !tokens || !top) return off;
  // Only frames on the same site as the tab: fill() refuses the others anyway.
  if (!sameSiteAsTab(sender)) return off;
  if (!(await vault.ensureUnlocked().catch(() => false))) return { mode: settings.inlineMenu, status: "locked", count: 0 };
  return { mode: settings.inlineMenu, status: "unlocked", count: (await matching(top.href)).length };
}

async function openInline(sender: chrome.runtime.MessageSender) {
  const tabId = sender.tab?.id;
  if (tabId === undefined || sender.frameId === undefined) return null;
  const all = (await scratch.get<InlineMenus>(INLINE_MENUS)) ?? {};
  for (const [k, m] of Object.entries(all)) if (m.expires < Date.now() || m.tabId === tabId) delete all[k];
  const nonce = crypto.randomUUID();
  all[nonce] = { tabId, frameId: sender.frameId, expires: Date.now() + 10 * 60_000 };
  await scratch.set(INLINE_MENUS, all);
  return nonce;
}

async function inlineMenu(nonce: string, sender: chrome.runtime.MessageSender, consume = false) {
  const all = (await scratch.get<InlineMenus>(INLINE_MENUS)) ?? {};
  const m = all[nonce];
  if (!m || m.expires < Date.now() || m.tabId !== sender.tab?.id) throw new Error("This menu has expired. Click the field again.");
  if (consume) {
    delete all[nonce];
    await scratch.set(INLINE_MENUS, all);
  }
  return m;
}

const closeInline = (m: { tabId: number; frameId: number }) =>
  chrome.tabs.sendMessage(m.tabId, { type: "inline:close" } satisfies ContentCommand, { frameId: m.frameId }).catch(() => {});

async function handleInline(req: Request, sender: chrome.runtime.MessageSender): Promise<unknown> {
  switch (req.type) {
    case "inline:items": {
      await inlineMenu(req.nonce, sender);
      const { server, settings } = await local.get();
      const base = { server, theme: settings.theme, showIcons: settings.showIcons };
      if (!(await vault.ensureUnlocked().catch(() => false))) return { ...base, locked: true, items: [] } satisfies InlineItems;
      const items = (await matching(sender.tab?.url ?? "")).map(vault.summarize);
      return { ...base, locked: false, items } satisfies InlineItems;
    }
    case "inline:fill": {
      const m = await inlineMenu(req.nonce, sender, true);
      // Only a fill is user activity; opening or closing the menu must not keep the vault unlocked.
      await touch();
      await closeInline(m);
      return fill(req.id, m.tabId, m.frameId);
    }
    case "inline:close": {
      const m = await inlineMenu(req.nonce, sender, true);
      return closeInline(m);
    }
    case "openPopup":
      return openPopup();
    default:
      throw new Error("Not allowed.");
  }
}

// ---------------------------------------------------------------- router

async function handle(req: Request, sender: chrome.runtime.MessageSender): Promise<unknown> {
  // Extension pages (popup, even when opened in a tab) vs. content scripts on websites.
  const fromExtension = sender.id === chrome.runtime.id && (sender.url ?? "").startsWith(chrome.runtime.getURL(""));
  // The inline menu and the save prompt are extension pages framed inside web pages: each only gets the few requests it needs.
  const page = fromExtension ? new URL(sender.url!).pathname : "";
  if (page === "/inline-menu.html") return handleInline(req, sender);
  if (page === "/save-prompt.html") return handleSavePrompt(req, sender);

  // Page-originated messages: only the small set content scripts need.
  if (!fromExtension) {
    switch (req.type) {
      case "page:submitted":
        return onSubmitted(sender, req.username, req.password);
      case "page:identifier":
        return rememberUser(sender, req.username);
      case "page:formDone": {
        // The login form went away without a page load (single-page apps): show the prompt in the top frame.
        const tabId = sender.tab?.id;
        const p = sameSiteAsTab(sender) ? await saveForTab(sender) : undefined;
        if (tabId !== undefined && p) await chrome.tabs.sendMessage(tabId, { type: "showSave", ...promptOf(p) } satisfies ContentCommand, { frameId: 0 }).catch(() => {});
        return null;
      }
      case "page:pendingSave":
        return pendingSaveFor(sender);
      case "page:saveDismiss":
        return dismissFromPage(sender, req.nonce);
      case "page:fillClaim": {
        const c = claims.get(req.token);
        if (c && c.tabId === sender.tab?.id && sender.frameId !== undefined) c.resolve(sender.frameId);
        return null;
      }
      case "page:inlineInfo":
        return inlineInfo(sender);
      case "page:inlineOpen":
        return openInline(sender);
      default:
        throw new Error("Not allowed.");
    }
  }

  await touch(req.type === "settings");
  switch (req.type) {
    case "state":
      if (await vault.ensureUnlocked().catch(() => false)) await vault.refreshIfStale().catch(() => {});
      return vault.state();
    case "setServer":
      return vault.setServer(req.url);
    case "login":
      return vault.login(req.email, req.password, req.secretKey);
    case "verify2fa":
      return vault.verifyTwoFactor(req.token, req.provider, req.code, req.remember);
    case "email2fa":
      return vault.sendTwoFactorEmail(req.token);
    case "unlock":
      return vault.unlock(req.password, req.secretKey);
    case "lock":
      return vault.lock();
    case "account:add":
      return vault.addAccount();
    case "account:switch":
      return vault.switchAccount(req.id);
    case "account:cancelAdd":
      return vault.cancelAddAccount();
    case "logout":
      return vault.logout();
    case "sync":
      return vault.sync();
    case "securityKeys":
      if (!(await vault.ensureUnlocked())) throw new Error("locked");
      return vault.securityKeys();
    case "securityKeys:remove":
      if (!(await vault.ensureUnlocked())) throw new Error("locked");
      return vault.removeSecurityKey(req.id, req.password);
    case "items": {
      if (!(await vault.ensureUnlocked())) throw new Error("locked");
      const suggested = req.url ? await matching(req.url) : [];
      return { suggested: suggested.map(vault.summarize), all: vault.allEntries().map(vault.summarize) };
    }
    case "item": {
      if (!(await vault.ensureUnlocked())) throw new Error("locked");
      const e = vault.getEntry(req.id);
      if (!e) throw new Error("Item not found.");
      return {
        item: e.item,
        vaultName: vault.vaultName(e.vaultId),
        vaultId: e.vaultId,
        canWrite: vault.canWrite(e),
        weakPassword: vault.weakPassword(e.item.login?.password ?? ""),
      };
    }
    case "totp": {
      if (!(await vault.ensureUnlocked())) throw new Error("locked");
      const secret = vault.getEntry(req.id)?.item.login?.totp;
      if (!secret) throw new Error("No authenticator key.");
      return vault.totp(secret);
    }
    case "fill":
      return fill(req.id, req.tabId);
    case "generate":
      return vault.generate(req.mode, req.options);
    case "createItem":
      if (!(await vault.ensureUnlocked())) throw new Error("locked");
      return vault.createItem(req.item, req.vaultId);
    case "updateItem":
    case "trashItem": {
      if (!(await vault.ensureUnlocked())) throw new Error("locked");
      const e = vault.getEntry(req.id);
      if (!e) throw new Error("Item not found.");
      return req.type === "updateItem" ? vault.updateItem(e, req.item) : vault.trashItem(e);
    }
    case "editorInfo":
      if (!(await vault.ensureUnlocked())) throw new Error("locked");
      return vault.editorInfo();
    case "settings": {
      const settings: Settings = { ...(await getSettings()), ...req.patch };
      await local.set({ settings });
      await touch(true);
      await vault.persistForNever();
      return settings;
    }
    case "neverSave:remove": {
      const { neverSave } = await local.get();
      return local.set({ neverSave: neverSave.filter((d) => d !== req.domain) });
    }
    case "copy":
      return copy(req.text);
    case "copyField": {
      if (!(await vault.ensureUnlocked())) throw new Error("locked");
      const login = vault.getEntry(req.id)?.item.login;
      const value = req.field === "totp" ? (login?.totp ? vault.totp(login.totp).code : "") : (login?.[req.field] ?? "");
      if (!value) throw new Error("Nothing to copy.");
      return copy(value);
    }
    case "openPopup":
      return openPopup();
    case "passkey:pending":
      return pendingRequest(req.requestId);
    case "passkey:decide":
      return decide(req.requestId, req.accept, req.credentialId, req.fallback, req.password);
    default:
      throw new Error("Unknown request.");
  }
}

const isPasskeyRequest = (m: any) => (m?.type === "passkey:create" || m?.type === "passkey:get") && "options" in m;

chrome.runtime.onMessage.addListener((req: Request, sender, respond) => {
  // WebAuthn requests from the page bridge get the authenticator's reply shape directly.
  if (isPasskeyRequest(req)) {
    if (!sender.tab?.id || sender.id !== chrome.runtime.id || sender.frameId === undefined) return false;
    const r = req as any;
    handlePasskey({
      type: r.type,
      options: r.options,
      bridgeId: typeof r.bridgeId === "string" ? r.bridgeId.slice(0, 100) : "",
      origin: new URL(sender.url ?? "about:blank").origin,
      topLevel: sender.frameId === 0,
      tabId: sender.tab.id,
      frameId: sender.frameId,
    }).then(respond, () => respond({ fallback: true }));
    return true;
  }
  if ((req as any)?.type === "passkey:cancel") {
    if (sender.tab?.id !== undefined && sender.frameId !== undefined) cancelPasskey(sender.tab.id, sender.frameId, String((req as any).bridgeId ?? ""));
    return false;
  }
  handle(req, sender).then(
    (data) => respond({ ok: true, data: data ?? null } satisfies Reply),
    (e) => respond({ ok: false, error: e instanceof Error ? e.message : String(e) } satisfies Reply),
  );
  return true;
});
