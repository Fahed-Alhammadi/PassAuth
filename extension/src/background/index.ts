/** PassAuth extension service worker: message router, autofill, inline menu, save prompts, vault timeout. */
import type { ContentCommand, InlineInfo, InlineItems, Request, Reply, SaveOffer, Settings } from "../shared/messages";
import type { LoginUrl } from "@web/lib/types";
import { copy } from "./clipboard";
import { getSettings, local, scratch } from "./storage";
import { cancelPasskey, decide, handlePasskey, pendingRequest } from "./passkey-handler";
import { baseDomain, downgrade, matchesUrl, parse } from "./urls";
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
  url: string;
  username: string;
  password: string;
  updateId?: string;
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

async function onSubmitted(sender: chrome.runtime.MessageSender, username: string, password: string): Promise<boolean> {
  const tabId = sender.tab?.id;
  const url = sender.url ?? "";
  if (tabId === undefined || !password || !sameSiteAsTab(sender) || !(await vault.ensureUnlocked().catch(() => false))) return false;
  const host = parse(url)?.hostname ?? "";
  const { neverSave, settings } = await local.get();
  if (!settings.askToSave || !host || neverSave.includes(baseDomain(host))) return false;
  if (!username) {
    // Identifier-first logins ask for the password on a second step without the username field.
    const last = ((await scratch.get<LastUsers>(LAST_USERS)) ?? {})[tabId];
    if (last && last.expires > Date.now() && last.site === baseDomain(host)) username = last.username;
  }
  const sameSite = await matching(url);
  const sameUser = sameSite.find((e) => e.item.login!.username.toLowerCase() === username.toLowerCase());
  if (sameUser?.item.login!.password === password) return false;
  if (sameUser && !vault.canWrite(sameUser)) return false;
  await putSave(tabId, { url, username, password, updateId: sameUser?.id, nonce: crypto.randomUUID(), expires: Date.now() + 120_000 });
  return true;
}

const offerOf = (p: PendingSave): SaveOffer => ({ host: parse(p.url)?.hostname ?? "", update: !!p.updateId, username: p.username, nonce: p.nonce });

/** The prompt is shown only in the top frame, on the same site as the login. */
async function pendingSaveFor(sender: chrome.runtime.MessageSender): Promise<SaveOffer | null> {
  const tabId = sender.tab?.id;
  if (tabId === undefined || sender.frameId !== 0) return null;
  const p = await getSave(tabId);
  const here = parse(sender.url ?? "")?.hostname ?? "";
  return p && baseDomain(here) === baseDomain(parse(p.url)?.hostname ?? "") ? offerOf(p) : null;
}

async function applySave(sender: chrome.runtime.MessageSender, accept: "save" | "never" | "dismiss", nonce: string) {
  const tabId = sender.tab?.id;
  if (tabId === undefined || sender.frameId !== 0) return;
  const p = await getSave(tabId);
  if (!p || p.nonce !== nonce) return;
  await putSave(tabId, null);
  const host = parse(p.url)?.hostname ?? "";
  if (accept === "never") {
    const l = await local.get();
    await local.set({ neverSave: [...new Set([...l.neverSave, baseDomain(host)])] });
    return;
  }
  if (accept !== "save" || !(await vault.ensureUnlocked())) return;
  const existing = p.updateId ? vault.getEntry(p.updateId) : undefined;
  if (existing?.item.login) {
    // updateItem moves the old password into the history.
    await vault.updateItem(existing, { ...existing.item, login: { ...existing.item.login, password: p.password } });
    return;
  }
  const origin = parse(p.url)!.origin;
  await vault.createItem({
    name: host.replace(/^www\./, ""),
    notes: "",
    favorite: false,
    folder: null,
    tags: [],
    login: { username: p.username, password: p.password, urls: [{ url: origin, match: "default" }], totp: null, passkeys: [] },
    card: null,
    identity: null,
    ssh_key: null,
    fields: [],
    password_history: [],
    created_at: 0,
    updated_at: 0,
  });
}

// ------------------------------------------------------------------ fill

const describe = (u: LoginUrl) => (u.match === "regex" ? u.url : (parse(u.url)?.host ?? u.url));

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
    throw new Error(`This login is saved for ${login.urls.map(describe).join(", ")}, not for this site.`);
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

const notifyTab = (tabId: number, text: string) =>
  chrome.tabs.sendMessage(tabId, { type: "toast", text } satisfies ContentCommand, { frameId: 0 }).catch(() => {});

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
    await notifyTab(tabId, e instanceof Error ? e.message : String(e));
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
    await chrome.windows.create({ url: chrome.runtime.getURL("popup.html"), type: "popup", width: 380, height: 620, focused: true });
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
  // The inline menu frame sits inside web pages: it only gets the few requests it needs.
  const fromInlineMenu = fromExtension && /^\/inline-menu\.html$/.test(new URL(sender.url!).pathname);

  if (fromInlineMenu) return handleInline(req, sender);

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
        const p = tabId !== undefined && sameSiteAsTab(sender) ? await getSave(tabId) : undefined;
        if (tabId !== undefined && p) await chrome.tabs.sendMessage(tabId, { type: "showSave", ...offerOf(p) } satisfies ContentCommand, { frameId: 0 }).catch(() => {});
        return null;
      }
      case "page:pendingSave":
        return pendingSaveFor(sender);
      case "page:save":
        return applySave(sender, req.accept, req.nonce);
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
