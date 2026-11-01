/** PassAuth extension service worker: message router, autofill, inline menu, save prompts, vault timeout. */
import type { ContentCommand, InlineInfo, InlineItems, Request, Reply, Settings } from "../shared/messages";
import type { LoginUrl } from "@web/lib/types";
import { copy } from "./clipboard";
import { getSettings, local } from "./storage";
import { decide, handlePasskey, pendingRequest } from "./passkey-handler";
import { baseDomain, downgrade, matchesUrl, parse } from "./urls";
import * as vault from "./vault";

// ---------------------------------------------------------- vault timeout

/** Run the user's timeout action (lock, or log out which also forgets the vault data). */
async function timeout() {
  const { settings, tokens } = await local.get();
  if (!tokens) return;
  if (settings.timeoutAction === "logout") await vault.logout();
  else await vault.lock();
}

/** Activity in PassAuth restarts the inactivity timer. */
async function touch() {
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
// Keys in session storage are gone after a browser restart (locked); "log out" also drops the session.
chrome.runtime.onStartup.addListener(async () => {
  const { vaultTimeout, timeoutAction } = await getSettings();
  if (vaultTimeout !== "never" && timeoutAction === "logout") await timeout();
});
// "Immediately": time out as soon as the popup closes.
chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "popup" || port.sender?.id !== chrome.runtime.id) return;
  port.onDisconnect.addListener(async () => {
    if ((await getSettings()).vaultTimeout === "immediately") await timeout();
  });
});

/** PassAuth's own web vault: never offer to fill or save there (it would capture the master password). */
async function isVaultPage(url: string) {
  const { server } = await local.get();
  const page = parse(url);
  return !!server && !!page && page.origin === new URL(server).origin;
}

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
  expires: number;
}
const saves = new Map<number, PendingSave>();

async function onSubmitted(tabId: number, url: string, username: string, password: string) {
  if (!password || !(await vault.ensureUnlocked())) return null;
  const host = parse(url)?.hostname ?? "";
  const { neverSave, settings } = await local.get();
  if (!settings.askToSave || !host || neverSave.includes(baseDomain(host)) || (await isVaultPage(url))) return null;
  const sameSite = await matching(url);
  const sameUser = sameSite.find((e) => e.item.login!.username.toLowerCase() === username.toLowerCase());
  if (sameUser?.item.login!.password === password) return null;
  if (sameUser && !vault.canWrite(sameUser)) return null;
  saves.set(tabId, { url, username, password, updateId: sameUser?.id, expires: Date.now() + 120_000 });
  return { host, update: !!sameUser };
}

async function applySave(tabId: number, accept: "save" | "never" | "dismiss") {
  const p = saves.get(tabId);
  saves.delete(tabId);
  if (!p || p.expires < Date.now()) return;
  const host = parse(p.url)?.hostname ?? "";
  if (accept === "never") {
    const l = await local.get();
    await local.set({ neverSave: [...new Set([...l.neverSave, baseDomain(host)])] });
    return;
  }
  if (accept !== "save") return;
  const existing = p.updateId ? vault.getEntry(p.updateId) : undefined;
  if (existing?.item.login) {
    const now = Math.floor(Date.now() / 1000);
    const old = existing.item.login.password;
    await vault.updateItem(existing, {
      ...existing.item,
      login: { ...existing.item.login, password: p.password },
      password_history: old ? [{ password: old, changed_at: now }, ...existing.item.password_history].slice(0, 20) : existing.item.password_history,
    });
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

async function fill(id: string, tabId: number) {
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
  const cmd: ContentCommand = { type: "fill", username: login.username, password: login.password, totp: code, site: baseDomain(page.hostname) };
  // Every frame receives the command; each frame fills only if it is on the same site as the tab.
  await chrome.tabs.sendMessage(tabId, cmd).catch(() => {
    throw new Error("This page can't be filled. Reload it and try again.");
  });
  if (code && settings.autoCopyTotp) {
    await copy(code);
    const toast: ContentCommand = { type: "toast", text: "Verification code copied. Paste it when the site asks." };
    await chrome.tabs.sendMessage(tabId, toast, { frameId: 0 }).catch(() => {});
  }
}

/** Keyboard shortcut / context menu: fill the single matching login, or open the popup. */
async function fillForActiveTab(tab?: chrome.tabs.Tab) {
  tab ??= (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
  if (!tab?.id || !tab.url) return;
  if (!(await vault.ensureUnlocked())) return chrome.action.openPopup().catch(() => {});
  const matches = await matching(tab.url);
  if (matches.length === 1) await fill(matches[0].id, tab.id).catch(() => {});
  else await chrome.action.openPopup().catch(() => {});
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
const inlineMenus = new Map<string, { tabId: number; frameId: number; expires: number }>();

async function inlineInfo(sender: chrome.runtime.MessageSender): Promise<InlineInfo> {
  const { settings, tokens } = await local.get();
  const off: InlineInfo = { mode: "off", status: "locked", count: 0 };
  const top = parse(sender.tab?.url ?? "");
  const frame = parse(sender.url ?? "");
  if (settings.inlineMenu === "off" || !tokens || !top || !frame || !/^https?:$/.test(top.protocol) || (await isVaultPage(top.href))) return off;
  // Only frames on the same site as the tab: fill() refuses the others anyway.
  if (baseDomain(top.hostname) !== baseDomain(frame.hostname)) return off;
  if (!(await vault.ensureUnlocked().catch(() => false))) return { mode: settings.inlineMenu, status: "locked", count: 0 };
  return { mode: settings.inlineMenu, status: "unlocked", count: (await matching(top.href)).length };
}

function inlineMenu(nonce: string, sender: chrome.runtime.MessageSender) {
  const m = inlineMenus.get(nonce);
  if (!m || m.expires < Date.now() || m.tabId !== sender.tab?.id) throw new Error("This menu has expired.");
  return m;
}

const closeInline = (m: { tabId: number; frameId: number }) =>
  chrome.tabs.sendMessage(m.tabId, { type: "inline:close" } satisfies ContentCommand, { frameId: m.frameId }).catch(() => {});

async function handleInline(req: Request, sender: chrome.runtime.MessageSender): Promise<unknown> {
  switch (req.type) {
    case "inline:items": {
      inlineMenu(req.nonce, sender);
      const { server, settings } = await local.get();
      if (!(await vault.ensureUnlocked().catch(() => false))) return { server, showIcons: settings.showIcons, locked: true, items: [] } satisfies InlineItems;
      const items = (await matching(sender.tab?.url ?? "")).map(vault.summarize);
      return { server, showIcons: settings.showIcons, locked: false, items } satisfies InlineItems;
    }
    case "inline:fill": {
      const m = inlineMenu(req.nonce, sender);
      inlineMenus.delete(req.nonce);
      await closeInline(m);
      return fill(req.id, m.tabId);
    }
    case "inline:close": {
      const m = inlineMenu(req.nonce, sender);
      inlineMenus.delete(req.nonce);
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
  const tabId = sender.tab?.id;

  if (fromInlineMenu) {
    await touch();
    return handleInline(req, sender);
  }

  // Page-originated messages: only the small set content scripts need.
  if (!fromExtension) {
    switch (req.type) {
      case "page:submitted":
        return tabId === undefined ? null : onSubmitted(tabId, sender.url ?? req.url, req.username, req.password);
      case "page:pendingSave": {
        const p = tabId !== undefined ? saves.get(tabId) : undefined;
        const here = parse(sender.url ?? "")?.hostname ?? "";
        const host = p ? (parse(p.url)?.hostname ?? "") : "";
        return p && p.expires > Date.now() && baseDomain(here) === baseDomain(host) ? { host, update: !!p.updateId } : null;
      }
      case "page:save":
        return tabId === undefined ? null : applySave(tabId, req.accept);
      case "page:fillRequest":
        return fillForActiveTab(sender.tab);
      case "page:inlineInfo":
        return inlineInfo(sender);
      case "page:inlineOpen": {
        if (tabId === undefined || sender.frameId === undefined) return null;
        for (const [k, m] of inlineMenus) if (m.expires < Date.now() || m.tabId === tabId) inlineMenus.delete(k);
        const nonce = crypto.randomUUID();
        inlineMenus.set(nonce, { tabId, frameId: sender.frameId, expires: Date.now() + 10 * 60_000 });
        return nonce;
      }
      default:
        throw new Error("Not allowed.");
    }
  }

  await touch();
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
      return { item: e.item, vaultName: vault.vaultName(e.vaultId) };
    }
    case "totp": {
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
      return vault.createItem(req.item);
    case "settings": {
      const settings: Settings = { ...(await getSettings()), ...req.patch };
      await local.set({ settings });
      await touch();
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
      return decide(req.requestId, req.accept, req.credentialId, req.fallback);
    default:
      throw new Error("Unknown request.");
  }
}

const isPasskeyRequest = (m: any) => (m?.type === "passkey:create" || m?.type === "passkey:get") && "options" in m;

chrome.runtime.onMessage.addListener((req: Request, sender, respond) => {
  // WebAuthn requests from the page bridge get the authenticator's reply shape directly.
  if (isPasskeyRequest(req)) {
    if (!sender.tab || sender.id !== chrome.runtime.id) return false;
    handlePasskey({ ...(req as any), origin: new URL(sender.url ?? "about:blank").origin, topLevel: sender.frameId === 0 }).then(respond, (e) =>
      respond({ error: { name: "NotAllowedError", message: e instanceof Error ? e.message : String(e) } }),
    );
    return true;
  }
  handle(req, sender).then(
    (data) => respond({ ok: true, data: data ?? null } satisfies Reply),
    (e) => respond({ ok: false, error: e instanceof Error ? e.message : String(e) } satisfies Reply),
  );
  return true;
});
