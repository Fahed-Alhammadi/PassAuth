/** PassAuth extension service worker: message router, autofill, save prompts, auto-lock. */
import type { ContentCommand, Request, Reply } from "../shared/messages";
import { local } from "./storage";
import { decide, handlePasskey, pendingRequest } from "./passkey-handler";
import { baseDomain, downgrade, matchesUrl, parse } from "./urls";
import * as vault from "./vault";

// ------------------------------------------------------------ auto-lock

async function touch() {
  const { autoLockMinutes } = await local.get();
  if (autoLockMinutes > 0) await chrome.alarms.create("autolock", { delayInMinutes: autoLockMinutes });
}

chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === "autolock") void vault.lock();
});
chrome.idle.setDetectionInterval(60);
chrome.idle.onStateChanged.addListener((s) => {
  if (s === "locked") void vault.lock();
});

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
  const { neverSave } = await local.get();
  if (!host || neverSave.includes(baseDomain(host))) return null;
  const sameSite = vault.allEntries().filter((e) => e.item.login?.urls.some((u) => matchesUrl(url, u)));
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
    login: { username: p.username, password: p.password, urls: [{ url: origin, match: "domain" }], totp: null, passkeys: [] },
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

async function fill(id: string, tabId: number) {
  if (!(await vault.ensureUnlocked())) throw new Error("Unlock PassAuth first.");
  const entry = vault.getEntry(id);
  const login = entry?.item.login;
  if (!login) throw new Error("This item has no login to fill.");
  const tab = await chrome.tabs.get(tabId);
  const url = tab.url ?? "";
  if (login.urls.length && !login.urls.some((u) => matchesUrl(url, u))) {
    throw new Error(`This login is saved for ${login.urls.map((u) => parse(u.url)?.host ?? u.url).join(", ")}, not for this site.`);
  }
  if (login.urls.some((u) => downgrade(url, u))) throw new Error("This page isn't secure (http). PassAuth won't fill a login saved for an https site here.");
  const cmd: ContentCommand = {
    type: "fill",
    username: login.username,
    password: login.password,
    totp: login.totp ? vault.totp(login.totp).code : undefined,
    itemUrls: login.urls.map((u) => u.url),
  };
  // Every frame receives the command; each frame fills only if its own origin matches.
  await chrome.tabs.sendMessage(tabId, cmd).catch(() => {
    throw new Error("This page can't be filled. Reload it and try again.");
  });
}

/** Keyboard shortcut / context menu: fill the single matching login, or open the popup. */
async function fillForActiveTab(tab?: chrome.tabs.Tab) {
  tab ??= (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
  if (!tab?.id || !tab.url) return;
  if (!(await vault.ensureUnlocked())) return chrome.action.openPopup().catch(() => {});
  const url = tab.url;
  const matches = vault.allEntries().filter((e) => e.item.login?.urls.some((u) => matchesUrl(url, u)));
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

// ---------------------------------------------------------------- router

async function handle(req: Request, sender: chrome.runtime.MessageSender): Promise<unknown> {
  // Extension pages (popup, even when opened in a tab) vs. content scripts on websites.
  const fromExtension = sender.id === chrome.runtime.id && (sender.url ?? "").startsWith(chrome.runtime.getURL(""));
  const tabId = sender.tab?.id;

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
      const all = vault.allEntries();
      const url = req.url ?? "";
      const suggested = url ? all.filter((e) => e.item.login?.urls.some((u) => matchesUrl(url, u))) : [];
      return { suggested: suggested.map(vault.summarize), all: all.map(vault.summarize) };
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
    case "settings":
      await local.set({ autoLockMinutes: req.autoLockMinutes });
      if (req.autoLockMinutes <= 0) await chrome.alarms.clear("autolock");
      return null;
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
