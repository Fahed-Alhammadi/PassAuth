/**
 * Background vault: authentication, key handles and decrypted items.
 * The service worker can be stopped at any time; unlocked keys survive in
 * chrome.storage.session and are restored on demand.
 */
import init, * as core from "../wasm/passauth_core";
import type { EncryptedItem, Item, Role } from "@web/lib/types";
import { kindOf, siteHost } from "@web/lib/types";
import { api, logoutRemote, setSessionLostHandler, timeoutSignal } from "./api";
import { activeId, local, scratch, session, syncCache, type AccountData, type SessionData } from "./storage";
import type { AccountSummary, ItemSummary, PopupState, SecurityKey, SecurityKeys, Status, TwoFactorChallenge } from "../shared/messages";

export interface Entry {
  id: string;
  item: Item;
  vaultId: string;
  revision: number;
  enc: EncryptedItem;
}

interface Vault {
  id: string;
  name: string;
  role: Role;
  /** "account": wrapped with this account's own key (the user's vaults); "sealed": shared by someone else. */
  kind: string;
  key: core.VaultKey;
}

let ready: Promise<unknown> | null = null;
let account: core.Account | null = null;
/** Local id of the account whose keys are loaded (`account`, `vaults`, `entries`). */
let currentId = "";
/**
 * Bumped whenever the loaded keys are dropped (lock, sign-out, account switch).
 * Async work captures it first and discards its result when it changed, so a
 * sync that finishes after a lock or switch can't resurrect or mix accounts.
 */
let generation = 0;
/** Single-flight restore after a service-worker restart. */
let restoring: { id: string; p: Promise<boolean> } | null = null;
let bundle: any = null;
let vaults: Vault[] = [];
let entries: Entry[] = [];
let revision = 0;
/** Whether the unlocked account has synced at least once (an empty vault is still "loaded"). */
let loaded = false;
let pendingMaster: core.MasterKeys | null = null;
let pendingEmail = "";

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export function initWasm() {
  // Vite emits the .wasm as a packaged extension file and rewrites this URL.
  ready ??= init({ module_or_path: new URL("../wasm/passauth_core_bg.wasm", import.meta.url) });
  return ready;
}

setSessionLostHandler(async (id) => {
  await clearUnlocked(id);
});

/** Set by the service worker: runs the "Immediately" vault timeout if the popup closed while the worker was asleep. */
let lockCheck: () => Promise<void> = async () => {};
export function setLockCheck(fn: () => Promise<void>) {
  lockCheck = fn;
}

// ------------------------------------------------------------------ state

async function statusOf(a: AccountData | undefined, id: string, neverTimeout: boolean): Promise<Status> {
  if (!a?.server) return "setup";
  if (!a.tokens) return "logged-out";
  return (await session.get(id)) || (neverTimeout && a.persistedKeys) ? "unlocked" : "locked";
}

export async function state(): Promise<PopupState> {
  const l = await local.get();
  const s = await session.get();
  const status = !l.server ? "setup" : !l.tokens ? "logged-out" : s || (account && currentId === l.activeId) ? "unlocked" : "locked";
  const never = l.settings.vaultTimeout === "never";
  const accounts: AccountSummary[] = [];
  for (const [id, a] of Object.entries(l.accounts)) {
    if (!a.server || !a.email) continue;
    accounts.push({ id, email: a.email, name: a.name, server: a.server, status: id === l.activeId ? status : await statusOf(a, id, never) });
  }
  return {
    status,
    activeId: l.activeId,
    accounts,
    name: l.name,
    server: l.server,
    email: l.email,
    secretKeyRequired: !!((currentId === l.activeId ? bundle : null) ?? s?.bundle ?? (await syncCache.get(l.activeId))?.bundle)?.secret_key_enabled,
    secretKeyStored: !!l.secretKeys[l.email],
    settings: l.settings,
    lastSync: l.lastSync,
    neverSave: l.neverSave,
  };
}

export async function setServer(url: string) {
  const clean = url.trim().replace(/\/+$/, "");
  const u = new URL(clean.includes("://") ? clean : `https://${clean}`);
  if (u.protocol !== "https:" && u.hostname !== "localhost" && u.hostname !== "127.0.0.1") {
    throw new Error("Use an https:// address. Plain http is only allowed for localhost.");
  }
  const origin = u.origin + u.pathname.replace(/\/+$/, "");
  const r = await fetch(`${origin}/api/config`, { signal: timeoutSignal() }).catch(() => null);
  const cfg = r?.ok ? await r.json().catch(() => null) : null;
  if (cfg?.name !== "PassAuth") throw new Error("No PassAuth server answered at that address.");
  await clearUnlocked();
  await local.set({ server: origin, tokens: null });
}

// ------------------------------------------------------------------- login

async function deviceInfo() {
  const { deviceId } = await local.get();
  return { id: deviceId, name: `PassAuth extension (${navigator.userAgent.includes("Edg/") ? "Edge" : "Chrome"})`, kind: "extension" };
}

export async function login(email: string, password: string, secretKey?: string): Promise<{ done: true } | { twoFactor: TwoFactorChallenge }> {
  await initWasm();
  const l = await local.get();
  const sk = secretKey?.trim() || l.secretKeys[email.trim().toLowerCase()];
  const pre = await api("/auth/prelogin", { body: { email }, auth: false });
  if (pre.secret_key_required && !sk) throw new Error("secret_key_required");
  const master = core.deriveMasterKeys(password, pre.secret_key_required ? sk : undefined, pre.account_id, pre.kdf, pre.secret_key_required);
  const start = core.opaqueLoginStart(master);
  const resp = await api("/auth/login/start", { body: { email, message: start.message }, auth: false });
  let fin: string;
  try {
    fin = core.opaqueLoginFinish(start.state, master, resp.message);
  } catch {
    master.free();
    throw new Error("Wrong email, master password or Secret Key.");
  }
  const key = email.trim().toLowerCase();
  const result = await api("/auth/login/finish", {
    auth: false,
    body: { login_id: resp.login_id, message: fin, device: await deviceInfo(), remember_token: l.rememberTokens[`${l.server}|${key}`] },
  });
  if (sk && pre.secret_key_required) await local.set({ secretKeys: { ...l.secretKeys, [key]: sk } });
  if (result.two_factor_required) {
    pendingMaster?.free();
    pendingMaster = master;
    pendingEmail = `${l.server}|${key}`;
    return { twoFactor: { token: result.two_factor_token, providers: result.providers } };
  }
  await finishLogin(master, result);
  return { done: true };
}

export async function verifyTwoFactor(token: string, provider: string, code: string, remember: boolean) {
  const result = await api("/auth/2fa/verify", { body: { two_factor_token: token, provider, code, remember }, auth: false });
  if (!pendingMaster) throw new Error("Sign-in expired. Start again.");
  const master = pendingMaster;
  pendingMaster = null;
  if (result.remember_token) {
    const l = await local.get();
    await local.set({ rememberTokens: { ...l.rememberTokens, [pendingEmail]: result.remember_token } });
  }
  await finishLogin(master, result);
}

export const sendTwoFactorEmail = (token: string) => api("/auth/2fa/email", { body: { two_factor_token: token }, auth: false });

async function finishLogin(master: core.MasterKeys, result: any) {
  try {
    await local.set({ tokens: { access: result.access_token, refresh: result.refresh_token }, email: result.email });
    const id = await activeId();
    const acct = master.unlock(result.bundle);
    unload();
    account = acct;
    bundle = result.bundle;
    currentId = id;
  } finally {
    master.free();
  }
  await persistUnlocked();
  await markVerified();
  await sync();
}

/** Derive the master keys and open the account bundle (throws a user-facing error). */
function openBundle(b: any, password: string, sk: string | undefined): core.Account {
  const master = core.deriveMasterKeys(password, sk, b.account_id, b.kdf, b.secret_key_enabled);
  try {
    return master.unlock(b);
  } catch {
    throw new Error(b.secret_key_enabled && !sk ? "secret_key_required" : "Wrong master password or Secret Key.");
  } finally {
    master.free();
  }
}

/**
 * Unlock with the master password. The bundle (wrapped account keys) comes
 * from the offline copy when there is one, so unlocking works without the
 * server; if that bundle is out of date (password changed on another device)
 * a fresh one is fetched and tried.
 */
export async function unlock(password: string, secretKey?: string) {
  await initWasm();
  const l = await local.get();
  const id = l.activeId;
  const cached = await syncCache.get(id);
  let fresh: any = null;
  let b = cached?.bundle;
  if (!b) {
    fresh = await api("/sync", { accountId: id });
    b = fresh.bundle;
  }
  const sk = secretKey?.trim() || l.secretKeys[l.email];
  let acct: core.Account;
  try {
    acct = openBundle(b, password, sk);
  } catch (e) {
    if (fresh) throw e;
    fresh = await api("/sync", { accountId: id }).catch(() => null);
    if (!fresh || JSON.stringify(fresh.bundle) === JSON.stringify(b)) throw e;
    b = fresh.bundle;
    acct = openBundle(b, password, sk);
  }
  unload();
  account = acct;
  bundle = b;
  currentId = id;
  if (secretKey?.trim()) await local.set({ secretKeys: { ...l.secretKeys, [l.email]: secretKey.trim() } });
  await persistUnlocked();
  await markVerified();
  if (fresh) await applyAndStore(fresh, id);
  else if (cached) {
    apply(cached);
    void refreshIfStale().catch(() => {});
  } else await sync();
}

async function persistUnlocked() {
  if (!account) return;
  const data: SessionData = { accountId: bundle.account_id, keys: b64(account.toSessionBytes()), bundle };
  await session.set(data, currentId);
  await persistForNever();
}

/** Vault timeout "never": keep unlocked keys on disk so a browser restart stays unlocked; otherwise remove them for every account. */
export async function persistForNever() {
  const { settings, accounts } = await local.get();
  for (const id of Object.keys(accounts)) {
    if (settings.vaultTimeout !== "never") {
      if (accounts[id].persistedKeys) await local.set({ persistedKeys: null }, id);
      continue;
    }
    const data = await session.get(id);
    if (data) await local.set({ persistedKeys: data }, id);
  }
}

// ------------------------------------------------------- user verification

const verifiedKey = (id: string) => `verified:${id}`;

/** The user just proved they know the master password (unlock, sign-in, or a passkey prompt). */
async function markVerified() {
  if (currentId) await scratch.set(verifiedKey(currentId), Date.now());
}

/** Whether the master password was entered for the active account within `ms`. */
export async function recentlyVerified(ms: number) {
  const at = currentId ? await scratch.get<number>(verifiedKey(currentId)) : undefined;
  return !!at && Date.now() - at < ms;
}

/** Check the master password again (passkey user verification); throws a user-facing error. */
export async function verifyMasterPassword(password: string) {
  if (!account || !bundle) throw new Error("locked");
  await initWasm();
  const l = await local.get();
  openBundle(bundle, password, l.secretKeys[l.email]).free();
  await markVerified();
}

/**
 * Fresh proof of the master password for sensitive account changes: an OPAQUE
 * login with purpose "reauth" for the active account. Returns the reauth token.
 */
async function reauthToken(password: string): Promise<string> {
  await initWasm();
  const { id: accountId } = await local.account();
  const l = await local.get();
  const email = l.email;
  const sk = l.secretKeys[email.trim().toLowerCase()];
  const pre = await api("/auth/prelogin", { body: { email }, auth: false, accountId });
  if (pre.secret_key_required && !sk) throw new Error("Your Secret Key isn't saved in this browser. Sign out and sign in again with it.");
  const master = core.deriveMasterKeys(password, pre.secret_key_required ? sk : undefined, pre.account_id, pre.kdf, pre.secret_key_required);
  try {
    const start = core.opaqueLoginStart(master);
    const resp = await api("/auth/login/start", { body: { email, message: start.message }, auth: false, accountId });
    let fin: string;
    try {
      fin = core.opaqueLoginFinish(start.state, master, resp.message);
    } catch {
      throw new Error("Wrong master password.");
    }
    const result = await api("/auth/login/finish", {
      body: { login_id: resp.login_id, message: fin, device: await deviceInfo(), purpose: "reauth" },
      accountId,
    });
    if (!result.reauth_token) throw new Error("Your server didn't confirm your master password. Try again.");
    return result.reauth_token as string;
  } finally {
    master.free();
  }
}

/** Two-step login security keys of the active account. */
export async function securityKeys(): Promise<SecurityKeys> {
  const a = await api("/account");
  const methods = ((a.two_factor ?? []) as string[]).filter((p) => p !== "recovery");
  return { keys: (a.passkeys ?? []) as SecurityKey[], methods };
}

/** Remove a two-step login security key, after the master password. */
export async function removeSecurityKey(id: string, password: string): Promise<SecurityKeys> {
  const token = await reauthToken(password);
  await api(`/account/2fa/passkey/${encodeURIComponent(id)}`, { method: "DELETE", headers: { "x-reauth-token": token } });
  return securityKeys();
}

// ------------------------------------------------------------- restore

/** Restore keys after a service-worker restart (single-flight per account). Returns false when locked. */
export async function ensureUnlocked(): Promise<boolean> {
  await lockCheck();
  const id = await activeId();
  if (!id) return false;
  if (account && currentId === id) {
    if (!loaded) await openVault(id);
    return true;
  }
  if (restoring?.id === id) return restoring.p;
  const p = restore(id).finally(() => {
    if (restoring?.p === p) restoring = null;
  });
  restoring = { id, p };
  return p;
}

async function restore(id: string): Promise<boolean> {
  let s = await session.get(id);
  if (!s) {
    const l = await local.get();
    if (l.activeId !== id || l.settings.vaultTimeout !== "never" || !l.persistedKeys || !l.tokens) return false;
    s = l.persistedKeys;
    await session.set(s, id);
  }
  await initWasm();
  if ((await activeId()) !== id) return false;
  unload();
  account = core.accountFromSessionBytes(s.accountId, unb64(s.keys));
  bundle = s.bundle;
  currentId = id;
  await openVault(id);
  return true;
}

/** Show the offline copy straight away and refresh in the background; without one, sync now. */
async function openVault(id: string) {
  const gen = generation;
  const cached = await syncCache.get(id);
  if (gen !== generation || currentId !== id) return;
  if (cached && !loaded) {
    apply(cached);
    void refreshIfStale().catch(() => {});
    return;
  }
  await sync();
}

/**
 * Called whenever an account's keys are dropped on purpose (lock, sign-out,
 * switching or adding accounts, vault timeout): short-lived state that belongs
 * to the unlocked account, like a typed login waiting to be saved, goes too.
 * Not called when the service worker merely reloads the keys from the session.
 */
let keysDropped: () => void = () => {};
export function setKeysDroppedHandler(fn: () => void) {
  keysDropped = fn;
}

/** Drop the keys of `id` (default: the active account), in memory, in the session and on disk. */
async function clearUnlocked(id?: string) {
  keysDropped();
  const aid = id ?? (await activeId());
  if (!id || aid === currentId) unload();
  await session.clear(aid);
  await local.set({ persistedKeys: null }, aid);
}

export async function lock() {
  await clearUnlocked();
}

/** Sign out of the active account. With other accounts present it's removed from the list and the next one becomes active. */
export async function logout() {
  try {
    await api("/auth/logout", { method: "POST" });
  } catch {
    /* already signed out */
  }
  const { activeId: id, accounts } = await local.get();
  await clearUnlocked(id);
  await syncCache.clear(id);
  if (Object.values(accounts).filter((a) => a.server).length > 1) await local.removeAccount(id);
  else await local.set({ tokens: null }, id);
}

/** Forget the loaded keys in memory only (the session stays, so switching back is instant). */
function unload() {
  generation++;
  vaults.forEach((v) => v.key.free());
  vaults = [];
  entries = [];
  revision = 0;
  loaded = false;
  account?.free();
  account = null;
  currentId = "";
  bundle = null;
  pendingMaster?.free();
  pendingMaster = null;
}

export async function switchAccount(id: string) {
  const { accounts, activeId } = await local.get();
  if (!accounts[id]?.server) throw new Error("That account isn't on this device any more.");
  if (id === activeId) return;
  keysDropped();
  unload();
  await local.setActive(id);
}

export async function addAccount() {
  keysDropped();
  unload();
  await local.addAccount();
}

/** Leave an unfinished "add account" (no sign-in yet) and go back to a signed-in account. */
export async function cancelAddAccount() {
  const { activeId, tokens, accounts } = await local.get();
  if (tokens || !Object.values(accounts).some((a) => a.tokens)) return;
  keysDropped();
  unload();
  await local.removeAccount(activeId);
}

/** Vault timeout: lock every account. */
export async function lockAll() {
  keysDropped();
  const { accounts } = await local.get();
  unload();
  for (const id of Object.keys(accounts)) await session.clear(id);
  for (const [id, a] of Object.entries(accounts)) if (a.persistedKeys) await local.set({ persistedKeys: null }, id);
}

/** Whether any account is unlocked right now (keys in memory or in the session). */
export async function anyUnlocked() {
  if (account) return true;
  const { accounts } = await local.get();
  for (const id of Object.keys(accounts)) if (await session.get(id)) return true;
  return false;
}

/** Vault timeout with the "sign out" action: sign every account out (they stay listed) and forget their offline copies. */
export async function logoutAll() {
  const { accounts } = await local.get();
  await lockAll();
  for (const [id, a] of Object.entries(accounts)) {
    await syncCache.clear(id);
    if (!a.tokens) continue;
    await logoutRemote(a.server, a.tokens);
    await local.set({ tokens: null }, id);
  }
}

// -------------------------------------------------------------------- sync

export async function sync() {
  if (!account) return;
  const id = currentId;
  const gen = generation;
  const data = await api("/sync", { accountId: id });
  // Locked, signed out or switched meanwhile, or an older response than what's shown.
  if (gen !== generation || !account || currentId !== id) return;
  if (loaded && data.revision < revision) return;
  await applyAndStore(data, id);
}

async function applyAndStore(data: any, id: string) {
  apply(data);
  await syncCache.set(id, data);
  await local.set({ lastSync: Date.now(), name: data.user?.name ?? "" }, id);
}

/** Decrypt a /sync response (fresh or the offline copy) into vaults and entries. */
function apply(data: any) {
  if (!account) return;
  if (data.bundle) bundle = data.bundle;
  const next: Vault[] = [];
  for (const v of data.vaults) {
    try {
      const key = account.openVaultKey(v.id, v.wrapped_key, v.key_kind);
      let name = "Vault";
      try {
        name = key.decryptMeta(v.id, v.meta).name ?? name;
      } catch {
        /* keep default name */
      }
      next.push({ id: v.id, name, role: v.role, kind: v.key_kind, key });
    } catch {
      /* vault key unavailable (rotated); skip */
    }
  }
  const byId = new Map(next.map((v) => [v.id, v]));
  const list: Entry[] = [];
  for (const row of data.items) {
    const vault = byId.get(row.vault_id);
    if (!vault || row.deleted_at) continue;
    const enc: EncryptedItem = { id: row.id, vault_id: row.vault_id, key: row.item_key, data: row.data };
    try {
      list.push({ id: row.id, item: vault.key.decryptItem(enc) as Item, vaultId: row.vault_id, revision: row.revision, enc });
    } catch {
      /* undecryptable item; skip */
    }
  }
  list.sort((a, b) => a.item.name.localeCompare(b.item.name, undefined, { sensitivity: "base" }));
  vaults.forEach((v) => v.key.free());
  vaults = next;
  entries = list;
  revision = data.revision;
  loaded = true;
}

/** Re-sync if the server has newer data (cheap revision check). */
export async function refreshIfStale() {
  if (!account) return;
  const id = currentId;
  const r = await api("/sync/revision", { accountId: id }).catch(() => null);
  if (r && currentId === id && r.revision > revision) await sync();
}

// ------------------------------------------------------------------- items

export function allEntries() {
  return entries;
}

export function getEntry(id: string) {
  return entries.find((e) => e.id === id);
}

export function vaultName(id: string) {
  return vaults.find((v) => v.id === id)?.name ?? "Vault";
}

export function summarize(e: Entry): ItemSummary {
  const i = e.item;
  const host = siteHost(i);
  return {
    id: e.id,
    name: i.name || "Untitled",
    subtitle: i.login?.username || host || (i.card ? `•••• ${i.card.number.slice(-4)}` : i.notes.split("\n")[0].slice(0, 50)),
    host,
    url: i.login?.urls.find((u) => u.match !== "regex" && /^https?:\/\//i.test(u.url))?.url ?? (host ? `https://${host}` : ""),
    folder: i.folder ?? "",
    kind: kindOf(i),
    favorite: i.favorite,
    hasPassword: !!i.login?.password,
    hasTotp: !!i.login?.totp,
    passkeys: i.login?.passkeys.length ?? 0,
    vaultName: vaultName(e.vaultId),
  };
}

/**
 * Where new items go when no vault is chosen (save prompts, passkeys): the
 * user's own vault, whose key is wrapped with their account key. A vault
 * shared by someone else ("sealed") is never picked automatically, so nobody
 * who adds you to their vault — nor the server — can collect your new logins.
 */
function personalVault(): Vault {
  const own = vaults.filter((x) => x.kind === "account" && x.role !== "read");
  const v = own.find((x) => x.role === "owner") ?? own[0];
  if (!v) throw new Error("PassAuth couldn't find your own vault to save to. Add the item in the PassAuth popup and choose a vault.");
  return v;
}

export async function createItem(item: Item, vaultId?: string): Promise<string> {
  const chosen = vaultId ? vaults.find((v) => v.id === vaultId) : undefined;
  if (vaultId && (!chosen || chosen.role === "read")) throw new Error("You can't add items to that vault.");
  const vault = chosen ?? personalVault();
  const id = core.newId();
  const now = Math.floor(Date.now() / 1000);
  const enc = vault.key.encryptItem({ ...item, created_at: now, updated_at: now }, id, vault.id);
  await api("/items", { body: enc });
  await sync();
  return id;
}

export async function updateItem(entry: Entry, item: Item) {
  const vault = vaults.find((v) => v.id === entry.vaultId);
  if (!vault) throw new Error("Vault not found.");
  if (vault.role === "read") throw new Error("You can only view items in this vault.");
  const now = Math.floor(Date.now() / 1000);
  const next = { ...item, updated_at: now };
  const old = entry.item.login?.password;
  // Compare by content: items from the popup arrive as structured clones, never the same object.
  if (next.login && old && old !== next.login.password && next.password_history[0]?.password !== old) {
    next.password_history = [{ password: old, changed_at: now }, ...next.password_history].slice(0, 20);
  }
  const enc = vault.key.updateItem(entry.enc, next);
  await api(`/items/${entry.id}`, { method: "PUT", body: { ...enc, revision: entry.revision } });
  await sync();
}

export async function trashItem(entry: Entry) {
  if (!canWrite(entry)) throw new Error("You can only view items in this vault.");
  await api(`/items/${entry.id}`, { method: "DELETE" });
  await sync();
}

/** Vaults the user can add items to, and folder names in use (for the item editor). */
export function editorInfo() {
  // The user's own vault first: the editor preselects the first one.
  let own: Vault | undefined;
  try {
    own = personalVault();
  } catch {
    own = undefined;
  }
  const writable = vaults.filter((v) => v.role !== "read");
  const ordered = own ? [own, ...writable.filter((v) => v !== own)] : writable;
  return {
    vaults: ordered.map((v) => ({ id: v.id, name: v.name })),
    /** Preselected only when it's the user's own vault; shared vaults are never picked for them. */
    defaultVault: own?.id ?? "",
    folders: [...new Set(entries.map((e) => e.item.folder).filter(Boolean))] as string[],
  };
}

export function canWrite(entry: Entry) {
  return vaults.find((v) => v.id === entry.vaultId)?.role !== "read";
}

/** In one of the user's own vaults (key wrapped with their account key), not a vault somebody shared with them. */
export function isPersonal(entry: Entry) {
  return vaults.find((v) => v.id === entry.vaultId)?.kind === "account";
}

/** Weak if it would take few guesses (same threshold as the web vault's "easy to guess"). */
export function weakPassword(password: string) {
  return !!password && core.estimateBits(password) < 50;
}

export function totp(secret: string) {
  return core.totpCode(secret, Date.now() / 1000) as { code: string; remaining: number; period: number };
}

export async function generate(mode: "password" | "passphrase", options?: Record<string, unknown>) {
  await initWasm();
  return mode === "password" ? core.generatePassword(options) : core.generatePassphrase(options);
}
