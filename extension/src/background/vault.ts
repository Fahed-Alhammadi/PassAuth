/**
 * Background vault: authentication, key handles and decrypted items.
 * The service worker can be stopped at any time; unlocked keys survive in
 * chrome.storage.session and are restored on demand.
 */
import init, * as core from "../wasm/passauth_core";
import type { EncryptedItem, Item, Role } from "@web/lib/types";
import { kindOf } from "@web/lib/types";
import { api, setSessionLostHandler } from "./api";
import { local, session } from "./storage";
import type { ItemSummary, PopupState, TwoFactorChallenge } from "../shared/messages";

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
  key: core.VaultKey;
}

let ready: Promise<unknown> | null = null;
let account: core.Account | null = null;
let bundle: any = null;
let vaults: Vault[] = [];
let entries: Entry[] = [];
let revision = 0;
let pendingMaster: core.MasterKeys | null = null;
let pendingEmail = "";

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export function initWasm() {
  // Vite emits the .wasm as a packaged extension file and rewrites this URL.
  ready ??= init({ module_or_path: new URL("../wasm/passauth_core_bg.wasm", import.meta.url) });
  return ready;
}

setSessionLostHandler(() => {
  void clearUnlocked();
});

// ------------------------------------------------------------------ state

export async function state(): Promise<PopupState> {
  const l = await local.get();
  const s = await session.get();
  const status = !l.server ? "setup" : !l.tokens ? "logged-out" : s || account ? "unlocked" : "locked";
  return {
    status,
    server: l.server,
    email: l.email,
    secretKeyRequired: !!(bundle ?? s?.bundle as any)?.secret_key_enabled,
    secretKeyStored: !!l.secretKeys[l.email],
    autoLockMinutes: l.autoLockMinutes,
  };
}

export async function setServer(url: string) {
  const clean = url.trim().replace(/\/+$/, "");
  const u = new URL(clean.includes("://") ? clean : `https://${clean}`);
  if (u.protocol !== "https:" && u.hostname !== "localhost" && u.hostname !== "127.0.0.1") {
    throw new Error("Use an https:// address. Plain http is only allowed for localhost.");
  }
  const origin = u.origin + u.pathname.replace(/\/+$/, "");
  const r = await fetch(`${origin}/api/config`).catch(() => null);
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
    body: { login_id: resp.login_id, message: fin, device: await deviceInfo(), remember_token: l.rememberTokens[key] },
  });
  if (sk && pre.secret_key_required) await local.set({ secretKeys: { ...l.secretKeys, [key]: sk } });
  if (result.two_factor_required) {
    pendingMaster?.free();
    pendingMaster = master;
    pendingEmail = key;
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
    bundle = result.bundle;
    account = master.unlock(bundle);
  } finally {
    master.free();
  }
  await persistUnlocked();
  await sync();
}

export async function unlock(password: string, secretKey?: string) {
  await initWasm();
  const l = await local.get();
  if (!bundle) bundle = (await api("/sync")).bundle;
  const sk = secretKey?.trim() || l.secretKeys[l.email];
  const master = core.deriveMasterKeys(password, sk, bundle.account_id, bundle.kdf, bundle.secret_key_enabled);
  try {
    account = master.unlock(bundle);
  } catch {
    throw new Error(bundle.secret_key_enabled && !sk ? "secret_key_required" : "Wrong master password or Secret Key.");
  } finally {
    master.free();
  }
  if (secretKey?.trim()) await local.set({ secretKeys: { ...l.secretKeys, [l.email]: secretKey.trim() } });
  await persistUnlocked();
  await sync();
}

async function persistUnlocked() {
  if (!account) return;
  await session.set({ accountId: bundle.account_id, keys: b64(account.toSessionBytes()), bundle });
}

/** Restore keys after a service-worker restart. Returns false when locked. */
export async function ensureUnlocked(): Promise<boolean> {
  if (account) {
    if (!entries.length && !revision) await sync();
    return true;
  }
  const s = await session.get();
  if (!s) return false;
  await initWasm();
  bundle = s.bundle;
  account = core.accountFromSessionBytes(s.accountId, unb64(s.keys));
  await sync();
  return true;
}

async function clearUnlocked() {
  vaults.forEach((v) => v.key.free());
  vaults = [];
  entries = [];
  revision = 0;
  account?.free();
  account = null;
  await session.clear();
}

export async function lock() {
  await clearUnlocked();
}

export async function logout() {
  try {
    await api("/auth/logout", { method: "POST" });
  } catch {
    /* already signed out */
  }
  await clearUnlocked();
  bundle = null;
  await local.set({ tokens: null });
}

// -------------------------------------------------------------------- sync

export async function sync() {
  if (!account) return;
  const data = await api("/sync");
  bundle = data.bundle;
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
      next.push({ id: v.id, name, role: v.role, key });
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
}

/** Re-sync if the server has newer data (cheap revision check). */
export async function refreshIfStale() {
  if (!account) return;
  const r = await api("/sync/revision").catch(() => null);
  if (r && r.revision > revision) await sync();
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
  const host = i.login?.urls[0]?.url ? new URL(i.login.urls[0].url.includes("://") ? i.login.urls[0].url : `https://${i.login.urls[0].url}`).host : "";
  return {
    id: e.id,
    name: i.name || "Untitled",
    subtitle: i.login?.username || host || (i.card ? `•••• ${i.card.number.slice(-4)}` : i.notes.split("\n")[0].slice(0, 50)),
    kind: kindOf(i),
    favorite: i.favorite,
    hasPassword: !!i.login?.password,
    hasTotp: !!i.login?.totp,
    passkeys: i.login?.passkeys.length ?? 0,
    vaultName: vaultName(e.vaultId),
  };
}

function writableVault(): Vault {
  const v = vaults.find((x) => x.role === "owner") ?? vaults.find((x) => x.role !== "read");
  if (!v) throw new Error("You don't have a vault you can save to.");
  return v;
}

export async function createItem(item: Item, vaultId?: string): Promise<string> {
  const vault = vaultId ? vaults.find((v) => v.id === vaultId)! : writableVault();
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
  const enc = vault.key.updateItem(entry.enc, { ...item, updated_at: Math.floor(Date.now() / 1000) });
  await api(`/items/${entry.id}`, { method: "PUT", body: { ...enc, revision: entry.revision } });
  await sync();
}

export function canWrite(entry: Entry) {
  return vaults.find((v) => v.id === entry.vaultId)?.role !== "read";
}

export function totp(secret: string) {
  return core.totpCode(secret, Date.now() / 1000) as { code: string; remaining: number; period: number };
}

export async function generate(mode: "password" | "passphrase", options?: Record<string, unknown>) {
  await initWasm();
  return mode === "password" ? core.generatePassword(options) : core.generatePassphrase(options);
}
