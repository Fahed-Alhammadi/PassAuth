/**
 * Vault session: authentication flows, key handles and the decrypted vault.
 * Decrypted data and key handles live only in memory; locking frees them.
 */
import { useSyncExternalStore } from "react";
import * as core from "../wasm/passauth_core";
import { api, deviceInfo, getTokens, onSessionLost, setTokens } from "./api";
import type { EncryptedItem, Item, Role, VaultEntry } from "./types";

export type Status = "loading" | "logged-out" | "locked" | "unlocked";

export interface Vault {
  id: string;
  name: string;
  role: Role;
  kind: "account" | "sealed";
  key: core.VaultKey;
}

export interface State {
  status: Status;
  email: string;
  userId: string;
  name: string;
  emailVerified: boolean;
  vaults: Vault[];
  items: VaultEntry[];
  revision: number;
  warnings: string[];
}

const initial: State = { status: "loading", email: "", userId: "", name: "", emailVerified: true, vaults: [], items: [], revision: 0, warnings: [] };
let state: State = initial;
let account: core.Account | null = null;
let bundle: any = null;
let socket: WebSocket | null = null;
const subs = new Set<() => void>();

function set(patch: Partial<State>) {
  state = { ...state, ...patch };
  subs.forEach((fn) => fn());
}

export function useVault(): State {
  return useSyncExternalStore(
    (fn) => (subs.add(fn), () => subs.delete(fn)),
    () => state,
  );
}

export const getState = () => state;
export const getAccount = () => account;
export const getBundle = () => bundle;

onSessionLost(() => resetToLoggedOut());

// ------------------------------------------------------------- Secret Key

const skKey = (email: string) => `pa.sk.${email.trim().toLowerCase()}`;
export function rememberedSecretKey(email: string): string | null {
  try {
    return localStorage.getItem(skKey(email));
  } catch {
    return null;
  }
}
export function rememberSecretKey(email: string, sk: string | null) {
  try {
    if (sk) localStorage.setItem(skKey(email), sk);
    else localStorage.removeItem(skKey(email));
  } catch {
    /* ignore */
  }
}
export function lastEmail(): string {
  try {
    return localStorage.getItem("pa.email") ?? "";
  } catch {
    return "";
  }
}

// ---------------------------------------------------------------- startup

export async function boot() {
  if (!getTokens()) return set({ status: "logged-out", email: lastEmail() });
  try {
    const sync = await api("/sync");
    bundle = sync.bundle;
    set({ status: "locked", email: sync.user.email, userId: sync.user.id, name: sync.user.name, emailVerified: sync.user.email_verified });
  } catch {
    resetToLoggedOut();
  }
}

function resetToLoggedOut() {
  dropKeys();
  setTokens(null);
  set({ ...initial, status: "logged-out", email: lastEmail() });
}

function dropKeys() {
  socket?.close();
  socket = null;
  state.vaults.forEach((v) => v.key.free());
  account?.free();
  account = null;
}

// ------------------------------------------------------------ registration

export interface RegisterResult {
  secretKey: string | null;
  emailVerificationRequired: boolean;
}

export async function register(email: string, name: string, password: string, withSecretKey: boolean): Promise<RegisterResult> {
  const init = await api("/auth/register/init", { body: { email }, auth: false });
  const created = core.createAccount(init.account_id, password, withSecretKey);
  const master = created.takeMaster();
  const acct = created.takeAccount();
  try {
    const start = core.opaqueRegisterStart(master);
    const resp = await api("/auth/register/start", { body: { registration_id: init.registration_id, message: start.message }, auth: false });
    const upload = core.opaqueRegisterFinish(start.state, master, resp.message);
    const vaultId = core.newId();
    const nv = acct.newVaultKey(vaultId);
    const vk = nv.takeKey();
    const meta = vk.encryptMeta(vaultId, { name: "Personal" });
    vk.free();
    const done = await api("/auth/register/finish", {
      auth: false,
      body: { registration_id: init.registration_id, upload, bundle: created.bundle, name, vault: { id: vaultId, meta, wrapped_key: nv.wrapped } },
    });
    if (created.secretKey) rememberSecretKey(email, created.secretKey);
    return { secretKey: created.secretKey ?? null, emailVerificationRequired: done.email_verification_required };
  } finally {
    master.free();
    acct.free();
    created.free();
  }
}

// ------------------------------------------------------------------- login

export type LoginOutcome = { done: true } | { done: false; twoFactorToken: string; providers: string[] };
let pendingMaster: core.MasterKeys | null = null;

async function opaqueLogin(email: string, password: string, secretKey: string | null, purpose?: "reauth") {
  const pre = await api("/auth/prelogin", { body: { email }, auth: false });
  if (pre.secret_key_required && !secretKey) throw new Error("secret_key_required");
  const master = core.deriveMasterKeys(password, pre.secret_key_required ? secretKey : undefined, pre.account_id, pre.kdf, pre.secret_key_required);
  const start = core.opaqueLoginStart(master);
  const resp = await api("/auth/login/start", { body: { email, message: start.message }, auth: false });
  let fin: string;
  try {
    fin = core.opaqueLoginFinish(start.state, master, resp.message);
  } catch {
    master.free();
    throw new Error("Wrong email, master password or Secret Key.");
  }
  const remember = rememberToken(email);
  const result = await api("/auth/login/finish", {
    auth: purpose === "reauth",
    body: { login_id: resp.login_id, message: fin, device: deviceInfo(), purpose, remember_token: remember },
  });
  return { master, result };
}

export async function login(email: string, password: string, secretKey: string | null): Promise<LoginOutcome> {
  const { master, result } = await opaqueLogin(email, password, secretKey);
  if (secretKey) rememberSecretKey(email, secretKey);
  if (result.two_factor_required) {
    pendingMaster?.free();
    pendingMaster = master;
    return { done: false, twoFactorToken: result.two_factor_token, providers: result.providers };
  }
  await finishLogin(master, result);
  return { done: true };
}

export async function verifyTwoFactor(token: string, provider: string, code: string, remember: boolean) {
  const result = await api("/auth/2fa/verify", { body: { two_factor_token: token, provider, code, remember }, auth: false });
  if (!pendingMaster) throw new Error("Sign-in expired, start again.");
  const master = pendingMaster;
  pendingMaster = null;
  await finishLogin(master, result);
}

export async function sendTwoFactorEmail(token: string) {
  await api("/auth/2fa/email", { body: { two_factor_token: token }, auth: false });
}

const rememberKey = (email: string) => `pa.remember.${email.trim().toLowerCase()}`;
function rememberToken(email: string) {
  try {
    return localStorage.getItem(rememberKey(email)) ?? undefined;
  } catch {
    return undefined;
  }
}

async function finishLogin(master: core.MasterKeys, result: any) {
  try {
    setTokens({ access: result.access_token, refresh: result.refresh_token });
    if (result.remember_token) localStorage.setItem(rememberKey(result.email), result.remember_token);
    localStorage.setItem("pa.email", result.email);
    bundle = result.bundle;
    account = master.unlock(bundle);
  } finally {
    master.free();
  }
  set({ email: result.email, userId: result.user_id });
  await sync();
  connectSocket();
}

/** Unlock a locked session locally (the bundle is already cached). */
export async function unlock(password: string, secretKey: string | null) {
  const master = core.deriveMasterKeys(password, secretKey ?? undefined, bundle.account_id, bundle.kdf, bundle.secret_key_enabled);
  try {
    account = master.unlock(bundle);
  } catch {
    throw new Error("Wrong master password or Secret Key.");
  } finally {
    master.free();
  }
  if (secretKey) rememberSecretKey(state.email, secretKey);
  await sync();
  connectSocket();
}

/** Fresh proof of the master password for sensitive settings. */
export async function reauth(password: string): Promise<string> {
  const sk = bundle.secret_key_enabled ? rememberedSecretKey(state.email) : null;
  const { master, result } = await opaqueLogin(state.email, password, sk, "reauth");
  master.free();
  return result.reauth_token;
}

export function lock() {
  dropKeys();
  set({ status: "locked", vaults: [], items: [], revision: 0 });
}

export async function logout() {
  try {
    await api("/auth/logout", { method: "POST" });
  } catch {
    /* already gone */
  }
  resetToLoggedOut();
}

// -------------------------------------------------------------------- sync

export async function sync() {
  if (!account) return;
  const data = await api("/sync");
  bundle = data.bundle;
  const warnings: string[] = [];
  const vaults: Vault[] = [];
  for (const v of data.vaults) {
    try {
      const key = account.openVaultKey(v.id, v.wrapped_key, v.key_kind);
      let name = "Vault";
      try {
        name = key.decryptMeta(v.id, v.meta).name ?? name;
      } catch {
        warnings.push(`Could not read the name of vault ${v.id}.`);
      }
      vaults.push({ id: v.id, name, role: v.role, kind: v.key_kind, key });
    } catch {
      warnings.push(`Could not open vault ${v.id}: its key may have been rotated.`);
    }
  }
  const byId = new Map(vaults.map((v) => [v.id, v]));
  const items: VaultEntry[] = [];
  for (const row of data.items) {
    const vault = byId.get(row.vault_id);
    if (!vault) continue;
    const enc: EncryptedItem = { id: row.id, vault_id: row.vault_id, key: row.item_key, data: row.data };
    try {
      const item = vault.key.decryptItem(enc) as Item;
      items.push({ id: row.id, item, vaultId: row.vault_id, revision: row.revision, deletedAt: row.deleted_at, enc });
    } catch {
      warnings.push(`An item in "${vault.name}" could not be decrypted and was skipped.`);
    }
  }
  items.sort((a, b) => a.item.name.localeCompare(b.item.name, undefined, { sensitivity: "base" }));
  state.vaults.forEach((v) => v.key.free());
  set({ status: "unlocked", vaults, items, revision: data.revision, warnings, name: data.user.name, emailVerified: data.user.email_verified });
}

function connectSocket() {
  socket?.close();
  const t = getTokens();
  if (!t) return;
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/api/ws?access_token=${encodeURIComponent(t.access)}`);
  socket = ws;
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === "sync" && msg.revision > state.revision) sync().catch(() => {});
    if (msg.type === "logout") resetToLoggedOut();
  };
  ws.onclose = () => {
    if (socket !== ws || state.status !== "unlocked") return;
    // Reconnect after the access token has had a chance to refresh.
    setTimeout(() => {
      if (state.status === "unlocked" && socket === ws) {
        api("/sync/revision")
          .then((r) => (r.revision > state.revision ? sync() : undefined))
          .catch(() => {})
          .finally(connectSocket);
      }
    }, 3000);
  };
}

// ------------------------------------------------------------------- items

function vaultKey(vaultId: string) {
  const v = state.vaults.find((x) => x.id === vaultId);
  if (!v) throw new Error("Vault not found.");
  return v.key;
}

export function writableVaults() {
  return state.vaults.filter((v) => v.role !== "read");
}

export async function createItem(vaultId: string, item: Item): Promise<string> {
  const id = core.newId();
  const now = Math.floor(Date.now() / 1000);
  const enc = vaultKey(vaultId).encryptItem({ ...item, created_at: now, updated_at: now }, id, vaultId);
  await api("/items", { body: enc });
  await sync();
  return id;
}

export async function updateItem(entry: VaultEntry, item: Item, vaultId = entry.vaultId) {
  const now = Math.floor(Date.now() / 1000);
  const old = entry.item.login?.password;
  const next = { ...item, updated_at: now };
  if (next.login && old && old !== next.login.password) {
    next.password_history = [{ password: old, changed_at: now }, ...next.password_history].slice(0, 20);
  }
  const enc =
    vaultId === entry.vaultId ? vaultKey(vaultId).updateItem(entry.enc, next) : vaultKey(vaultId).encryptItem(next, entry.id, vaultId);
  await api(`/items/${entry.id}`, { method: "PUT", body: { ...enc, revision: entry.revision } });
  await sync();
}

export async function trashItem(id: string) {
  await api(`/items/${id}`, { method: "DELETE" });
  await sync();
}

export async function restoreItem(id: string) {
  await api(`/items/${id}/restore`, { method: "POST" });
  await sync();
}

export async function purgeItem(id: string) {
  await api(`/items/${id}/permanent`, { method: "DELETE" });
  await sync();
}

/** Encrypt and upload imported items in batches. */
export async function importItems(vaultId: string, items: Item[], progress?: (done: number) => void) {
  const key = vaultKey(vaultId);
  const now = Math.floor(Date.now() / 1000);
  for (let i = 0; i < items.length; i += 250) {
    const batch = items.slice(i, i + 250).map((it) => {
      const id = core.newId();
      return key.encryptItem({ ...it, created_at: it.created_at || now, updated_at: now }, id, vaultId);
    });
    await api("/items/import", { body: { items: batch } });
    progress?.(Math.min(i + 250, items.length));
  }
  await sync();
}

// ------------------------------------------------------------------ vaults

export async function createVault(name: string): Promise<string> {
  if (!account) throw new Error("Vault is locked.");
  const id = core.newId();
  const nv = account.newVaultKey(id);
  const key = nv.takeKey();
  const meta = key.encryptMeta(id, { name });
  key.free();
  await api("/vaults", { body: { id, meta, wrapped_key: nv.wrapped } });
  await sync();
  return id;
}

export async function renameVault(id: string, name: string) {
  await api(`/vaults/${id}`, { method: "PUT", body: { meta: vaultKey(id).encryptMeta(id, { name }) } });
  await sync();
}

export async function deleteVault(id: string) {
  await api(`/vaults/${id}`, { method: "DELETE" });
  await sync();
}

export async function lookupUser(email: string) {
  return api<{ user_id: string; name: string; public_key: string }>(`/users/lookup?email=${encodeURIComponent(email)}`);
}

export async function shareVault(vaultId: string, user: { user_id: string; public_key: string }, role: Role) {
  const sealed = vaultKey(vaultId).shareTo(vaultId, user.public_key);
  await api(`/vaults/${vaultId}/members`, { body: { user_id: user.user_id, role, sealed_key: sealed } });
}

/**
 * Remove a member and rotate the vault key so they can't read future changes:
 * a fresh key is sealed to every remaining member and all items re-encrypted.
 */
export async function removeMember(vaultId: string, userId: string) {
  if (!account) throw new Error("Vault is locked.");
  await api(`/vaults/${vaultId}/members/${userId}`, { method: "DELETE" });
  const { members } = await api(`/vaults/${vaultId}/members`);
  const nv = account.newVaultKey(vaultId);
  const fresh = nv.takeKey();
  try {
    const keys = members.map((m: any) =>
      m.user_id === state.userId
        ? { user_id: m.user_id, wrapped_key: nv.wrapped, key_kind: "account" }
        : { user_id: m.user_id, wrapped_key: fresh.shareTo(vaultId, m.public_key), key_kind: "sealed" },
    );
    const items = state.items
      .filter((e) => e.vaultId === vaultId)
      .map((e) => fresh.encryptItem(e.item, e.id, vaultId));
    await api(`/vaults/${vaultId}/rotate`, { body: { keys, items } });
    const v = state.vaults.find((x) => x.id === vaultId);
    if (v) await api(`/vaults/${vaultId}`, { method: "PUT", body: { meta: fresh.encryptMeta(vaultId, { name: v.name }) } });
  } finally {
    fresh.free();
  }
  await sync();
}

// ---------------------------------------------------- password / Secret Key

/** Change master password and/or Secret Key setting. Returns the new Secret Key, if any. */
export async function changeKeys(currentPassword: string, newPassword: string, withSecretKey: boolean): Promise<string | null> {
  if (!account) throw new Error("Vault is locked.");
  const reauthToken = await reauth(currentPassword);
  const existing = bundle.secret_key_enabled ? rememberedSecretKey(state.email) : null;
  const next = account.rewrap(bundle, newPassword, withSecretKey, existing ?? undefined);
  const master = next.takeMaster();
  try {
    const start = core.opaqueRegisterStart(master);
    const resp = await api("/account/keys/start", { body: { message: start.message } });
    const upload = core.opaqueRegisterFinish(start.state, master, resp.message);
    await api("/account/keys/finish", { body: { upload, bundle: next.bundle }, headers: { "x-reauth-token": reauthToken } });
    bundle = next.bundle;
    if (!withSecretKey) rememberSecretKey(state.email, null);
    else if (next.secretKey) rememberSecretKey(state.email, next.secretKey);
    return next.secretKey ?? null;
  } finally {
    master.free();
    next.takeAccount().free();
    next.free();
  }
}

export const generatePassword = core.generatePassword;
export const generatePassphrase = core.generatePassphrase;
export const estimateBits = core.estimateBits;
export const totpCode = core.totpCode;
export const importFile = core.importFile;
export const exportVaultJson = core.exportVaultJson;
export const exportVaultEncrypted = core.exportVaultEncrypted;
export const exportVaultCsv = core.exportVaultCsv;
export const fingerprint = core.fingerprint;
