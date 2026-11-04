/**
 * Vault session: authentication flows, key handles and the decrypted vault.
 * Decrypted data and key handles live only in memory; locking frees them.
 *
 * Key handles are WASM objects that `sync()` frees when it replaces them, so code must
 * never hold a `VaultKey` across an `await`: look it up again with `vaultKey()` instead.
 */
import { useSyncExternalStore } from "react";
import * as core from "../wasm/passauth_core";
import { ApiError, UnreachableError, api, deviceInfo, getTokens, onSessionLost, setTokens } from "./api";
import {
  isSyncResponse,
  type Bundle,
  type EncryptedItem,
  type Item,
  type KeyKind,
  type LoginFinishResponse,
  type MemberRow,
  type PreloginResponse,
  type Role,
  type VaultEntry,
} from "./types";

export type Status = "loading" | "unreachable" | "logged-out" | "locked" | "unlocked";

export interface Vault {
  id: string;
  name: string;
  role: Role;
  kind: KeyKind;
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
  /** Vaults whose key still has to be replaced after a member was removed. */
  pendingRotations: string[];
}

const initial: State = {
  status: "loading",
  email: "",
  userId: "",
  name: "",
  emailVerified: true,
  vaults: [],
  items: [],
  revision: 0,
  warnings: [],
  pendingRotations: [],
};
let state: State = initial;
let account: core.Account | null = null;
let bundle: Bundle | null = null;
let socket: WebSocket | null = null;
/** Bumped whenever the keys are dropped (lock, sign-out): async work started before that is discarded. */
let generation = 0;
/** Items per vault that couldn't be decrypted in the last sync. */
let undecryptable = new Map<string, number>();
const subs = new Set<() => void>();

function set(patch: Partial<State>) {
  state = { ...state, ...patch };
  subs.forEach((fn) => fn());
}

const subscribe = (fn: () => void) => {
  subs.add(fn);
  return () => {
    subs.delete(fn);
  };
};
const snapshot = () => state;

export function useVault(): State {
  return useSyncExternalStore(subscribe, snapshot);
}

export const getState = () => state;
export const getAccount = () => account;
export const getBundle = () => bundle;

onSessionLost(() => resetToLoggedOut());

// Explicit locks and sign-outs apply to every open tab.
const channel = typeof BroadcastChannel === "function" ? new BroadcastChannel("passauth") : null;
channel?.addEventListener("message", (e: MessageEvent<{ type?: string }>) => {
  if (e.data?.type === "lock" && state.status === "unlocked") lock(false);
});

function store(key: string, value: string | null) {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    /* storage unavailable */
  }
}
function read(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

// ------------------------------------------------------------- Secret Key

const skKey = (email: string) => `pa.sk.${email.trim().toLowerCase()}`;
export function rememberedSecretKey(email: string): string | null {
  return read(skKey(email));
}
export function rememberSecretKey(email: string, sk: string | null) {
  store(skKey(email), sk);
}
export function lastEmail(): string {
  return read("pa.email") ?? "";
}

/**
 * Tidy a Secret Key typed from paper: Secret Keys use only A–Z and 2–7 after the PA1 prefix,
 * so a 0 is always an O and an 8 always a B.
 */
export function normalizeSecretKey(input: string): string {
  const t = input.trim().toUpperCase().replace(/\s+/g, "");
  if (!t.startsWith("PA1")) return t;
  return `PA1${t.slice(3).replace(/0/g, "O").replace(/8/g, "B")}`;
}

// ---------------------------------------------------------------- startup

export async function boot() {
  if (!getTokens()) return set({ status: "logged-out", email: lastEmail() });
  if (state.status !== "loading") set({ status: "loading" });
  try {
    const sync = await api("/sync");
    if (!isSyncResponse(sync)) throw new ApiError(200, "bad_response", "The server sent an unexpected response.");
    bundle = sync.bundle;
    set({ status: "locked", email: sync.user.email, userId: sync.user.id, name: sync.user.name, emailVerified: sync.user.email_verified });
  } catch (e) {
    // Only a server that rejects the session signs the user out; a network or server problem keeps it.
    if (!getTokens() || (e instanceof ApiError && (e.status === 401 || e.status === 403))) resetToLoggedOut();
    else set({ status: "unreachable", email: lastEmail() });
  }
}

function resetToLoggedOut() {
  dropKeys();
  setTokens(null);
  set({ ...initial, status: "logged-out", email: lastEmail() });
}

function dropKeys() {
  generation++;
  socket?.close();
  socket = null;
  const old = state.vaults;
  account?.free();
  account = null;
  undecryptable = new Map();
  if (old.length || state.items.length) set({ vaults: [], items: [] });
  old.forEach((v) => v.key.free());
}

// ------------------------------------------------------------ registration

export interface RegisterResult {
  secretKey: string | null;
  emailVerificationRequired: boolean;
}

export async function register(email: string, name: string, password: string, withSecretKey: boolean): Promise<RegisterResult> {
  const init = await api<{ account_id: string; registration_id: string }>("/auth/register/init", { body: { email }, auth: false });
  const created = core.createAccount(init.account_id, password, withSecretKey);
  const master = created.takeMaster();
  const acct = created.takeAccount();
  try {
    const start = core.opaqueRegisterStart(master);
    const resp = await api<{ message: string }>("/auth/register/start", { body: { registration_id: init.registration_id, message: start.message }, auth: false });
    const upload = core.opaqueRegisterFinish(start.state, master, resp.message);
    const vaultId = core.newId();
    const nv = acct.newVaultKey(vaultId);
    const vk = nv.takeKey();
    const meta = vk.encryptMeta(vaultId, { name: "Personal" });
    vk.free();
    const done = await api<{ email_verification_required: boolean }>("/auth/register/finish", {
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

/** Thrown when the master password or Secret Key is wrong. */
export const WRONG_CREDENTIALS = "Wrong email, master password or Secret Key.";

async function opaqueLogin(email: string, password: string, secretKey: string | null, purpose?: "reauth") {
  const pre = await api<PreloginResponse>("/auth/prelogin", { body: { email }, auth: false });
  if (pre.secret_key_required && !secretKey) throw new Error("secret_key_required");
  const sk = pre.secret_key_required && secretKey ? normalizeSecretKey(secretKey) : undefined;
  const master = core.deriveMasterKeys(password, sk, pre.account_id, pre.kdf, pre.secret_key_required);
  const start = core.opaqueLoginStart(master);
  let resp: { login_id: string; message: string };
  try {
    resp = await api("/auth/login/start", { body: { email, message: start.message }, auth: false });
  } catch (e) {
    master.free();
    throw e;
  }
  let fin: string;
  try {
    fin = core.opaqueLoginFinish(start.state, master, resp.message);
  } catch {
    master.free();
    throw new Error(WRONG_CREDENTIALS);
  }
  const remember = rememberToken(email);
  try {
    const result = await api<LoginFinishResponse>("/auth/login/finish", {
      auth: purpose === "reauth",
      body: { login_id: resp.login_id, message: fin, device: deviceInfo(), purpose, remember_token: remember },
    });
    return { master, result, secretKey: sk ?? null };
  } catch (e) {
    master.free();
    throw e;
  }
}

export async function login(email: string, password: string, secretKey: string | null): Promise<LoginOutcome> {
  const { master, result, secretKey: sk } = await opaqueLogin(email, password, secretKey);
  if (sk) rememberSecretKey(email, sk);
  if (result.two_factor_required) {
    pendingMaster?.free();
    pendingMaster = master;
    return { done: false, twoFactorToken: result.two_factor_token ?? "", providers: result.providers ?? [] };
  }
  await finishLogin(master, result);
  return { done: true };
}

export async function verifyTwoFactor(token: string, provider: string, code: string, remember: boolean) {
  const result = await api<LoginFinishResponse>("/auth/2fa/verify", { body: { two_factor_token: token, provider, code, remember }, auth: false });
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
  return read(rememberKey(email)) ?? undefined;
}

async function finishLogin(master: core.MasterKeys, result: LoginFinishResponse) {
  dropKeys();
  try {
    setTokens({ access: result.access_token, refresh: result.refresh_token });
    if (result.remember_token) store(rememberKey(result.email), result.remember_token);
    store("pa.email", result.email);
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
  if (!bundle) throw new Error("Sign in again to unlock this vault.");
  const sk = secretKey ? normalizeSecretKey(secretKey) : undefined;
  const master = core.deriveMasterKeys(password, sk, bundle.account_id, bundle.kdf, bundle.secret_key_enabled);
  dropKeys();
  try {
    account = master.unlock(bundle);
  } catch {
    throw new Error("Wrong master password or Secret Key.");
  } finally {
    master.free();
  }
  try {
    await sync();
  } catch (e) {
    dropKeys();
    throw e;
  }
  if (sk) rememberSecretKey(state.email, sk);
  connectSocket();
}

/** Fresh proof of the master password for sensitive settings. */
export async function reauth(password: string): Promise<string> {
  const sk = bundle?.secret_key_enabled ? rememberedSecretKey(state.email) : null;
  const { master, result } = await opaqueLogin(state.email, password, sk, "reauth");
  master.free();
  if (!result.reauth_token) throw new Error("reauth_required");
  return result.reauth_token;
}

/** Lock this tab; `everywhere` also locks the vault in this browser's other tabs. */
export function lock(everywhere = true) {
  dropKeys();
  set({ status: "locked", vaults: [], items: [], revision: 0, warnings: [] });
  if (everywhere) channel?.postMessage({ type: "lock" });
}

export async function logout() {
  try {
    await api("/auth/logout", { method: "POST" });
  } catch {
    /* already gone */
  }
  resetToLoggedOut();
}

export function dismissWarnings() {
  set({ warnings: [] });
}

// -------------------------------------------------------------------- sync

let running: Promise<void> | null = null;
let queued: Promise<void> | null = null;

/**
 * Fetch and decrypt the vault. Calls are serialised (a call made while one runs gets a fresh run
 * afterwards, so a write is always reflected), and a result that arrives after a lock is dropped.
 */
export function sync(): Promise<void> {
  if (queued) return queued;
  if (!running) {
    running = doSync().finally(() => (running = null));
    return running;
  }
  queued = running
    .catch(() => {})
    .then(() => {
      queued = null;
      running = doSync().finally(() => (running = null));
      return running;
    });
  return queued;
}

async function doSync() {
  if (!account) return;
  const gen = generation;
  const data = await api("/sync");
  if (gen !== generation || !account) return;
  if (!isSyncResponse(data)) throw new Error("The server sent an unexpected response. Reload the page to try again.");
  if (state.status === "unlocked" && data.revision < state.revision) return;
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
        warnings.push(`Couldn't read the name of one of your vaults.`);
      }
      vaults.push({ id: v.id, name, role: v.role, kind: v.key_kind, key });
    } catch {
      warnings.push(`One vault couldn't be opened: its key may have been replaced. Ask the person who manages it to share it with you again.`);
    }
  }
  const byId = new Map(vaults.map((v) => [v.id, v]));
  const items: VaultEntry[] = [];
  const failed = new Map<string, number>();
  for (const row of data.items) {
    const vault = byId.get(row.vault_id);
    if (!vault) continue;
    const enc: EncryptedItem = { id: row.id, vault_id: row.vault_id, key: row.item_key, data: row.data };
    try {
      const item = vault.key.decryptItem(enc) as Item;
      items.push({ id: row.id, item, vaultId: row.vault_id, revision: row.revision, deletedAt: row.deleted_at, enc });
    } catch {
      failed.set(row.vault_id, (failed.get(row.vault_id) ?? 0) + 1);
    }
  }
  for (const [id, n] of failed) {
    const name = byId.get(id)?.name ?? "a vault";
    warnings.push(`${n === 1 ? "An item" : `${n} items`} in "${name}" couldn't be decrypted and ${n === 1 ? "is" : "are"} hidden.`);
  }
  items.sort((a, b) => a.item.name.localeCompare(b.item.name, undefined, { sensitivity: "base" }));
  state.vaults.forEach((v) => v.key.free());
  undecryptable = failed;
  pinPersonalVault(data.user.id, vaults);
  set({
    status: "unlocked",
    vaults,
    items,
    revision: data.revision,
    warnings,
    name: data.user.name,
    emailVerified: data.user.email_verified,
    pendingRotations: readPendingRotations(data.user.id).filter((id) => byId.has(id)),
  });
}

function connectSocket() {
  socket?.close();
  const t = getTokens();
  if (!t) return;
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/api/ws?access_token=${encodeURIComponent(t.access)}`);
  socket = ws;
  ws.onmessage = (e) => {
    let msg: { type?: string; revision?: number };
    try {
      msg = JSON.parse(e.data);
    } catch {
      return;
    }
    if (msg.type === "sync" && (msg.revision ?? 0) > state.revision) sync().catch(() => {});
    if (msg.type === "logout") resetToLoggedOut();
  };
  ws.onclose = () => {
    if (socket !== ws || state.status !== "unlocked") return;
    // Reconnect after the access token has had a chance to refresh.
    setTimeout(() => {
      if (state.status === "unlocked" && socket === ws) {
        api<{ revision: number }>("/sync/revision")
          .then((r) => (r.revision > state.revision ? sync() : undefined))
          .catch(() => {})
          .finally(() => {
            if (state.status === "unlocked" && socket === ws) connectSocket();
          });
      }
    }, 3000);
  };
}

// -------------------------------------------------------------- save target

const personalKey = (userId: string) => `pa.personal.${userId}`;

/**
 * Remember the user's own vault. Only a vault wrapped with the user's account key ("account")
 * can be one they created; a shared ("sealed") vault is never chosen automatically, because
 * whoever shared it holds its key.
 */
function pinPersonalVault(userId: string, vaults: Vault[]) {
  const pinned = read(personalKey(userId));
  const own = vaults.filter((v) => v.kind === "account" && v.role === "owner");
  if (pinned && own.some((v) => v.id === pinned)) return;
  if (own[0]) store(personalKey(userId), own[0].id);
}

/** Where new items go unless the user picks another vault: their own vault, never a shared one. */
export function defaultVaultId(): string {
  const pinned = read(personalKey(state.userId));
  const own = state.vaults.filter((v) => v.kind === "account" && v.role === "owner");
  return own.find((v) => v.id === pinned)?.id ?? own[0]?.id ?? "";
}

// ------------------------------------------------------------------- items

function vaultKey(vaultId: string) {
  const v = state.vaults.find((x) => x.id === vaultId);
  if (!v) throw new Error(state.status === "unlocked" ? "Vault not found." : "The vault is locked. Unlock it and try again.");
  return v.key;
}

/** Vaults the user can write to, their own vault first. */
export function writableVaults() {
  const first = defaultVaultId();
  return state.vaults.filter((v) => v.role !== "read").sort((a, b) => (a.id === first ? -1 : b.id === first ? 1 : 0));
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
  if (next.login && old && old !== next.login.password && next.password_history[0]?.password !== old) {
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
  const gen = generation;
  const now = Math.floor(Date.now() / 1000);
  for (let i = 0; i < items.length; i += 250) {
    if (gen !== generation) throw new Error("The vault was locked during the import. Unlock it and import the file again.");
    // Look the key up for every batch: a sync triggered by the previous batch replaces (and frees) the old handle.
    const key = vaultKey(vaultId);
    const batch = items.slice(i, i + 250).map((it) => key.encryptItem({ ...it, created_at: it.created_at || now, updated_at: now }, core.newId(), vaultId));
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

const rotationKey = (userId: string) => `pa.rotate.${userId}`;
function readPendingRotations(userId: string): string[] {
  try {
    const v = JSON.parse(read(rotationKey(userId)) ?? "[]");
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}
function setPendingRotation(vaultId: string, pending: boolean) {
  const list = readPendingRotations(state.userId).filter((id) => id !== vaultId);
  if (pending) list.push(vaultId);
  store(rotationKey(state.userId), list.length ? JSON.stringify(list) : null);
  set({ pendingRotations: list });
}

/**
 * Remove a member and rotate the vault key so they can't read future changes:
 * a fresh key is sealed to every remaining member and all items re-encrypted.
 */
export async function removeMember(vaultId: string, userId: string) {
  if (!account) throw new Error("Vault is locked.");
  // Rotation must re-encrypt every item, so check that all of them can be read before removing anyone.
  await sync();
  if (undecryptable.get(vaultId)) {
    throw new Error(
      "Some items in this vault can't be decrypted, so PassAuth can't replace the vault key after removing this person. Nobody was removed.",
    );
  }
  const r = await api<{ rotation_required?: boolean }>(`/vaults/${vaultId}/members/${userId}`, { method: "DELETE" });
  if (r?.rotation_required === false) return sync();
  setPendingRotation(vaultId, true);
  await rotateVaultKey(vaultId);
}

/** Replace a vault's key and re-encrypt its items (finishes a member removal). */
export async function rotateVaultKey(vaultId: string) {
  if (!account) throw new Error("Vault is locked.");
  const gen = generation;
  await sync();
  if (gen !== generation || !account) throw new Error("The vault was locked. Unlock it and try again.");
  if (undecryptable.get(vaultId)) throw new Error("Some items in this vault can't be decrypted, so its key can't be replaced yet.");
  const { members } = await api<{ members: MemberRow[] }>(`/vaults/${vaultId}/members`);
  if (gen !== generation || !account) throw new Error("The vault was locked. Unlock it and try again.");
  const nv = account.newVaultKey(vaultId);
  const fresh = nv.takeKey();
  try {
    const keys = members.map((m) =>
      m.user_id === state.userId
        ? { user_id: m.user_id, wrapped_key: nv.wrapped, key_kind: "account" }
        : { user_id: m.user_id, wrapped_key: fresh.shareTo(vaultId, m.public_key), key_kind: "sealed" },
    );
    const items = state.items.filter((e) => e.vaultId === vaultId).map((e) => fresh.encryptItem(e.item, e.id, vaultId));
    const v = state.vaults.find((x) => x.id === vaultId);
    const meta = v ? fresh.encryptMeta(vaultId, { name: v.name }) : undefined;
    await api(`/vaults/${vaultId}/rotate`, { body: { keys, items, meta } });
    if (meta) await api(`/vaults/${vaultId}`, { method: "PUT", body: { meta } });
  } finally {
    fresh.free();
  }
  setPendingRotation(vaultId, false);
  await sync();
}

// ---------------------------------------------------- password / Secret Key

/** Change master password and/or Secret Key setting. Returns the new Secret Key, if any. */
export async function changeKeys(currentPassword: string, newPassword: string, withSecretKey: boolean): Promise<string | null> {
  if (!account || !bundle) throw new Error("Vault is locked.");
  const reauthToken = await reauth(currentPassword);
  const existing = bundle.secret_key_enabled ? rememberedSecretKey(state.email) : null;
  const next = account.rewrap(bundle, newPassword, withSecretKey, existing ?? undefined);
  const master = next.takeMaster();
  try {
    const start = core.opaqueRegisterStart(master);
    const resp = await api<{ message: string }>("/account/keys/start", { body: { message: start.message } });
    const upload = core.opaqueRegisterFinish(start.state, master, resp.message);
    await api("/account/keys/finish", { body: { upload, bundle: next.bundle }, headers: { "x-reauth-token": reauthToken } });
    bundle = next.bundle as Bundle;
    if (!withSecretKey) rememberSecretKey(state.email, null);
    else if (next.secretKey) rememberSecretKey(state.email, next.secretKey);
    return next.secretKey ?? null;
  } finally {
    master.free();
    next.takeAccount().free();
    next.free();
  }
}

export { UnreachableError };
export const generatePassword = core.generatePassword;
export const generatePassphrase = core.generatePassphrase;
export const estimateBits = core.estimateBits;
export const totpCode = core.totpCode;
export const importFile = core.importFile;
export const exportVaultJson = core.exportVaultJson;
export const exportVaultEncrypted = core.exportVaultEncrypted;
export const exportVaultCsv = core.exportVaultCsv;
export const fingerprint = core.fingerprint;
