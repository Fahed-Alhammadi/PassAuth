/**
 * Background vault: authentication, key handles and decrypted items.
 * The service worker can be stopped at any time; unlocked keys survive in
 * chrome.storage.session and are restored on demand (`ensureUnlocked`, single-flight),
 * and the vault opens from the offline copy (`openVault`, single-flight) before it
 * checks the server. Syncs are coalesced: calls during one share one follow-up.
 *
 * Delta sync (servers with the `delta_sync` feature; merge rules in `@web/lib/delta`, the extension's own in
 * sync-rules.ts): the offline copy is a snapshot, the last answer with every later change merged in, written as one
 * IndexedDB record with its cursor and vault numbers. A sync asks `GET /sync?since=<cursor>&trash=summary` (the
 * extension never shows the trash) and decrypts only what changed. After this browser's own writes, the answer's
 * `vault_seq` decides: the next number → shown as sent without asking; anything else → a delta sync. Live sync
 * (live-sync.ts) asks `liveNotice` whether a message needs a sync.
 */

import { afterWrite, applyOwnWrite, knownSeq, type Merged, mergeSync, noticeAction, type OwnWrite, type Snapshot, type SyncNotice, sameCiphertext, vaultKeyChanged } from "@web/lib/delta";
import { approval, type SignInRequest, secretKeyToKeep } from "@web/lib/device-login";
import { WEAK_BITS } from "@web/lib/health";
import type { Bundle, EncryptedItem, Item, LoginFinishResponse, PreloginResponse, Role, SyncItemRow, SyncResponse, SyncVaultRow } from "@web/lib/types";
import { isSyncResponse, kindOf, siteHost } from "@web/lib/types";
import { AppError, codeOf, EXPIRED, FAILED, lockedError, SECRET_KEY_REQUIRED, SIGNED_OUT, TWO_STEP_REQUIRED } from "../shared/errors";
import { log, logged } from "../shared/log";
import { POPUP_VIEW_KEY } from "../shared/storage-keys";
import { totpExpiry } from "../shared/totp";
import type {
  AccountSummary,
  DeviceSignIn,
  EditorInfo,
  ItemSummary,
  LoginResult,
  PopupState,
  SecurityKey,
  SecurityKeys,
  SharingIdentity,
  SharingNotice,
  Status,
  TotpCode,
  VaultSigner,
} from "../shared/types";
import * as core from "../wasm/passauth_core";
import { ApiError, api, forgetServerFeatures, iconsShown, logoutRemote, refreshServerInfo, serverConfig, serverInfo } from "./api";
import { initCore } from "./core";
import { forgetLastUsed } from "./last-used";
import { type IndexedLogin, type MatchIndex, matchIndex } from "./match-index";
import { forgetPolicyState, noteTwoStepDone, policyState } from "./policies";
import {
  ASK_OWNER_TEXT,
  CHECK_LATER_TEXT,
  type ChangedKey,
  checkInvitation,
  checkVault,
  collectRosters,
  contextStamp,
  coreCode,
  emptyMemory,
  firstSignedText,
  type InvitationCheck,
  invitationText,
  MAX_PENDING,
  MEMORY_MISSING_TEXT,
  mergeMemory,
  NEW_DEVICE_TEXT,
  ownVaultText,
  PAUSED_TEXT,
  PINS_ROLLBACK_TEXT,
  pinsDigest,
  readMemory,
  refusedUnopened,
  remembersSigned,
  replacedSignedText,
  replacedText,
  rosterVersion,
  rowStamp,
  type SignedInvitation,
  type SignedVaultRow,
  type SignerView,
  type StoredVerdict,
  signedByLabel,
  type Trust,
  type TrustMemory,
  UNREADABLE_TEXT,
  UNSIGNED_LABEL,
  unsignedLockedText,
  type VaultCheck,
  WRONG_ACCOUNT_TEXT,
  waitingText,
} from "./signed-sharing";
import { type AccountData, accountKey, activeId, earlierVaults, local, pinCopies, pinsFloor, type SessionData, scratch, session, syncCache, trustMemory } from "./storage";
import { fromStored, isStale, type RevisionAnswer, readRevision, type StoredSync, toStored, withSignedFields } from "./sync-rules";

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
  /** The vault key's `key_epoch` from /sync (newer servers): sent with every write made with this key. */
  epoch: number | undefined;
}

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
/** Single-flight first load of the unlocked account (offline copy or first sync), per generation. */
let opening: { gen: number; p: Promise<void> } | null = null;
let bundle: Bundle | null = null;
let vaults: Vault[] = [];
let entries: Entry[] = [];
let revision = 0;
/** Whether the unlocked account has synced at least once (an empty vault is still "loaded"). */
let loaded = false;
/** The loaded account's match index (match-index.ts), kept in memory too. */
let index: MatchIndex | null = null;
/**
 * The loaded account's encrypted rows: the last answer with every later change merged in (`@web/lib/delta`
 * `Snapshot`), the same as its offline copy holds. Without delta sync it is simply the last answer (no cursor).
 */
let synced: Snapshot | null = null;
/** Per vault, the row its key handle was opened from: the handle is kept while the key fields stay the same. */
let openedFrom = new Map<string, SyncVaultRow>();
/** Per item, the row it was decrypted from and the result (null: it can't be decrypted), reused while the ciphertext stays. */
let decrypted = new Map<string, { row: SyncItemRow; entry: Entry | null }>();
/**
 * Signed sharing for the loaded account (signed-sharing.ts): checks run (`sharingOn`) on servers with `signed_sharing`
 * and for accounts this browser has seen anything signed for. `verdicts`: each vault row's last check, which
 * `materialize` follows (a vault without a verdict for its current row, or a refused one, is never opened).
 */
let sharingOn = false;
let verdicts = new Map<string, StoredVerdict>();
/** This account's signing identity while unlocked (freed on lock), and the `/sync` record it was opened from ("created": made here). */
let signing: core.SigningIdentity | null = null;
let signingRecord = "";
/** The server lists a signing identity this account's key doesn't open. */
let identityBroken = false;
/** Sharing is paused here (identity broken, or not the one the account remembers): no shared vault is used. */
let sharingPaused = false;
/** Vaults waiting for consent the user accepted in the popup, with the consent token of what it showed (`acceptSharedVault`). */
const accepting = new Map<string, string>();
/** The web vault's "Vaults & sharing" page of the loaded account's server, for the popup's links. */
let vaultsUrl = "";
/** The account's key pins as this browser has them after the last check. */
let keyPins: core.KeyPins | null = null;
let sharingWarnings: string[] = [];
let invitationChecks: InvitationCheck[] = [];
/** A sync should follow this one (another device made the account's signing identity meanwhile). */
let sharingResync = false;
/** The keys were installed by a new unlock (not reloaded from the session after a worker restart): see `earlierVaultIds`. */
let freshSession = false;
/** The vaults (id → key id) of the account's offline copy from before this unlock, once per generation (`earlierVaultIds`). */
let earlier: { gen: number; ids: Promise<Map<string, string>> } | null = null;
/** The server answered the identity upload with 404 (it doesn't sign) in this generation: not tried again until the next unlock. */
let identityUnsupported = -1;
/** What this browser remembers for signed sharing couldn't be read at the last check (rule 7): nothing is accepted or pinned. */
let memoryUnreadable = false;
/** Sign-in waiting for its two-step code: the derived keys, and the Secret Key to remember once it succeeds. */
let pendingMaster: core.MasterKeys | null = null;
let pendingLogin: { server: string; email: string; secretKey?: string } | null = null;

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** Set by the service worker: runs the "Immediately" vault timeout if the popup closed while the worker was asleep. */
let lockCheck: () => Promise<void> = async () => {};
export function setLockCheck(fn: () => Promise<void>) {
  lockCheck = fn;
}

/** Install the keys of `id` (after dropping whatever was loaded). `fresh`: a new unlock, or keys from disk in a new browser session (false: reloaded from the session after a worker restart). */
function install(acct: core.Account, b: Bundle, id: string, fresh = true) {
  unload();
  account = acct;
  bundle = b;
  currentId = id;
  freshSession = fresh;
}

/** Set by the service worker: the user just unlocked or signed in (sign-in requests waiting for an answer are listed). */
let onUnlocked: () => void = () => {};
export function setUnlockedHandler(fn: () => void) {
  onUnlocked = fn;
}

/**
 * The user unlocked or signed in to `server`: its features and policies are asked for again now, so a policy the
 * admin changed (a lower `max_vault_timeout_minutes`) applies from this unlock instead of within the hour. Requests
 * meanwhile (the popup's next state) wait for the answer.
 */
function unlocked(server: string) {
  void refreshServerInfo(server).catch(logged("Asking the server for its features and policies"));
  onUnlocked();
}

/** Keep whether the account needs a Secret Key in its record (the lock screen reads it there), when it changed. */
function noteSecretKey(id: string, b: Bundle) {
  const enabled = !!b.secret_key_enabled;
  void local.update((l) => (l.accounts[id] && l.accounts[id].secretKeyEnabled !== enabled ? { secretKeyEnabled: enabled } : null), id).catch(logged("Noting the Secret Key setting"));
}

// ------------------------------------------------------------------ state

async function statusOf(a: AccountData | undefined, id: string, neverTimeout: boolean): Promise<Status> {
  if (!a?.server) return "setup";
  if (!a.tokens) return "logged-out";
  return (await session.get(id)) || (neverTimeout && a.persistedKeys) ? "unlocked" : "locked";
}

/** Whether the active account needs a Secret Key: from its record; records from before 0.7 look it up once. */
async function secretKeyRequired(l: { activeId: string; secretKeyEnabled?: boolean }, s: SessionData | null): Promise<boolean> {
  if (typeof l.secretKeyEnabled === "boolean" || !l.activeId) return !!l.secretKeyEnabled;
  const b = (currentId === l.activeId ? bundle : null) ?? s?.bundle ?? (await syncCache.get(l.activeId))?.bundle;
  if (b) noteSecretKey(l.activeId, b);
  return !!b?.secret_key_enabled;
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
    secretKeyRequired: await secretKeyRequired(l, s),
    secretKeyStored: !!l.secretKeys[accountKey(l.server, l.email)],
    rememberedDevice: !!l.rememberTokens[accountKey(l.server, l.email)],
    settings: l.settings,
    lastSync: l.lastSync,
    neverSave: l.neverSave,
    hiddenSites: l.hiddenSites,
    pinUnlock: !!l.tokens && !never && !!(await pinCopies.get(l.activeId)),
    ...(l.tokens ? await policyState(l.activeId) : {}),
    iconsShown: await iconsShown(l.server, l.settings.showIcons),
    ...(status === "logged-out" && (await serverInfo(l.server))?.features.has("login_with_device") ? { deviceSignIn: true } : {}),
  };
}

/**
 * The active account's state for the toolbar icon and the right-click menu, without loading any keys: signed out
 * (or no server yet), locked, or unlocked (keys in memory or in the session; on disk only with the timeout "never").
 */
export async function lockStatus(): Promise<"signed-out" | "locked" | "unlocked"> {
  const { id, data } = await local.account();
  if (!data?.server || !data.tokens) return "signed-out";
  if ((account && currentId === id) || (await session.get(id))) return "unlocked";
  if (data.persistedKeys && (await local.get()).settings.vaultTimeout === "never") return "unlocked";
  return "locked";
}

export async function setServer(url: string) {
  const clean = url.trim().replace(/\/+$/, "");
  const u = new URL(clean.includes("://") ? clean : `https://${clean}`);
  if (u.protocol !== "https:" && u.hostname !== "localhost" && u.hostname !== "127.0.0.1") {
    throw new Error("Use an https:// address. Plain http is only allowed for localhost.");
  }
  const origin = u.origin + u.pathname.replace(/\/+$/, "");
  const cfg = await serverConfig(origin);
  if (cfg?.name !== "PassAuth") throw new Error("No PassAuth server answered at that address.");
  forgetServerFeatures(origin);
  await clearUnlocked();
  await local.set({ server: origin, tokens: null });
}

// ------------------------------------------------------------------- login

/** How this browser names itself to the server at sign-in (also for a sign-in approved from another device). */
export async function deviceInfo() {
  return { id: await local.deviceId(), name: `PassAuth extension (${navigator.userAgent.includes("Edg/") ? "Edge" : "Chrome"})`, kind: "extension" };
}

const secretKeyMissing = () => new AppError(SECRET_KEY_REQUIRED, "This account uses a Secret Key. Enter it from your Emergency Kit.");

/** A server's answer that isn't what PassAuth asked for. */
const UNEXPECTED_ANSWER = "Your PassAuth server sent an unexpected answer. Try again in a moment.";

/**
 * A server value the core takes as text: a string, or the request fails here. The core's bindings don't check: a
 * number traps inside the core, and an object with a large `length` makes its glue allocate memory it never frees.
 */
function serverText(v: unknown): string {
  if (typeof v !== "string") throw new AppError(FAILED, UNEXPECTED_ANSWER);
  return v;
}

/** `POST /auth/prelogin`, with what the core takes from it checked (a strict yes for `secret_key_required`). */
async function prelogin(email: string, accountId?: string): Promise<PreloginResponse> {
  const pre = await api<PreloginResponse>("/auth/prelogin", { body: { email }, auth: false, ...(accountId ? { accountId } : {}) });
  if (!pre || typeof pre !== "object") throw new AppError(FAILED, UNEXPECTED_ANSWER);
  return { ...pre, account_id: serverText(pre.account_id), secret_key_required: pre.secret_key_required === true };
}

/** `POST /auth/login/start`: its `login_id` and OPAQUE `message`, both checked to be text. */
async function loginStart(email: string, message: string, accountId?: string): Promise<{ login_id: string; message: string }> {
  const resp = await api<{ login_id?: unknown; message?: unknown } | null>("/auth/login/start", { body: { email, message }, auth: false, ...(accountId ? { accountId } : {}) });
  return { login_id: serverText(resp?.login_id), message: serverText(resp?.message) };
}

export async function login(email: string, password: string, secretKey?: string): Promise<LoginResult> {
  await initCore();
  const l = await local.get();
  const server = l.server;
  const typed = secretKey?.trim();
  const sk = typed || l.secretKeys[accountKey(server, email)];
  const pre = await prelogin(email);
  if (pre.secret_key_required && !sk) throw secretKeyMissing();
  const master = core.deriveMasterKeys(password, pre.secret_key_required ? sk : undefined, pre.account_id, pre.kdf, pre.secret_key_required);
  const start = core.opaqueLoginStart(master);
  let resp: { login_id: string; message: string };
  try {
    resp = await loginStart(email, start.message);
  } catch (e) {
    master.free();
    throw e;
  }
  let fin: string;
  try {
    fin = core.opaqueLoginFinish(start.state, master, resp.message);
  } catch {
    master.free();
    throw new Error("Wrong email, master password or Secret Key.");
  }
  const result = await api<LoginFinishResponse>("/auth/login/finish", {
    auth: false,
    body: { login_id: resp.login_id, message: fin, device: await deviceInfo(), remember_token: l.rememberTokens[accountKey(server, email)] },
  });
  // Remembered only once the sign-in has worked (after the two-step code, if any).
  const remember = { server, email, ...(sk && pre.secret_key_required ? { secretKey: sk } : {}) };
  if (result.two_factor_required) {
    pendingMaster?.free();
    pendingMaster = master;
    pendingLogin = remember;
    return { twoFactor: { token: result.two_factor_token ?? "", providers: result.providers ?? [] } };
  }
  await finishLogin(master, result, remember);
  return { done: true };
}

/** `remember`: keep a "remember this device" token, so this browser skips the two-step code for 30 days. */
export async function verifyTwoFactor(token: string, provider: string, code: string, remember: boolean) {
  const result = await api<LoginFinishResponse>("/auth/2fa/verify", { body: { two_factor_token: token, provider, code, remember }, auth: false });
  if (!pendingMaster || !pendingLogin) throw new Error("Sign-in expired. Start again.");
  const master = pendingMaster;
  const who = pendingLogin;
  pendingMaster = null;
  pendingLogin = null;
  // A token this browser had didn't spare the code (expired or revoked): it goes, unless a new one was asked for.
  await local.setRememberToken(who.server, who.email, remember && typeof result.remember_token === "string" ? result.remember_token : null);
  await finishLogin(master, result, who);
}

export async function sendTwoFactorEmail(token: string) {
  await api("/auth/2fa/email", { body: { two_factor_token: token }, auth: false });
}

async function finishLogin(master: core.MasterKeys, result: LoginFinishResponse, who: { server: string; email: string; secretKey?: string }) {
  let id: string;
  try {
    if (typeof result.access_token !== "string" || typeof result.refresh_token !== "string" || typeof result.email !== "string" || !result.bundle) {
      throw new AppError(FAILED, UNEXPECTED_ANSWER);
    }
    await local.set({ tokens: { access: result.access_token, refresh: result.refresh_token }, email: result.email });
    id = await activeId();
    install(master.unlock(result.bundle), result.bundle, id);
  } finally {
    master.free();
  }
  noteSecretKey(id, result.bundle);
  unlocked(who.server);
  if (who.secretKey) await local.setSecretKey(who.server, who.email, who.secretKey);
  await persistUnlocked();
  await markVerified();
  try {
    await sync();
  } catch (e) {
    // Signed in, but the server requires two-step login first: the popup shows what to do (policies.ts).
    if (codeOf(e) !== TWO_STEP_REQUIRED) throw e;
  }
}

/**
 * Finish a sign-in that another device approved. The popup ran the request (its key can't be saved, so it never
 * leaves the popup), opened the approval's sealed key with it and unlocked the account bundle: `keys` is that
 * account (`Account.toSessionBytes()`, base64) for the session the same answer brought. Installed like a password
 * sign-in, for the account the request was made from (`account`, which must still be active and signed out), except
 * that it never counts as typing the master password here: passkey user verification still asks for it. A Secret Key
 * that came along is kept only for the email typed on this device (`typedEmail`) when the session is for that same
 * email, and never over a different Secret Key already kept for it (a server can't swap a stored Secret Key this way).
 */
export async function finishDeviceSignIn(account: string, s: DeviceSignIn, typedEmail?: string): Promise<void> {
  await initCore();
  const l = await local.get();
  if (l.activeId !== account || !l.server) throw new AppError(EXPIRED, "PassAuth switched accounts while you signed in. Start again.");
  if (l.tokens) throw new AppError(EXPIRED, "This account is signed in already.");
  if (!s.bundle || s.bundle.account_id !== s.accountId) throw new Error("The approval doesn't belong to this account. Start again.");
  // Only keys the core authenticates against the approval's bundle (round 5: "me" is always an authenticated id).
  const acct = sessionAccount({ accountId: s.accountId, keys: s.keys, bundle: s.bundle });
  if (!acct) throw new Error("The approved sign-in couldn't be opened. Start again.");
  try {
    await local.set({ tokens: { access: s.accessToken, refresh: s.refreshToken }, email: s.email }, account);
  } catch (e) {
    acct.free();
    throw e;
  }
  install(acct, s.bundle, account);
  noteSecretKey(account, s.bundle);
  unlocked(l.server);
  // The Secret Key the approving app sent, kept like one typed here (for unlocking with the master password later):
  // only for the email typed here, and never in place of a different one kept for it (the web vault's rule).
  const kept = typedEmail ? (l.secretKeys[accountKey(l.server, typedEmail)] ?? null) : null;
  const keep = typedEmail ? secretKeyToKeep(typedEmail, s.email, s.secretKey, kept) : null;
  if (keep && typedEmail && keep !== kept) await local.setSecretKey(l.server, typedEmail, keep);
  if (s.rememberToken) await local.setRememberToken(l.server, s.email, s.rememberToken);
  await persistUnlocked();
  try {
    await sync();
  } catch (e) {
    // Signed in, but the server requires two-step login first: the popup shows what to do (policies.ts).
    if (codeOf(e) !== TWO_STEP_REQUIRED) throw e;
  }
}

/** Derive the master keys and open the account bundle (throws a user-facing error). */
function openBundle(b: Bundle, password: string, sk: string | undefined): core.Account {
  const master = core.deriveMasterKeys(password, sk, serverText(b?.account_id), b.kdf, b.secret_key_enabled === true);
  try {
    return master.unlock(b);
  } catch {
    if (b.secret_key_enabled && !sk) throw secretKeyMissing();
    throw new Error("Wrong master password or Secret Key.");
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
  await initCore();
  const l = await local.get();
  const id = l.activeId;
  const cached = await syncCache.get(id);
  let fresh: SyncResponse | null = null;
  let b = cached?.bundle;
  if (!b) {
    fresh = await fetchFull(id);
    b = fresh.bundle;
  }
  const typed = secretKey?.trim();
  const sk = typed || l.secretKeys[accountKey(l.server, l.email)];
  let acct: core.Account;
  try {
    acct = openBundle(b, password, sk);
  } catch (e) {
    if (fresh) throw e;
    fresh = await fetchFull(id).catch((err: unknown) => {
      log.debug("Fetching a newer bundle failed:", err);
      return null;
    });
    if (!fresh || JSON.stringify(fresh.bundle) === JSON.stringify(b)) throw e;
    b = fresh.bundle;
    acct = openBundle(b, password, sk);
  }
  install(acct, b, id);
  noteSecretKey(id, b);
  unlocked(l.server);
  // Started now, so a request that arrives meanwhile waits for this load instead of starting its own.
  const opened = fresh ? acceptFull(fresh, id) : openVault(id, cached);
  if (typed) await local.setSecretKey(l.server, l.email, typed);
  await persistUnlocked();
  await markVerified();
  await opened;
}

async function persistUnlocked() {
  if (!account || !bundle) return;
  const data: SessionData = { accountId: bundle.account_id, keys: b64(account.toSessionBytes()), bundle };
  await session.set(data, currentId);
  await persistForNever();
}

/** Vault timeout "never": keep unlocked keys on disk so a browser restart stays unlocked; otherwise remove them for every account. */
export async function persistForNever() {
  const { accounts } = await local.get();
  let never = false;
  for (const id of Object.keys(accounts)) {
    await local.update(async (l) => {
      const record = l.accounts[id];
      if (!record) return null;
      never = l.settings.vaultTimeout === "never";
      if (!never) return record.persistedKeys ? { persistedKeys: null } : null;
      // Read inside the write queue: a lock that cleared the session keys meanwhile wins.
      const data = await session.get(id);
      return data ? { persistedKeys: data } : null;
    }, id);
  }
  // PIN unlock isn't offered with "never" (nothing locks by itself), so a PIN set before doesn't linger unseen.
  if (never) await pinCopies.remove(Object.keys(accounts));
}

/** "Forget this browser" for the active account: its remember-device token and stored Secret Key. */
export async function forgetBrowser() {
  const { server, email } = await local.get();
  if (server && email) await local.forgetDevice(server, email);
}

// ------------------------------------------------------- user verification

/** How long a master-password entry counts as user verification (WebAuthn UV) for passkeys. */
export const VERIFIED_MS = 5 * 60_000;

const verifiedKey = (id: string) => `verified:${id}`;

/**
 * The user just typed the master password for the loaded account (unlock,
 * sign-in, reauth, a passkey prompt). Kept in session storage, so it lasts for
 * this browser session only; keys restored from disk (timeout "never") never
 * count as an entry.
 */
async function markVerified() {
  if (currentId) await scratch.set(verifiedKey(currentId), Date.now());
}

/** Whether the master password was entered for the loaded account within `ms`. */
export async function recentlyVerified(ms = VERIFIED_MS) {
  const at = currentId ? await scratch.get<number>(verifiedKey(currentId)) : undefined;
  return typeof at === "number" && Date.now() - at < ms && Date.now() >= at;
}

/** Check the master password again, locally (passkey user verification); throws a user-facing error. */
export async function verifyMasterPassword(password: string) {
  if (!account || !bundle) throw lockedError();
  await initCore();
  const l = await local.get();
  openBundle(bundle, password, l.secretKeys[accountKey(l.server, l.email)]).free();
  await markVerified();
}

// ------------------------------------------------------------- PIN unlock (pin.ts)

/**
 * The loaded account's keys re-wrapped under a key the core derives from `pin` (its Argon2id, a new salt; no
 * Secret Key), with the bundle they came from and who owned them. The result is only ever kept in session storage.
 */
export async function wrapForPin(pin: string): Promise<{ wrapped: Bundle; base: Bundle; owner: { id: string; generation: number } }> {
  if (!account || !bundle) throw lockedError();
  await initCore();
  const o = owner();
  const base = bundle;
  const fresh = account.rewrap(base, pin, false, undefined);
  try {
    return { wrapped: fresh.bundle as Bundle, base, owner: o };
  } finally {
    // Frees the copies of the keys the core handed back (the Account Key, the key pair and the derived keys).
    fresh.free();
  }
}

/**
 * Unlock `id` with a PIN-wrapped copy: false for a wrong PIN. The account's own bundle (`base`) is installed as
 * after a master-password unlock, but a PIN is never a master-password entry: passkey user verification still
 * asks for the master password (`recentlyVerified` stays as it was).
 */
export async function unlockWithPin(wrapped: Bundle, base: Bundle, pin: string, id: string): Promise<boolean> {
  await initCore();
  const gen = generation;
  let acct: core.Account;
  try {
    acct = openBundle(wrapped, pin, undefined);
  } catch {
    return false;
  }
  // The bundle installed with it must be this account's (round 5: never another account id than the core's).
  if (!acct.matchesBundle(base)) {
    acct.free();
    throw new Error("This PIN copy doesn't match your account. Unlock with your master password.");
  }
  // Locked, signed out or switched while the PIN was checked: that wins.
  if (gen !== generation || (await activeId()) !== id) {
    acct.free();
    throw lockedError();
  }
  install(acct, base, id);
  noteSecretKey(id, base);
  void local.account(id).then((a) => unlocked(a.data?.server ?? ""), logged("Reading the account's server"));
  const opened = openVault(id);
  await persistUnlocked();
  await opened;
  return true;
}

/** A sync brought a different account bundle than the one a PIN copy was made from: the master password or Secret Key changed, so the copy goes. */
async function dropStalePin(id: string, b: Bundle) {
  const copy = await pinCopies.get(id);
  if (copy && stableJson(copy.base) !== stableJson(b)) {
    await pinCopies.update(id, (c) => (c && stableJson(c.base) !== stableJson(b) ? null : undefined));
    log.debug("The account's master password or Secret Key changed: PIN unlock was turned off.");
  }
}

/**
 * Fresh proof of the master password for sensitive account changes: an OPAQUE
 * login with purpose "reauth" for the active account. Returns the reauth token.
 */
async function reauthToken(password: string): Promise<string> {
  await initCore();
  const { id: accountId } = await local.account();
  const l = await local.get();
  const email = l.email;
  const sk = l.secretKeys[accountKey(l.server, email)];
  const pre = await prelogin(email, accountId);
  if (pre.secret_key_required && !sk) throw new Error("Your Secret Key isn't saved in this browser. Sign out and sign in again with it.");
  const master = core.deriveMasterKeys(password, pre.secret_key_required ? sk : undefined, pre.account_id, pre.kdf, pre.secret_key_required);
  try {
    const start = core.opaqueLoginStart(master);
    const resp = await loginStart(email, start.message, accountId);
    let fin: string;
    try {
      fin = core.opaqueLoginFinish(start.state, master, resp.message);
    } catch {
      throw new Error("Wrong master password.");
    }
    const result = await api<LoginFinishResponse>("/auth/login/finish", {
      body: { login_id: resp.login_id, message: fin, device: await deviceInfo(), purpose: "reauth" },
      accountId,
    });
    if (!result.reauth_token || typeof result.reauth_token !== "string") throw new Error("Your server didn't confirm your master password. Try again.");
    if (accountId === currentId) await markVerified();
    return result.reauth_token;
  } finally {
    master.free();
  }
}

/** `POST /account/auth-requests/{id}` approving a request. */
export interface ApprovalBody {
  approve: true;
  sealed_key: string;
  proof: string;
}

/**
 * Approve a sign-in request from another device with the loaded (active, unlocked) account, for the words the user
 * picked (`phrase`), by the web vault's rule (`@web/lib/device-login` `approval`): the core refuses with
 * `phrase_mismatch` unless they are the request key's own; otherwise the account key — and the Secret Key this browser
 * keeps, so the new device can later unlock with the master password (one the core can't read is left out) — sealed
 * to the request's own key, the request's challenge opened as proof, and the 6-digit code the user then enters on
 * the new device.
 */
export async function approveSignIn(req: Pick<SignInRequest, "id" | "publicKey" | "challenge">, phrase: string): Promise<{ body: ApprovalBody; code: string }> {
  const l = await local.get();
  const acct = account;
  if (!acct || currentId !== l.activeId) throw lockedError();
  const { body, code } = approval(acct, req, phrase, l.secretKeys[accountKey(l.server, l.email)] ?? null);
  if (!body.approve) throw new Error("unexpected approval");
  return { body, code };
}

/** Two-step login security keys of the active account. */
export async function securityKeys(): Promise<SecurityKeys> {
  const a = await api<{ two_factor?: string[]; passkeys?: SecurityKey[] }>("/account");
  const methods = (a.two_factor ?? []).filter((p) => p !== "recovery");
  return { keys: a.passkeys ?? [], methods };
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

/**
 * Load the keys of `id` from the session (or, with the timeout "never", from
 * disk). A lock, sign-out or account switch while this waits (any of them bumps
 * `generation`) or the session keys being gone aborts it, so a restore that
 * started before a lock can never install the keys after it.
 */
async function restore(id: string): Promise<boolean> {
  const gen = generation;
  const stale = () => gen !== generation;
  let s = await session.get(id);
  if (stale()) return false;
  // Keys from disk (the timeout "never", a new browser session): the session storage started empty, so the offline copy
  // is from an earlier session (signed sharing's `earlierVaultIds`); from the session: a worker restart in this unlock.
  const fromDisk = !s;
  if (!s) {
    const l = await local.get();
    if (stale() || l.activeId !== id || l.settings.vaultTimeout !== "never" || !l.persistedKeys || !l.tokens) return false;
    s = l.persistedKeys;
    await session.set(s, id);
    if (stale()) {
      // Locked meanwhile: take back what was just written.
      await session.clear(id);
      return false;
    }
  }
  await initCore();
  if (stale() || (await activeId()) !== id) return false;
  const still = await session.get(id);
  if (stale() || !still || still.keys !== s.keys) return false;
  const acct = sessionAccount(s);
  if (!acct) {
    // Round 5 (iOS H): keys whose stored bundle the core doesn't authenticate for them are never used (a bundle the
    // server swapped would make "me" another account id): the session is dropped, so the master password is asked for.
    log.warn("The kept unlocked keys don't match their account bundle; unlock with the master password.");
    await session.clear(id);
    if (fromDisk) await local.set({ persistedKeys: null }, id);
    return false;
  }
  install(acct, s.bundle, id, fromDisk);
  await openVault(id);
  return true;
}

/**
 * The account kept in session bytes, only when the core authenticates its stored bundle for it (`Account.matchesBundle`:
 * the bundle's private-key blob opens under the Account Key with its own account id): the account id the keys are
 * restored with is then one the core authenticated, never just the bundle's claim. Null otherwise.
 */
function sessionAccount(s: SessionData): core.Account | null {
  if (!s.bundle) return null;
  let acct: core.Account;
  try {
    acct = core.accountFromSessionBytes(s.accountId, unb64(s.keys));
  } catch {
    return null;
  }
  if (acct.matchesBundle(s.bundle)) return acct;
  acct.free();
  return null;
}

/**
 * The first load of the unlocked account, once per generation (concurrent callers share it): the offline copy
 * straight away with a cheap revision check behind it, or without one a full sync. `cached`: the copy the caller
 * already read.
 */
function openVault(id: string, cached?: StoredSync): Promise<void> {
  if (opening?.gen === generation) return opening.p;
  const gen = generation;
  const p = (async () => {
    const copy = cached ?? (await syncCache.get(id));
    if (gen !== generation || currentId !== id || loaded) return;
    // Which vaults this browser had before this unlock (signed sharing, M1), from the copy just read.
    if (account) void earlierVaultIds(id, account, { copy });
    // The copy is checked like a server's answer (sync-rules.ts `fromStored`); one that isn't one is replaced by a sync.
    const parsed = copy ? fromStored(copy) : null;
    // A copy for another account than the one the core authenticated (review H1) is replaced by a sync.
    const snap = parsed && account && ownSnapshot(account, parsed) ? parsed : null;
    if (snap) {
      // Shared vaults as the copy's verdicts say (rows without one are checked here, without the network where possible).
      await checkSharing(snap, id, "open", copy?.trust);
      if (gen !== generation || currentId !== id || loaded) return;
      show(snap);
      void refreshIfStale().catch(logged("Checking for changes"));
      return;
    }
    await sync();
  })().finally(() => {
    // Done (or failed: the next request tries again).
    if (opening?.p === p) opening = null;
  });
  opening = { gen, p };
  return p;
}

/**
 * Called whenever an account's keys are dropped on purpose (lock, sign-out,
 * switching or adding accounts, vault timeout): short-lived state that belongs
 * to the unlocked account, like a typed login waiting to be saved, goes too.
 * Not called when the service worker merely reloads the keys from the session.
 */
let keysDropped: (accountId?: string) => void = () => {};
/** `fn(accountId)`: the keys of that one account went (a lost session); without it, the active account's or every account's. */
export function setKeysDroppedHandler(fn: (accountId?: string) => void) {
  keysDropped = fn;
}

/** Drop the keys of `id` (default: the active account), in memory, in the session and on disk. Also what a lost session (refresh token refused) does. */
export async function clearUnlocked(id?: string) {
  keysDropped(id);
  const aid = id ?? (await activeId());
  if (!id || aid === currentId || restoring?.id === aid) {
    unload();
    restoring = null;
  }
  await session.clear(aid);
  await scratch.remove([verifiedKey(aid), POPUP_VIEW_KEY]);
  // Signed out (or the server ended the session): a PIN can't open this account any more.
  await pinCopies.remove([aid]);
  await matchIndex.clear([aid]);
  await forgetPolicyState([aid]);
  await local.set({ persistedKeys: null }, aid);
}

/** Lock: every account, like the vault timeout (one click must not leave other accounts open). */
export async function lock() {
  await lockAll();
}

/** Sign out of the active account. With other accounts present it's removed from the list and the next one becomes active. */
export async function logout() {
  try {
    await api("/auth/logout", { method: "POST" });
  } catch {
    /* already signed out, or the server is unreachable: signed out here either way */
  }
  const { activeId: id, accounts, server, email } = await local.get();
  await clearUnlocked(id);
  await syncCache.clear(id);
  await forgetLastUsed(id);
  // Signing out forgets this browser for the account: its Secret Key and two-step "remember" token go too.
  if (server && email) await local.forgetDevice(server, email);
  if (Object.values(accounts).filter((a) => a.server).length > 1) await local.removeAccount(id);
  else await local.set({ tokens: null }, id);
}

/** Forget the loaded keys in memory only (the session stays, so switching back is instant). */
function unload() {
  generation++;
  for (const v of vaults) v.key.free();
  vaults = [];
  entries = [];
  revision = 0;
  loaded = false;
  index = null;
  synced = null;
  openedFrom = new Map();
  decrypted = new Map();
  opening = null;
  sharingOn = false;
  verdicts = new Map();
  signing?.free();
  signing = null;
  signingRecord = "";
  identityBroken = false;
  sharingPaused = false;
  accepting.clear();
  vaultsUrl = "";
  keyPins = null;
  sharingWarnings = [];
  invitationChecks = [];
  sharingResync = false;
  account?.free();
  account = null;
  currentId = "";
  bundle = null;
  pendingMaster?.free();
  pendingMaster = null;
  pendingLogin = null;
}

export async function switchAccount(id: string) {
  const { accounts, activeId } = await local.get();
  if (!accounts[id]?.server) throw new Error("That account isn't on this device any more.");
  if (id === activeId) return;
  keysDropped();
  unload();
  // PIN unlock belongs to the account it was set for while it stays active: switching away turns it off.
  await pinCopies.remove([activeId]);
  await scratch.remove(POPUP_VIEW_KEY);
  await local.setActive(id);
}

export async function addAccount() {
  keysDropped();
  unload();
  const { activeId } = await local.get();
  await local.addAccount();
  await pinCopies.remove([activeId]);
  await scratch.remove(POPUP_VIEW_KEY);
}

/** Leave an unfinished "add account" (no sign-in yet) and go back to a signed-in account. */
export async function cancelAddAccount() {
  const { activeId, tokens, accounts } = await local.get();
  if (tokens || !Object.values(accounts).some((a) => a.tokens)) return;
  keysDropped();
  unload();
  await local.removeAccount(activeId);
}

/** Vault timeout and Lock: lock every account. */
export async function lockAll() {
  keysDropped();
  // Before anything else (and before the first await): a restore still on its way sees the new generation and gives up.
  unload();
  restoring = null;
  const { accounts } = await local.get();
  const ids = Object.keys(accounts);
  for (const id of ids) {
    await session.clear(id);
    await scratch.remove(verifiedKey(id));
  }
  // Where the popup was (an open item, the search) goes with the keys. PIN copies stay: they are what a PIN unlocks.
  await scratch.remove(POPUP_VIEW_KEY);
  await matchIndex.clear(ids);
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
  await pinCopies.remove(Object.keys(accounts));
  await forgetPolicyState(Object.keys(accounts));
  for (const [id, a] of Object.entries(accounts)) {
    await syncCache.clear(id);
    await forgetLastUsed(id);
    if (!a.tokens) continue;
    await logoutRemote(a.server, a.tokens);
    await local.set({ tokens: null }, id);
  }
}

/** The account whose keys are loaded, and the generation they were loaded in (see `stillOwner`). */
export function owner(): { id: string; generation: number } {
  return { id: currentId, generation };
}

/** Whether the keys loaded at `o` are still loaded: not locked, signed out or switched since. */
export function stillOwner(o: { id: string; generation: number }) {
  return !!account && !!o.id && currentId === o.id && generation === o.generation;
}

/**
 * The active account's match index (match-index.ts) when it is unlocked, without loading its keys: from memory
 * when the vault is open here, else from the session (after a service-worker restart). Null when locked or when
 * there is none yet: then the caller opens the vault (`ensureUnlocked`).
 */
export async function unlockedIndex(): Promise<MatchIndex | null> {
  await lockCheck();
  const id = await activeId();
  if (!id) return null;
  if (account && currentId === id) return loaded ? index : null;
  if (!(await session.get(id))) return null;
  return matchIndex.get(id);
}

// -------------------------------------------------------------------- sync

let syncing: Promise<void> | null = null;
let syncAgain: Promise<void> | null = null;

/**
 * Fetch /sync and apply it. A call while one is running doesn't start a second
 * one alongside: every such call shares a single follow-up that starts when the
 * running one ends, so each caller still gets the server's state from after its call.
 */
export function sync(): Promise<void> {
  if (!syncing) {
    const p = syncNow().finally(() => {
      if (syncing === p) syncing = null;
    });
    syncing = p;
    return p;
  }
  syncAgain ??= syncing
    .catch(() => {}) // the running sync's own callers get its failure
    .then(() => {
      syncAgain = null;
      return sync();
    });
  return syncAgain;
}

/** Resolves once no sync is running (its failure belongs to its own callers). */
async function syncIdle() {
  const running = syncing;
  if (running) await running.catch(() => {});
}

const UNEXPECTED_SYNC = "Your PassAuth server sent an unexpected answer. Try again in a moment.";

/** Whether `id`'s server has delta sync (`delta_sync` in its features; unknown while unreachable: no). */
async function deltaFor(id: string): Promise<boolean> {
  const server = (await local.account(id)).data?.server ?? "";
  return !!server && !!(await serverInfo(server))?.features.has("delta_sync");
}

/** The whole vault of `id` (with delta sync `trash=summary`: the extension never shows the trash). */
async function fetchFull(id: string): Promise<SyncResponse> {
  const data = await api<unknown>((await deltaFor(id)) ? "/sync?trash=summary" : "/sync", { accountId: id });
  if (!isSyncResponse(data)) throw new AppError(FAILED, UNEXPECTED_SYNC);
  return data;
}

async function syncNow() {
  if (!account) return;
  const id = currentId;
  const gen = generation;
  // Locked, signed out or switched meanwhile: the answer is dropped.
  const stale = () => gen !== generation || !account || currentId !== id;
  const delta = await deltaFor(id);
  if (stale()) return;
  // Older servers get the whole vault every time, as before; a copy without a cursor gets it once.
  let merged = await fetchSync(id, delta, delta ? synced : null, stale);
  // A delta this browser can't use (malformed, or about data it doesn't have): everything, once.
  if (merged === "full") merged = await fetchSync(id, delta, null, stale);
  if (!merged || merged === "full" || stale()) return;
  await accept(merged.snapshot, id);
  await noteTwoStepDone(id);
  // Not expected: the answer was older than an own write already shown. Ask again rather than keep it stale.
  if (merged.behind) void sync().catch(logged("Syncing again"));
}

/**
 * One `GET /sync`: with `base`'s cursor only what changed since (`trash=summary`), merged into `base`. Null when the
 * answer is dropped (locked or switched meanwhile, or older than what is shown); "full" when a delta can't be used.
 */
async function fetchSync(id: string, delta: boolean, base: Snapshot | null, stale: () => boolean): Promise<Merged | "full" | null> {
  const since = base?.cursor ?? null;
  const path = !delta ? "/sync" : since ? `/sync?since=${encodeURIComponent(since)}&trash=summary` : "/sync?trash=summary";
  const data = await api<unknown>(path, { accountId: id });
  if (stale()) return null;
  if (!isSyncResponse(data)) {
    if (since) return "full";
    throw new AppError(FAILED, UNEXPECTED_SYNC);
  }
  if (loaded && data.revision < revision) return null;
  let merged: Merged | null = null;
  try {
    merged = mergeSync(since ? base : null, data);
  } catch (e) {
    log.debug("A sync answer couldn't be used:", e);
  }
  if (merged) return withSignedInvitations(merged, data);
  if (since) return "full";
  throw new AppError(FAILED, UNEXPECTED_SYNC);
}

/** `merged` with its invitations' signed-sharing fields from the answer `data` (`readInvitations` drops them). */
function withSignedInvitations(merged: Merged, data: SyncResponse): Merged {
  return { ...merged, snapshot: { ...merged.snapshot, invitations: withSignedFields(merged.snapshot.invitations, data.invitations) } };
}

/** A new snapshot for the loaded account: its owner checked, its shared vaults checked, shown, kept as its offline copy, and the time noted. */
async function accept(snap: Snapshot, id: string) {
  const gen = generation;
  if (account && !ownSnapshot(account, snap)) {
    // Review H1: an answer for another account than the one the core authenticated is never shown or kept.
    log.warn("The server sent a sync answer for another account; it isn't used.");
    throw new AppError(FAILED, WRONG_ACCOUNT_TEXT);
  }
  await checkSharing(snap, id, "sync");
  if (gen !== generation || currentId !== id || !account) return;
  show(snap);
  await persist(id);
  await local.set({ lastSync: Date.now(), name: typeof snap.user?.name === "string" ? snap.user.name : "" }, id);
  if (sharingResync) {
    sharingResync = false;
    void sync().catch(logged("Syncing again"));
  }
}

/** A whole vault fetched while unlocking (no offline copy, or a newer account bundle). */
async function acceptFull(data: SyncResponse, id: string) {
  const merged = mergeSync(null, data);
  if (!merged || !account || currentId !== id) return;
  await accept(withSignedInvitations(merged, data).snapshot, id);
}

/** The account id the core authenticated (the unlocked account's own), never `/sync` `user.id` (review H1). */
const meOf = (acct: core.Account) => acct.legacyIdentity().user_id;

/**
 * Whether `snap` is the unlocked account's: its `user.id` is the id the core authenticated, and its account bundle (if
 * it carries one) is one the core authenticates for this account (round 5: a bundle with another `account_id` is never
 * kept, or a later session restore would take that id for "me").
 */
const ownSnapshot = (acct: core.Account, snap: Snapshot) => snap.user?.id === meOf(acct) && (!snap.bundle || acct.matchesBundle(snap.bundle));

// ------------------------------------------------------------ signed sharing

/** `/sync` `user` with the signed-sharing fields (servers with `signed_sharing`). */
type SharingUser = SyncResponse["user"] & { identity?: unknown; key_pins_seq?: unknown };

/** A whole number from the server, or null. */
const whole = (v: unknown): number | null => (typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : null);

/** Every roster of `vaultId` after version `after`, oldest first, within the caps (signed-sharing.ts `collectRosters`). */
function fetchRosters(id: string, vaultId: string, after: number): Promise<string[]> {
  return collectRosters(after, async (from) => {
    const r = await api<{ rosters?: unknown; more?: unknown } | null>(`/vaults/${encodeURIComponent(vaultId)}/rosters?after=${from}`, { accountId: id });
    const list = r?.rosters;
    if (!Array.isArray(list) || !list.every((x): x is string => typeof x === "string")) throw new AppError(FAILED, UNEXPECTED_ANSWER);
    return { rosters: list, more: r?.more === true };
  });
}

/** `GET /account/key-pins`: the sealed key pins (null: none yet) and their version. */
async function fetchKeyPins(id: string): Promise<{ sealed: string | null; seq: number }> {
  const r = await api<{ key_pins?: unknown; seq?: unknown } | null>("/account/key-pins", { accountId: id });
  const seq = whole(r?.seq);
  if (seq === null || (r?.key_pins !== null && typeof r?.key_pins !== "string")) throw new AppError(FAILED, UNEXPECTED_ANSWER);
  return { sealed: (r?.key_pins as string | null) ?? null, seq };
}

/** Where the account's trust memory is kept: the server's address and the account id the core authenticated. */
interface MemoryPlace {
  server: string;
  userId: string;
}

/** Two sealed copies of the key pins merged (the higher version's, with the lower one's unsent changes). */
function mergeSealedPins(acct: core.Account, higher: TrustMemory, lower: TrustMemory): TrustMemory {
  try {
    if (!higher.pinsSealed || !lower.pinsSealed) return higher;
    const merged = core.mergePins(acct.openKeyPins(higher.pinsSealed, higher.pinsSeq), acct.openKeyPins(lower.pinsSealed, lower.pinsSeq));
    return { ...higher, pinsSealed: acct.sealKeyPins(merged, higher.pinsSeq), pinsDirty: true };
  } catch (e) {
    // `identity_mismatch` (round 5): copies of two own identities are never merged; the higher one stays.
    log.warn("Merging this browser's copies of the known keys failed:", coreCode(e));
    return higher;
  }
}

/**
 * Store `memory` merged with what is stored (never a blind overwrite); resolves to what was stored. `basis`: the sealed
 * key pins `memory` started from, so pins changed meanwhile (with unsent changes) are merged in, not dropped (review L7).
 */
function saveMemory(acct: core.Account, place: MemoryPlace, memory: TrustMemory, basis?: string | null): Promise<TrustMemory> {
  return trustMemory.update(place.server, place.userId, (stored) => mergeMemory(readMemory(stored, place.userId), memory, (h, l) => mergeSealedPins(acct, h, l), basis));
}

/** Change the stored key pins with `fn` in one step (read, open, change, seal, mark unsent, write). */
function updateStoredPins(acct: core.Account, place: MemoryPlace, fn: (pins: core.KeyPins | null) => core.KeyPins): Promise<TrustMemory> {
  return trustMemory.update(place.server, place.userId, (stored) => {
    const read = readMemory(stored, place.userId);
    // A record that isn't one is never replaced by a new memory (rule 7): the change is refused.
    if (stored !== undefined && stored !== null && !read) throw new Error(UNREADABLE_TEXT);
    const m = read ?? emptyMemory(place.userId);
    const pins = m.pinsSealed ? acct.openKeyPins(m.pinsSealed, m.pinsSeq) : null;
    return { ...m, pinsSealed: acct.sealKeyPins(fn(pins), m.pinsSeq), pinsDirty: true };
  });
}

/**
 * The vault ids that were in the account's offline copy when this unlock started: from an earlier session, never from
 * this one (ARCHITECTURE "Grandfathering", extension re-review M1). Only these may be grandfathered: a browser with no
 * earlier copy (a new install, an account added again) grandfathers nothing, so a vault a server plants at the first
 * signed sync can only ever wait for consent. Read once per unlock, before this session writes its own copy, and kept
 * in session storage, so a worker restart doesn't take this session's copy for an earlier one. Failing: none.
 * `read`: the offline copy the caller already read at the start of this unlock (saves a second read).
 */
function earlierVaultIds(id: string, acct: core.Account, read?: { copy: StoredSync | undefined }): Promise<Map<string, string>> {
  if (earlier?.gen === generation) return earlier.ids;
  const fresh = freshSession;
  const toMap = (list: core.GrandfatherCandidate[]) => new Map(list.map((c) => [c.vault_id, c.key_id]));
  const ids = (async () => {
    try {
      // A worker restart: the list kept for this unlock. Without one (its write failed) none: the offline copy is this
      // session's own by now, never an earlier one.
      if (!fresh) return toMap((await earlierVaults.get(id)) ?? []);
      // The copy the caller just read (`openVault`), else read here.
      const copy = read ? read.copy : await syncCache.get(id);
      const usable = copy && copy.user?.id === meOf(acct) ? new Set(usableVaultIds(copy)) : new Set<string>();
      // Each with the key id of the key it had there (round 5: grandfathering covers only that key).
      const list = (copy?.vaults ?? []).flatMap((v): core.GrandfatherCandidate[] => {
        if (typeof v.id !== "string" || !usable.has(v.id) || typeof v.wrapped_key !== "string" || typeof v.key_kind !== "string") return [];
        try {
          const key = acct.openVaultKey(v.id, v.wrapped_key, v.key_kind, whole(v.key_epoch) ?? 0, true);
          try {
            return [{ vault_id: v.id, key_id: key.keyId(v.id) }];
          } finally {
            key.free();
          }
        } catch {
          return [];
        }
      });
      await earlierVaults.set(id, list);
      return toMap(list);
    } catch (e) {
      log.debug("Reading which vaults this browser had before failed:", e);
      return new Map<string, string>();
    }
  })();
  earlier = { gen: generation, ids };
  return ids;
}

/**
 * The vaults an offline copy showed as usable (extension final review M): only rows whose kept verdict is for exactly
 * that row and is ok or "Not yet signed", never waiting, held or refused ones a server planted. A copy written with the
 * checks off (`checks: "off"`, round 5 H: a server can turn them off for a new browser by omitting `signed_sharing`)
 * gives none; only a copy from before signed sharing existed (neither verdicts nor that mark) gives every row.
 */
export function usableVaultIds(copy: Pick<StoredSync, "vaults" | "trust" | "checks">): string[] {
  const trust = copy.trust;
  if (!trust && copy.checks === "off") return [];
  return copy.vaults.flatMap((v) => {
    if (typeof v.id !== "string") return [];
    if (!trust) return [v.id];
    const t = trust[v.id];
    return t && t.row === rowStamp(v as SignedVaultRow) && (t.trust?.state === "ok" || t.trust?.state === "unsigned") ? [v.id] : [];
  });
}

/** This account's signing identity as far as this sync tells (`ensureIdentity`). */
interface IdentityState {
  /** The identity hash the server lists for this account as far as this browser can tell (null: none, or not known). */
  listed: string | null;
  /** This browser made the identity: now, or by an upload whose answer was lost (the listed one opens to its hash). */
  created: boolean;
  /** Whether the state is known (review M2): a listed identity opened, or one made now. Only then is grandfathering written. */
  known: boolean;
  /** The upload was answered 404: this server doesn't sign (for this sync). */
  unsupported: boolean;
  /** The record uploaded now: copied into the snapshot, so the offline copy lists it (review L3). */
  record?: core.IdentityRecord;
}

/**
 * This account's signing identity (ARCHITECTURE "Signed sharing", "App, at every unlock"): opened from `/sync`
 * `user.identity` (a record this account's key doesn't open → `identityBroken`: sharing paused here), or, when the
 * server lists none and the key pins don't remember one, made here on a sync with a server that has `signed_sharing`
 * and uploaded (`PUT /account/identity`; 409 `identity_exists`: another device made one meanwhile, so sync again and
 * open that one). Tried again at every sync until it is listed (cross-client rule 2), except after a 404 (this server
 * doesn't sign: not before the next unlock). Before uploading, the new identity's hash is added to the trust memory
 * (`pendingIdentities`), and the first time also the vaults grandfathering may cover (`candidates`, rule 6: the ones
 * the offline copy from an earlier session showed as usable): if the answer is lost, a later sync that lists an
 * identity opening to one of those hashes counts it as made here, but only when the key pins knew no own identity
 * before this check.
 */
async function ensureIdentity(
  acct: core.Account,
  id: string,
  user: SharingUser,
  mode: "sync" | "open",
  features: ReadonlySet<string> | undefined,
  pins: core.KeyPins | null,
  memory: TrustMemory,
  place: MemoryPlace,
  mayCreate: boolean,
  before: Map<string, string>,
  stale: () => boolean,
): Promise<IdentityState> {
  const unknown: IdentityState = { listed: null, created: false, known: false, unsupported: false };
  const rec = user.identity;
  if (rec && typeof rec === "object") {
    const json = JSON.stringify(rec);
    if (json !== signingRecord) {
      signing?.free();
      signing = null;
      identityBroken = false;
      signingRecord = json;
      try {
        signing = acct.openSigningIdentity(rec as core.IdentityRecord);
      } catch (e) {
        // `identity_mismatch` (keys that aren't this account's) or `decrypt_failed`: nothing is signed or trusted here.
        log.warn("The server's signing identity for this account doesn't open:", coreCode(e));
        identityBroken = true;
      }
    }
    const listed = signing ? signing.identityHash() : null;
    // Made here (an upload whose answer was lost) only if the pins didn't know an own identity before (rule 6).
    const created = !!listed && !pins?.own_identity && (memory.pendingIdentities ?? []).includes(listed);
    return { listed, created, known: listed !== null, unsupported: false };
  }
  // The server lists none: whatever was opened before isn't what it lists any more.
  signing?.free();
  signing = null;
  signingRecord = "";
  identityBroken = false;
  if (identityUnsupported === generation) return { ...unknown, unsupported: true };
  // Remembered one (then this is a mismatch: sharing paused), or nothing to make it with.
  if (pins?.own_identity || mode !== "sync" || !features?.has("signed_sharing") || !mayCreate) return unknown;
  const fresh = acct.newSigningIdentity();
  let made: core.SigningIdentity | null = null;
  try {
    made = fresh.takeIdentity();
    const hash = made.identityHash();
    const record = fresh.record;
    // Kept before the upload (in this check's memory too, which is written at its end); the candidates only once.
    const add = (m: TrustMemory): TrustMemory => ({
      ...m,
      pendingIdentities: [...(m.pendingIdentities ?? []).filter((h) => h !== hash), hash].slice(-MAX_PENDING),
      candidates: m.candidates ?? [...before].map(([vault_id, key_id]) => ({ vault_id, key_id })),
    });
    try {
      const stored = await trustMemory.update(place.server, place.userId, (s) => {
        const read = readMemory(s, place.userId);
        if (s !== undefined && s !== null && !read) throw new Error("unreadable trust memory");
        return add(read ?? emptyMemory(place.userId));
      });
      memory.pendingIdentities = stored.pendingIdentities;
      memory.candidates = stored.candidates;
    } catch (e) {
      log.debug("Keeping the new signing identity's hash failed; it isn't uploaded now:", e);
      return unknown;
    }
    if (stale()) return unknown;
    try {
      await api("/account/identity", { method: "PUT", body: record, accountId: id });
    } catch (e) {
      if (isCode(e, "identity_exists")) sharingResync = true;
      else log.debug("Uploading the signing identity failed:", e);
      const unsupported = e instanceof ApiError && e.status === 404;
      if (unsupported) identityUnsupported = generation;
      return { ...unknown, unsupported };
    }
    if (stale()) return unknown;
    // Any success: `created: true`, or `created: false` = the server already stored exactly this record (an upload of
    // this one whose answer was lost); either way it is the identity this browser just made.
    signing = made;
    made = null;
    signingRecord = JSON.stringify(record);
    return { listed: hash, created: true, known: true, unsupported: false, record };
  } finally {
    made?.free();
    fresh.free();
  }
}

/** The key pins for a check, and whether they couldn't be fetched on a browser without a copy of its own. */
interface LoadedPins {
  pins: core.KeyPins | null;
  /**
   * The server lists key pins but this browser, which has none of its own (a new install), couldn't get them (offline,
   * an error, an answer without them): like offline. Nothing is grandfathered or written, no identity is made, and
   * shared vaults wait for the next sync; never read as "trust memory missing".
   */
  offline: boolean;
  /**
   * This browser's own copy doesn't open and the server's can't stand in for it (rule 7: unsent changes in it, or no
   * server copy at least as new): the checks don't run on pins that may be missing what this browser knew.
   */
  unreadable?: boolean;
  /**
   * The server's newer copy remembers another own identity than this browser's (round 5 H: `identity_mismatch` from the
   * merge): nothing is merged or written, `pins` stay this browser's, and sharing is paused here.
   */
  mismatch?: boolean;
}

/** Whether the core refused to merge two key pin copies remembering different own identities. */
const isIdentityMismatch = (e: unknown) => coreCode(e) === "identity_mismatch";

/**
 * The account's key pins for this check: this browser's copy (sealed in its trust memory), replaced by the server's
 * newer one on a sync, always merged with this browser's copy (cross-client rule 5: what this browser knew — retired
 * keys, tombstones, rosters — is never dropped because another device wrote first; when the merge adds anything, the
 * pins are marked unsent and written back). A server version below the highest this browser opened is a rollback: the
 * browser's copy stays and the popup says so. On a sync, a newer version the server lists but doesn't give (or that
 * doesn't open) throws (review L4): the checks don't run on pins known to be incomplete (on a browser with no copy of
 * its own: `offline`). This browser's copy not opening is `unreadable` (rule 7), unless it had no unsent changes and
 * the server's copy is at least as new (then nothing is lost: the server's replaces it).
 */
async function loadKeyPins(acct: core.Account, id: string, memory: TrustMemory, user: SharingUser, mode: "sync" | "open", warnings: string[]): Promise<LoadedPins> {
  let pins: core.KeyPins | null = null;
  const serverSeq = whole(user.key_pins_seq);
  if (memory.pinsSealed) {
    try {
      pins = acct.openKeyPins(memory.pinsSealed, memory.pinsSeq);
    } catch (e) {
      log.warn("This browser's copy of the known keys doesn't open:", coreCode(e));
      // Repaired only from a strictly newer server copy (round 5 Info): at the same version it may lack what this copy held.
      if (memory.pinsDirty || mode !== "sync" || serverSeq === null || serverSeq === 0 || serverSeq <= memory.pinsSeq) return { pins: null, offline: false, unreadable: true };
      try {
        const got = await fetchKeyPins(id);
        if (got.sealed === null || got.seq <= memory.pinsSeq) return { pins: null, offline: false, unreadable: true };
        const theirs = acct.openKeyPins(got.sealed, got.seq);
        memory.pinsSeq = got.seq;
        memory.pinsSealed = null;
        return { pins: theirs, offline: false };
      } catch {
        return { pins: null, offline: false, unreadable: true };
      }
    }
  }
  const ok = (p: core.KeyPins | null): LoadedPins => ({ pins: p, offline: false });
  if (serverSeq === null) return ok(pins);
  if (serverSeq < memory.pinsSeq) {
    warnings.push(PINS_ROLLBACK_TEXT);
    return ok(pins);
  }
  if (serverSeq === 0 || (serverSeq === memory.pinsSeq && pins) || mode !== "sync") return ok(pins);
  const own = pins !== null || memory.pinsSeq > 0;
  let got: { sealed: string | null; seq: number };
  try {
    got = await fetchKeyPins(id);
  } catch (e) {
    if (own) throw e;
    log.debug("The known keys couldn't be fetched; shared vaults are checked at the next sync:", e);
    return { pins, offline: true };
  }
  if (got.seq < memory.pinsSeq) {
    warnings.push(PINS_ROLLBACK_TEXT);
    return ok(pins);
  }
  if (got.sealed === null) {
    if (got.seq <= memory.pinsSeq) return ok(pins);
    // L4: a newer version listed without its pins: never checked against older ones.
    if (own) throw new Error("key pins listed but not given");
    return { pins, offline: true };
  }
  let theirs: core.KeyPins;
  try {
    theirs = acct.openKeyPins(got.sealed, got.seq);
  } catch (e) {
    if (coreCode(e) === "rollback") {
      warnings.push(PINS_ROLLBACK_TEXT);
      return ok(pins);
    }
    throw e;
  }
  if (!pins) {
    memory.pinsSeq = got.seq;
    return ok(theirs);
  }
  // Rule 5 (round 5 M1): this browser's last-known pins merged into every newer server copy with `pinsMergeLastKnown`
  // (only what never goes back; a person pinned with another identity keeps the server's, decided later elsewhere);
  // `mergePins` (this browser's decision wins) only for its unsent changes. Written back only when that adds anything.
  let merged: core.KeyPins;
  try {
    merged = memory.pinsDirty ? core.mergePins(theirs, pins) : core.pinsMergeLastKnown(theirs, pins);
  } catch (e) {
    if (!isIdentityMismatch(e)) throw e;
    // Another own identity: neither copy is merged into the other, nothing is written, sharing is paused.
    log.warn("Your server's list of known keys remembers another signing key for this account; sharing is paused here.");
    return { pins, offline: false, mismatch: true };
  }
  memory.pinsSeq = got.seq;
  if (JSON.stringify(merged) !== JSON.stringify(core.pinsMergeLastKnown(theirs, theirs))) memory.pinsDirty = true;
  return ok(merged);
}

/**
 * Write the key pins (`PUT /account/key-pins`, compare-and-swap on `seq`): on 409 `key_pins_changed` the server's are
 * fetched, merged with these (this browser's newer decision wins for the same person) and written once more; otherwise
 * they stay marked unsent for the next sync. Returns the pins as they are now.
 */
async function writeKeyPins(acct: core.Account, id: string, memory: TrustMemory, pins: core.KeyPins): Promise<core.KeyPins> {
  let current = pins;
  for (let attempt = 0; attempt < 2; attempt++) {
    const seq = memory.pinsSeq + 1;
    let sealed: string;
    try {
      sealed = acct.sealKeyPins(current, seq);
    } catch (e) {
      log.warn("Sealing the known keys failed:", coreCode(e));
      return current;
    }
    try {
      await api("/account/key-pins", { method: "PUT", body: { key_pins: sealed, seq }, accountId: id });
      memory.pinsSeq = seq;
      memory.pinsDirty = false;
      return current;
    } catch (e) {
      if (attempt > 0 || !isCode(e, "key_pins_changed")) {
        log.debug("Writing the known keys failed:", e);
        return current;
      }
      try {
        const got = await fetchKeyPins(id);
        if (got.seq < memory.pinsSeq || got.sealed === null) return current;
        // This browser's unsent changes win (`mergePins`); another own identity (`identity_mismatch`) stops the write:
        // nothing is merged (the next check pauses sharing).
        current = core.mergePins(acct.openKeyPins(got.sealed, got.seq), current);
        memory.pinsSeq = got.seq;
      } catch (err) {
        log.debug(isIdentityMismatch(err) ? "The server's known keys remember another signing key; nothing was written." : "Merging the known keys failed:", err);
        return current;
      }
    }
  }
  return current;
}

/**
 * Whether the server says this account isn't a member of `vaultId` any more (its rosters answer 404, what the server
 * answers a non-member): a removal confirmed. Any other refusal (403: a policy, two-step login, …) confirms nothing
 * (round 5 Info).
 */
async function rostersGone(id: string, vaultId: string): Promise<boolean> {
  try {
    await api(`/vaults/${encodeURIComponent(vaultId)}/rosters?after=0`, { accountId: id });
    return false;
  } catch (e) {
    return e instanceof ApiError && e.status === 404;
  }
}

/**
 * Check every vault row of `snap` (signed-sharing.ts `checkVault`) and its invitations, and keep the verdicts for
 * `materialize`. `mode` "sync": after an answer from the server (every row checked, the identity made if missing, the
 * key pins fetched, grandfathered at the account's first signed sync and written); "open": the offline copy (rows
 * whose stored verdict has the same stamp keep it; others are checked; nothing is written to the server). Locked or
 * switched meanwhile: nothing changes.
 *
 * While the server's features are unknown (`/api/config` unreachable) the checks run too, but nothing that would turn
 * them on for good (trust memory, key pins) is kept until the server has shown it signs (cross-client review A).
 */
async function checkSharing(snap: Snapshot, id: string, mode: "sync" | "open", stored?: Record<string, StoredVerdict>): Promise<void> {
  const acct = account;
  if (!acct) return;
  const gen = generation;
  const stale = () => gen !== generation || currentId !== id || account !== acct;
  try {
    // Before anything of this session is kept (M1): what the offline copy held when this unlock started.
    const before = await earlierVaultIds(id, acct);
    if (stale()) return;
    const legacy = acct.legacyIdentity();
    const data = (await local.account(id)).data;
    const server = data?.server ?? "";
    const place: MemoryPlace = { server, userId: legacy.user_id };
    // Unknown (the server can't be reached): never read as "off" for an account that has signed state here.
    const features = server ? (await serverInfo(server))?.features : undefined;
    const user = snap.user as SharingUser;
    const rows = snap.vaults as SignedVaultRow[];
    const invitations = snap.invitations as SignedInvitation[];
    // Rule 7: a memory that can't be read (the read fails, or the record isn't one) is never taken for "none".
    let unreadable = false;
    let raw: unknown;
    try {
      raw = await trustMemory.read(server, place.userId);
    } catch (e) {
      log.warn("Reading what this browser trusted for signed sharing failed:", e);
      unreadable = true;
    }
    let memory = unreadable ? null : readMemory(raw, place.userId);
    if (raw !== undefined && raw !== null && memory === null) unreadable = true;
    if (stale()) return;
    if (data && data.userId !== place.userId) await local.set({ userId: place.userId }, id);
    // What this answer itself shows of signing (besides the features list).
    const signedData =
      (!!user.identity && typeof user.identity === "object") ||
      (whole(user.key_pins_seq) ?? 0) > 0 ||
      rows.some((r) => (r.share !== undefined && r.share !== null) || (r.member_roster !== undefined && r.member_roster !== null)) ||
      invitations.some((i) => i.share !== undefined && i.share !== null);
    const remembered = unreadable || remembersSigned(memory);
    // Features unknown: checked, unless the rows can't be from a signing server (they always name key epochs).
    const unknownOn = features === undefined && rows.some((r) => r.key_epoch !== undefined && r.key_epoch !== null);
    const on = !!features?.has("signed_sharing") || remembered || signedData || unknownOn;
    if (!on) {
      sharingOn = false;
      memoryUnreadable = false;
      verdicts = new Map();
      sharingWarnings = [];
      invitationChecks = [];
      return;
    }
    memory ??= emptyMemory(place.userId);
    const unchanged = JSON.stringify(memory);
    // The sealed copy this check starts from (review L7: pins changed meanwhile are merged in when it is stored).
    const basis = memory.pinsSealed;
    const seqBefore = memory.pinsSeq;
    const warnings: string[] = [];
    const loadedPins: LoadedPins = unreadable ? { pins: null, offline: false, unreadable: true } : await loadKeyPins(acct, id, memory, user, mode, warnings);
    if (stale()) return;
    if (loadedPins.unreadable) return await checkUnreadable(acct, id, snap, mode, stored, { user, features, before, place, stale });
    let pins = loadedPins.pins;
    const pinsOffline = loadedPins.offline;
    const loaded = JSON.stringify(pins);
    const ident = await ensureIdentity(acct, id, user, mode, features, pins, memory, place, !pinsOffline, before, stale);
    if (stale()) return;
    // L3: the identity made now is in the snapshot (and so in the offline copy), or an offline open would see none.
    if (ident.record) snap.user = { ...snap.user, identity: ident.record } as Snapshot["user"];
    const { listed, created } = ident;
    // Kept only once the server has shown it signs (review A); a 404 for the upload says it doesn't (this sync).
    const keep = remembered || signedData || ident.created || (!!features?.has("signed_sharing") && !ident.unsupported);
    // The identity the server lists for me against the one the account remembers (review L4), and a server copy of the
    // key pins remembering another own identity (round 5 H).
    let paused = identityBroken || loadedPins.mismatch === true;
    if (!paused) {
      const own = core.pinsCheckOwnIdentity(pins, listed);
      if (own === "mismatch") paused = true;
      else if (own === "new" && listed) pins = core.pinsSetOwnIdentity(pins, listed);
    }
    if (paused) warnings.push(PAUSED_TEXT);
    const me = signing && !paused ? signing.publicIdentity() : legacy;
    const meHash = core.verifyIdentity(me).hash;
    // The account's first signed sync: `grandfathered` written once, only when the identity state is known (M2: never
    // after a failed or unanswered upload; tried again at the next sync) and the key pins are (not offline). Only an
    // unlock that made the signing identity grandfathers, and only the vaults this browser's offline copy from an
    // earlier session showed as usable, as recorded when the identity was first made (M1, rule 6): the shares from
    // before, unsigned, stay usable without consent. The other shared vaults wait for consent and may be accepted here
    // (by the key shown), like with a lost trust memory: an identity that exists with no key pins anywhere grandfathers
    // nothing (remembered in `missing`).
    if (mode === "sync" && keep && !pinsOffline && !paused && ident.known && features?.has("signed_sharing") && (pins?.grandfathered ?? null) === null) {
      const sealedIds = rows.flatMap((r) => (typeof r.id === "string" && r.key_kind === "sealed" ? [r.id] : []));
      // Each candidate with the key id it had in the earlier copy (round 5): a key served under that id now that isn't
      // it needs consent.
      const covered = created ? (memory.candidates ? new Map(memory.candidates.map((c) => [c.vault_id, c.key_id])) : before) : new Map<string, string>();
      if (!created && loaded === "null" && memory.pinsSeq === 0) {
        memory.missing = sealedIds;
        delete memory.missingWhy;
      } else if (created) {
        const unseen = sealedIds.filter((v) => !covered.has(v));
        if (unseen.length) {
          memory.missing = unseen;
          memory.missingWhy = "device";
        }
      }
      pins = core.pinsGrandfather(
        pins,
        rows.flatMap((r): core.GrandfatherCandidate[] => {
          const keyId = typeof r.id === "string" ? covered.get(r.id) : undefined;
          return keyId !== undefined ? [{ vault_id: r.id, key_id: keyId }] : [];
        }),
        created,
      );
    }
    // Rule 6: once the pins hold the own identity and `grandfathered`, the identities made here and the candidates are done.
    if (pins?.own_identity && (pins.grandfathered ?? null) !== null) {
      delete memory.pendingIdentities;
      delete memory.candidates;
    }
    // Rule 2: until this browser finished the account's first signed sync, unsigned shared vaults are held, not consents.
    const firstDone = keep && !pinsOffline && ident.known && (pins?.grandfathered ?? null) !== null;
    const missing = new Set(memory.missing ?? []);
    const gone: NonNullable<TrustMemory["gone"]> = { ...(memory.gone ?? {}) };
    const now = Math.floor(Date.now() / 1000);
    // Observed removals (cross-client rule 3): an accepted shared vault this browser used is tombstoned (with its
    // remembered roster version, so a server can't bring it back later without a newer signed member list and the
    // user's consent) only once its removal is confirmed: absent from two verified syncs in a row, or its rosters
    // answering 403/404. Never after one sync that omitted it.
    if (mode === "sync" && keep && !pinsOffline && !paused && currentId === id) {
      const present = new Set(rows.map((r) => r.id));
      const confirm = (vaultId: string, g: { roster: number; leave: boolean }) => {
        if (g.leave) {
          try {
            pins = core.pinsLeave(pins, vaultId, g.roster, now);
          } catch (e) {
            log.debug("Remembering a removed shared vault failed:", coreCode(e));
          }
        }
        missing.delete(vaultId);
        delete gone[vaultId];
      };
      // Missing from the last verified sync too: confirmed; back: forgotten.
      for (const [vaultId, g] of Object.entries(memory.gone ?? {})) {
        if (present.has(vaultId)) delete gone[vaultId];
        else confirm(vaultId, g);
      }
      const newly = new Map<string, { roster: number; leave: boolean }>();
      for (const old of synced?.vaults ?? []) {
        if (typeof old.id !== "string" || old.key_kind !== "sealed" || present.has(old.id) || memory.gone?.[old.id]) continue;
        const was = verdicts.get(old.id);
        const used = !!was && was.row === rowStamp(old as SignedVaultRow) && (was.trust.state === "ok" || was.trust.state === "unsigned");
        if (used) newly.set(old.id, { roster: rosterVersion(memory.rosters[old.id] ?? "") ?? 0, leave: true });
      }
      // Vaults waiting since the trust memory was found missing, gone now: forgotten the same way (nothing to leave).
      for (const v of missing) if (!present.has(v) && !memory.gone?.[v] && !newly.has(v)) newly.set(v, { roster: 0, leave: false });
      for (const [vaultId, g] of newly) {
        if (g.leave && (await rostersGone(id, vaultId))) confirm(vaultId, g);
        else gone[vaultId] = g;
        if (stale()) return;
      }
    }
    if (Object.keys(gone).length) memory.gone = gone;
    else delete memory.gone;
    const startDigest = await pinsDigest(pins);
    const rosters = { ...memory.rosters };
    const signed = new Set(memory.signed);
    const results = new Map<string, { row: SignedVaultRow; trust: Trust }>();
    for (const row of rows) {
      if (typeof row.id !== "string" || typeof row.wrapped_key !== "string" || typeof row.key_kind !== "string") continue;
      if (mode === "open") {
        const kept = stored?.[row.id];
        const ctx = { pins: startDigest, remembered: rosters[row.id] ?? null, seenSigned: signed.has(row.id), paused, me: meHash };
        if (kept && typeof kept.stamp === "string" && kept.trust && kept.stamp === (await contextStamp(row, ctx))) {
          results.set(row.id, { row, trust: kept.trust });
          continue;
        }
      }
      const epoch = whole(row.key_epoch);
      let r: VaultCheck;
      if (epoch === null || (row.key_kind === "sealed" && paused)) {
        r = { trust: refusedUnopened(epoch === null ? "missing_epoch" : "paused"), pins, roster: null, signed: false };
      } else if (row.key_kind === "sealed" && pinsOffline) {
        // The key pins couldn't be had on a browser without its own: shared vaults wait for the next sync.
        r = { trust: { state: "refused", reason: CHECK_LATER_TEXT, why: "key pins not fetched" }, pins, roster: null, signed: false };
      } else {
        let key: core.VaultKey;
        try {
          key = acct.openVaultKey(row.id, row.wrapped_key, row.key_kind, epoch, core.pinsLegacyWrapAllowed(pins, row.id));
        } catch {
          continue; // a key this account can't open: the vault stays hidden anyway
        }
        try {
          r = await checkVault({
            row,
            key,
            me,
            pins,
            remembered: rosters[row.id] ?? null,
            seenSigned: signed.has(row.id),
            paused,
            fetchRosters: (after) => fetchRosters(id, row.id, after),
            now,
            ...(accepting.has(row.id) ? { accept: accepting.get(row.id) } : {}),
            ...(missing.has(row.id) ? { memoryMissing: true } : {}),
            ...(firstDone ? {} : { holdUnsigned: true }),
          });
        } finally {
          key.free();
        }
      }
      if (stale()) return;
      if (r.trust.state === "refused") log.warn(`A shared vault failed its check and isn't used (${r.trust.why}).`);
      pins = r.pins;
      if (r.roster !== null) rosters[row.id] = r.roster;
      if (r.signed) signed.add(row.id);
      results.set(row.id, { row, trust: r.trust });
    }
    memory.rosters = rosters;
    memory.signed = [...signed];
    // The lost-memory (or new-browser) state lasts until each vault it covers was accepted or is confirmed gone: never
    // shortened by a sync that couldn't check one ("check later") or that omitted it once.
    const stillMissing = [...missing].filter((v) => {
      const t = results.get(v)?.trust.state;
      return t !== "ok" && t !== "unsigned";
    });
    if (stillMissing.length) {
      memory.missing = stillMissing;
      if (stillMissing.some((v) => results.get(v)?.trust.state === "waiting")) warnings.push(memory.missingWhy === "device" ? NEW_DEVICE_TEXT : MEMORY_MISSING_TEXT);
    } else {
      delete memory.missing;
      delete memory.missingWhy;
    }
    if (keep && !pinsOffline) {
      const changedPins = JSON.stringify(pins) !== loaded;
      if (changedPins) memory.pinsDirty = true;
      // Never written while sharing is paused (round 5 H: a device the server gave another identity must not spread
      // what it pinned); the changes stay unsent here.
      if (pins && memory.pinsDirty && mode === "sync" && !paused) pins = await writeKeyPins(acct, id, memory, pins);
      if (stale()) return;
      // The browser's sealed copy follows whenever the pins or their version changed (sealing isn't deterministic).
      if (pins && (changedPins || memory.pinsSeq !== seqBefore || memory.pinsSealed === null)) {
        try {
          memory.pinsSealed = acct.sealKeyPins(pins, memory.pinsSeq);
        } catch (e) {
          log.warn("Keeping the known keys failed:", coreCode(e));
        }
      }
      if (JSON.stringify(memory) !== unchanged) memory = await saveMemory(acct, place, memory, basis);
      // The floor a later unreadable memory keeps to in this browser session (round 5 L).
      if (memory.pinsSeq > 0 && memory.pinsSeq > (await pinsFloor.get(id).catch(() => 0))) await pinsFloor.set(id, memory.pinsSeq).catch(logged("Keeping the known keys' version"));
    }
    if (stale()) return;
    await publish(results, pins, paused, meHash, warnings, invitations, me, features, server, rosters, signed);
  } catch (e) {
    // Unexpected (storage, the core, pins the server lists but didn't give): the verdicts stay as they were, so a
    // vault without one stays closed.
    log.warn("Checking shared vaults failed:", e);
    if (!stale()) sharingOn = true;
  }
}

/** Keep the verdicts of a check (stamped with the state they now rest on) and what the popup shows about them. */
async function publish(
  results: Map<string, { row: SignedVaultRow; trust: Trust }>,
  pins: core.KeyPins | null,
  paused: boolean,
  meHash: string,
  warnings: string[],
  invitations: SignedInvitation[],
  me: core.PublicIdentity,
  features: ReadonlySet<string> | undefined,
  server: string,
  rosters: Record<string, string>,
  signed: Set<string>,
  unreadable = false,
): Promise<void> {
  const gen = generation;
  const id = currentId;
  // Stamps with the state the verdicts now rest on (an offline open compares them before reusing a verdict).
  const digest = await pinsDigest(pins);
  const next = new Map<string, StoredVerdict>();
  for (const [vaultId, { row, trust }] of results) {
    const ctx = { pins: digest, remembered: rosters[vaultId] ?? null, seenSigned: signed.has(vaultId), paused, me: meHash };
    next.set(vaultId, { row: rowStamp(row), stamp: await contextStamp(row, ctx), trust });
  }
  if (gen !== generation || currentId !== id) return;
  const signedServer = !!features?.has("signed_sharing") || invitations.some((i) => i.share !== undefined);
  invitationChecks = signedServer ? invitations.map((i) => checkInvitation(i, me, pins, paused)) : [];
  sharingOn = true;
  sharingPaused = paused;
  memoryUnreadable = unreadable;
  keyPins = pins;
  verdicts = next;
  sharingWarnings = warnings;
  vaultsUrl = server ? `${server.replace(/\/+$/, "")}/settings/vaults` : "";
}

/**
 * The checks when this browser's trust memory can't be read (cross-client rule 7): never as a new device with no pins.
 * Shared (sealed) vaults are refused; own vaults keep their epoch and key id checks against the server's key pins,
 * opened read-only (a sync), else keep the verdict they last had for the same row, else wait. Nothing is made,
 * grandfathered, pinned, tombstoned or written; accepting and trusting keys are refused until the memory reads again.
 */
async function checkUnreadable(
  acct: core.Account,
  id: string,
  snap: Snapshot,
  mode: "sync" | "open",
  stored: Record<string, StoredVerdict> | undefined,
  c: { user: SharingUser; features: ReadonlySet<string> | undefined; before: Map<string, string>; place: MemoryPlace; stale: () => boolean },
): Promise<void> {
  let pins: core.KeyPins | null = null;
  let mismatch = false;
  // Round 5 L: never below what this browser session already opened (`pinsFloor`, outliving worker restarts), and the
  // pins this session last used merged in read-only (`pinsMergeLastKnown`), so a server can't serve an older copy here.
  const floor = await pinsFloor.get(id).catch(() => 0);
  const seq = whole(c.user.key_pins_seq);
  if (mode === "sync" && seq !== null && seq > 0 && seq >= floor) {
    try {
      const got = await fetchKeyPins(id);
      if (got.sealed !== null && got.seq >= floor) pins = acct.openKeyPins(got.sealed, got.seq);
    } catch (e) {
      log.debug("The server's known keys couldn't be read:", e);
    }
  }
  if (c.stale()) return;
  const last = keyPins;
  if (last) {
    try {
      pins = pins ? core.pinsMergeLastKnown(pins, last) : last;
    } catch (e) {
      if (!isIdentityMismatch(e)) throw e;
      mismatch = true;
      pins = last;
    }
  }
  await ensureIdentity(acct, id, c.user, mode, c.features, pins, emptyMemory(c.place.userId), c.place, false, c.before, c.stale);
  if (c.stale()) return;
  const listed = signing ? signing.identityHash() : null;
  const paused = identityBroken || mismatch || (pins !== null && core.pinsCheckOwnIdentity(pins, listed) === "mismatch");
  const me = signing && !paused ? signing.publicIdentity() : acct.legacyIdentity();
  const meHash = core.verifyIdentity(me).hash;
  const now = Math.floor(Date.now() / 1000);
  const results = new Map<string, { row: SignedVaultRow; trust: Trust }>();
  for (const row of snap.vaults as SignedVaultRow[]) {
    if (typeof row.id !== "string" || typeof row.wrapped_key !== "string" || typeof row.key_kind !== "string") continue;
    const epoch = whole(row.key_epoch);
    let trust: Trust;
    if (row.key_kind === "sealed") trust = { state: "refused", reason: UNREADABLE_TEXT, why: "memory_unreadable" };
    else if (epoch === null) trust = refusedUnopened("missing_epoch");
    else if (pins) {
      let key: core.VaultKey;
      try {
        key = acct.openVaultKey(row.id, row.wrapped_key, row.key_kind, epoch, core.pinsLegacyWrapAllowed(pins, row.id));
      } catch {
        continue;
      }
      try {
        trust = (await checkVault({ row, key, me, pins, remembered: null, seenSigned: false, paused, fetchRosters: (after) => fetchRosters(id, row.id, after), now })).trust;
      } finally {
        key.free();
      }
    } else {
      const prev = mode === "open" ? stored?.[row.id] : verdicts.get(row.id);
      trust = prev && prev.row === rowStamp(row) && prev.trust?.state === "ok" ? prev.trust : { state: "refused", reason: CHECK_LATER_TEXT, why: "memory_unreadable" };
    }
    if (c.stale()) return;
    results.set(row.id, { row, trust });
  }
  await publish(results, pins, paused, meHash, [UNREADABLE_TEXT, ...(paused ? [PAUSED_TEXT] : [])], snap.invitations as SignedInvitation[], me, c.features, c.place.server, {}, new Set(), true);
}

/** The loaded account's verdict for a vault (undefined: none, or checks are off for the account). */
function trustOf(vaultId: string): Trust | undefined {
  return sharingOn ? verdicts.get(vaultId)?.trust : undefined;
}

/** How a signer shows in the popup (the display rule: pinned email first; "Verified" only with a pinned email). */
const signerOut = (s: SignerView): VaultSigner => ({
  email: s.email,
  pinned: s.pinned,
  ...(s.listedAs ? { listedAs: s.listedAs } : {}),
  deleted: s.deleted,
  fingerprint: s.fingerprint,
  verified: s.verified && s.pinned,
});

/** Signed sharing as the popup's notice shows it; null when there is nothing to say. */
export function sharingNotice(): SharingNotice | null {
  if (!sharingOn) return null;
  const live = new Set((synced?.vaults ?? []).map((v) => v.id));
  const refused: SharingNotice["refused"] = [];
  const waiting: SharingNotice["waiting"] = [];
  for (const [vaultId, v] of verdicts) {
    if (!live.has(vaultId)) continue;
    const t = v.trust;
    if (t.state === "refused") {
      const c = t.changed;
      refused.push({
        vaultId,
        reason: t.reason,
        ...(c ? { changed: { kind: c.kind, userId: c.userId, email: c.email, fingerprint: c.fingerprint, newEmail: c.newEmail } } : {}),
      });
    } else if (t.state === "waiting") {
      // A new key on a vault never seen signed names its signer (pinned email first) for the fingerprint check; a vault
      // the account held with its own key wrap gets the extra warning (round 4 `consent.own`).
      const base = t.replaced
        ? t.signer
          ? replacedSignedText(t.name, t.signer.email, t.signer.pinned)
          : replacedText(t.name)
        : t.firstSigned && t.signer
          ? firstSignedText(t.name, t.signer.email, t.signer.pinned)
          : t.signer || t.acceptable
            ? waitingText(t.name)
            : unsignedLockedText(t.name);
      waiting.push({
        vaultId,
        name: t.name,
        text: t.own ? `${base} ${ownVaultText(t.name)}` : base,
        ...(t.signer ? { signer: signerOut(t.signer) } : {}),
        acceptable: t.acceptable,
        token: t.token,
        replaced: t.replaced,
        own: t.own === true,
        firstSigned: t.firstSigned === true,
        // Decline (in the web vault) only where the core says `declinable` (round 5 M2): never for a vault the
        // account holds (replaced, first signed, own, re-join), where declining would give up a vault it uses.
        declinable: t.declinable === true,
        // Unsigned: accepted by the key id shown (when allowed), else locked with no Decline (cross-client rule 1).
        ...(t.signer ? {} : t.acceptable ? { note: UNSIGNED_LABEL, keyId: t.keyId } : { note: ASK_OWNER_TEXT }),
      });
    }
  }
  const invitations = invitationChecks.flatMap((c) => {
    const text = invitationText(c);
    return text ? [{ vaultId: c.vaultId, text }] : [];
  });
  if (!refused.length && !waiting.length && !sharingWarnings.length && !invitations.length) return null;
  const key = JSON.stringify([refused.map((r) => [r.vaultId, r.reason]), waiting.map((w) => [w.vaultId, w.token]), sharingWarnings, invitations.map((i) => [i.vaultId, i.text])]);
  return { refused, waiting, warnings: sharingWarnings, invitations, key, ...(vaultsUrl ? { vaultsUrl } : {}) };
}

/** This account's signing identity, as Settings shows it. */
export function sharingIdentity(): SharingIdentity {
  return { fingerprint: signing && !sharingPaused ? signing.fingerprint() : null, paused: sharingPaused };
}

/** A vault's label and signer for the popup: "Not yet signed", or who signed its share. */
export function vaultTrust(vaultId: string): { vaultLabel?: string; signer?: VaultSigner } {
  const t = trustOf(vaultId);
  if (t?.state === "unsigned") return { vaultLabel: UNSIGNED_LABEL };
  if (t?.state !== "ok" || !t.signer) return {};
  const s = t.signer;
  // L6: an email that isn't the pinned one is the server's claim, also in the label of a deleted signer's vault.
  return { ...(s.deleted ? { vaultLabel: signedByLabel(s.email, true, s.pinned) } : {}), signer: signerOut(s) };
}

/**
 * "Trust the new key": the user compared the new fingerprint of `userId` (whose pinned keys changed) with them. Only
 * the identity the popup showed (`fingerprint`) is pinned, as verified, with the email pinned before (in this browser's
 * copy, written to the server at the sync that follows), and the vaults it signed are checked again.
 */
export async function trustNewKey(userId: string, fingerprint: string): Promise<void> {
  await syncIdle();
  const acct = account;
  const id = currentId;
  if (!acct || !id || !synced) throw lockedError();
  let changed: ChangedKey | undefined;
  for (const v of verdicts.values()) {
    const c = v.trust.state === "refused" ? v.trust.changed : undefined;
    if (c?.kind === "changed" && c.userId === userId && c.fingerprint === fingerprint) changed = c;
  }
  if (!changed) throw new Error("Their keys changed again, or there's nothing to trust any more. Compare the fingerprint shown now.");
  if (memoryUnreadable) throw new Error(UNREADABLE_TEXT);
  const c = changed;
  const server = (await local.account(id)).data?.server ?? "";
  if (account !== acct || currentId !== id) throw lockedError();
  await updateStoredPins(acct, { server, userId: meOf(acct) }, (pins) => core.pinSet(pins, c.identity, c.pinEmail, true, Math.floor(Date.now() / 1000)));
  await sync();
}

/**
 * Accept a shared vault the server added to this account without the account ever accepting it (it waits for consent):
 * only exactly what the popup showed (`token` = signed-sharing.ts `consentToken`: key id and epoch, signer identity,
 * roster, role; review L1). The next check pins its key, its signer and its roster (ARCHITECTURE "Vault admission",
 * consent), after every check of the row passed again, and only if that row still has the same token: a row the
 * server changed meanwhile keeps waiting, with what it is now.
 */
export async function acceptSharedVault(vaultId: string, token: string): Promise<void> {
  await syncIdle();
  if (!account || !currentId) throw lockedError();
  if (memoryUnreadable) throw new Error(UNREADABLE_TEXT);
  const t = trustOf(vaultId);
  if (t?.state !== "waiting" || !t.acceptable || !token || t.token !== token) throw new Error("This vault changed. Check what the popup shows now.");
  accepting.set(vaultId, token);
  try {
    await sync();
  } finally {
    accepting.delete(vaultId);
  }
  const after = trustOf(vaultId);
  if (after?.state === "waiting" && after.token !== token) throw new Error("This vault changed just now, so it wasn't accepted. Check what the popup shows now.");
  if (after?.state !== "ok" && after?.state !== "unsigned") throw new Error("PassAuth couldn't accept this vault. Check what the popup shows now.");
}

/** Called whenever the loaded account's vault was opened or changed (live-sync.ts keeps its socket up then). */
let opened: () => void = () => {};
export function setOpenedHandler(fn: () => void) {
  opened = fn;
}

/** Show `snap` for the loaded account (decrypting only what changed). */
function show(snap: Snapshot) {
  synced = snap;
  materialize(snap);
  opened();
}

let storing: Promise<void> = Promise.resolve();

/**
 * Keep the loaded account's snapshot as its offline copy: one IndexedDB record, so the cursor and the vault numbers
 * are never kept without the rows they describe, and a write that doesn't happen (the worker stopped) leaves the
 * previous copy whole. Writes run one after another and each takes the newest snapshot; none after a lock,
 * sign-out or switch.
 */
function persist(id: string): Promise<void> {
  const gen = generation;
  const p = storing.then(async () => {
    if (gen !== generation || currentId !== id || !synced) return;
    await syncCache.set(id, sharingOn ? { ...toStored(synced), trust: Object.fromEntries(verdicts) } : { ...toStored(synced), checks: "off" });
  });
  storing = p.catch(() => {});
  return p;
}

const byName = new Intl.Collator(undefined, { sensitivity: "base" });

function decryptRow(key: core.VaultKey, row: SyncItemRow): Entry | null {
  // Trash summaries (and anything else without ciphertext) can't be opened.
  if (typeof row.item_key !== "string" || typeof row.data !== "string") return null;
  const enc: EncryptedItem = { id: row.id, vault_id: row.vault_id, key: row.item_key, data: row.data };
  try {
    return { id: row.id, item: key.decryptItem(enc) as Item, vaultId: row.vault_id, revision: row.revision, enc };
  } catch {
    return null;
  }
}

/**
 * Decrypt `snap` into vaults and entries, and publish the match index. A vault's key handle is kept while its key
 * fields (`wrapped_key`, `key_kind`, `key_epoch`) stay the same, otherwise it is opened again and its items decrypted
 * again; an item whose ciphertext didn't change keeps its decrypted copy. The trash isn't shown.
 */
function materialize(snap: Snapshot) {
  const acct = account;
  if (!acct) return;
  if (snap.bundle) {
    bundle = snap.bundle;
    void dropStalePin(currentId, snap.bundle).catch(logged("Checking the PIN copy"));
  }
  const previous = new Map(vaults.map((v) => [v.id, v]));
  const kept = new Set<core.VaultKey>();
  const keysFrom = new Map<string, SyncVaultRow>();
  const next: Vault[] = [];
  for (const v of snap.vaults) {
    // What the core takes as text must be text (serverText): a row that isn't stays closed, like a key it can't open.
    if (typeof v.id !== "string" || typeof v.wrapped_key !== "string" || typeof v.key_kind !== "string") continue;
    // Signed sharing: only a vault whose current row passed its check (or is a share from before) is opened at all.
    if (sharingOn) {
      const verdict = verdicts.get(v.id);
      const state = verdict?.row === rowStamp(v) ? verdict.trust.state : null;
      if (state !== "ok" && state !== "unsigned") continue;
    }
    const old = previous.get(v.id);
    const from = openedFrom.get(v.id);
    let key: core.VaultKey;
    let name: string | null = null;
    if (old && from && !vaultKeyChanged(from, v)) {
      key = old.key;
      kept.add(key);
      if (from.meta === v.meta) name = old.name;
    } else {
      try {
        // Account wraps open with the row's key epoch; a v1 wrap only where the account's pins allow it.
        const legacyOk = sharingOn ? core.pinsLegacyWrapAllowed(keyPins, v.id) : true;
        key = acct.openVaultKey(v.id, v.wrapped_key, v.key_kind, Number.isSafeInteger(v.key_epoch) && (v.key_epoch as number) >= 0 ? (v.key_epoch as number) : 0, legacyOk);
      } catch {
        continue; // vault key unavailable (replaced): its items stay hidden
      }
    }
    if (name === null) {
      try {
        const meta = typeof v.meta === "string" ? (key.decryptMeta(v.id, v.meta) as { name?: unknown }) : null;
        name = typeof meta?.name === "string" ? meta.name : "Vault";
      } catch {
        name = "Vault";
      }
    }
    keysFrom.set(v.id, v);
    // A role that isn't text is read as the least: view only.
    const role: Role = typeof v.role === "string" ? v.role : "read";
    next.push({ id: v.id, name, role, kind: v.key_kind, key, epoch: Number.isSafeInteger(v.key_epoch) ? v.key_epoch : undefined });
  }
  const byId = new Map(next.map((v) => [v.id, v]));
  const copies = new Map<string, { row: SyncItemRow; entry: Entry | null }>();
  const list: Entry[] = [];
  for (const row of snap.items.values()) {
    const vault = byId.get(row.vault_id);
    if (!vault || row.deleted_at) continue;
    const old = decrypted.get(row.id);
    let entry: Entry | null;
    if (old && kept.has(vault.key) && sameCiphertext(old.row, row)) {
      entry = old.entry && old.entry.revision !== row.revision ? { ...old.entry, revision: row.revision } : old.entry;
    } else {
      entry = decryptRow(vault.key, row);
    }
    copies.set(row.id, { row, entry });
    if (entry) list.push(entry);
  }
  list.sort((a, b) => byName.compare(a.item.name, b.item.name));
  // Handles the new state no longer uses (a vault gone, or its key replaced).
  for (const v of vaults) if (!kept.has(v.key)) v.key.free();
  vaults = next;
  entries = list;
  decrypted = copies;
  openedFrom = keysFrom;
  revision = snap.revision;
  loaded = true;
  const logins: IndexedLogin[] = list.flatMap((e) => (e.item.login ? [{ id: e.id, urls: e.item.login.urls, personal: isPersonal(e) }] : []));
  index = { revision, logins, cards: list.filter((e) => e.item.card).length, identities: list.filter((e) => e.item.identity).length };
  void matchIndex.set(currentId, index).catch(logged("Storing the match index"));
  if (bundle) noteSecretKey(currentId, bundle);
}

/** `GET /sync/revision` for `id` (with every vault's number on servers with delta sync). */
async function revisionOf(id: string): Promise<RevisionAnswer> {
  const r = readRevision(await api<unknown>("/sync/revision", { accountId: id }));
  if (!r) throw new AppError(FAILED, UNEXPECTED_SYNC);
  // It answered: whatever two-step setup the server asked for is done.
  await noteTwoStepDone(id);
  return r;
}

/** Re-sync if the server has something the vault doesn't (cheap revision check; sync-rules.ts `isStale`). */
export async function refreshIfStale() {
  if (!account) return;
  const id = currentId;
  const r = await revisionOf(id).catch((e: unknown) => {
    // Offline or the server is down: the vault stays as it is.
    log.debug("Revision check failed:", e);
    return null;
  });
  if (r && account && currentId === id && isStale(r, synced)) await sync();
}

/** The snapshot of `id` without decrypting anything: in memory when its vault is open here, else its offline copy. */
async function snapshotOf(id: string): Promise<Snapshot | null> {
  if (account && currentId === id && synced) return synced;
  const copy = id ? await syncCache.get(id) : undefined;
  return copy ? fromStored(copy) : null;
}

/** What the check before a live-sync connection found (live-sync.ts). */
export type LiveCheck = "ok" | "unsupported" | "signed_out" | "two_step" | "offline";

/**
 * Before the live-sync socket (re)connects, and on its fallback alarm: is the active account still signed in, and
 * does its server have delta sync (the socket is used only then; older servers keep today's behaviour)? Asks
 * `GET /sync/revision`, which also refreshes an expired access token, and syncs when the copy lacks something. The
 * copy's numbers come from memory or the offline copy: no keys are loaded unless there is something to sync.
 */
export async function checkForChanges(): Promise<LiveCheck> {
  const { id, data } = await local.account();
  if (!id || !data?.server || !data.tokens) return "signed_out";
  const info = await serverInfo(data.server);
  if (!info) return "offline";
  if (!info.features.has("delta_sync")) return "unsupported";
  try {
    const r = await revisionOf(id);
    if ((await activeId()) === id && isStale(r, await snapshotOf(id)) && (await ensureUnlocked())) await sync();
    return "ok";
  } catch (e) {
    const code = codeOf(e);
    if (code === SIGNED_OUT) return "signed_out";
    if (code === TWO_STEP_REQUIRED) return "two_step";
    log.debug("Checking for changes failed:", e);
    return "offline";
  }
}

/**
 * A live-sync `sync` message for the active account: sync only when it announces something the copy doesn't have yet
 * (`noticeAction`: a newer or unknown vault number, `vaults: {}`, or without delta sync a newer revision). A sync
 * already on its way may bring it, so that one is waited for first. The message's origin is never a reason to skip
 * it: every PassAuth context sharing this session shares it. Nothing is unlocked for it.
 */
export async function liveNotice(msg: SyncNotice): Promise<void> {
  const id = await activeId();
  await syncIdle();
  const snap = await snapshotOf(id);
  if (!snap) return;
  if (noticeAction(msg, (v) => knownSeq(snap, v), snap.revision, !!snap.cursor) !== "sync") return;
  if ((await activeId()) !== id || !(await ensureUnlocked())) return;
  await sync();
}

/**
 * A live-sync `logout` message: sessions of the account were ended on the server. A request tells whether this one
 * was: an ended session signs the account out here (api.ts: refresh token refused); a live one stays.
 */
export async function checkSession(): Promise<void> {
  const { id, data } = await local.account();
  if (!id || !data?.tokens) return;
  await api("/sync/revision", { accountId: id }).catch((e: unknown) => log.debug("Checking the session:", e));
}

/** Vaults shared with the active account and not accepted yet (servers with `vault_invitations`): how many, and which (for the popup's notice). */
export function invitations(): { count: number; key: string } {
  const list = synced?.invitations ?? [];
  return {
    count: list.length,
    key: list
      .map((i) => i.vault_id)
      .sort()
      .join(","),
  };
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

/**
 * A list row's second line. It never carries a secret or a note's text (a secure note says "Secure note"): lists
 * are drawn on screen in full, often with someone nearby.
 */
export function subtitleOf(i: Item): string {
  const kind = kindOf(i);
  if (kind === "login") return i.login?.username || siteHost(i);
  if (kind === "card") {
    const last4 = (i.card?.number ?? "").replace(/\s+/g, "").slice(-4);
    return [i.card?.brand, last4 ? `•••• ${last4}` : ""].filter(Boolean).join(" ") || "Card";
  }
  if (kind === "identity") {
    const id = i.identity;
    const name = [id?.first_name, id?.last_name].filter(Boolean).join(" ");
    return [name, id?.email].filter(Boolean).join(" · ") || "Identity";
  }
  if (kind === "ssh_key") return i.ssh_key?.fingerprint || "SSH key";
  return "Secure note";
}

export function summarize(e: Entry): ItemSummary {
  const i = e.item;
  const host = siteHost(i);
  const { vaultLabel } = vaultTrust(e.vaultId);
  return {
    id: e.id,
    name: i.name || "Untitled",
    subtitle: subtitleOf(i),
    host,
    url: i.login?.urls.find((u) => u.match !== "regex" && /^https?:\/\//i.test(u.url))?.url ?? (host ? `https://${host}` : ""),
    folder: i.folder ?? "",
    kind: kindOf(i),
    favorite: i.favorite,
    hasPassword: !!i.login?.password,
    hasTotp: !!i.login?.totp,
    passkeys: i.login?.passkeys.length ?? 0,
    vaultName: vaultName(e.vaultId),
    vaultId: e.vaultId,
    shared: !isPersonal(e),
    ...(vaultLabel ? { vaultLabel } : {}),
    username: i.login?.username ?? "",
    websites: (i.login?.urls ?? []).map((u) => u.url).filter(Boolean),
    tags: i.tags ?? [],
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

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** An item id a client may choose itself (so a retried create keeps it): a UUID. */
export const validItemId = (id: unknown): id is string => typeof id === "string" && UUID.test(id);

/** The write carries the epoch of the vault key it was encrypted with, when the server supports it (API v2 `key_epoch`). */
function withEpoch<T extends object>(body: T, vault: Vault, features: ReadonlySet<string>): T & { key_epoch?: number } {
  return features.has("key_epoch") && vault.epoch !== undefined ? { ...body, key_epoch: vault.epoch } : body;
}

const isCode = (e: unknown, code: string) => e instanceof ApiError && e.status === 409 && e.code === code;

/** JSON with object keys in a fixed order, so two decryptions of the same item compare equal. */
function stableJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stableJson).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stableJson((v as Record<string, unknown>)[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v) ?? "null";
}

/** Same item content, apart from what re-encrypting may change (the format stamp) and the times a create sets. */
export function sameContent(a: Item, b: Item, ignoreTimes = false): boolean {
  const strip = ({ format: _f, ...rest }: Item) => (ignoreTimes ? { ...rest, created_at: 0, updated_at: 0 } : rest);
  return stableJson(strip(a)) === stableJson(strip(b));
}

/** Sync, and fail if the vault was locked or switched meanwhile (what follows would use another account's keys). */
async function syncFor(gen: number) {
  await sync();
  if (gen !== generation || !account) throw lockedError();
}

/** What item writes answer: the item's new revision and, with delta sync, the vault's number after the write. */
type WriteAnswer = { revision?: unknown; vault_seq?: unknown } | null;

/**
 * After one of this browser's item writes, bring the vault up to date with the least work. Without delta sync: a
 * sync, as before. With it, the answer's `vault_seq` decides (`afterWrite`): a number the copy already has → a sync
 * since brought the write; exactly the next one → the write was the only change, so `own()` (the row as the server
 * stored it) is shown and kept without asking; anything else → a delta sync. A sync that was already asking before
 * the write was answered may not include it, so it is waited for first.
 */
async function settle(vaultId: string | undefined, answer: WriteAnswer, own?: (vaultSeq: number) => OwnWrite | null): Promise<void> {
  const gen = generation;
  const id = currentId;
  const vaultSeq = answer?.vault_seq;
  if (!vaultId || typeof vaultSeq !== "number" || !synced?.cursor) return sync();
  await syncIdle();
  if (gen !== generation || currentId !== id || !synced) return;
  const action = afterWrite(knownSeq(synced, vaultId), vaultSeq, !!own);
  if (action === "none") return;
  if (action === "apply" && own) {
    const write = own(vaultSeq);
    if (write) {
      show(applyOwnWrite(synced, write));
      await persist(id);
      return;
    }
  }
  return sync();
}

/** The row the server stored for an item this browser just sent (`enc`); `base`: its row before (an edit keeps its times and trash state). */
function storedRow(enc: EncryptedItem, answer: WriteAnswer, base: SyncItemRow | undefined): SyncItemRow | null {
  if (typeof answer?.revision !== "number") return null;
  const now = Math.floor(Date.now() / 1000);
  return {
    id: enc.id,
    vault_id: enc.vault_id,
    item_key: enc.key,
    data: enc.data,
    revision: answer.revision,
    deleted_at: base?.deleted_at ?? null,
    created_at: base?.created_at ?? now,
    updated_at: now,
  };
}

/**
 * Add an item. `id`: the caller's own id for this new item, so that trying
 * again after a failure or a timeout re-sends the same item instead of
 * creating a second one (API v2: a create of an existing id with the same
 * content succeeds; older servers say it exists, and then the copy that
 * arrived earlier is used).
 */
export async function createItem(item: Item, vaultId?: string, id?: string): Promise<string> {
  if (id !== undefined && !validItemId(id)) throw new Error("Not allowed.");
  const itemId = id ?? core.newId();
  const gen = generation;
  const owner = currentId;
  // By id: after a sync the vault objects (and keys) are new.
  const target = vaultId ?? personalVault().id;
  const now = Math.floor(Date.now() / 1000);
  const plain: Item = { ...item, created_at: now, updated_at: now };
  const features = (await serverInfo((await local.account(owner)).data?.server ?? ""))?.features ?? new Set<string>();
  for (let attempt = 0; ; attempt++) {
    if (gen !== generation || !account) throw lockedError();
    const vault = vaults.find((v) => v.id === target);
    if (!vault || vault.role === "read") throw new Error(vaultId ? "You can't add items to that vault." : "PassAuth couldn't find your own vault to save to.");
    const enc = vault.key.encryptItem(plain, itemId, vault.id) as EncryptedItem;
    let answer: WriteAnswer;
    try {
      answer = await api<WriteAnswer>("/items", { body: withEpoch(enc, vault, features), accountId: owner });
    } catch (e) {
      if (attempt === 0 && isCode(e, "vault_key_changed")) {
        // A member was removed and the vault has a new key: sync brings it; the item is encrypted again with it, once.
        await syncFor(gen);
        continue;
      }
      // An earlier try reached the server: the sync that found out shows it (brought up to date if it was changed).
      if (isCode(e, "item_exists") && (await arrivedEarlier(itemId, target, plain, gen))) return itemId;
      throw e;
    }
    await settle(target, answer, (vaultSeq) => {
      const row = storedRow(enc, answer, undefined);
      return row && { kind: "upsert", row, vaultSeq };
    });
    return itemId;
  }
}

/**
 * A create was refused because the id exists: an earlier try of this very
 * create (one that timed out) reached the server. Use it, bringing its
 * content up to date if the item was changed before trying again.
 */
async function arrivedEarlier(id: string, vaultId: string, plain: Item, gen: number): Promise<boolean> {
  await syncFor(gen);
  const existing = getEntry(id);
  if (!existing || existing.vaultId !== vaultId) return false;
  if (!sameContent(existing.item, plain, true)) await updateItem(existing, { ...plain, created_at: existing.item.created_at });
  return true;
}

export async function updateItem(entry: Entry, item: Item) {
  const gen = generation;
  const features = (await serverInfo((await local.account(currentId)).data?.server ?? ""))?.features ?? new Set<string>();
  let base = entry;
  for (let attempt = 0; ; attempt++) {
    if (gen !== generation || !account) throw lockedError();
    const vault = vaults.find((v) => v.id === base.vaultId);
    if (!vault) throw new Error("Vault not found.");
    if (vault.role === "read") throw new Error("You can only view items in this vault.");
    const now = Math.floor(Date.now() / 1000);
    const next = { ...item, updated_at: now };
    const old = base.item.login?.password;
    // Compare by content: items from the popup arrive as structured clones, never the same object.
    if (next.login && old && old !== next.login.password && next.password_history[0]?.password !== old) {
      next.password_history = [{ password: old, changed_at: now }, ...next.password_history].slice(0, 20);
    }
    const enc = vault.key.updateItem(base.enc, next) as EncryptedItem;
    let answer: WriteAnswer;
    try {
      answer = await api<WriteAnswer>(`/items/${base.id}`, { method: "PUT", body: withEpoch({ ...enc, revision: base.revision }, vault, features), accountId: currentId });
    } catch (e) {
      if (isCode(e, "revision_conflict")) {
        // Changed on another device: get the latest so the next try starts from it.
        await sync().catch(logged("Syncing after a conflict"));
        throw e;
      }
      if (attempt > 0 || !isCode(e, "vault_key_changed")) throw e;
      // The vault has a new key (a member was removed): sync brings it and the item re-encrypted under it.
      // The same change is then applied to that copy, once, unless the item itself was changed meanwhile.
      await syncFor(gen);
      const fresh = getEntry(base.id);
      if (!fresh || fresh.vaultId !== base.vaultId || !sameContent(fresh.item, base.item)) {
        throw new ApiError(409, "revision_conflict", "This item was changed on another device. PassAuth has the latest version now; check it and try again.");
      }
      base = fresh;
      continue;
    }
    // An edit in place: the row as stored is known (the item keeps its vault, times and trash state).
    const vaultId = base.vaultId;
    await settle(vaultId, answer, (vaultSeq) => {
      const before = synced?.items.get(enc.id);
      const row = before?.vault_id === vaultId ? storedRow(enc, answer, before) : null;
      return row && { kind: "upsert", row, vaultSeq };
    });
    return;
  }
}

export async function trashItem(entry: Entry) {
  if (!canWrite(entry)) throw new Error("You can only view items in this vault.");
  const answer = await api<WriteAnswer>(`/items/${entry.id}`, { method: "DELETE" });
  // Shown as in the trash (which the extension never shows) until the next delta brings the server's own row.
  await settle(entry.vaultId, answer, (vaultSeq) => {
    const before = synced?.items.get(entry.id);
    if (!before || before.vault_id !== entry.vaultId || typeof answer?.revision !== "number") return null;
    const now = Math.floor(Date.now() / 1000);
    return { kind: "upsert", vaultSeq, row: { ...before, deleted_at: now, revision: answer.revision, updated_at: now } };
  });
}

/** Vaults the user can add items to, and folder names in use (for the item editor). */
export function editorInfo(): EditorInfo {
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
    folders: [...new Set(entries.map((e) => e.item.folder).filter((f): f is string => !!f))],
  };
}

export function canWrite(entry: Entry) {
  return vaults.find((v) => v.id === entry.vaultId)?.role !== "read";
}

/** In one of the user's own vaults (key wrapped with their account key), not a vault somebody shared with them. */
export function isPersonal(entry: Entry) {
  return vaults.find((v) => v.id === entry.vaultId)?.kind === "account";
}

/** Weak if it would take few guesses: the web vault's threshold (`WEAK_BITS`, the same in every client). */
export function weakPassword(password: string) {
  // Item data is whatever a vault member saved: only text goes to the core.
  return typeof password === "string" && !!password && core.estimateBits(password) < WEAK_BITS;
}

/** The current code; `expires`: when it changes (ms, see shared/totp.ts). */
export function totp(secret: string, now = Date.now()): TotpCode {
  if (typeof secret !== "string") throw new Error("This verification code key can't be read.");
  const t = core.totpCode(secret, now / 1000) as { code: string; remaining: number; period: number };
  return { ...t, expires: totpExpiry(t.period, now) };
}

export async function generate(mode: "password" | "passphrase", options?: Record<string, unknown>): Promise<string> {
  await initCore();
  return mode === "password" ? core.generatePassword(options) : core.generatePassphrase(options);
}
