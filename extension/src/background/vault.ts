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

import { afterWrite, applyOwnWrite, knownSeq, mergeSync, noticeAction, type OwnWrite, type Snapshot, type SyncNotice, sameCiphertext, vaultKeyChanged } from "@web/lib/delta";
import { approval, type SignInRequest, secretKeyToKeep } from "@web/lib/device-login";
import { WEAK_BITS } from "@web/lib/health";
import type { Bundle, EncryptedItem, Item, LoginFinishResponse, PreloginResponse, Role, SyncItemRow, SyncResponse, SyncVaultRow } from "@web/lib/types";
import { isSyncResponse, kindOf, siteHost } from "@web/lib/types";
import { AppError, codeOf, EXPIRED, FAILED, lockedError, SECRET_KEY_REQUIRED, SIGNED_OUT, TWO_STEP_REQUIRED } from "../shared/errors";
import { log, logged, loggedAs } from "../shared/log";
import { POPUP_VIEW_KEY } from "../shared/storage-keys";
import { totpExpiry } from "../shared/totp";
import type {
  AccountSummary,
  DeviceSignIn,
  EditorInfo,
  ItemSummary,
  LoginResult,
  OtherItem,
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
import { ApiError, api, forgetServerFeatures, iconsShown, logoutRemote, outdatedServer, refreshServerInfo, refuseOutdated, serverConfig, serverInfo, serverOutdated } from "./api";
import { AVATAR_FEATURE, avatarSeqOf, avatars, deleteAvatar, refreshAvatar, showKeptAvatar, uploadAvatar } from "./avatar";
import { initCore } from "./core";
import { type DeviceMemory, mergedDeviceMemory, readDeviceMemory } from "./device-memory";
import { capRevMemory, emptyRevMemory, forgetRev, itemRevOf, noteServed, type RevMemory, readRevMemory, rollbackNotice } from "./item-revs";
import { forgetLastUsed } from "./last-used";
import {
  acceptedEntry,
  acceptsIn,
  acceptVault,
  behindOwn,
  collectLog,
  dueTrash,
  entryOf,
  epochOf,
  ITEM_LOCKED_TITLE,
  ITEM_NEWER_NOTE,
  ITEM_NEWER_TITLE,
  isTrashed,
  MANIFEST_BUSY,
  MANIFEST_BUSY_TEXT,
  MANIFEST_CHANGED_TEXT,
  MANIFEST_FEATURE,
  MANIFEST_HELD,
  MANIFEST_HELD_TEXT,
  MANIFEST_ITEM_WHERE_TEXT,
  MANIFEST_NOT_ACCEPTABLE_TEXT,
  MANIFEST_READER_TEXT,
  MANIFEST_REVIEW_TEXT,
  MANIFEST_TRIES,
  MANIFEST_UNCHECKED_TEXT,
  type ManifestEntry,
  type ManifestItem,
  type ManifestMemory,
  type ManifestNotice,
  type ManifestStatus,
  MEMORY_RESET_ACTION,
  MEMORY_RESET_BODY,
  MEMORY_UNREAD_TRIES,
  MEMORY_UNREADABLE_TEXT,
  type MemoryEntry,
  manifestItem,
  manifestItems,
  manifestNotice,
  manifestPrevOf,
  manifestSeqOf,
  manifestTextOf,
  mayStart,
  mergeManifestMemory,
  notCheckedNotice,
  noteTrash,
  openFailure,
  purgeBatch,
  readServed,
  readStanding,
  rememberedOf,
  rememberManifest,
  rowStampOf,
  type Served,
  type Standing,
  sentEntry,
  stripPrivate,
  type TrashSeen,
  unresolved,
  unsettled,
  validNumbers,
  verifyVault,
  type WarningCause,
  warningOf,
  withManifest,
  writeQuery,
} from "./manifests";
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
import { type AccountData, accountKey, activeId, deviceMemory, earlierVaults, local, memoryUnread, pinCopies, pinsFloor, type SessionData, scratch, session, syncCache, trustMemory } from "./storage";
import { emptyExtras, fromStored, isStale, olderAnswer, type RevisionAnswer, type RowExtras, readExtras, readRevision, STASH_CAP, type StoredSync, toStored, withSignedFields } from "./sync-rules";

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
let decrypted = new Map<string, Copy>();
/**
 * The live rows of open vaults that aren't shown as items, for the list: "newer" = the row decrypts but its content
 * isn't an item this version reads (an item from a newer version of PassAuth: no notice, nothing held); "locked" = it
 * doesn't decrypt (`name`: the item's last known name, from the copy this browser opened before, when it has one).
 */
interface Unopened {
  id: string;
  vaultId: string;
  kind: "newer" | "locked";
  name?: string;
}
let unopened = new Map<string, Unopened>();
/**
 * For each row that holds this browser's kept newer copy (`extras.served`): the row the server sent in its place, as
 * far as an answer of this worker brought it (a whole answer brings every one). "Use the server's copy" puts these
 * rows back (`dropItemMarks`).
 */
let servedRows = new Map<string, SyncItemRow>();
/** Counts every state shown (`commit`: a server's answer adopted, an own write applied): `fetchSync` tells a race by it. */
let shownCount = 0;
/**
 * What this browser remembers for the loaded account to notice a rollback (device-memory.ts), read from its own
 * stored record once per generation (`revGen`) before anything is shown, and written back with every offline copy:
 * `revMem` (item-revs.ts: the highest item edit counters seen and the items marked), `manifestMem` (manifests.ts: per
 * vault the version and link of the last manifest checked "ok" or written here) and `trashSeen` (when each trashed
 * item was first seen in the trash). It outlives the offline copy (a sign-out, a "log out" timeout). `memUnreadable`:
 * the record couldn't be read: nothing is checked against it or written over it, no vault counts as checked, and the
 * next sync tries again. `memPlace`: where the record lives (server address + the account id the core authenticated).
 */
let revMem = emptyRevMemory();
let revGen = -1;
let manifestMem: ManifestMemory = new Map();
let trashSeen: TrashSeen = new Map();
let memUnreadable = false;
let memPlace: { server: string; userId: string } | null = null;
/**
 * While the record can't be read: where it lives, and how often in a row it failed to read with whether a whole sync
 * was done meanwhile (storage.ts `memoryUnread`, counted across worker starts). After `MEMORY_UNREAD_TRIES` failures
 * and a whole sync the popup offers "Reset on this device" (`resetDeviceMemory`).
 */
let unreadPlace: { server: string; userId: string } | null = null;
let unread: { fails: number; full: boolean } | null = null;
/**
 * What belongs to the rows of `synced` without being on them (sync-rules.ts `RowExtras`, kept in the offline copy
 * beside the rows, read from it once per generation: `extrasGen`): the hashes of what the server sent for rows that
 * hold this browser's kept newer copy, and openable rows the server stopped listing without proof.
 */
let extras: RowExtras = emptyExtras();
let extrasGen = -1;
/**
 * Vault manifests (manifests.ts). `manifestStates`: each open vault's state for the snapshot shown: the core's
 * verdict on the server's answer that brought it ("ok", "none", and after a full answer "rollback" / "mismatch": the
 * vault stays readable, shows the warning and takes no writes), or "unchecked" (nothing a server sent as one answer
 * was checked for it yet: no warning, writes wait for the sync). `upkeepTried`: the one try per vault state at
 * starting a manifest or deleting old trash. `fullNext`: the next sync asks for everything (a vault is unchecked).
 */
let manifestStates = new Map<string, ManifestStatus>();
const upkeepTried = new Map<string, string>();
let fullNext = false;
/**
 * The vaults that show their warning, each with its cause and the vault row it was judged on (manifests.ts
 * `Standing`): always from a server's whole answer, kept with the offline copy. While a vault's row stays the one its
 * warning was judged on, a delta doesn't ask for everything again, and a worker start shows the warning without a
 * whole fetch. `unopenableVaults`: the open vaults holding a row (live, or trashed with its data) that doesn't decrypt
 * and for which this browser has no copy of its own to go on with: they show the item notice, start no first manifest,
 * and take writes like any other vault.
 * `trashOpens`: whether each trashed row that came with its data opened, so it isn't opened again at every sync.
 * `fullAnswers`: counts the whole answers shown ("Use the server's copy" needs a fresh one).
 */
let standing = new Map<string, Standing>();
let unopenableVaults = new Set<string>();
let trashOpens = new Map<string, { row: SyncItemRow; opens: boolean }>();
let fullAnswers = 0;
/**
 * Vaults whose last answer couldn't be checked because their manifest log couldn't be fetched: the answer wasn't used,
 * the vault keeps its previous copy and state, and nothing is written into it until a sync got through (else a
 * server could keep this browser writing on an old state by failing that one request).
 */
const logPending = new Set<string>();
/**
 * Signed sharing for the loaded account (signed-sharing.ts): checks run (`sharingOn`) on servers with `signed_sharing`
 * and for accounts this browser has seen anything signed for. `verdicts`: each vault row's last check, which
 * `prepare` follows (a vault without a verdict for its current row, or a refused one, is never opened).
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
  const pictures = await avatars.many(Object.keys(l.accounts));
  for (const [id, a] of Object.entries(l.accounts)) {
    if (!a.server || !a.email) continue;
    const st = id === l.activeId ? status : await statusOf(a, id, never);
    // A picture only for an unlocked account: a locked one shows its initials.
    const avatar = st === "unlocked" ? pictures[id] : undefined;
    accounts.push({ id, email: a.email, name: a.name, server: a.server, status: st, ...(avatar ? { avatar } : {}) });
  }
  const avatar = status === "unlocked" ? pictures[l.activeId] : undefined;
  return {
    status,
    activeId: l.activeId,
    accounts,
    name: l.name,
    ...(avatar ? { avatar } : {}),
    ...(status === "unlocked" && (await serverInfo(l.server))?.features.has(AVATAR_FEATURE) ? { avatarEditable: true } : {}),
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
  // A server from before signed sharing (or one that doesn't list it) is refused before any sign-in (asked again: an upgraded server passes).
  await refuseOutdated(origin);
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

// ---------------------------------------------------------- profile picture

/** After a sync of `id`: fetch and open its profile picture when the server's number changed (in the background; a failure only leaves the old one). */
function syncAvatar(id: string, user: unknown) {
  const acct = account;
  const gen = generation;
  if (!acct || currentId !== id) return;
  const stale = () => gen !== generation || currentId !== id || account !== acct;
  void refreshAvatar(id, avatarSeqOf(user), (sealed) => acct.openAvatar(sealed), stale).catch(logged("Fetching the profile picture"));
}

/** At unlock, before the popup asks for its state: the profile picture of `id` from its sealed copy on disk (no network; a failure only leaves the initials). */
async function showAvatar(id: string) {
  const acct = account;
  const gen = generation;
  if (!acct || currentId !== id) return;
  const stale = () => gen !== generation || currentId !== id || account !== acct;
  await showKeptAvatar(id, (sealed) => acct.openAvatar(sealed), stale).catch(logged("Opening the profile picture"));
}

/** Set the active account's profile picture (a JPEG the popup made, ≤ 256 KiB): sealed with the Account Key here, then uploaded. */
export async function setAvatar(jpeg: Uint8Array) {
  if (!account || !currentId) throw lockedError();
  const acct = account;
  const id = currentId;
  const gen = generation;
  await uploadAvatar(
    id,
    jpeg,
    (image) => acct.sealAvatar(image),
    () => gen !== generation || currentId !== id || account !== acct,
  );
}

/** Remove the active account's profile picture. */
export async function removeAvatar() {
  if (!account || !currentId) throw lockedError();
  await deleteAvatar(currentId);
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
    await showAvatar(id);
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
      await loadMemory(id, { copy });
      if (gen !== generation || currentId !== id || loaded) return;
      const prepared = prepare(snap, null);
      if (!prepared) return;
      // The copy against its vaults' manifests, now that the keys are here. A copy that doesn't check out (or holds
      // rows from before the server sent their hashes) is still this browser's own copy and is shown, but it is no
      // server's answer: no warning comes from it. One full sync decides (`syncNow`), and writes wait for it.
      // A warning the copy was stored with (from a whole answer, for the vault row it still holds) stands as it was.
      const judged = judgeCached(prepared, readStanding(copy?.warnings));
      commit(prepared, judged.statuses, null, judged.standing);
      syncAvatar(id, snap.user);
      // Not while the memory can't be read and a whole sync already found that out: it would find the same again
      // at every worker start (the way out is the reset the popup offers).
      if (judged.unchecked && !(memUnreadable && unread?.full)) {
        fullNext = true;
        void sync().catch(logged("Syncing"));
      } else void refreshIfStale().catch(logged("Checking for changes"));
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
  await avatars.remove([id]);
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
  unopened = new Map();
  servedRows = new Map();
  revMem = emptyRevMemory();
  revGen = -1;
  manifestMem = new Map();
  trashSeen = new Map();
  memUnreadable = false;
  memPlace = null;
  unreadPlace = null;
  unread = null;
  standing = new Map();
  unopenableVaults = new Set();
  trashOpens = new Map();
  extras = emptyExtras();
  extrasGen = -1;
  manifestStates = new Map();
  upkeepTried.clear();
  fullNext = false;
  logPending.clear();
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

/**
 * Vault timeout with the "sign out" action: sign every account out (they stay listed) and forget their offline copies.
 * What this browser remembers to notice a rollback (storage.ts `deviceMemory`) stays: it goes only with the account.
 */
export async function logoutAll() {
  const { accounts } = await local.get();
  await lockAll();
  await pinCopies.remove(Object.keys(accounts));
  await forgetPolicyState(Object.keys(accounts));
  for (const [id, a] of Object.entries(accounts)) {
    await syncCache.clear(id);
    await forgetLastUsed(id);
    await avatars.remove([id]);
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

/** How often an answer that is behind one of this browser's own writes is asked for again before it is used as it is. */
const BEHIND_RETRIES = 2;

async function syncNow() {
  if (!account) return;
  const id = currentId;
  const gen = generation;
  // Locked, signed out or switched meanwhile: the answer is dropped.
  const stale = () => gen !== generation || !account || currentId !== id;
  const delta = await deltaFor(id);
  if (stale()) return;
  // Older servers get the whole vault every time, as before; a copy without a cursor gets it once; so does an
  // unchecked vault (`fullNext`).
  let everything = fullNext || !delta;
  let behind = 0;
  // Bounded: a delta that can't be used, an answer that needs the whole vault to be judged, and the retries of an
  // answer that is behind each turn `everything` on, and none of them repeats after that.
  for (let round = 0; round < 3 + BEHIND_RETRIES; round++) {
    const got = await fetchSync(id, delta, everything ? null : synced, stale);
    // A delta this browser can't use (malformed, or about data it doesn't have): everything, once.
    if (got === "full") {
      everything = true;
      continue;
    }
    if (!got || stale()) return;
    if (got.behind && behind < BEHIND_RETRIES) {
      // The answer is older than an own write already shown (it was read before that write, or the server went
      // back): it is not used. Everything is asked for again; an answer that stays behind is then judged like any
      // other, so a vault with a manifest reports the rollback.
      behind++;
      everything = true;
      continue;
    }
    const result = await accept(got.snapshot, id, got.full, got.arrived);
    // The answer can't be judged as a delta (rows from before the server sent their hashes, or a vault that
    // wouldn't check out): nothing of it is used; the whole vault decides, once.
    if (result === "full" && !got.full) {
      everything = true;
      continue;
    }
    if (result !== "done" || stale()) return;
    if (got.full) fullNext = false;
    await noteTwoStepDone(id);
    if (await manifestUpkeep(id, got.served, stale).catch(loggedAs(false, "Vault manifest upkeep"))) void sync().catch(logged("Syncing again"));
    return;
  }
}

/**
 * A merged answer: the candidate snapshot (nothing of it is shown or kept before `accept` checked it), whether it is
 * behind an own write shown, whether it is a whole answer (not a delta merged into the copy), which rows came from
 * the server with it, and the server's clock and trash setting it came with (vault manifests: old trash).
 */
interface Fetched {
  snapshot: Snapshot;
  behind: boolean;
  full: boolean;
  arrived: ReadonlySet<string> | "all";
  served: Served;
}

/**
 * One `GET /sync`: with `base`'s cursor only what changed since (`trash=summary`), merged into `base`. Null when the
 * answer is dropped (locked or switched meanwhile, or older than something shown since the request was sent); "full"
 * when a delta can't be used (also a delta from a server whose revision went back: the whole account decides).
 * Rows are taken as the server's and nothing more: a number that isn't one makes the answer invalid (`validNumbers`),
 * and device-private fields a server put on a row are deleted before anything is merged (`stripPrivate`).
 */
async function fetchSync(id: string, delta: boolean, base: Snapshot | null, stale: () => boolean): Promise<Fetched | "full" | null> {
  const since = base?.cursor ?? null;
  const path = !delta ? "/sync" : since ? `/sync?since=${encodeURIComponent(since)}&trash=summary` : "/sync?trash=summary";
  const shownBefore = shownCount;
  const data = await api<unknown>(path, { accountId: id });
  if (stale()) return null;
  if (!isSyncResponse(data) || !validNumbers(data)) {
    if (since) return "full";
    throw new AppError(FAILED, UNEXPECTED_SYNC);
  }
  if (loaded && data.revision < revision) {
    // An answer older than what is shown. A race when something else was shown since this request was sent (another
    // answer adopted, an own write applied): dropped. Otherwise the server itself went back (restored from a backup,
    // or worse): never ignored. One whole answer is judged like any other, so the vaults' records report it and "Use
    // the server's copy" works.
    const older = olderAnswer(shownCount !== shownBefore, !!since && data.delta === true);
    if (older === "drop") return null;
    if (older === "full") return "full";
  }
  stripPrivate(data.items);
  let snapshot: Snapshot | null = null;
  try {
    snapshot = mergeSync(since ? base : null, data)?.snapshot ?? null;
  } catch (e) {
    log.debug("A sync answer couldn't be used:", e);
  }
  if (!snapshot) {
    if (since) return "full";
    throw new AppError(FAILED, UNEXPECTED_SYNC);
  }
  const full = !(since && data.delta === true);
  return {
    snapshot: withSignedInvitations(snapshot, data),
    behind: behindOwn(synced?.own ?? {}, snapshot.vaults),
    full,
    arrived: full ? "all" : new Set(data.items.map((r) => r.id)),
    served: readServed(data),
  };
}

/** `snap` with its invitations' signed-sharing fields from the answer `data` (`readInvitations` drops them). */
function withSignedInvitations(snap: Snapshot, data: SyncResponse): Snapshot {
  return { ...snap, invitations: withSignedFields(snap.invitations, data.invitations) };
}

/**
 * A candidate snapshot for the loaded account: its owner checked, its shared vaults checked, opened and judged
 * against its vaults' manifests (`judge`), and only then shown, kept as the offline copy, and the time noted. Nothing
 * of an answer that wasn't judged is ever shown or stored: the previous copy stays, with its states.
 * `full`: the snapshot is one whole answer; `arrived`: the rows the server sent with it.
 * Resolves to "done"; to "full" when a delta can't be judged (then nothing was used and the caller fetches
 * everything); to "stale" when the answer was dropped (locked, switched, or something else was shown meanwhile).
 * Rejects when a vault's manifest log was needed and couldn't be fetched: the sync has failed, nothing changed.
 */
async function accept(snap: Snapshot, id: string, full: boolean, arrived: ReadonlySet<string> | "all"): Promise<"done" | "full" | "stale"> {
  const gen = generation;
  const before = synced;
  const stale = () => gen !== generation || currentId !== id || !account || synced !== before;
  if (account && !ownSnapshot(account, snap)) {
    // Review H1: an answer for another account than the one the core authenticated is never shown or kept.
    log.warn("The server sent a sync answer for another account; it isn't used.");
    throw new AppError(FAILED, WRONG_ACCOUNT_TEXT);
  }
  await checkSharing(snap, id, "sync");
  if (stale()) return "stale";
  await loadMemory(id);
  if (stale()) return "stale";
  const prepared = prepare(snap, arrived);
  if (!prepared) return "stale";
  let judged: Judged | "full" | null;
  try {
    judged = await judge(prepared, id, full, stale);
  } catch (e) {
    discard(prepared);
    throw e;
  }
  if (!judged || judged === "full" || stale()) {
    discard(prepared);
    return judged === "full" ? "full" : "stale";
  }
  for (const r of judged.remember) rememberManifest(manifestMem, r.vaultId, r.version, r.link);
  logPending.clear();
  commit(prepared, judged.statuses, before, judged.standing);
  if (full) {
    fullAnswers++;
    // A whole sync got through while the memory can't be read: with three failed reads, the reset is offered.
    const place = unreadPlace;
    if (memUnreadable && place && !unread?.full) {
      // (Kept in this worker when the count can't be stored: else every sync would ask for everything.)
      const count = await memoryUnread.update(place.server, place.userId, (c) => ({ fails: c.fails, full: true })).catch(() => null);
      if (gen === generation && memUnreadable) unread = count ?? { fails: unread?.fails ?? 0, full: true };
    }
  }
  await persist(id);
  await local.set({ lastSync: Date.now(), name: typeof snap.user?.name === "string" ? snap.user.name : "" }, id);
  syncAvatar(id, snap.user);
  if (sharingResync) {
    sharingResync = false;
    void sync().catch(logged("Syncing again"));
  }
  return "done";
}

/** A whole vault fetched while unlocking (no offline copy, or a newer account bundle). */
async function acceptFull(data: SyncResponse, id: string) {
  if (!validNumbers(data)) throw new AppError(FAILED, UNEXPECTED_SYNC);
  stripPrivate(data.items);
  const merged = mergeSync(null, data);
  if (!merged || !account || currentId !== id) return;
  await showAvatar(id);
  if (!account || currentId !== id) return;
  await accept(withSignedInvitations(merged.snapshot, data), id, true, "all");
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
 * `prepare`. `mode` "sync": after an answer from the server (every row checked, the identity made if missing, the
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
    // A sync answer is always checked: a server that doesn't sign is refused before it is asked (api.ts
    // `serverOutdated`), and one whose features can't be read gets no benefit of the doubt (it could leave out the
    // key epochs to pass for an old server on a new browser). Only an offline copy written with the checks off, before
    // this version (no verdicts in it), is still read as it was stored.
    // A copy this version (or any with signed sharing) wrote with the checks on carries its verdicts (`stored`): they
    // keep deciding which vaults open, also while the server is one this app refuses.
    const on = mode === "sync" || stored !== undefined || !!features?.has("signed_sharing") || remembered || signedData || unknownOn;
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
          key = acct.openVaultKey(row.id, row.wrapped_key, row.key_kind, epoch, core.pinsLegacyWrapAllowed(pins, row.id, epoch));
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
        key = acct.openVaultKey(row.id, row.wrapped_key, row.key_kind, epoch, core.pinsLegacyWrapAllowed(pins, row.id, epoch));
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

/**
 * Show a snapshot this browser made itself from the one shown: an own write the server stored exactly as sent
 * (`settle`). `rewritten`: the items whose ciphertext the write replaced. The vaults' states stay: this browser made
 * that manifest, and nothing a server sent is in it.
 */
function showOwn(next: Snapshot, rewritten: ReadonlySet<string> | null) {
  const prepared = prepare(next, rewritten);
  if (prepared) commit(prepared, new Map(manifestStates), null);
}

let storing: Promise<void> = Promise.resolve();

/**
 * Keep the loaded account's snapshot as its offline copy: one IndexedDB record, so the cursor and the vault numbers
 * are never kept without the rows they describe, and a write that doesn't happen (the worker stopped) leaves the
 * previous copy whole. Writes run one after another and each takes the newest snapshot; none after a lock,
 * sign-out or switch. What this browser remembers (`deviceMemory`) is written first, in its own record: read, merged
 * and written in one step, only once it was read for this generation, and never over a record that can't be read.
 * First, so that nothing seen is ever lost: if the worker stops between the two writes, the memory is ahead of the
 * copy, which the next unlock finds ("unchecked": one full sync, no warning), never the other way round with
 * something forgotten.
 */
function persist(id: string): Promise<void> {
  const gen = generation;
  const current = () => gen === generation && currentId === id && !!synced;
  const p = storing.then(async () => {
    if (!current()) return;
    const place = memPlace;
    if (revGen === gen && !memUnreadable && place) {
      const mine: DeviceMemory = { revs: revMem, manifests: manifestMem, trashSeen };
      try {
        const stored = readDeviceMemory(await deviceMemory.update(place.server, place.userId, (old) => mergedDeviceMemory(old, mine)));
        // What was stored higher than this worker knew (nothing is ever lowered) is what it checks against from now on.
        if (stored !== "missing" && stored !== "unreadable" && current()) manifestMem = mergeManifestMemory(stored.manifests, manifestMem);
      } catch (e) {
        log.warn("Storing what this browser remembers about the vault's versions failed:", e);
      }
    }
    // Checked again and queued in the same step: a sign-out's removal of the copy, queued after it, always runs after it.
    if (!current() || !synced) return;
    const copy = toStored(synced, extras, standing);
    await syncCache.set(id, sharingOn ? { ...copy, trust: Object.fromEntries(verdicts) } : { ...copy, checks: "off" });
  });
  storing = p.catch(() => {});
  return p;
}

/**
 * Read what this browser remembers for the loaded account, once per generation, before anything is shown: the row
 * extras of its offline copy (`read`: the copy the caller already read) and its device memory. A copy for another
 * account gives none. No device memory yet (a browser from before it): the item edit counters an older offline copy
 * kept are taken over; manifest versions kept in the first format (a bare number) are nothing remembered. A record
 * that can't be read is never "nothing remembered": `memUnreadable`, and the next sync tries again.
 */
async function loadMemory(id: string, read?: { copy: StoredSync | undefined }): Promise<void> {
  if (revGen === generation) return;
  const gen = generation;
  const acct = account;
  if (!acct) return;
  const fresh = () => gen === generation && revGen !== gen && currentId === id && account === acct;
  const copy = read ? read.copy : await syncCache.get(id);
  if (!fresh()) return;
  const mine = !!copy && copy.user?.id === meOf(acct);
  if (extrasGen !== gen) {
    extras = mine ? readExtras(copy) : emptyExtras();
    extrasGen = gen;
  }
  const server = (await local.account(id)).data?.server ?? "";
  const userId = meOf(acct);
  let state: ReturnType<typeof readDeviceMemory>;
  try {
    state = readDeviceMemory(await deviceMemory.read(server, userId));
  } catch (e) {
    log.warn("Reading what this browser remembers about the vault's versions failed:", e);
    state = "unreadable";
  }
  if (!fresh()) return;
  if (state === "unreadable") {
    memUnreadable = true;
    unreadPlace = { server, userId };
    // Counted across worker starts; until a whole sync got through in this state, the next sync asks for everything.
    const count = await memoryUnread.update(server, userId, (c) => ({ fails: c.fails + 1, full: c.full })).catch(() => null);
    if (!fresh()) return;
    unread = count ?? { fails: (unread?.fails ?? 0) + 1, full: unread?.full ?? false };
    if (!unread.full) fullNext = true;
    return;
  }
  memUnreadable = false;
  unreadPlace = null;
  unread = null;
  void memoryUnread.update(server, userId, () => null).catch(logged("Forgetting the unreadable-memory count"));
  if (state === "missing") {
    revMem = mine ? readRevMemory(copy) : emptyRevMemory();
    manifestMem = new Map();
    trashSeen = new Map();
  } else {
    revMem = state.revs;
    manifestMem = state.manifests;
    trashSeen = state.trashSeen;
  }
  // "Kept" says this browser shows its own newer copy. Without the copy's row (the offline copy went at a sign-out or
  // a "log out" timeout) there is none any more: the item stays marked, as one the server sent in an older version.
  const rows = new Set(mine && Array.isArray(copy?.items) ? copy.items.map((r) => r?.id) : []);
  for (const [itemId, how] of revMem.rolledBack) if (how === "kept" && !rows.has(itemId)) revMem.rolledBack.set(itemId, "older");
  memPlace = { server, userId };
  revGen = gen;
}

/** Whether the server sent an older version of item `id` than this browser had seen (item-revs.ts). */
export const rolledBack = (id: string): boolean => revMem.rolledBack.has(id);

/** The vault-wide notice about items a server sent in an older version, or null. */
export function rollbackSummary(): { text: string; key: string } | null {
  return rollbackNotice(revMem, new Set(entries.map((e) => e.id)));
}

// ----------------------------------------------------------- vault manifests

/** The loaded snapshot's row of a vault. */
const rowOf = (vaultId: string): SyncVaultRow | undefined => synced?.vaults.find((v) => v.id === vaultId);

/** The link of the row's manifest (`manifestLink`), or null when the row has none or its fields aren't one. */
function linkOf(row: SyncVaultRow): string | null {
  const seq = manifestSeqOf(row);
  const prev = manifestPrevOf(row);
  const sealed = manifestTextOf(row);
  if (seq === 0 || !prev || !sealed) return null;
  try {
    return core.manifestLink(seq, prev, sealed);
  } catch {
    return null;
  }
}

/** One page of a vault's manifest log; null for a 404 or 400 (an answer: there is no log for this browser). Rejects when there is no answer. */
async function fetchLogPage(id: string, vaultId: string, after: number): Promise<unknown> {
  try {
    return await api<unknown>(`/vaults/${encodeURIComponent(vaultId)}/manifest-log?after=${after}`, { accountId: id });
  } catch (e) {
    if (e instanceof ApiError && (e.status === 404 || e.status === 400)) return null;
    throw e;
  }
}

/** What `judge` decided for a candidate: each open vault's state, and what to remember for the vaults that are "ok". */
interface Judged {
  statuses: Map<string, ManifestStatus>;
  remember: { vaultId: string; version: number; link: string }[];
  /** The vaults that show their warning, with cause and the row judged. */
  standing: Map<string, Standing>;
}

/**
 * Judge a candidate (a server's answer applied to the copy, opened by `prepare`, not shown yet): the core's verdict
 * on every open vault's row, what this browser remembers of the vault (version and link) and every row of the vault.
 * - "need_log": the manifest is more than one step ahead of the remembered one. The vault's manifest log is fetched
 *   and the core decides again with it. A log that can't be fetched rejects: the answer isn't checked, so it isn't
 *   used (a server must not get its answer shown by failing one request). A 404 or 400, or a log that doesn't lead
 *   back to the remembered manifest, is a mismatch.
 * - an item that doesn't open changes no verdict (final review T1: holding the vault for it only pushed its members to
 *   delete an item a server may have made unreadable on purpose). `prepare` keeps this browser's own copy of the row
 *   when only the served item key fails; what remains is listed as "Item that can't be opened" and the vault shows
 *   its notice (`unopenableVaults`), with every write still possible.
 * - a delta that would give "rollback" / "mismatch", or whose rows are "incomplete" (kept before the server sent
 *   their hashes): "full". Nothing is used and no warning is raised from a delta merged into this browser's own copy;
 *   the caller fetches everything, and that answer decides (`full`: then "incomplete" counts as a mismatch too).
 * - except for a vault that already shows its warning (`standing`: raised by a whole answer): it keeps it without
 *   everything being fetched again at every sync, as in the web vault. The delta is still judged, so the warning
 *   goes by itself when an answer checks out (another device's new record on this browser's history); what a whole
 *   fetch would find otherwise is found by "Use the server's copy", which starts with one.
 * - a "rollback" / "mismatch" also asks the core whether the served copy checks out on its own (`acceptVault`): that
 *   decides what the popup offers ("accept" / "forget": "Use the server's copy", for every role, with the
 *   confirmation that fits; "review": elsewhere).
 * - what this browser remembers can't be read: nothing is checked against it. A vault that fails on its own rows is
 *   still a mismatch; one that would pass is "unchecked", never "ok", and nothing is remembered.
 * The verdict rests on the rows alone, not on the server's feature list: a vault whose manifest this browser has seen
 * stays checked on a server that stops listing the feature ("rollback"). Null: dropped (`stale`).
 */
async function judge(p: Prepared, id: string, full: boolean, stale: () => boolean): Promise<Judged | "full" | null> {
  const items = manifestItems(p.snap, p.extras.served);
  const rows = new Map(p.snap.vaults.map((v) => [v.id, v]));
  const readable = p.checkRevs;
  const out: Judged = { statuses: new Map(), remember: [], standing: new Map() };
  for (const vault of p.vaults) {
    const row = rows.get(vault.id);
    if (!row) continue;
    // The vault shows its warning already: no whole fetch to find it again.
    const warned = standing.has(vault.id) && unresolved(manifestStates.get(vault.id));
    const mine = readable ? rememberedOf(manifestMem, vault.id) : undefined;
    const held = items.get(vault.id) ?? [];
    let check = verifyVault(vault.key, row, mine, held);
    if (check.status === "need_log") {
      let log: unknown[] | null = null;
      try {
        if (mine) log = await collectLog(mine.version, (after) => fetchLogPage(id, vault.id, after));
      } catch (e) {
        // No answer: the vault's history can't be checked now. Not a warning; the sync has failed.
        logPending.add(vault.id);
        throw e;
      }
      if (stale()) return null;
      check = verifyVault(vault.key, row, mine, held, log ?? []);
    }
    let status: ManifestStatus = check.status === "need_log" ? "mismatch" : check.status;
    if (status === "incomplete") {
      if (!full && !warned) return "full";
      status = "mismatch";
    }
    if (unresolved(status) && !full && !warned) return "full";
    if (status === "rollback" || status === "mismatch") {
      const a = acceptVault(vault.key, row, held).status;
      const cause: WarningCause = a === "no" ? "review" : a === "none" ? "forget" : "accept";
      out.standing.set(vault.id, { status, cause, stamp: rowStampOf(row) });
    }
    if (status === "ok") {
      if (!readable) status = "unchecked";
      else if (check.link) out.remember.push({ vaultId: vault.id, version: check.version, link: check.link });
    }
    out.statuses.set(vault.id, status);
  }
  return out;
}

/**
 * The offline copy at unlock, judged without the network. It is this browser's own copy, so it is shown whatever
 * comes out; but only "ok" and "none" are states: a copy that doesn't check out (its row is behind or ahead of what
 * is remembered, rows from before the server sent hashes, memory that can't be read) is
 * "unchecked". No warning is raised from bookkeeping: the caller syncs in full, and that answer decides.
 * One exception, which is no bookkeeping: a warning the copy was stored with (`stored`: raised by a server's whole
 * answer, for the very vault row the copy holds) stands as it was, so a worker start doesn't fetch everything again
 * to find the same verdict. Only warnings are taken from the copy, never an "ok".
 */
function judgeCached(p: Prepared, stored: ReadonlyMap<string, Standing>): { statuses: Map<string, ManifestStatus>; standing: Map<string, Standing>; unchecked: boolean } {
  const items = manifestItems(p.snap, p.extras.served);
  const rows = new Map(p.snap.vaults.map((v) => [v.id, v]));
  const statuses = new Map<string, ManifestStatus>();
  const kept = new Map<string, Standing>();
  let unchecked = false;
  for (const vault of p.vaults) {
    const row = rows.get(vault.id);
    if (!row) continue;
    const check = verifyVault(vault.key, row, p.checkRevs ? rememberedOf(manifestMem, vault.id) : undefined, items.get(vault.id) ?? []);
    const was = stored.get(vault.id);
    let status: ManifestStatus = "unchecked";
    if (check.status === "none") status = "none";
    else if (check.status === "ok" && p.checkRevs) {
      status = "ok";
      rememberManifest(manifestMem, vault.id, check.version, check.link);
    } else if (was && was.stamp === rowStampOf(row)) {
      status = was.status;
      kept.set(vault.id, was);
    }
    if (status === "unchecked") unchecked = true;
    statuses.set(vault.id, status);
  }
  return { statuses, standing: kept, unchecked };
}

/** The popup's warning about vaults that don't match their manifest, or null. */
export function manifestSummary(): ManifestNotice | null {
  return manifestNotice(vaults, manifestStates, standing, unopenableVaults);
}

/** The quiet note about vaults that aren't checked since "no record" was accepted for them, or null. */
export function notCheckedSummary(): { text: string; vaults: { id: string; name: string }[]; key: string } | null {
  return memUnreadable || revGen !== generation ? null : notCheckedNotice(vaults, manifestStates, manifestMem);
}

/**
 * The live rows that aren't shown as items, for the end of the list: an item from a newer version of PassAuth (with
 * "Update PassAuth to see this item."; for an owner or admin of its vault also where it can be deleted for good), and
 * an item that can't be opened (with its last known name, when this browser has one). Nothing can be done with them
 * here.
 */
export function otherItems(): OtherItem[] {
  return [...unopened.values()].map((u) => ({
    id: u.id,
    title: u.kind === "newer" ? ITEM_NEWER_TITLE : ITEM_LOCKED_TITLE,
    ...(u.kind === "newer" ? { note: ITEM_NEWER_NOTE } : u.name ? { name: u.name } : {}),
    // An owner or admin can delete an item from a newer version for good, though not from here: the row says where.
    ...(u.kind === "newer" && canRemoveNewer(u.vaultId) ? { hint: MANIFEST_ITEM_WHERE_TEXT } : {}),
    vaultName: vaultName(u.vaultId),
  }));
}

/** Whether this account is an owner or admin of the vault (who can delete an item from a newer version, in the web vault or the desktop app). */
function canRemoveNewer(vaultId: string): boolean {
  const role = vaults.find((v) => v.id === vaultId)?.role;
  return role === "owner" || role === "admin";
}

/** Whether the vault shows the manifest warning (its item pages say so too). */
export const manifestWarned = (vaultId: string): boolean => unresolved(manifestStates.get(vaultId));

/** The vault's warning as one line for an item page (what is wrong, and where it is resolved when not in the list's notice), or null. */
export function manifestWarning(vaultId: string): string | null {
  if (!manifestWarned(vaultId)) return null;
  const w = warningOf(standing.get(vaultId)?.cause, vaults.find((v) => v.id === vaultId)?.role !== "read");
  return w.hint ? `${w.text} ${w.hint}` : w.text;
}

/** Resolves once no sync is running or queued behind one. */
async function syncsDone() {
  while (syncing) await syncing.catch(() => {});
}

/**
 * "Use the server's copy" for one vault that shows its warning (the popup, after its confirmation; every role).
 * `forget`: which confirmation the user gave (true: the one that says the server shows no record and checking stops).
 * 1. everything is fetched afresh and checked as always. The vault is fine now (another device wrote a new record on
 *    this browser's history, or the cause went away): done.
 * 2. the core says whether the served copy checks out on its own, nothing remembered taken into account
 *    (`manifestAccept`). If the served manifest describes the served rows, this browser's memory of the vault is
 *    REPLACED by that manifest's version and link, also when it remembered a higher version (that is the point: the
 *    user accepts what is missing, restored or out of date). If the server shows no manifest, the memory is forgotten
 *    and the entry marked "not checked" (the popup's quiet note, until the vault has a record again).
 *    Nothing is sent: accepting changes nothing for anyone else.
 * 3. otherwise nothing may be remembered: only a new record written by someone with write access (in the web vault
 *    or the desktop app; the extension writes none) can resolve it, and this fails saying so.
 * What the fresh answer needs must be what the user confirmed: a server that showed a record and then serves none (or
 * the other way round) gets nothing accepted; the popup shows the vault as it is now, to be confirmed again.
 * The acceptance is counted in the entry (`accepts`), so no older copy of the memory can bring the earlier version
 * back (manifests.ts `mergeManifestMemory`). With it go the vault's item marks (`dropItemMarks`): the user accepted
 * "anything that is missing, restored or out of date". A vault that holds an item that can't be opened keeps that
 * notice (it never held a write).
 * If the copy shown changed while the memory was being stored (a sync took another answer over), that answer was
 * judged against the accepted memory already: its states are left alone, and one more sync decides.
 */
export async function acceptServerCopy(vaultId: string, forget = false): Promise<void> {
  const gen = generation;
  const id = currentId;
  if (!account || !id) throw lockedError();
  await syncsDone();
  if (gen !== generation) throw lockedError();
  if (!unresolved(manifestStates.get(vaultId))) return;
  if (memUnreadable) throw new AppError(FAILED, MEMORY_UNREADABLE_TEXT, true);
  // The vault's items as this browser holds them before the fetch (not ids a later answer places there): their marks
  // go with the acceptance.
  const priorIds = new Set<string>();
  for (const r of synced?.items.values() ?? []) if (r.vault_id === vaultId) priorIds.add(r.id);
  for (const r of extras.stash.values()) if (r.vault_id === vaultId) priorIds.add(r.id);
  const answersBefore = fullAnswers;
  fullNext = true;
  await syncFor(gen);
  await syncsDone();
  if (gen !== generation || currentId !== id) throw lockedError();
  // The answer was dropped (something newer was shown meanwhile, or nothing came): nothing is accepted unseen.
  if (fullAnswers === answersBefore) throw new AppError(FAILED, MANIFEST_UNCHECKED_TEXT, true);
  if (!unresolved(manifestStates.get(vaultId))) return;
  const vault = vaults.find((v) => v.id === vaultId);
  const row = rowOf(vaultId);
  const place = memPlace;
  const judgedCopy = synced;
  if (!vault || !row || !judgedCopy) throw new AppError(FAILED, MANIFEST_UNCHECKED_TEXT, true);
  if (memUnreadable || !place || revGen !== generation) throw new AppError(FAILED, MEMORY_UNREADABLE_TEXT, true);
  const a = acceptVault(vault.key, row, manifestItems(judgedCopy, extras.served).get(vaultId) ?? []);
  if (a.status === "no") throw new AppError(FAILED, `${MANIFEST_NOT_ACCEPTABLE_TEXT} ${vault.role === "read" ? MANIFEST_READER_TEXT : MANIFEST_REVIEW_TEXT}`, true);
  // Not what was confirmed (the popup now shows the vault as this answer has it).
  if ((a.status === "none") !== forget) throw new AppError(FAILED, MANIFEST_CHANGED_TEXT, true);
  const accepted = a.status === "ok" ? { version: a.version, link: a.link } : null;
  // In this worker first (no sync that starts from here on checks against the old memory), then the stored record,
  // read and written in one step with the acceptance counted above whatever is stored.
  const prior = manifestMem.get(vaultId);
  let entry: MemoryEntry = acceptedEntry(accepted, acceptsIn(manifestMem, vaultId));
  manifestMem.set(vaultId, entry);
  try {
    await deviceMemory.update(place.server, place.userId, (old) => {
      const read = readDeviceMemory(old);
      if (read === "unreadable") throw new AppError(FAILED, MEMORY_UNREADABLE_TEXT, true);
      if (gen !== generation) throw lockedError();
      const there = read === "missing" ? 0 : acceptsIn(read.manifests, vaultId);
      if (there >= (entry.accepts ?? 0)) {
        entry = acceptedEntry(accepted, there);
        manifestMem.set(vaultId, entry);
      }
      return mergedDeviceMemory(old, { revs: revMem, manifests: manifestMem, trashSeen });
    });
  } catch (e) {
    if (gen === generation && manifestMem.get(vaultId) === entry) {
      if (prior) manifestMem.set(vaultId, prior);
      else manifestMem.delete(vaultId);
    }
    throw e;
  }
  if (gen !== generation || currentId !== id) throw lockedError();
  log.warn("The server's copy of a vault was accepted on this browser (\"Use the server's copy\").");
  if (synced !== judgedCopy) {
    // Something else was shown while the record was written (final review, finding 4): what was judged here is no
    // longer the copy. Whatever took its place was judged against the accepted memory; its states stand, and a sync
    // decides. The marks go only if that leaves the vault without its warning.
    await syncFor(gen);
    await syncsDone();
    if (gen !== generation || currentId !== id) throw lockedError();
    if (unresolved(manifestStates.get(vaultId))) throw new AppError(FAILED, MANIFEST_CHANGED_TEXT, true);
  } else {
    manifestStates.set(vaultId, a.status === "ok" ? "ok" : "none");
    standing.delete(vaultId);
  }
  upkeepTried.delete(vaultId);
  dropItemMarks(vaultId, priorIds);
  await persist(id);
}

/**
 * With an accepted copy of a vault ("Use the server's copy"), for the items this browser held in that vault before
 * (`priorIds`), and only while they are still the vault's: the server's rows are what this browser saw from now on.
 * - a row that holds this browser's kept newer copy gets the row the server sent back (`servedRows`), and its counter
 *   becomes that row's;
 * - an item marked as an older version loses the mark, and its counter becomes the shown row's;
 * - an item the server no longer lists is forgotten (its counter, its mark, the row kept aside).
 * So no "older versions" notice remains for the vault. Ids of other vaults, and ids only a later answer placed in
 * this one, are left alone.
 */
function dropItemMarks(vaultId: string, priorIds: ReadonlySet<string>) {
  if (!synced || revGen !== generation || memUnreadable) return;
  const items = new Map(synced.items);
  const back = new Set<string>();
  for (const id of priorIds) {
    const row = items.get(id);
    if (!row) {
      const aside = extras.stash.get(id);
      if (aside && aside.vault_id !== vaultId) continue;
      extras.stash.delete(id);
      forgetRev(revMem, id);
      continue;
    }
    if (row.vault_id !== vaultId) continue;
    if (extras.served.has(id)) {
      const sent = servedRows.get(id);
      // Without the server's row (no answer of this worker brought it) the kept copy stays, marked as it is.
      if (!sent || sent.vault_id !== vaultId) continue;
      items.set(id, sent);
      back.add(id);
      // No counter: `prepare` opens the server's row as one seen for the first time and remembers its counter.
      forgetRev(revMem, id);
    } else if (revMem.rolledBack.has(id)) {
      const shown = decrypted.get(id)?.entry;
      revMem.rolledBack.delete(id);
      if (shown) revMem.revs.set(id, itemRevOf(shown.item));
      else revMem.revs.delete(id);
    }
  }
  // Shown again from the rows put back (the vaults' states stay as they are).
  showOwn(back.size ? { ...synced, items } : synced, back);
}

/** What this browser remembers can't be read, and the way out is on offer: the popup's notice, or null. */
export function memoryNotice(): { text: string; action: string; body: string } | null {
  if (!memUnreadable || !unread || unread.fails < MEMORY_UNREAD_TRIES || !unread.full) return null;
  return { text: MEMORY_UNREADABLE_TEXT, action: MEMORY_RESET_ACTION, body: MEMORY_RESET_BODY };
}

/**
 * "Reset on this device" (the popup, after its confirmation): the record that can't be read is moved aside (kept
 * under its own key, never read again) and this browser goes on as one that remembers nothing for the account: it
 * trusts what the server shows now, with one whole sync, and starts a new record. A record that reads again is left
 * alone.
 */
export async function resetDeviceMemory(): Promise<void> {
  const gen = generation;
  const id = currentId;
  const acct = account;
  if (!acct || !id) throw lockedError();
  await syncsDone();
  if (gen !== generation) throw lockedError();
  if (!memUnreadable) return;
  const server = (await local.account(id)).data?.server ?? "";
  const userId = meOf(acct);
  if (gen !== generation) throw lockedError();
  await deviceMemory.setAside(server, userId, (stored) => readDeviceMemory(stored) === "unreadable");
  await memoryUnread.update(server, userId, () => null).catch(logged("Forgetting the unreadable-memory count"));
  if (gen !== generation) throw lockedError();
  log.warn("What this browser remembered about the vault's versions couldn't be read and was reset.");
  unread = null;
  // Read again (nothing is stored now) by the sync that follows, which asks for everything.
  fullNext = true;
  await syncFor(gen);
}

const heldError = () => new AppError(MANIFEST_HELD, MANIFEST_HELD_TEXT, true);
/** A write into a vault no server's answer was checked for yet, after the sync that should have decided. */
const uncheckedError = () => new AppError(FAILED, memoryNotice() ? MEMORY_UNREADABLE_TEXT : MANIFEST_UNCHECKED_TEXT, true);
const busyError = () => new AppError(MANIFEST_BUSY, MANIFEST_BUSY_TEXT, true);

/**
 * The server refused a write for the vault's manifest: something else was written into the vault since this browser's
 * copy (409 `manifest_conflict`), or the copy still said the vault has no manifest (400 `manifest_required`). Both mean:
 * sync, check, compute again, send again.
 */
const manifestRefused = (e: unknown): boolean => e instanceof ApiError && (e.code === "manifest_conflict" || e.code === "manifest_required");

/**
 * Before a write into `vaultId`: a vault that isn't settled (nothing a server sent as one answer was checked for it
 * yet: the offline copy at unlock didn't check out) waits for the sync that decides, in full; so does one whose
 * last answer couldn't be checked for want of its manifest log.
 */
async function manifestSettled(vaultId: string, gen: number): Promise<void> {
  if (logPending.has(vaultId)) return syncFor(gen);
  if (!unsettled(manifestStates.get(vaultId))) return;
  // Not everything again when it is what this browser remembers that can't be read (a whole sync already found
  // that out): the sync only tries the read again.
  if (!(memUnreadable && unread?.full)) fullNext = true;
  await syncFor(gen);
}

/**
 * The manifest to send with a write into `vault`: `removed` = the affected rows as the copy holds them (before the
 * write; a row that holds this browser's kept newer copy counts with the hash of what the server sent), `added` = as
 * they are after it. The core names the row's manifest as the new one's predecessor. Null when the vault has no
 * manifest (the write goes as it always did). Refused here, before anything is sent, while the vault's warning is
 * unresolved, and for a vault whose last state didn't come from a checked answer.
 */
function nextManifest(vault: Vault, removed: SyncItemRow[], added: ManifestItem[]): ManifestEntry | null {
  const row = rowOf(vault.id);
  const status = manifestStates.get(vault.id);
  if (unresolved(status)) throw heldError();
  if (unsettled(status) || logPending.has(vault.id)) throw uncheckedError();
  if (!row || manifestSeqOf(row) === 0) return null;
  const sealed = manifestTextOf(row);
  const prev = manifestPrevOf(row);
  // A vault with a manifest and no "ok" for the row shown: never written from here.
  if (status !== "ok") throw uncheckedError();
  if (!sealed || !prev) throw heldError();
  try {
    return entryOf(
      vault.id,
      vault.key.manifestNext(
        vault.id,
        epochOf(row),
        manifestSeqOf(row),
        prev,
        sealed,
        removed.map((r) => manifestItem(r, extras.served.get(r.id))),
        added,
      ),
    );
  } catch (e) {
    log.warn("Computing a vault's next manifest failed:", coreCode(e));
    throw new AppError(FAILED, "PassAuth couldn't prepare this change. Sync and try again.", true);
  }
}

/** What the manifest endpoints answer. */
type ManifestAnswer = { vault_seq?: unknown; manifest_seq?: unknown; manifest_link?: unknown } | null;

/** Whether the copy's vault row is still the one `sent` was built on: the version before it, and (when there was one) the manifest it names. */
const stillBase = (row: SyncVaultRow, sent: ManifestEntry): boolean => manifestSeqOf(row) === sent.seq - 1 && (sent.seq === 1 || linkOf(row) === sent.prev);

/**
 * Whether an own manifest write can be shown without asking: the server's manifest of the vault is exactly the one
 * sent (the answer's `manifest_link` is its link: a version number alone would also fit another sealing of it), stored
 * as the vault's next write (`known`: the vault's number the write was computed from), and nothing else was shown
 * meanwhile.
 */
function ownManifestApplies(vaultId: string, known: number | undefined, sent: ManifestEntry, answer: ManifestAnswer): answer is { vault_seq: number; manifest_link: string } {
  const row = rowOf(vaultId);
  if (!synced || !row || known === undefined || answer?.manifest_link !== sent.link || answer.vault_seq !== known + 1 || knownSeq(synced, vaultId) !== known) return false;
  return stillBase(row, sent);
}

/**
 * After a sync, for every open vault this account may write to, on servers with `vault_manifest` (one try each per
 * vault state, every failure ignored: another device probably did it, and the next sync decides again):
 * - a vault without a manifest gets its first one when the server says every member's apps can keep it (`mayStart`);
 * - a vault with one (verdict "ok") has its old trash deleted for good: the server's sweeper skips such vaults, since
 *   only an app can write the manifest that goes with the deletion. An item goes only when the server's rule says
 *   so AND this browser has itself seen it in the trash for the whole period (`dueTrash`): the server's word alone
 *   never empties the trash.
 * Nothing of this runs while what this browser remembers can't be read.
 * Resolves to whether a sync should follow (a purge the copy couldn't apply itself).
 */
async function manifestUpkeep(id: string, served: Served, stale: () => boolean): Promise<boolean> {
  const server = (await local.account(id)).data?.server ?? "";
  const info = server ? await serverInfo(server) : null;
  if (!info?.features.has(MANIFEST_FEATURE) || memUnreadable || revGen !== generation) return false;
  let again = false;
  for (const vault of [...vaults]) {
    if (stale() || !synced) return false;
    const row = rowOf(vault.id);
    if (!row || vault.role === "read") continue;
    const status = manifestStates.get(vault.id);
    const known = knownSeq(synced, vault.id);
    if (known === undefined) continue;
    if (status === "none") {
      const rows = manifestItems(synced, extras.served).get(vault.id) ?? [];
      // Never over a kept newer copy: the server sent an older version of an item of this vault.
      const kept = rows.some((r) => extras.served.has(r.id));
      // Never over a row that doesn't decrypt either: this browser can't vouch for it (an item from a newer version
      // of PassAuth, which decrypts, is no such row).
      if (!mayStart({ features: info.features, row, role: vault.role, status, remembered: rememberedOf(manifestMem, vault.id), items: rows, kept, unopenable: unopenableVaults.has(vault.id) }))
        continue;
      if (upkeepTried.get(vault.id) === `start:${known}`) continue;
      upkeepTried.set(vault.id, `start:${known}`);
      let sent: ManifestEntry;
      let answer: ManifestAnswer;
      try {
        sent = entryOf(vault.id, vault.key.manifestStart(vault.id, epochOf(row), 1, null, rows));
        answer = await api<ManifestAnswer>(`/vaults/${encodeURIComponent(vault.id)}/manifest`, {
          method: "PUT",
          body: { base_seq: 0, seq: sent.seq, prev: sent.prev, sealed: sent.sealed, vault_seq: known },
          accountId: id,
        });
      } catch (e) {
        log.debug("Starting a vault's manifest didn't work now:", codeOf(e) ?? e);
        continue;
      }
      if (stale() || !synced) return false;
      if (!ownManifestApplies(vault.id, known, sent, answer)) continue; // the next sync brings it
      synced = withManifest(synced, sent, answer.vault_seq);
      rememberManifest(manifestMem, vault.id, sent.seq, sent.link);
      manifestStates.set(vault.id, "ok");
      await persist(id);
    } else if (status === "ok" && manifestSeqOf(row) > 0) {
      const due = dueTrash(synced.items.values(), vault.id, served, trashSeen, Math.floor(Date.now() / 1000)).slice(0, purgeBatch(info.limits));
      if (!due.length || upkeepTried.get(vault.id) === `purge:${known}`) continue;
      upkeepTried.set(vault.id, `purge:${known}`);
      let sent: ManifestEntry | null;
      let answer: ManifestAnswer;
      try {
        sent = nextManifest(vault, due, []);
        if (!sent) continue;
        answer = await api<ManifestAnswer>(`/vaults/${encodeURIComponent(vault.id)}/trash/purge`, {
          body: { items: due.map((r) => ({ id: r.id, revision: r.revision })), manifests: [sentEntry(sent)] },
          accountId: id,
        });
      } catch (e) {
        log.debug("Deleting a vault's old trash didn't work now:", codeOf(e) ?? e);
        continue;
      }
      if (stale() || !synced) return false;
      if (!ownManifestApplies(vault.id, known, sent, answer)) {
        again = true;
        continue;
      }
      // The trash is never shown: the rows go from the copy, nothing is decrypted again.
      const items = new Map(synced.items);
      for (const r of due) {
        items.delete(r.id);
        // Deleted for good from here: the one case besides a checked answer where an item is forgotten.
        forgetRev(revMem, r.id);
        extras.served.delete(r.id);
        extras.stash.delete(r.id);
        trashSeen.delete(r.id);
      }
      synced = withManifest({ ...synced, items }, sent, answer.vault_seq);
      rememberManifest(manifestMem, vault.id, sent.seq, sent.link);
      await persist(id);
    }
  }
  return again;
}

/** Whether the active account's server is one this app refuses ("Update your PassAuth server…"), as far as known. */
export async function serverNeedsUpdate(): Promise<boolean> {
  return outdatedServer((await local.account()).data?.server ?? "");
}

const byName = new Intl.Collator(undefined, { sensitivity: "base" });

/**
 * Open a row: the entry, or why not: "locked" = it doesn't decrypt (a wrong key, other data, or none: trash summaries
 * and anything else without ciphertext), "newer" = it decrypts, but its content isn't an item this version reads
 * (manifests.ts `openFailure`).
 */
function openRow(key: core.VaultKey, row: SyncItemRow): Entry | "locked" | "newer" {
  if (typeof row.item_key !== "string" || typeof row.data !== "string") return "locked";
  const enc: EncryptedItem = { id: row.id, vault_id: row.vault_id, key: row.item_key, data: row.data };
  try {
    return { id: row.id, item: key.decryptItem(enc) as Item, vaultId: row.vault_id, revision: row.revision, enc };
  } catch (e) {
    return openFailure(e);
  }
}

function decryptRow(key: core.VaultKey, row: SyncItemRow): Entry | null {
  const opened = openRow(key, row);
  return typeof opened === "string" ? null : opened;
}

/** A row with what opening it gave (`fail`: why there is no entry), reused while its ciphertext stays. */
interface Copy {
  row: SyncItemRow;
  entry: Entry | null;
  fail?: "locked" | "newer";
}

/**
 * A candidate state: a snapshot with its vault keys opened and its items decrypted, nothing of it shown or kept yet.
 * `commit` makes it the loaded state; `discard` drops it (the state shown stays exactly as it was).
 */
interface Prepared {
  snap: Snapshot;
  vaults: Vault[];
  /** Key handles taken over from the state shown (the others were opened for this candidate). */
  kept: Set<core.VaultKey>;
  keysFrom: Map<string, SyncVaultRow>;
  entries: Entry[];
  copies: Map<string, Copy>;
  /** The item edit counters as they are after this candidate (a copy: `revMem` is untouched until `commit`). */
  revs: RevMemory;
  /** Whether what this browser remembers was read for this generation (else nothing is checked against it). */
  checkRevs: boolean;
  extras: RowExtras;
  /**
   * Open vaults with an item that doesn't decrypt and no copy of this browser's own to go on with: a live one (also
   * one without data), or a trashed one that came with its data.
   */
  hidden: Set<string>;
  /** The live rows that aren't shown as items (`unopened`). */
  unopened: Map<string, Unopened>;
  /** The server's rows behind this browser's kept newer copies (`servedRows`). */
  servedRows: Map<string, SyncItemRow>;
  /** Whether each trashed row that came with its data opened. */
  trashOpens: Map<string, { row: SyncItemRow; opens: boolean }>;
}

/**
 * Open and decrypt `snap` as a candidate. A vault's key handle is kept while its key fields (`wrapped_key`,
 * `key_kind`, `key_epoch`) stay the same, otherwise it is opened again and its items decrypted again; an item whose
 * ciphertext didn't change keeps its decrypted copy. The trash isn't shown (in the trash: `deleted_at` is not null).
 * `arrived`: the rows a server just sent ("all": a whole answer) or this browser just rewrote; null: none (the
 * offline copy, an own write that kept its data). For those the hash of what the server sent earlier no longer
 * applies: the row is the server's (or this browser's own write) now.
 *
 * A row that doesn't open (final review T1), three cases:
 * (a) this browser holds a row of the same id, vault and `data` that it opened before (the copy shown, a trashed row,
 *     a row kept aside, the server's row behind a kept newer copy), and only the served `item_key` fails: it goes on
 *     with its own row, whose key stays in the copy. Nothing is wrong with the item (the vault's record covers its
 *     data, not its key), nothing is listed, warned or held for the key: a server can't make a member delete a good
 *     item by damaging its key in an answer. The item's edit counter is checked like that of any row that opened
 *     (final review C1): an old version is marked, and a newer copy this browser has is kept.
 * (b) the row decrypts but isn't an item this version reads (a type or format from a newer app): listed as "Item from
 *     a newer version of PassAuth"; no notice, it blocks nothing, and it counts in the record like any row.
 * (c) anything else: listed as "Item that can't be opened" (with the name the last opened copy had: that copy stays
 *     aside in `stash` for it), and its vault shows the notice (`hidden`). No write is held for it.
 * Null when no account is loaded.
 */
function prepare(snap: Snapshot, arrived: ReadonlySet<string> | "all" | null): Prepared | null {
  const acct = account;
  if (!acct) return null;
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
        const rowEpoch = whole(v.key_epoch) ?? 0;
        const legacyOk = sharingOn ? core.pinsLegacyWrapAllowed(keyPins, v.id, rowEpoch) : true;
        key = acct.openVaultKey(v.id, v.wrapped_key, v.key_kind, rowEpoch, legacyOk);
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
  const copies = new Map<string, Copy>();
  const list: Entry[] = [];
  const hidden = new Set<string>();
  const closed = new Map<string, Unopened>();
  // Only once this account's remembered counters are read (always so through openVault and accept).
  const checkRevs = revGen === generation && !memUnreadable;
  const revs: RevMemory = checkRevs ? { revs: new Map(revMem.revs), rolledBack: new Map(revMem.rolledBack) } : emptyRevMemory();
  // The hashes of what the server sent, for rows that still hold this browser's kept copy.
  const served = new Map<string, string>();
  if (arrived !== "all") for (const [id, hash] of extras.served) if (!arrived?.has(id) && snap.items.has(id)) served.set(id, hash);
  const stash = new Map(extras.stash);
  // The server's rows behind kept copies no answer replaced now.
  const behind = new Map<string, SyncItemRow>();
  for (const id of served.keys()) {
    const sent = servedRows.get(id);
    if (sent) behind.set(id, sent);
  }
  const trashed = new Map<string, { row: SyncItemRow; opens: boolean }>();
  // Case (a): the row with this browser's own key for the same data, when it has one that opens it.
  const withOwnKey = (vault: Vault, row: SyncItemRow): { row: SyncItemRow; entry: Entry } | null => {
    if (typeof row.data !== "string") return null;
    const shown = decrypted.get(row.id);
    const inTrash = trashOpens.get(row.id);
    // (`servedRows`: the older version a server sent before, behind the newer copy this browser kept and shows.)
    for (const prior of [shown?.entry ? shown.row : undefined, inTrash?.opens ? inTrash.row : undefined, stash.get(row.id), servedRows.get(row.id)]) {
      if (!prior || prior.vault_id !== row.vault_id || prior.data !== row.data || typeof prior.item_key !== "string" || prior.item_key === row.item_key) continue;
      const mine: SyncItemRow = { ...row, item_key: prior.item_key };
      const entry = decryptRow(vault.key, mine);
      if (entry) return { row: mine, entry };
    }
    return null;
  };
  for (const sent of snap.items.values()) {
    let row = sent;
    const vault = byId.get(row.vault_id);
    if (!vault) continue;
    if (isTrashed(row)) {
      // The trash is never shown, but a trashed row that came with its data must open like any other (as the web
      // vault counts it); a trash summary (no data, only its hash) can't be told and is the manifest's business alone.
      if (typeof row.data === "string") {
        const was = trashOpens.get(row.id);
        let opens: boolean;
        if (was && kept.has(vault.key) && sameCiphertext(was.row, row)) opens = was.opens;
        else {
          const opened = openRow(vault.key, row);
          const own = opened === "locked" ? withOwnKey(vault, row) : null;
          if (own) {
            snap.items.set(row.id, own.row);
            trashed.set(row.id, { row: own.row, opens: true });
            continue;
          }
          // An item from a newer version decrypts: nothing is wrong with it.
          opens = opened !== "locked";
        }
        trashed.set(row.id, { row, opens });
        if (!opens) hidden.add(vault.id);
      }
      continue;
    }
    const old = decrypted.get(row.id);
    let entry: Entry | null = null;
    let fail: "locked" | "newer" | undefined;
    if (old && kept.has(vault.key) && sameCiphertext(old.row, row)) {
      entry = old.entry && old.entry.revision !== row.revision ? { ...old.entry, revision: row.revision } : old.entry;
      if (!entry) fail = old.fail ?? "locked";
      // The server now sends exactly the copy this browser kept: nothing is marked any more.
      if (checkRevs && extras.served.has(row.id) && !served.has(row.id)) revs.rolledBack.delete(row.id);
    } else {
      const opened = openRow(vault.key, row);
      if (opened === "locked") {
        const own = withOwnKey(vault, row);
        if (own) {
          // Case (a): only the served key fails. This browser's row for the same data goes on, key and all, and is
          // judged below exactly as if the served key had opened it: its own row may be one from the trash, where
          // no edit counter is checked, so a damaged key must not be a way round the "older version" mark.
          row = own.row;
          entry = own.entry;
          snap.items.set(row.id, row);
        } else fail = "locked";
      } else if (opened === "newer") fail = "newer";
      else entry = opened;
      if (entry && checkRevs) {
        // Item rollback detection: the core's verdict on the counter inside the ciphertext against the highest seen.
        let verdict: string;
        try {
          verdict = core.itemRevCheck(revs.revs.get(row.id) ?? null, itemRevOf(entry.item));
        } catch {
          verdict = "rollback";
        }
        // The copy this browser had: the one shown before, or one the server stopped listing without proof (`stash`).
        const prior = old?.entry ? old.row : stash.get(row.id);
        const held: { mine: Entry | null } = { mine: null };
        const how = noteServed(revs, row.id, itemRevOf(entry.item), verdict, !!old || stash.has(row.id), () => {
          // Opened again with the vault key it has now (with the server's revision, so an edit made from it isn't
          // refused as a conflict, and the row's trash state).
          if (!prior || prior.vault_id !== row.vault_id || typeof prior.item_key !== "string" || typeof prior.data !== "string") return null;
          held.mine = decryptRow(vault.key, { ...row, item_key: prior.item_key, data: prior.data });
          return held.mine ? itemRevOf(held.mine.item) : null;
        });
        const mine = held.mine;
        if (how === "keep" && mine) {
          // Vault manifests are about the server's rows: the hash of the data the server sent is kept beside the
          // rows (never on the row, where a server could put one).
          const keptRow: SyncItemRow = { ...row, item_key: mine.enc.key, data: mine.enc.data };
          served.set(row.id, core.manifestDataHash(row.data));
          behind.set(row.id, row);
          snap.items.set(row.id, keptRow);
          copies.set(row.id, { row: keptRow, entry: mine });
          list.push(mine);
          continue;
        }
      }
    }
    copies.set(row.id, fail ? { row, entry, fail } : { row, entry });
    if (entry) list.push(entry);
    else if (fail === "newer") closed.set(row.id, { id: row.id, vaultId: vault.id, kind: "newer" });
    else {
      // Case (c): a live item of an open vault that has no data or doesn't decrypt. Its vault shows the notice and
      // gets no first manifest from here. The copy this browser opened before stays aside (its name is shown, and a
      // later answer is compared with it).
      hidden.add(vault.id);
      if (old?.entry && old.row.vault_id === row.vault_id && typeof old.row.item_key === "string" && typeof old.row.data === "string") stash.set(row.id, old.row);
      const aside = stash.get(row.id);
      const name = old?.entry?.item.name ?? unopened.get(row.id)?.name ?? (aside && aside.vault_id === row.vault_id ? decryptRow(vault.key, aside)?.item.name : undefined);
      closed.set(row.id, { id: row.id, vaultId: vault.id, kind: "locked", ...(typeof name === "string" && name ? { name } : {}) });
    }
  }
  // A row kept aside is a row again, except the last opened copy of one that doesn't open now.
  for (const id of [...stash.keys()]) if (snap.items.has(id) && closed.get(id)?.kind !== "locked") stash.delete(id);
  list.sort((a, b) => byName.compare(a.item.name, b.item.name));
  for (const id of [...behind.keys()]) if (!served.has(id)) behind.delete(id);
  return { snap, vaults: next, kept, keysFrom, entries: list, copies, revs, checkRevs, extras: { served, stash }, hidden, unopened: closed, servedRows: behind, trashOpens: trashed };
}

/** Drop a candidate: the key handles opened for it are freed; the state shown is untouched. */
function discard(p: Prepared) {
  for (const v of p.vaults) if (!p.kept.has(v.key)) v.key.free();
}

/**
 * Make a candidate the loaded state: shown, with `statuses` as its vaults' manifest states, and the match index
 * published. `before`: the snapshot shown until now, when the candidate is a server's answer (null: the offline copy
 * or an own write). `warnings`: the standing warnings that go with `statuses` (left out: the ones shown stay). Then the rows that are gone are sorted: an item absent from a vault that checked "ok" for this
 * very answer is gone for certain and is forgotten (its edit counter, its marks, its kept copy); any other missing
 * item keeps its counter, and its row is kept aside (`stash`): a server that hides an item once can't then bring back
 * an older version of it unnoticed.
 */
function commit(p: Prepared, statuses: Map<string, ManifestStatus>, before: Snapshot | null, warnings?: ReadonlyMap<string, Standing>) {
  if (before && p.checkRevs) {
    const listed = new Set(p.snap.vaults.map((v) => v.id));
    const proven = (row: SyncItemRow) => listed.has(row.vault_id) && statuses.get(row.vault_id) === "ok";
    for (const [id, row] of before.items) {
      if (p.snap.items.has(id)) continue;
      p.extras.stash.delete(id);
      if (proven(row)) forgetRev(p.revs, id);
      else if (typeof row.item_key === "string" && typeof row.data === "string") p.extras.stash.set(id, row);
    }
    for (const [id, row] of [...p.extras.stash]) {
      // (A row kept aside for an item the copy holds, one that doesn't open now, is not a missing item.)
      if (before.items.has(id) || p.snap.items.has(id) || !proven(row)) continue;
      p.extras.stash.delete(id);
      forgetRev(p.revs, id);
    }
    for (const id of [...p.extras.stash.keys()].slice(0, Math.max(0, p.extras.stash.size - STASH_CAP))) p.extras.stash.delete(id);
  }
  for (const [id, status] of statuses) {
    if (unresolved(status) && !unresolved(manifestStates.get(id))) log.warn(`A vault doesn't match its manifest (${status}); nothing is written into it until that is resolved.`);
  }
  if (p.snap.bundle) {
    bundle = p.snap.bundle;
    void dropStalePin(currentId, p.snap.bundle).catch(logged("Checking the PIN copy"));
  }
  // Handles the new state no longer uses (a vault gone, or its key replaced).
  for (const v of vaults) if (!p.kept.has(v.key)) v.key.free();
  synced = p.snap;
  vaults = p.vaults;
  entries = p.entries;
  decrypted = p.copies;
  openedFrom = p.keysFrom;
  extras = p.extras;
  manifestStates = statuses;
  // `warnings`: with a judged candidate. Without (an own write shown): the warnings shown stay with their vaults.
  standing = new Map([...(warnings ?? standing)].filter(([id]) => unresolved(statuses.get(id))));
  unopenableVaults = p.hidden;
  unopened = p.unopened;
  servedRows = p.servedRows;
  shownCount++;
  trashOpens = p.trashOpens;
  if (p.checkRevs) {
    revMem = p.revs;
    capRevMemory(revMem, p.snap.items);
    // When this browser first saw each trashed item in the trash, by its own clock (old trash: `dueTrash`).
    trashSeen = noteTrash(trashSeen, p.snap.items.values(), Math.floor(Date.now() / 1000));
  }
  revision = p.snap.revision;
  loaded = true;
  const list = p.entries;
  const logins: IndexedLogin[] = list.flatMap((e) => (e.item.login ? [{ id: e.id, urls: e.item.login.urls, personal: isPersonal(e) }] : []));
  index = { revision, logins, cards: list.filter((e) => e.item.card).length, identities: list.filter((e) => e.item.identity).length };
  void matchIndex.set(currentId, index).catch(logged("Storing the match index"));
  if (bundle) noteSecretKey(currentId, bundle);
  opened();
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
  // A server this app refuses is never asked (no socket either).
  if (serverOutdated(info) || !info.features.has("delta_sync")) return "unsupported";
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
  // `rev`: the edit counter the core raises on every write, never content.
  const strip = ({ format: _f, rev: _r, ...rest }: Item & { rev?: unknown }) => (ignoreTimes ? { ...rest, created_at: 0, updated_at: 0 } : rest);
  return stableJson(strip(a)) === stableJson(strip(b));
}

/** Sync, and fail if the vault was locked or switched meanwhile (what follows would use another account's keys). */
async function syncFor(gen: number) {
  await sync();
  if (gen !== generation || !account) throw lockedError();
}

/** What item writes answer: the item's new revision and, with delta sync, the vault's number after the write. */
type WriteAnswer = { revision?: unknown; vault_seq?: unknown; manifest_seq?: unknown; manifest_link?: unknown } | null;

/**
 * After one of this browser's item writes, bring the vault up to date with the least work. Without delta sync: a
 * sync, as before. With it, the answer's `vault_seq` decides (`afterWrite`): a number the copy already has → a sync
 * since brought the write; exactly the next one → the write was the only change, so `own()` (the row as the server
 * stored it) is shown and kept without asking; anything else → a delta sync. A sync that was already asking before
 * the write was answered may not include it, so it is waited for first.
 *
 * `sent`: the manifest the write carried (null: the vault has none). Then the write is shown without asking only when
 * the answer's `manifest_link` is the link of the manifest sent (not merely its version: a create sent again after a
 * lost answer is answered as a repeat, with the manifest the first try stored, which is another sealing with another
 * link) and the copy still holds the manifest it was built on; the vault row
 * gets the manifest sent (`manifest`, `manifest_seq`, `manifest_prev`), and its version and link are remembered.
 * Anything else → a sync, which checks the vault.
 */
async function settle(vaultId: string | undefined, answer: WriteAnswer, own?: (vaultSeq: number) => OwnWrite | null, sent?: ManifestEntry | null): Promise<void> {
  const gen = generation;
  const id = currentId;
  const vaultSeq = answer?.vault_seq;
  if (!vaultId || typeof vaultSeq !== "number" || !synced?.cursor) return sync();
  await syncIdle();
  if (gen !== generation || currentId !== id || !synced) return;
  const row = rowOf(vaultId);
  const mine = !sent || (answer?.manifest_link === sent.link && !!row && stillBase(row, sent));
  const action = afterWrite(knownSeq(synced, vaultId), vaultSeq, !!own && mine);
  if (action === "none") return;
  if (action === "apply" && own) {
    const write = own(vaultSeq);
    if (write) {
      const next = applyOwnWrite(synced, write);
      // The manifest sent is the vault's now: its version and link are remembered with the copy that carries it.
      if (sent) rememberManifest(manifestMem, vaultId, sent.seq, sent.link);
      // A row whose data this write replaced is this browser's own now (no "kept" copy of an older answer any more).
      const rewritten = write.kind === "upsert" && synced.items.get(write.row.id)?.data !== write.row.data ? new Set([write.row.id]) : null;
      showOwn(sent ? withManifest(next, sent) : next, rewritten);
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
  let keyRetried = false;
  for (let tries = 1; ; ) {
    if (gen !== generation || !account) throw lockedError();
    await manifestSettled(target, gen);
    const vault = vaults.find((v) => v.id === target);
    if (!vault || vault.role === "read") throw new Error(vaultId ? "You can't add items to that vault." : "PassAuth couldn't find your own vault to save to.");
    const enc = vault.key.encryptItem(plain, itemId, vault.id) as EncryptedItem;
    // Vault manifests: the vault's next manifest, with this item added.
    const sent = nextManifest(vault, [], [{ id: itemId, deleted_at: null, data: enc.data }]);
    let answer: WriteAnswer;
    try {
      answer = await api<WriteAnswer>("/items", { body: { ...withEpoch(enc, vault, features), ...(sent ? { manifests: [sentEntry(sent)] } : {}) }, accountId: owner });
    } catch (e) {
      if (!keyRetried && isCode(e, "vault_key_changed")) {
        // A member was removed and the vault has a new key: sync brings it; the item is encrypted again with it, once.
        keyRetried = true;
        await syncFor(gen);
        continue;
      }
      if (manifestRefused(e)) {
        // Something else was written into the vault: sync (which checks it), then the same item with the manifest
        // computed again, three tries in all.
        if (tries >= MANIFEST_TRIES) throw busyError();
        tries++;
        await syncFor(gen);
        continue;
      }
      // An earlier try reached the server: the sync that found out shows it (brought up to date if it was changed).
      if (isCode(e, "item_exists") && (await arrivedEarlier(itemId, target, plain, gen))) return itemId;
      throw e;
    }
    await settle(
      target,
      answer,
      (vaultSeq) => {
        const row = storedRow(enc, answer, undefined);
        return row && { kind: "upsert", row, vaultSeq };
      },
      sent,
    );
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
  let keyRetried = false;
  const changedElsewhere = () => new ApiError(409, "revision_conflict", "This item was changed on another device. PassAuth has the latest version now; check it and try again.");
  for (let tries = 1; ; ) {
    if (gen !== generation || !account) throw lockedError();
    await manifestSettled(base.vaultId, gen);
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
    // Vault manifests: the row as the copy holds it goes, the same row with the new data comes.
    const before = synced?.items.get(base.id);
    const held = before?.vault_id === vault.id ? before : undefined;
    const sent = nextManifest(vault, held ? [held] : [], [{ id: base.id, deleted_at: held?.deleted_at ?? null, data: enc.data }]);
    if (sent && !held) {
      // The copy no longer has the item in this vault: it changed on another device.
      await sync().catch(logged("Syncing after a conflict"));
      throw changedElsewhere();
    }
    let answer: WriteAnswer;
    try {
      answer = await api<WriteAnswer>(`/items/${base.id}`, {
        method: "PUT",
        body: { ...withEpoch({ ...enc, revision: base.revision }, vault, features), ...(sent ? { manifests: [sentEntry(sent)] } : {}) },
        accountId: currentId,
      });
    } catch (e) {
      if (isCode(e, "revision_conflict")) {
        // Changed on another device: get the latest so the next try starts from it.
        await sync().catch(logged("Syncing after a conflict"));
        throw e;
      }
      if (manifestRefused(e)) {
        // Something else was written into the vault (not this item: that is a revision conflict). Three tries in all.
        if (tries >= MANIFEST_TRIES) throw busyError();
        tries++;
      } else if (!keyRetried && isCode(e, "vault_key_changed")) keyRetried = true;
      else throw e;
      // A new vault key (a member was removed) or other writes into the vault: sync brings them (and checks the vault).
      // The same change is then applied to that copy, unless the item itself was changed meanwhile.
      await syncFor(gen);
      const fresh = getEntry(base.id);
      if (!fresh || fresh.vaultId !== base.vaultId || !sameContent(fresh.item, base.item)) throw changedElsewhere();
      base = fresh;
      continue;
    }
    // An edit in place: the row as stored is known (the item keeps its vault, times and trash state).
    const vaultId = base.vaultId;
    await settle(
      vaultId,
      answer,
      (vaultSeq) => {
        const stored = synced?.items.get(enc.id);
        const row = stored?.vault_id === vaultId ? storedRow(enc, answer, stored) : null;
        return row && { kind: "upsert", row, vaultSeq };
      },
      sent,
    );
    return;
  }
}

export async function trashItem(entry: Entry) {
  if (!canWrite(entry)) throw new Error("You can only view items in this vault.");
  const gen = generation;
  const owner = currentId;
  for (let tries = 1; ; tries++) {
    if (gen !== generation || !account) throw lockedError();
    await manifestSettled(entry.vaultId, gen);
    // Refused here while the vault's warning is unresolved (also for an item the copy no longer lists).
    if (unresolved(manifestStates.get(entry.vaultId))) throw heldError();
    if (unsettled(manifestStates.get(entry.vaultId)) || logPending.has(entry.vaultId)) throw uncheckedError();
    const vault = vaults.find((v) => v.id === entry.vaultId);
    const before = synced?.items.get(entry.id);
    const held = before?.vault_id === entry.vaultId ? before : undefined;
    // After a refusal and the sync that followed: gone, or in the trash already. Nothing is left to do.
    if (tries > 1 && (!held || isTrashed(held))) return;
    const now = Math.floor(Date.now() / 1000);
    // Vault manifests: the same row (same data), now in the trash; with it the item's revision, so "this item changed"
    // and "something else in the vault changed" are told apart by the server.
    const sent = vault && held ? nextManifest(vault, [held], [{ ...manifestItem(held, extras.served.get(held.id)), deleted_at: now }]) : null;
    let answer: WriteAnswer;
    try {
      answer = await api<WriteAnswer>(`/items/${entry.id}${writeQuery(sent && held ? held.revision : undefined, sent)}`, { method: "DELETE", accountId: owner });
    } catch (e) {
      // Other writes into the vault, or (with a manifest) this item changed elsewhere: sync and try again, three tries in all.
      if (!manifestRefused(e) && !(sent && isCode(e, "revision_conflict"))) throw e;
      if (tries >= MANIFEST_TRIES) throw busyError();
      await syncFor(gen);
      continue;
    }
    // Shown as in the trash (which the extension never shows) until the next delta brings the server's own row. The
    // row keeps its data until then, so the vault's manifest still counts it.
    await settle(
      entry.vaultId,
      answer,
      (vaultSeq) => {
        const stored = synced?.items.get(entry.id);
        if (!stored || stored.vault_id !== entry.vaultId || typeof answer?.revision !== "number") return null;
        return { kind: "upsert", vaultSeq, row: { ...stored, deleted_at: now, revision: answer.revision, updated_at: now } };
      },
      sent,
    );
    return;
  }
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
