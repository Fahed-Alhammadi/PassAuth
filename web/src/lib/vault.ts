/**
 * Vault session: authentication flows, key handles and the decrypted vault.
 * Decrypted data and key handles live only in memory; locking frees them.
 *
 * Key handles are WASM objects that `sync()` frees when it replaces them, so code must
 * never hold a `VaultKey` across an `await`: look it up again with `vaultFor()` instead.
 *
 * Writes encrypted with a vault key send that key's epoch (`key_epoch`, from /sync). A server whose key is newer
 * refuses them (409 vault_key_changed, nothing written): the write syncs, encrypts again with the new key and is
 * sent once more; a key replacement (rotate, remove member) instead asks the user to try again.
 *
 * Delta sync (servers with the `delta_sync` feature; rules in `delta.ts`): the encrypted rows of the last /sync
 * answer are kept with its cursor, later syncs ask only for what changed since, and decrypted items are reused while
 * their ciphertext and vault key stay the same. Without the feature every sync fetches the whole account, as before.
 *
 * Invitations (servers with `vault_invitations`; `invitations.ts`): every /sync lists the vaults shared with the account
 * and not accepted yet. Their sealed keys are opened only to read the vault's name, then freed; accepting makes the vault
 * a membership and it arrives whole with the next sync.
 *
 * Emergency access (`emergency-client.ts`) wraps the keys of the account's personal vaults for its emergency contacts.
 * After anything that can leave a personal vault without those wraps (unlocking, a new vault, a replaced key), the hook
 * set with `onVaultKeysChange` runs once the vault shows the change.
 */
import { useSyncExternalStore } from "react";
import * as core from "../wasm/passauth_core";
import {
  ApiError,
  UnreachableError,
  api,
  deviceInfo,
  friendlyError,
  getTokens,
  hasErrorCode,
  hasFeature,
  isOutOfStorage,
  knownPublicConfig,
  loadPublicConfig,
  onSessionLost,
  onTwoStepRequired,
  refreshPublicConfig,
  setTokens,
} from "./api";
import { stripAttachments } from "./attachments";
import { afterTwoStepSetup, isTwoStepClose, isTwoStepNotice, readPolicies, readViolations, type Violation } from "./policies";
import { checkCode, secretKeyToKeep, type CodeOutcome } from "./device-login";
import { afterWrite, applyOwnWrite, knownSeq, mergeSync, noticeAction, sameCiphertext, vaultKeyChanged, type Merged, type OwnWrite, type Snapshot, type SyncNotice } from "./delta";
import { readVersion, readVersions, restoredItem, type ItemVersion } from "./history";
import { openInvitations, type Invitation } from "./invitations";
import { secretStore } from "./platform";
import { server } from "./server";
import { encryptedSizeBound } from "./sizes";
import { getCredential } from "./webauthn";
import {
  UNEXPECTED_RESPONSE,
  expectStrings,
  isSyncResponse,
  readFoundUser,
  readLoginFinish,
  readMembers,
  readPrelogin,
  type Bundle,
  type EncryptedItem,
  type Item,
  type KeyKind,
  type LoginFinishResponse,
  type Role,
  type SyncItemRow,
  type SyncVaultRow,
  type VaultEntry,
} from "./types";

/**
 * "two-step": the server requires two-step login (policy) and the account has no method yet, so it refuses everything
 * but setting one up and signing out. The account keys stay in memory when the screen came up at sign-in, unlock or
 * while the vault was open (`holdsKeys()`), so the vault opens as soon as a method is set up.
 */
export type Status = "loading" | "unreachable" | "logged-out" | "locked" | "unlocked" | "two-step";

export interface Vault {
  id: string;
  name: string;
  role: Role;
  kind: KeyKind;
  key: core.VaultKey;
  /** Epoch of `key` (from the same /sync); undefined with servers that don't have key epochs. */
  epoch?: number;
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
  /** Vaults shared with the account and waiting for it to accept or decline (empty while locked). */
  invitations: Invitation[];
  /** What the account still has to change for the server's policies (`GET /account`, read after sign-in and unlock). */
  policyViolations: Violation[];
  /** Emergency access: why PassAuth left the contacts' keys alone (the server's list of them looked rolled back). */
  emergencyNotice: string | null;
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
  invitations: [],
  policyViolations: [],
  emergencyNotice: null,
};
let state: State = initial;
let account: core.Account | null = null;
let bundle: Bundle | null = null;
let socket: WebSocket | null = null;
/** The session's live-sync origin from the socket's `hello` (shared by every tab and window of this session). */
let liveOrigin: string | null = null;
/** Bumped whenever the keys are dropped (lock, sign-out): async work started before that is discarded. */
let generation = 0;
/** Items per vault that couldn't be decrypted in the last sync. */
let undecryptable = new Map<string, number>();
/**
 * Delta sync: the encrypted rows of the last /sync answer with its cursor (null without the feature). Memory only,
 * like the rest: kept while locked (the answer `boot()` fetched for the bundle, so unlocking asks only for what changed
 * since), dropped on sign-out and at sign-in.
 */
let synced: Snapshot | null = null;
/** Whether the last sync used delta sync (live-sync messages are then judged by vault numbers). */
let deltaOn = false;
/** Decrypted copy of each row by item id (null: it couldn't be decrypted), reused while the row and its vault key stay the same. */
let decrypted = new Map<string, { row: SyncItemRow; entry: VaultEntry | null }>();
/** The vault row each open key handle came from: the handle is kept while the row's key fields stay the same. */
let openedFrom = new Map<string, SyncVaultRow>();
/** Vault names read from invitations, by vault, sealed key and encrypted name (null: it couldn't be opened). */
let invitationNames = new Map<string, string | null>();
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
/** Run `fn` after every state change (outside React); returns the unsubscribe. */
export const onVaultChange = subscribe;

/** Desktop vault timeout "never": the unlocked account keys for the OS keychain; null while locked. */
export function sessionKeys(): { accountId: string; keys: Uint8Array } | null {
  if (!account || !bundle) return null;
  return { accountId: bundle.account_id, keys: account.toSessionBytes() };
}

/** Whether the account keys are in memory: the vault is open, or the two-step screen came up after it was unlocked. */
export const holdsKeys = (): boolean => account !== null;

onSessionLost(() => resetToLoggedOut());
onTwoStepRequired(() => enterTwoStepGate());

// Explicit locks and sign-outs apply to every open tab.
const channel = typeof BroadcastChannel === "function" ? new BroadcastChannel("passauth") : null;
channel?.addEventListener("message", (e: MessageEvent<{ type?: string }>) => {
  if (e.data?.type === "lock" && (state.status === "unlocked" || (state.status === "two-step" && account))) lock(false);
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

/** Keys of the secrets kept per account (see `secretStore`); the desktop app preloads them from its keychain. */
export const EMAIL_KEY = "pa.email";
export const secretKeyKey = (email: string) => `pa.sk.${email.trim().toLowerCase()}`;
export const rememberKey = (email: string) => `pa.remember.${email.trim().toLowerCase()}`;

export function rememberedSecretKey(email: string): string | null {
  return secretStore.get(secretKeyKey(email));
}
export function rememberSecretKey(email: string, sk: string | null) {
  secretStore.set(secretKeyKey(email), sk);
}
export function lastEmail(): string {
  return secretStore.get(EMAIL_KEY) ?? "";
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
  // Policies and features may have changed since this page last asked.
  void refreshPublicConfig();
  try {
    const sync = await api("/sync");
    if (!isSyncResponse(sync)) throw new ApiError(200, "bad_response", "The server sent an unexpected response.");
    bundle = sync.bundle;
    // Delta sync: keep the (encrypted) answer, so unlocking asks only for what changed since.
    synced = null;
    if (typeof sync.cursor === "string") {
      try {
        synced = mergeSync(null, sync)?.snapshot ?? null;
      } catch {
        /* unusable: the first sync after unlocking fetches everything */
      }
    }
    set({ status: "locked", email: sync.user.email, userId: sync.user.id, name: sync.user.name, emailVerified: sync.user.email_verified });
  } catch (e) {
    // The server requires two-step login and the account has none: the session stays, for setting a method up.
    if (getTokens() && twoStepRequired(e)) return showTwoStepGate();
    // Only a server that rejects the session signs the user out; a network or server problem keeps it.
    if (!getTokens() || (e instanceof ApiError && (e.status === 401 || e.status === 403))) resetToLoggedOut();
    else set({ status: "unreachable", email: lastEmail() });
  }
}

// ---------------------------------------------------------- two-step gate

const twoStepRequired = (e: unknown) => hasErrorCode(e, "two_step_required");

/**
 * The server answered 403 `two_step_required` (policy: every account needs two-step login, and this one has no
 * method): show the screen that only sets a method up or signs out. The keys stay in memory if they are (see
 * `continueAfterTwoStep`); live sync stops, because the server refuses it too.
 */
function enterTwoStepGate() {
  if (!getTokens()) return;
  socket?.close();
  socket = null;
  liveOrigin = null;
  if (state.status !== "two-step") set({ status: "two-step" });
}

/** Start-up found the gate: the account's address and name come from `GET /account`, which the server still answers. */
async function showTwoStepGate() {
  enterTwoStepGate();
  try {
    const a = await api<{ email?: unknown; name?: unknown; user_id?: unknown; email_verified?: unknown }>("/account");
    if (state.status !== "two-step" || !a) return;
    set({
      email: typeof a.email === "string" ? a.email : lastEmail(),
      name: typeof a.name === "string" ? a.name : "",
      userId: typeof a.user_id === "string" ? a.user_id : "",
      emailVerified: a.email_verified !== false,
    });
  } catch {
    if (state.status === "two-step" && !state.email) set({ email: lastEmail() });
  }
}

/**
 * A two-step method is set up: leave the gate. With the keys in memory the vault syncs and opens (live sync again);
 * without them the session loads again and the vault asks to be unlocked. Throws when the server still refuses (or
 * can't be reached); the gate then stays.
 */
export async function continueAfterTwoStep(): Promise<void> {
  if (state.status !== "two-step") return;
  if (afterTwoStepSetup(account !== null) === "boot") return boot();
  await sync();
  // Locked meanwhile, or a sync that was dropped: nothing to connect.
  if (getState().status !== "unlocked") return;
  connectSocket();
  void refreshPolicyViolations().catch(() => {});
  vaultKeysChanged();
}

// ------------------------------------------------------------- policies

const sameList = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Note `policy_violations` from a `GET /account` answer (Settings reads it anyway). */
export function notePolicyViolations(value: unknown) {
  const next = readViolations(value);
  if (!sameList(next, state.policyViolations)) set({ policyViolations: next });
}

/** After sign-in and unlock: ask what the account still has to change for the server's policies (servers with `policies`). */
export async function refreshPolicyViolations(): Promise<void> {
  const gen = generation;
  if (!hasFeature(await loadPublicConfig(), "policies")) return notePolicyViolations([]);
  const a = await api<{ policy_violations?: unknown } | null>("/account");
  if (gen === generation) notePolicyViolations(a?.policy_violations);
}

/**
 * The server announces a sign-out to every connection of the account, including the one that just changed
 * the master password or Secret Key and keeps its session. Ask the server: a session that is gone answers
 * 401, which signs this client out; anything but a clear "still signed in" within 10 s does the same.
 */
function confirmSignedOut() {
  let settled = false;
  const timer = setTimeout(() => {
    if (!settled) resetToLoggedOut();
    settled = true;
  }, 10_000);
  api("/account/sessions")
    .then(() => {
      settled = true;
    })
    .catch(() => {
      if (!settled) resetToLoggedOut();
      settled = true;
    })
    .finally(() => clearTimeout(timer));
}

function resetToLoggedOut() {
  dropKeys();
  synced = null;
  setTokens(null);
  set({ ...initial, status: "logged-out", email: lastEmail() });
}

/** Free the keys and every decrypted item. The encrypted rows stay (see `synced`). */
function dropKeys() {
  generation++;
  socket?.close();
  socket = null;
  liveOrigin = null;
  const old = state.vaults;
  account?.free();
  account = null;
  undecryptable = new Map();
  decrypted = new Map();
  openedFrom = new Map();
  invitationNames = new Map();
  if (old.length || state.items.length || state.invitations.length) set({ vaults: [], items: [], invitations: [] });
  old.forEach((v) => v.key.free());
}

// ------------------------------------------------------------ registration

export interface RegisterResult {
  secretKey: string | null;
  emailVerificationRequired: boolean;
}

/**
 * The server's key-derivation minimums for new account keys (policy `min_kdf_memory_mib` / `min_kdf_iterations`), read
 * again before keys are made, so a policy the admin just raised is followed. The core then uses memory = max(128 MiB,
 * minimum) and passes = max(3, minimum). Nothing (the core's own settings) for servers without policies.
 */
async function kdfMinimums(): Promise<{ memory?: number; iterations?: number }> {
  const config = (await refreshPublicConfig()) ?? knownPublicConfig();
  if (!hasFeature(config, "policies")) return {};
  const p = readPolicies(config);
  return { memory: p.minKdfMemoryMib, iterations: p.minKdfIterations };
}

export async function register(email: string, name: string, password: string, withSecretKey: boolean): Promise<RegisterResult> {
  const kdf = await kdfMinimums();
  const init = expectStrings(await api("/auth/register/init", { body: { email }, auth: false }), "account_id", "registration_id");
  const created = core.createAccountWithKdf(init.account_id, password, withSecretKey, kdf.memory, kdf.iterations);
  const master = created.takeMaster();
  const acct = created.takeAccount();
  try {
    const start = core.opaqueRegisterStart(master);
    const resp = expectStrings(await api("/auth/register/start", { body: { registration_id: init.registration_id, message: start.message }, auth: false }), "message");
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

/**
 * A sign-in waiting for its two-step login (memory only): the master keys of a password sign-in, or the request key of
 * a sign-in another device approved (`device-login.ts`), whose sealed account key comes with the session; `email` is
 * the address typed on this device.
 */
type PendingSignIn = { kind: "password"; master: core.MasterKeys } | { kind: "device"; key: core.LoginRequestKey; requestId: string; email: string };
let pending: PendingSignIn | null = null;

/** Keep `next` for the two-step answer, freeing whatever was kept before. */
function holdPending(next: PendingSignIn | null) {
  const old = pending;
  pending = next;
  if (old && old !== next) (old.kind === "password" ? old.master : old.key).free();
}

/** The sign-in waiting for its two-step login, taken over by the caller (who frees it). */
function takePending(): PendingSignIn {
  const p = pending;
  pending = null;
  if (!p) throw new Error("Sign-in expired, start again.");
  return p;
}

/**
 * An approved sign-in request needs two-step login first: keep its key until the two-step answer brings the session.
 * `email` is the address typed on this device.
 */
export function holdDeviceSignIn(key: core.LoginRequestKey, requestId: string, email: string) {
  holdPending({ kind: "device", key, requestId, email });
}

/**
 * Drop a sign-in waiting for its two-step login or for the approving app's code (the user started over or left the
 * sign-in page); a session issued for one that waited for its code is signed out again.
 */
export function cancelPendingSignIn() {
  holdPending(null);
  dropApproval(true);
}

/** Thrown when the master password or Secret Key is wrong. */
export const WRONG_CREDENTIALS = "Wrong email, master password or Secret Key.";

/**
 * A sign-in's answer with every field checked: for `sign-in` a session or a two-step step, for `session` a session
 * only (the two-step answers), for `reauth` a reauth token. Anything else is the unexpected-answer error.
 */
function loginAnswer(body: unknown, want: "sign-in" | "session" | "reauth"): LoginFinishResponse {
  const a = readLoginFinish(body);
  const session = !!a && !a.two_factor_required && !!a.access_token;
  const ok = !!a && (want === "reauth" ? !!a.reauth_token : want === "session" ? session : session || a.two_factor_required === true);
  if (!a || !ok) throw new Error(UNEXPECTED_RESPONSE);
  return a;
}

async function opaqueLogin(email: string, password: string, secretKey: string | null, purpose?: "reauth") {
  const pre = readPrelogin(await api("/auth/prelogin", { body: { email }, auth: false }));
  if (!pre) throw new Error(UNEXPECTED_RESPONSE);
  if (pre.secret_key_required && !secretKey) throw new Error("secret_key_required");
  const sk = pre.secret_key_required && secretKey ? normalizeSecretKey(secretKey) : undefined;
  const master = core.deriveMasterKeys(password, sk, pre.account_id, pre.kdf, pre.secret_key_required);
  const start = core.opaqueLoginStart(master);
  let resp: { login_id: string; message: string };
  try {
    resp = expectStrings(await api("/auth/login/start", { body: { email, message: start.message }, auth: false }), "login_id", "message");
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
    const result = loginAnswer(
      await api("/auth/login/finish", {
        auth: purpose === "reauth",
        body: { login_id: resp.login_id, message: fin, device: deviceInfo(), purpose, remember_token: remember },
      }),
      purpose === "reauth" ? "reauth" : "sign-in",
    );
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
    holdPending({ kind: "password", master });
    return { done: false, twoFactorToken: result.two_factor_token ?? "", providers: result.providers ?? [] };
  }
  holdPending(null);
  await finishLogin(master, result);
  return { done: true };
}

/**
 * After a two-step login: "done" (signed in), or "confirm" for a sign-in another device approved, which then waits for
 * the approving app's code (`confirmDeviceLogin`).
 */
export type TwoStepOutcome = "done" | "confirm";

export async function verifyTwoFactor(token: string, provider: string, code: string, remember: boolean): Promise<TwoStepOutcome> {
  const result = await api("/auth/2fa/verify", { body: { two_factor_token: token, provider, code, remember }, auth: false });
  return finishPending(result);
}

/** The two-step answer's session: finish the sign-in that was waiting for it, by password or by another device's approval. */
async function finishPending(body: unknown): Promise<TwoStepOutcome> {
  const result = loginAnswer(body, "session");
  const p = takePending();
  if (p.kind === "password") {
    await finishLogin(p.master, result);
    return "done";
  }
  openDeviceApproval(p.key, p.requestId, result, p.email);
  return "confirm";
}

export async function sendTwoFactorEmail(token: string) {
  await api("/auth/2fa/email", { body: { two_factor_token: token }, auth: false });
}

/** Two-step login with a security key or passkey: server challenge → browser WebAuthn → session. */
export async function verifyTwoFactorPasskey(token: string, remember: boolean): Promise<TwoStepOutcome> {
  const { options } = await api<{ options: unknown }>("/auth/2fa/passkey/start", { body: { two_factor_token: token }, auth: false });
  const credential = await getCredential(options);
  const result = await api("/auth/2fa/passkey/finish", { body: { two_factor_token: token, credential, remember }, auth: false });
  return finishPending(result);
}

function rememberToken(email: string) {
  return secretStore.get(rememberKey(email)) ?? undefined;
}

async function finishLogin(master: core.MasterKeys, result: LoginFinishResponse) {
  dropKeys();
  // A new session (maybe another account) starts from the whole account.
  synced = null;
  try {
    setTokens({ access: result.access_token, refresh: result.refresh_token });
    if (result.remember_token) secretStore.set(rememberKey(result.email), result.remember_token);
    secretStore.set(EMAIL_KEY, result.email);
    bundle = result.bundle;
    account = master.unlock(bundle);
  } finally {
    master.free();
  }
  set({ email: result.email, userId: result.user_id });
  void refreshPublicConfig();
  if (!(await openVault())) return;
  connectSocket();
}

/** Shown when an approved sign-in's sealed key doesn't open with this device's request key, or doesn't fit the account. */
export const DEVICE_KEY_UNUSABLE =
  "This sign-in couldn't be finished: the approval doesn't match the request this device made. Start again, and check that both devices show the same words.";

/**
 * A sign-in another device approved, opened and waiting for the code the approving app shows (memory only): until the
 * code is confirmed, nothing of it is used or kept, not even the session's tokens.
 */
let approved: { login: core.ApprovedLogin; result: LoginFinishResponse; email: string } | null = null;

/** Drop the approval waiting for its code; `signOut`: also end the session the server issued for it (best effort). */
function dropApproval(signOut: boolean) {
  const a = approved;
  approved = null;
  if (!a) return;
  if (signOut) endSession(a.result.access_token);
  a.login.free();
}

/**
 * Open the sealed account key of a sign-in another device approved (`device-login.ts`) with the request's key, and keep
 * it until the user types the approving app's code (`confirmDeviceLogin`): only the real account key gives that code,
 * so a server can't hand this device a key of its own choosing. `email` is the address typed on this device. Takes over
 * `key` and frees it. When the sealed key can't be opened, the session the server just issued is signed out again and
 * nothing is kept.
 */
export function openDeviceApproval(key: core.LoginRequestKey, requestId: string, result: LoginFinishResponse, email: string): void {
  dropApproval(true);
  let login: core.ApprovedLogin;
  try {
    const sealed = (result as { sealed_key?: unknown }).sealed_key;
    if (typeof sealed !== "string" || !sealed) throw new Error("no sealed key");
    login = key.open(sealed, result.user_id, requestId);
  } catch {
    endSession(result.access_token);
    throw new Error(DEVICE_KEY_UNUSABLE);
  } finally {
    key.free();
  }
  approved = { login, result, email };
}

/** Whether a sign-in another device approved waits for the approving app's code. */
export const awaitsDeviceCode = (): boolean => approved !== null;

/** How entering the code went: signed in, a wrong code (with the tries left), or stopped after the third wrong one. */
export type DeviceCodeResult = { kind: "done"; email: string } | Exclude<CodeOutcome, { kind: "confirmed" }>;

/**
 * Check the code the approving app shows. Right: the account opens without the master password and the sign-in goes on
 * exactly as after a password sign-in (tokens, remember token and email are kept, and a Secret Key that came along is
 * kept for the typed email unless a different one is kept for it already). The third wrong code ends it: the session
 * is signed out and everything dropped. Throws for anything but 6 digits (not counted).
 */
export async function confirmDeviceLogin(code: string): Promise<DeviceCodeResult> {
  const a = approved;
  if (!a) throw new Error("Sign-in expired, start again.");
  const outcome = checkCode(a.login, code);
  if (outcome.kind === "wrong") return outcome;
  if (outcome.kind === "stopped") {
    dropApproval(true);
    return outcome;
  }
  approved = null;
  const result = a.result;
  let opened: core.Account;
  let received: string | null;
  try {
    opened = a.login.unlock(result.bundle);
    received = a.login.secretKey() ?? null;
  } catch {
    endSession(result.access_token);
    throw new Error(DEVICE_KEY_UNUSABLE);
  } finally {
    a.login.free();
  }
  dropKeys();
  // A new session (maybe another account) starts from the whole account.
  synced = null;
  setTokens({ access: result.access_token, refresh: result.refresh_token });
  if (result.remember_token) secretStore.set(rememberKey(result.email), result.remember_token);
  secretStore.set(EMAIL_KEY, result.email);
  const keep = secretKeyToKeep(a.email, result.email, received, rememberedSecretKey(result.email));
  if (keep) rememberSecretKey(result.email, keep);
  bundle = result.bundle;
  account = opened;
  set({ email: result.email, userId: result.user_id });
  void refreshPublicConfig();
  if (await openVault()) connectSocket();
  return { kind: "done", email: result.email };
}

/** Sign out a session this app won't keep (best effort): one issued for a sign-in that can't be finished or was cancelled. */
export function endSession(accessToken: string) {
  void api("/auth/logout", { method: "POST", auth: false, headers: { authorization: `Bearer ${accessToken}` } }).catch(() => {});
}

/**
 * The first sync after the keys are in memory (sign-in, unlock, restore). False when the server requires two-step
 * login first: the gate is showing and the keys stay for `continueAfterTwoStep`. Other failures are thrown.
 */
async function openVault(): Promise<boolean> {
  try {
    await sync();
  } catch (e) {
    if (twoStepRequired(e) && getTokens() && account) {
      enterTwoStepGate();
      return false;
    }
    throw e;
  }
  void refreshPolicyViolations().catch(() => {});
  vaultKeysChanged();
  return true;
}

let afterVaultKeys: (() => Promise<void>) | null = null;

/**
 * `fn` runs (in the background, its failures ignored) after the vault opened, a vault was created and vault keys were
 * replaced: when personal vaults may need new emergency-access wraps. One hook; null removes it.
 */
export function onVaultKeysChange(fn: (() => Promise<void>) | null) {
  afterVaultKeys = fn;
}

function vaultKeysChanged() {
  const fn = afterVaultKeys;
  if (fn && account && state.status === "unlocked") void fn().catch(() => {});
}

/** Shown with the vault notices (emergency access); null hides it. Cleared when the vault locks. */
export function setEmergencyNotice(text: string | null) {
  if (state.emergencyNotice !== text) set({ emergencyNotice: text });
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
  void refreshPublicConfig();
  let opened: boolean;
  try {
    opened = await openVault();
  } catch (e) {
    dropKeys();
    throw e;
  }
  if (sk) rememberSecretKey(state.email, sk);
  if (opened) connectSocket();
}

/** Open a locked session with keys saved by `sessionKeys()` (desktop, vault timeout "never") instead of the master password. */
export async function restoreUnlocked(accountId: string, keys: Uint8Array) {
  if (!bundle) throw new Error("Sign in again to unlock this vault.");
  if (bundle.account_id !== accountId) throw new Error("The saved keys belong to another account.");
  dropKeys();
  account = core.accountFromSessionBytes(accountId, keys);
  let opened: boolean;
  try {
    opened = await openVault();
  } catch (e) {
    dropKeys();
    throw e;
  }
  if (opened) connectSocket();
}

/** Fresh proof of the master password for sensitive settings. */
export async function reauth(password: string): Promise<string> {
  // Before the first sync of a session (the two-step screen at start-up) the bundle isn't known: the server's
  // prelogin says whether the Secret Key is needed, and the one this app remembers is used then.
  const sk = bundle && !bundle.secret_key_enabled ? null : rememberedSecretKey(state.email);
  const { master, result } = await opaqueLogin(state.email, password, sk, "reauth");
  master.free();
  if (typeof result.reauth_token !== "string" || !result.reauth_token) throw new Error("reauth_required");
  return result.reauth_token;
}

/** Lock this tab; `everywhere` also locks the vault in this browser's other tabs. */
export function lock(everywhere = true) {
  dropKeys();
  set({ status: "locked", vaults: [], items: [], revision: 0, warnings: [], invitations: [], emergencyNotice: null });
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

/**
 * Forget a device (servers with `forget_device`): every session it holds ends at once and the server drops its record
 * with its "remember this device" token, so its next sign-in counts as a new device and asks for two-step login again.
 * When it is this device (`current` in the answer), this app is signed out too.
 */
export async function forgetDevice(deviceId: string): Promise<{ signedOut: number; current: boolean }> {
  const r = await api<{ signed_out?: unknown; current?: unknown } | null>(`/account/devices/${encodeURIComponent(deviceId)}/forget`, {
    method: "POST",
    body: {},
  });
  const current = r?.current === true;
  if (current) {
    // The server forgot the token; a copy kept here would only be refused.
    if (state.email) secretStore.set(rememberKey(state.email), null);
    resetToLoggedOut();
  }
  return { signedOut: typeof r?.signed_out === "number" ? r.signed_out : 0, current };
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

const UNEXPECTED_SYNC = "The server sent an unexpected response. Reload the page to try again.";

async function doSync() {
  if (!account) return;
  const gen = generation;
  // The last answer known, so a refresh on its way (sign-in, unlock) doesn't hold the sync up.
  const delta = hasFeature(knownPublicConfig() ?? (await loadPublicConfig()), "delta_sync");
  if (gen !== generation || !account) return;
  deltaOn = delta;
  if (!delta) synced = null;
  let merged = await fetchSync(synced?.cursor ?? null, gen);
  // A delta this client can't use (malformed, or about data it no longer has): fetch everything once.
  if (merged === "full") merged = await fetchSync(null, gen);
  if (!merged || merged === "full" || gen !== generation || !account) return;
  if (delta) synced = merged.snapshot;
  bundle = merged.snapshot.bundle;
  materialize(merged.snapshot);
  // Not expected: the answer was older than an own write already shown. Ask again rather than keep it stale.
  if (merged.behind) sync().catch(() => {});
}

/**
 * `GET /sync`, or with a cursor only what changed since, merged into `synced`. Null when the answer is dropped
 * (locked meanwhile, or older than what is shown); "full" when a delta can't be used.
 */
async function fetchSync(cursor: string | null, gen: number): Promise<Merged | "full" | null> {
  const data = await api(cursor ? `/sync?since=${encodeURIComponent(cursor)}` : "/sync");
  if (gen !== generation || !account) return null;
  if (!isSyncResponse(data)) throw new Error(UNEXPECTED_SYNC);
  if (state.status === "unlocked" && data.revision < state.revision) return null;
  let merged: Merged | null = null;
  try {
    merged = mergeSync(cursor ? synced : null, data);
  } catch {
    /* malformed */
  }
  if (merged) return merged;
  if (cursor) return "full";
  throw new Error(UNEXPECTED_SYNC);
}

const byName = new Intl.Collator(undefined, { sensitivity: "base" });

function decryptRow(key: core.VaultKey, row: SyncItemRow): VaultEntry | null {
  const enc: EncryptedItem = { id: row.id, vault_id: row.vault_id, key: row.item_key, data: row.data };
  try {
    const item = key.decryptItem(enc) as Item;
    return { id: row.id, item, vaultId: row.vault_id, revision: row.revision, deletedAt: row.deleted_at, enc };
  } catch {
    return null;
  }
}

/**
 * Decrypt `snap` into the state. A vault's key handle is kept while its key fields stay the same (otherwise it is
 * opened again and its items decrypted again), and an item whose ciphertext didn't change keeps its decrypted copy,
 * so a small delta costs little. Warnings are worked out again each time, as before.
 */
function materialize(snap: Snapshot) {
  const acct = account;
  if (!acct) return;
  const warnings: string[] = [];
  const before = state.vaults;
  const previous = new Map(before.map((v) => [v.id, v]));
  const kept = new Set<core.VaultKey>();
  const opened = new Map<string, SyncVaultRow>();
  const vaults: Vault[] = [];
  for (const v of snap.vaults) {
    const old = previous.get(v.id);
    const from = openedFrom.get(v.id);
    let key: core.VaultKey;
    if (old && from && !vaultKeyChanged(from, v)) {
      key = old.key;
      kept.add(key);
    } else {
      try {
        key = acct.openVaultKey(v.id, v.wrapped_key, v.key_kind);
      } catch {
        warnings.push(`One vault couldn't be opened: its key may have been replaced. Ask the person who manages it to share it with you again.`);
        continue;
      }
    }
    opened.set(v.id, v);
    let name = "Vault";
    try {
      name = key.decryptMeta(v.id, v.meta).name ?? name;
    } catch {
      warnings.push(`Couldn't read the name of one of your vaults.`);
    }
    vaults.push({ id: v.id, name, role: v.role, kind: v.key_kind, key, epoch: typeof v.key_epoch === "number" ? v.key_epoch : undefined });
  }
  const byId = new Map(vaults.map((v) => [v.id, v]));
  const copies = new Map<string, { row: SyncItemRow; entry: VaultEntry | null }>();
  const items: VaultEntry[] = [];
  const failed = new Map<string, number>();
  for (const row of snap.items.values()) {
    const vault = byId.get(row.vault_id);
    if (!vault) continue;
    const old = decrypted.get(row.id);
    let entry: VaultEntry | null;
    if (old && kept.has(vault.key) && sameCiphertext(old.row, row)) {
      entry = old.entry;
      if (entry && (entry.revision !== row.revision || entry.deletedAt !== row.deleted_at)) entry = { ...entry, revision: row.revision, deletedAt: row.deleted_at };
    } else {
      entry = decryptRow(vault.key, row);
    }
    copies.set(row.id, { row, entry });
    if (entry) items.push(entry);
    else failed.set(row.vault_id, (failed.get(row.vault_id) ?? 0) + 1);
  }
  for (const [id, n] of failed) {
    const name = byId.get(id)?.name ?? "a vault";
    warnings.push(`${n === 1 ? "An item" : `${n} items`} in "${name}" couldn't be decrypted and ${n === 1 ? "is" : "are"} hidden.`);
  }
  items.sort((a, b) => byName.compare(a.item.name, b.item.name));
  decrypted = copies;
  openedFrom = opened;
  undecryptable = failed;
  pinPersonalVault(snap.user.id, vaults);
  const names = new Map<string, string | null>();
  const invitations = openInvitations(snap.invitations, (inv) => {
    const cacheKey = `${inv.vault_id}\n${inv.wrapped_key}\n${inv.meta}`;
    let name = invitationNames.get(cacheKey);
    if (name === undefined) name = invitationName(acct, inv.vault_id, inv.wrapped_key, inv.meta);
    names.set(cacheKey, name);
    return name;
  });
  invitationNames = names;
  set({
    status: "unlocked",
    vaults,
    items,
    revision: snap.revision,
    warnings,
    invitations,
    name: snap.user.name,
    emailVerified: snap.user.email_verified,
    pendingRotations: [
      ...new Set([
        ...readPendingRotations(snap.user.id).filter((id) => byId.has(id)),
        // Marked by the server when someone left or was removed without a key change; only admins can replace it.
        ...snap.vaults.filter((v) => v.rotation_pending && (v.role === "owner" || v.role === "admin")).map((v) => v.id),
      ]),
    ],
  });
  // Handles the new state no longer uses (a vault gone, or its key replaced).
  before.forEach((v) => {
    if (!kept.has(v.key)) v.key.free();
  });
  // A vault came or went, or a key was replaced (on another device too): personal vaults may need new
  // emergency-access wraps. The first sync after unlocking runs the hook itself (`openVault`).
  if (before.length && vaultsMoved(before, vaults)) vaultKeysChanged();
}

/** Whether two vault lists differ in their vaults or in a vault's key epoch. */
function vaultsMoved(before: readonly Vault[], after: readonly Vault[]): boolean {
  if (before.length !== after.length) return true;
  const epochs = new Map(before.map((v) => [v.id, v.epoch]));
  return after.some((v) => !epochs.has(v.id) || epochs.get(v.id) !== v.epoch);
}

/**
 * The name of a vault offered in an invitation: its key, sealed to this account, is opened for that alone and freed at
 * once (nothing of the vault is read or kept before the user accepts). Null when it can't be opened.
 */
function invitationName(acct: core.Account, vaultId: string, sealed: string, meta: string): string | null {
  let key: core.VaultKey;
  try {
    key = acct.openVaultKey(vaultId, sealed, "sealed");
  } catch {
    return null;
  }
  try {
    const name = (key.decryptMeta(vaultId, meta) as { name?: unknown } | null)?.name;
    return typeof name === "string" && name.trim() ? name : "Shared vault";
  } catch {
    return null;
  } finally {
    key.free();
  }
}

/**
 * A live-sync message: sync only when it announces something this client doesn't have yet (`noticeAction`). With
 * delta sync, a sync already on its way may bring it, so that one is waited for before deciding.
 */
async function onSyncNotice(msg: SyncNotice) {
  if (!deltaOn) {
    if (noticeAction(msg, () => undefined, state.revision, false) === "sync") sync().catch(() => {});
    return;
  }
  const pending = running;
  if (pending) await pending.catch(() => {});
  if (state.status !== "unlocked") return;
  if (noticeAction(msg, (id) => knownSeq(synced, id), state.revision, true) === "sync") sync().catch(() => {});
}

/** This session's live-sync origin (the socket's `hello`), or null while not connected. Every tab of the session shares it. */
export const liveSyncOrigin = (): string | null => liveOrigin;

/**
 * Live-sync news for other parts of the app (`device-login-client.ts`): a new connection (`connected`), a device asking
 * to sign in to the account (`auth_request`) and a request answered by any app (`auth_request_answered`).
 */
export type LiveNotice = { type: "connected" } | { type: "auth_request" | "auth_request_answered"; id: string };
const liveListeners = new Set<(n: LiveNotice) => void>();

/** Run `fn` for every live-sync notice; returns the unsubscribe. */
export function onLiveNotice(fn: (n: LiveNotice) => void) {
  liveListeners.add(fn);
  return () => {
    liveListeners.delete(fn);
  };
}

function emitLive(n: LiveNotice) {
  liveListeners.forEach((fn) => {
    try {
      fn(n);
    } catch {
      /* a listener's failure is its own, never the socket's */
    }
  });
}

/** Reconnect delay: 3 s after a healthy connection drops, doubling to 2 min while the server stays unreachable. */
const RECONNECT_MIN = 3000;
const RECONNECT_MAX = 120_000;
let reconnectDelay = RECONNECT_MIN;
let onlineListener: (() => void) | null = null;

function connectSocket() {
  socket?.close();
  const t = getTokens();
  // The server refuses live sync until two-step login is set up (`continueAfterTwoStep` connects).
  if (!t || state.status === "two-step") return;
  if (typeof navigator !== "undefined" && navigator.onLine === false) {
    // Offline: don't hammer the network; reconnect when the browser/OS reports a connection again.
    if (!onlineListener && typeof window !== "undefined") {
      onlineListener = () => {
        window.removeEventListener("online", onlineListener!);
        onlineListener = null;
        if (state.status === "unlocked") connectSocket();
      };
      window.addEventListener("online", onlineListener);
    }
    return;
  }
  const ws = new WebSocket(server.wsUrl(`/ws?access_token=${encodeURIComponent(t.access)}`));
  socket = ws;
  liveOrigin = null;
  ws.onopen = () => {
    reconnectDelay = RECONNECT_MIN;
    // Anything announced while this app wasn't connected (sign-in requests) is listed again.
    if (socket === ws) emitLive({ type: "connected" });
  };
  ws.onmessage = (e) => {
    let msg: { type?: string; origin?: unknown; id?: unknown } | null;
    try {
      msg = JSON.parse(e.data);
    } catch {
      return;
    }
    if (!msg || typeof msg !== "object") return;
    // Remembered, but never a reason to skip a message: every tab and window of this session shares it.
    if (msg.type === "hello" && socket === ws) liveOrigin = typeof msg.origin === "string" ? msg.origin : null;
    if (msg.type === "sync") void onSyncNotice(msg as SyncNotice);
    if (msg.type === "logout") confirmSignedOut();
    // The admin now requires two-step login and the account has no method yet: the server closes the connection next.
    if (isTwoStepNotice(msg) && socket === ws) enterTwoStepGate();
    if ((msg.type === "auth_request" || msg.type === "auth_request_answered") && typeof msg.id === "string" && socket === ws) emitLive({ type: msg.type, id: msg.id });
  };
  ws.onclose = (e) => {
    // Closed because two-step login is required first (policy): the gate shows, and nothing reconnects until a method
    // is set up (`continueAfterTwoStep`), as after a 403 `two_step_required`.
    if (socket === ws && isTwoStepClose(e.code, e.reason)) return enterTwoStepGate();
    if (socket !== ws || state.status !== "unlocked") return;
    // Reconnect after the access token has had a chance to refresh; back off while the server is unreachable
    // (a desktop app in the tray would otherwise retry every few seconds all night). `resync()` on wake/focus
    // reconnects at once regardless of the delay.
    const delay = reconnectDelay + Math.random() * 1000;
    reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX);
    setTimeout(() => {
      if (state.status === "unlocked" && socket === ws) {
        api<{ revision: number }>("/sync/revision")
          .then((r) => (r.revision > state.revision ? sync() : undefined))
          .catch(() => {})
          .finally(() => {
            if (state.status === "unlocked" && socket === ws) connectSocket();
          });
      }
    }, delay);
  };
}

/**
 * Desktop: after sleep, a network change or on the background-sync timer. The live connection can die without a
 * close event, so the server is asked for its revision first (which also refreshes an expired access token),
 * the connection is reopened and the vault synced if the server has anything newer. A no-op while locked.
 */
export async function resync(): Promise<void> {
  if (state.status !== "unlocked") return;
  const r = await api<{ revision: number }>("/sync/revision");
  if (state.status !== "unlocked") return;
  reconnectDelay = RECONNECT_MIN;
  connectSocket();
  if (r.revision > state.revision) await sync();
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

const LOCKED = "The vault is locked. Unlock it and try again.";
const KEY_CHANGED_AGAIN = "Someone replaced this vault's key just now. Try again.";
const CHANGED_ELSEWHERE =
  "This item was changed on another device or by someone you share the vault with, so your changes weren't saved. Choose which version to keep, then save again.";
const ITEM_GONE = "This item is no longer in your vault. It may have been deleted on another device.";

/** A vault with its key handle and that key's epoch, read together: both come from the same /sync. */
function vaultFor(vaultId: string): Vault {
  const v = state.vaults.find((x) => x.id === vaultId);
  if (!v) throw new Error(state.status === "unlocked" ? "Vault not found." : LOCKED);
  return v;
}

/** `key_epoch` for a body encrypted with (or wrapping) `v.key`; nothing for servers without key epochs. */
const epochOf = (v: Vault | undefined) => (v?.epoch === undefined ? {} : { key_epoch: v.epoch });

/** 409 vault_key_changed: the vault's key was replaced after our last sync, and nothing was written. */
const keyChanged = (e: unknown) => hasErrorCode(e, "vault_key_changed");
/** 409: the item's revision isn't the one the edit started from. */
const revisionConflict = (e: unknown) => hasErrorCode(e, "revision_conflict", "item changed on another device; sync and retry");
/** 409: a create named an id that already exists (with other content, on servers that accept repeated creates). */
const itemExists = (e: unknown) => hasErrorCode(e, "item_exists", "item id already exists");
/** Worth another try after a pause: no connection, the server failing for a moment, or too many requests. */
const transient = (e: unknown) => e instanceof UnreachableError || (e instanceof ApiError && (e.status === 429 || (e.status >= 500 && !isOutOfStorage(e))));

/** Sync after the server reported newer data (a new vault key, a newer item); fails when the vault was locked meanwhile. */
async function catchUp() {
  await sync();
  if (state.status !== "unlocked") throw new Error(LOCKED);
}

/** What item writes answer: the item's new revision and, with delta sync, the vault's number after the write. */
type WriteAnswer = { revision?: unknown; vault_seq?: unknown } | null;

/**
 * After one of this client's item writes, update the vault with the least work. Without delta sync: a sync, as
 * before. With it, the write's `vault_seq` says whether anything else happened in the vault (`afterWrite`): a number
 * this client already has means a sync since brought the write (nothing to do); exactly the next number means the
 * write was the only change, so `own()` (the row as the server stored it, when this client knows it) is shown
 * without asking; anything else is a delta sync. A sync that was already asking before the write was answered may
 * not include it, so it is waited for before deciding.
 */
async function settle(vaultId: string | undefined, answer: WriteAnswer, own?: (vaultSeq: number) => OwnWrite | null): Promise<void> {
  const gen = generation;
  const vaultSeq = answer?.vault_seq;
  if (!deltaOn || !vaultId || typeof vaultSeq !== "number") return sync();
  const pending = running;
  if (pending) await pending.catch(() => {});
  if (gen !== generation) return;
  const action = afterWrite(knownSeq(synced, vaultId), vaultSeq, !!own);
  if (action === "none") return;
  if (action === "apply" && own && synced && state.status === "unlocked") {
    const write = own(vaultSeq);
    if (write) {
      synced = applyOwnWrite(synced, write);
      materialize(synced);
      return;
    }
  }
  return sync();
}

/**
 * The row the server stored for an item this client just sent (`enc`): `base` is its row before the write (edits keep
 * its trash state). Row times are the server's own; nothing reads them, and the next delta brings the stored ones.
 */
function storedRow(enc: EncryptedItem, answer: WriteAnswer, base: SyncItemRow | null): SyncItemRow | null {
  if (typeof answer?.revision !== "number") return null;
  const now = Math.floor(Date.now() / 1000);
  return { id: enc.id, vault_id: enc.vault_id, item_key: enc.key, data: enc.data, revision: answer.revision, deleted_at: base?.deleted_at ?? null, created_at: base?.created_at ?? now, updated_at: now };
}

/** The vault an item is in, read before a write that names only the item. */
const vaultOf = (id: string): string | undefined => synced?.items.get(id)?.vault_id ?? state.items.find((x) => x.id === id)?.vaultId;

/**
 * Send a write encrypted with a vault key. When the server has replaced that key since our last sync (409
 * vault_key_changed, nothing written), sync, which brings the new key, and send it once more. `send` must look the
 * vault up again on every call: the sync frees the old key handles.
 */
async function withCurrentKey<T>(send: () => Promise<T>): Promise<T> {
  try {
    return await send();
  } catch (e) {
    if (!keyChanged(e)) throw e;
  }
  await catchUp();
  try {
    return await send();
  } catch (e) {
    throw keyChanged(e) ? new Error(KEY_CHANGED_AGAIN) : e;
  }
}

/** Vaults the user can write to, their own vault first. */
export function writableVaults() {
  const first = defaultVaultId();
  return state.vaults.filter((v) => v.role !== "read").sort((a, b) => (a.id === first ? -1 : b.id === first ? 1 : 0));
}

/** A new item id. The editor keeps one per new item, so saving again after a failure can't make a second copy. */
export const newItemId = (): string => core.newId();

/**
 * Save a new item. When trying again after a failure, pass the same `id`: if the earlier try was saved and only its
 * answer got lost, the item is updated with this content instead of being saved twice.
 */
export async function createItem(vaultId: string, item: Item, id: string = newItemId()): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const data = { ...item, created_at: now, updated_at: now };
  let sent: { enc: EncryptedItem; answer: WriteAnswer };
  try {
    sent = await withCurrentKey(async () => {
      const v = vaultFor(vaultId);
      const enc = v.key.encryptItem(data, id, vaultId) as EncryptedItem;
      return { enc, answer: await api<WriteAnswer>("/items", { body: { ...enc, ...epochOf(v) } }) };
    });
  } catch (e) {
    if (!itemExists(e)) throw e;
    // An earlier try with this id was saved. This try was encrypted afresh, so the server can't tell it's the same
    // item: save this content over the saved one.
    await catchUp();
    const saved = state.items.find((x) => x.id === id);
    if (!saved) throw e;
    await saveOver(saved, { ...data, created_at: saved.item.created_at }, vaultId);
    return id;
  }
  await settle(vaultId, sent.answer, (vaultSeq) => {
    const row = storedRow(sent.enc, sent.answer, null);
    return row && { kind: "upsert", row, vaultSeq };
  });
  return id;
}

export async function updateItem(entry: VaultEntry, item: Item, vaultId = entry.vaultId) {
  const now = Math.floor(Date.now() / 1000);
  const old = entry.item.login?.password;
  const next = { ...item, updated_at: now };
  if (next.login && old && old !== next.login.password && next.password_history[0]?.password !== old) {
    next.password_history = [{ password: old, changed_at: now }, ...next.password_history].slice(0, 20);
  }
  await saveOver(entry, next, vaultId);
}

/** `putItem`, then show the result. A move changes two vaults but answers only the target's number: never shown as sent. */
async function saveOver(base: VaultEntry, next: Item, vaultId: string) {
  const sent = await putItem(base, next, vaultId);
  // An earlier try had been stored: the sync that found out already shows it.
  if (!sent) return;
  const own =
    sent.from === vaultId
      ? (vaultSeq: number): OwnWrite | null => {
          const before = synced?.items.get(sent.enc.id);
          const row = before?.vault_id === vaultId ? storedRow(sent.enc, sent.answer, before) : null;
          return row && { kind: "upsert", row, vaultSeq };
        }
      : undefined;
  await settle(vaultId, sent.answer, own);
}

/** JSON with object keys sorted, to compare items whatever order their fields were set in. */
function canonical(item: Item, ignore: string[] = []): string {
  const sort = (v: unknown): unknown =>
    Array.isArray(v)
      ? v.map(sort)
      : v && typeof v === "object"
        ? Object.fromEntries(
            Object.keys(v)
              .sort()
              .map((k) => [k, sort((v as Record<string, unknown>)[k])]),
          )
        : v;
  const copy: Record<string, unknown> = { ...item };
  ignore.forEach((k) => delete copy[k]);
  return JSON.stringify(sort(copy));
}

/** Only the item's encryption or revision changed (e.g. its vault key was replaced), not its content or place. */
function sameItem(a: VaultEntry, b: VaultEntry) {
  return a.vaultId === b.vaultId && a.deletedAt === b.deletedAt && canonical(a.item) === canonical(b.item);
}

/** The server already holds `next` in `vaultId`: an earlier try of this save was stored, only its answer got lost. */
function holds(entry: VaultEntry, next: Item, vaultId: string) {
  // updated_at is set per try, and the core stamps `format` when it encrypts.
  return entry.vaultId === vaultId && canonical(entry.item, ["updated_at", "format"]) === canonical(next, ["updated_at", "format"]);
}

/**
 * PUT `next` over `base` (into `vaultId`; another vault moves it) with the revision the edit started from. When the
 * server has newer data (a new vault key, or a newer revision), sync: if only the item's encryption changed, send it
 * again on top of the new version; if its content changed, stop, so nobody's change is overwritten unseen (the
 * synced vault shows the newer version, and the editor offers to keep or discard the user's changes).
 */
async function putItem(base: VaultEntry, next: Item, vaultId: string): Promise<{ enc: EncryptedItem; answer: WriteAnswer; from: string } | null> {
  for (let attempt = 1; ; attempt++) {
    try {
      const v = vaultFor(vaultId);
      const enc = (vaultId === base.vaultId ? v.key.updateItem(base.enc, next) : v.key.encryptItem(next, base.id, vaultId)) as EncryptedItem;
      const answer = await api<WriteAnswer>(`/items/${base.id}`, { method: "PUT", body: { ...enc, revision: base.revision, ...epochOf(v) } });
      return { enc, answer, from: base.vaultId };
    } catch (e) {
      if (!keyChanged(e) && !revisionConflict(e)) throw e;
      await catchUp();
      const fresh = state.items.find((x) => x.id === base.id);
      if (!fresh) throw new Error(ITEM_GONE);
      if (fresh.deletedAt === base.deletedAt && holds(fresh, next, vaultId)) return null;
      if (!sameItem(fresh, base)) throw new Error(CHANGED_ELSEWHERE);
      if (attempt > 1) throw new Error(keyChanged(e) ? KEY_CHANGED_AGAIN : CHANGED_ELSEWHERE);
      base = fresh;
    }
  }
}

export async function trashItem(id: string) {
  const vaultId = vaultOf(id);
  const answer = await api<WriteAnswer>(`/items/${id}`, { method: "DELETE" });
  // The server stamps when it went to the trash, so it is fetched rather than guessed.
  await settle(vaultId, answer);
}

export async function restoreItem(id: string) {
  const vaultId = vaultOf(id);
  const answer = await api<WriteAnswer>(`/items/${id}/restore`, { method: "POST" });
  await settle(vaultId, answer, (vaultSeq) => {
    const before = synced?.items.get(id);
    if (!before || before.vault_id !== vaultId || typeof answer?.revision !== "number") return null;
    return { kind: "upsert", vaultSeq, row: { ...before, deleted_at: null, revision: answer.revision, updated_at: Math.floor(Date.now() / 1000) } };
  });
}

export async function purgeItem(id: string) {
  const vaultId = vaultOf(id);
  const answer = await api<WriteAnswer>(`/items/${id}/permanent`, { method: "DELETE" });
  await settle(vaultId, answer, vaultId ? (vaultSeq) => ({ kind: "remove", id, vaultId, vaultSeq }) : undefined);
}

// ---------------------------------------------------------------- history

/** Earlier versions of an item, newest first (servers with `item_history`; any member of its vault may list them). */
export async function listItemVersions(itemId: string): Promise<ItemVersion[]> {
  return readVersions(await api(`/items/${itemId}/versions`));
}

/**
 * One earlier version, decrypted with its vault's key. A version is encrypted with the vault key of its time; replacing
 * the key deletes the vault's versions, so the current key opens every version the server still lists.
 */
export async function openItemVersion(itemId: string, seq: number): Promise<{ version: ItemVersion; item: Item }> {
  const stored = readVersion(await api(`/items/${itemId}/versions/${seq}`));
  if (!stored) throw new Error("The server sent an unexpected response. Try again.");
  // Looked up after the request: a sync meanwhile may have replaced the key handle.
  const v = vaultFor(stored.vaultId);
  let item: Item;
  try {
    item = v.key.decryptItem({ id: itemId, vault_id: stored.vaultId, key: stored.itemKey, data: stored.data }) as Item;
  } catch {
    throw new Error("This version can't be opened with the vault's current key.");
  }
  return { version: { seq: stored.seq, savedAt: stored.savedAt, savedBy: stored.savedBy }, item };
}

/**
 * Restore an earlier version: an ordinary edit with its content (key epoch, revision check, delta sync as any save), so
 * what the item holds now becomes a version in turn. Earlier passwords of both are kept in the password history.
 */
export async function restoreItemVersion(entry: VaultEntry, version: Item) {
  await updateItem(entry, restoredItem(version, entry.item));
}

const IMPORT_BATCH = 250;
/** Encrypted bytes per import request at most, well below the server's 64 MiB limit for a request body. */
const IMPORT_BATCH_BYTES = 16 * 1024 * 1024;
/** Tries per batch after network or server failures (a vault key change gets one more). */
const IMPORT_TRIES = 3;
const LOCKED_DURING_IMPORT = "The vault was locked during the import. Unlock it and import the file again.";

/** What the server takes per import (`/api/config` `limits`; older servers don't say). */
export interface ImportLimits {
  max_import_items?: number;
  max_item_kib?: number;
}

const positive = (n: unknown): number | undefined => (typeof n === "number" && Number.isFinite(n) && n >= 1 ? Math.floor(n) : undefined);

/**
 * An imported item as it is saved: the file's creation time when it has one, saved now. A file list is left out: its
 * files belong to the item they were attached to (removing one from the copy would delete the original's file).
 */
const forImport = (it: Item, now: number): Item => ({ ...stripAttachments(it), created_at: it.created_at || now, updated_at: now });

/**
 * Indexes of the items whose encrypted form is larger than the server takes (`max_item_kib`): they can't be imported.
 * Only items near the limit are measured exactly, by encrypting them.
 */
export function oversizedForImport(vaultId: string, items: Item[], maxItemKib: number): number[] {
  const limit = maxItemKib * 1024;
  const now = Math.floor(Date.now() / 1000);
  const out: number[] = [];
  items.forEach((it, i) => {
    const item = forImport(it, now);
    if (encryptedSizeBound(item) <= limit) return;
    try {
      const enc = vaultFor(vaultId).key.encryptItem(item, core.newId(), vaultId) as EncryptedItem;
      if (enc.data.length > limit || enc.key.length > limit) out.push(i);
    } catch {
      /* not encryptable at all: the import itself reports it */
    }
  });
  return out;
}

/**
 * Encrypt and upload imported items in batches: at most the server's `max_import_items` (and 250) items and 16 MiB
 * per request. After a network or server failure a batch is sent again with the same item ids and the same request,
 * so a batch that was saved but whose answer got lost isn't saved twice. Items too large for the server must be left
 * out first (`oversizedForImport`): a batch is saved whole or not at all.
 */
export async function importItems(vaultId: string, items: Item[], progress?: (done: number) => void, limits?: ImportLimits) {
  const gen = generation;
  const now = Math.floor(Date.now() / 1000);
  const perRequest = Math.min(IMPORT_BATCH, positive(limits?.max_import_items) ?? IMPORT_BATCH);
  let batch: { id: string; item: Item }[] = [];
  let bytes = 0;
  let done = 0;
  const send = async () => {
    if (gen !== generation) throw new Error(LOCKED_DURING_IMPORT);
    await sendImportBatch(vaultId, batch, gen);
    done += batch.length;
    progress?.(done);
    batch = [];
    bytes = 0;
  };
  for (const it of items) {
    const item = forImport(it, now);
    const size = encryptedSizeBound(item);
    if (batch.length && (batch.length >= perRequest || bytes + size > IMPORT_BATCH_BYTES)) await send();
    batch.push({ id: core.newId(), item });
    bytes += size;
  }
  if (batch.length) await send();
  await sync();
}

async function sendImportBatch(vaultId: string, batch: { id: string; item: Item }[], gen: number) {
  // Look the key up for every encryption: a sync (the previous batch's, or after a key change) frees the old handle.
  const encrypt = () => {
    const v = vaultFor(vaultId);
    return { items: batch.map((b) => ({ ...v.key.encryptItem(b.item, b.id, vaultId), ...epochOf(v) })) };
  };
  let body = encrypt();
  let rekeyed = false;
  for (let attempt = 1; ; attempt++) {
    try {
      await api("/items/import", { body });
      return;
    } catch (e) {
      if (gen !== generation) throw new Error(LOCKED_DURING_IMPORT);
      if (keyChanged(e) && !rekeyed) {
        rekeyed = true;
        await catchUp();
        body = encrypt(); // the same ids under the new key
      } else if (attempt > 1 && itemExists(e)) {
        // A batch is saved whole or not at all, and its ids are new: an earlier try was saved, only its answer got lost.
        return;
      } else if (attempt < IMPORT_TRIES && transient(e)) {
        const seconds = e instanceof ApiError && e.retryAfter !== undefined ? Math.min(e.retryAfter, 60) : attempt * 2;
        await new Promise((resolve) => setTimeout(resolve, seconds * 1000));
        if (gen !== generation) throw new Error(LOCKED_DURING_IMPORT);
      } else throw keyChanged(e) ? new Error(KEY_CHANGED_AGAIN) : e;
    }
  }
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
  vaultKeysChanged();
  return id;
}

export async function renameVault(id: string, name: string) {
  await withCurrentKey(() => {
    const v = vaultFor(id);
    return api(`/vaults/${id}`, { method: "PUT", body: { meta: v.key.encryptMeta(id, { name }), ...epochOf(v) } });
  });
  await sync();
}

export async function deleteVault(id: string) {
  await api(`/vaults/${id}`, { method: "DELETE" });
  await sync();
}

/** Someone on this server to share a vault with, by email (404 when there is nobody); their public key checked to be a string. */
export async function lookupUser(email: string): Promise<{ user_id: string; name: string; public_key: string }> {
  const found = readFoundUser(await api(`/users/lookup?email=${encodeURIComponent(email)}`));
  if (!found) throw new Error(UNEXPECTED_RESPONSE);
  return found;
}

/**
 * Share a vault (or change an existing member's or invitee's access). With servers that have invitations, someone who
 * isn't a member yet gets an invitation: "invited" until they accept. Null from older servers (always a member at once).
 */
export async function shareVault(vaultId: string, user: { user_id: string; public_key: string }, role: Role): Promise<"invited" | "active" | null> {
  if (typeof user.user_id !== "string" || typeof user.public_key !== "string" || !user.public_key) throw new Error(UNEXPECTED_RESPONSE);
  const r = await withCurrentKey(() => {
    const v = vaultFor(vaultId);
    return api<{ status?: unknown; rotation_pending?: unknown } | null>(`/vaults/${vaultId}/members`, {
      body: { user_id: user.user_id, role, sealed_key: v.key.shareTo(vaultId, user.public_key), ...epochOf(v) },
    });
  });
  if (r?.rotation_pending === true) {
    // The vault was personal and wrapped for emergency contacts, who may hold its key: replace it now, for everyone
    // in it (the new invitee too). If that fails, the vault notices keep asking for it.
    try {
      await rotateVaultKey(vaultId);
    } catch (e) {
      throw new Error(`Shared, but the vault's key wasn't replaced yet: ${friendlyError(e)} Finish it with "Replace vault key" in this vault's settings.`);
    }
  }
  return r?.status === "invited" || r?.status === "active" ? r.status : null;
}

/** Accept a vault shared with the account: it becomes a membership, and the next sync brings the vault whole. */
export async function acceptInvitation(vaultId: string) {
  try {
    await api(`/vaults/${vaultId}/invitation/accept`, { method: "POST" });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 404)) throw e;
    // Cancelled by the person who shared it, or the vault is gone: show what is there now.
    await sync().catch(() => {});
    throw new Error("This invitation is no longer open. The person who shared the vault may have cancelled it.");
  }
  await sync();
}

/**
 * Decline a vault shared with the account. The server then asks the vault's owners and admins to replace its key: the
 * invitation already gave this account the key. Already gone (404) is fine: the list is refreshed.
 */
export async function declineInvitation(vaultId: string) {
  try {
    await api(`/vaults/${vaultId}/invitation`, { method: "DELETE" });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 404)) throw e;
  }
  await sync();
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
  // Removal and the new key in one request, so nobody is ever removed without the key change.
  try {
    await sendRotation(vaultId, `/vaults/${vaultId}/members/${userId}/remove`, userId);
  } catch (e) {
    // Servers before 0.6.4 don't have the combined request: remove, then replace the key.
    if (!(e instanceof ApiError) || (e.status !== 404 && e.status !== 405)) throw e;
    const r = await api<{ rotation_required?: boolean }>(`/vaults/${vaultId}/members/${userId}`, { method: "DELETE" });
    if (r?.rotation_required === false) return sync();
    setPendingRotation(vaultId, true);
    await rotateVaultKey(vaultId);
    return;
  }
  setPendingRotation(vaultId, false);
  await sync();
  // Without its last other member the vault may be personal again.
  vaultKeysChanged();
}

/** Replace a vault's key and re-encrypt its items (finishes a member removal). */
export async function rotateVaultKey(vaultId: string) {
  await sendRotation(vaultId, `/vaults/${vaultId}/rotate`);
  setPendingRotation(vaultId, false);
  await sync();
  vaultKeysChanged();
}

/**
 * Replace the keys of these vaults, one after the other (after an emergency contact who may have kept their keys was
 * removed). Vaults this account no longer has or can't manage are skipped. The first failure stops it and is thrown;
 * the server keeps asking for the rest (`rotation_pending`).
 */
export async function rotateVaultKeys(vaultIds: readonly string[]) {
  await sync();
  try {
    for (const id of vaultIds) {
      const v = state.vaults.find((x) => x.id === id);
      if (!v || (v.role !== "owner" && v.role !== "admin")) continue;
      await sendRotation(id, `/vaults/${id}/rotate`);
      setPendingRotation(id, false);
    }
  } finally {
    await sync().catch(() => {});
    vaultKeysChanged();
  }
}

/**
 * Make a new vault key, seal it to every member except `without`, re-encrypt all
 * items and the vault name with it, and POST that to `path` (rotate, or remove + rotate).
 */
async function sendRotation(vaultId: string, path: string, without?: string) {
  if (!account) throw new Error("Vault is locked.");
  const gen = generation;
  await sync();
  if (gen !== generation || !account) throw new Error("The vault was locked. Unlock it and try again.");
  if (undecryptable.get(vaultId)) throw new Error("Some items in this vault can't be decrypted, so its key can't be replaced yet.");
  // Every member and invitee gets the new key: a row that can't be read stops the replacement (nobody is skipped).
  const all = readMembers(await api(`/vaults/${vaultId}/members`));
  if (!all) throw new Error(UNEXPECTED_RESPONSE);
  if (gen !== generation || !account) throw new Error("The vault was locked. Unlock it and try again.");
  const members = all.filter((m) => m.user_id !== without);
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
    let r: { key_epoch?: number } | null;
    try {
      // key_epoch: the epoch of the key being replaced, from the same sync as the items re-encrypted above.
      r = await api<{ key_epoch?: number } | null>(path, { body: { keys, items, meta, ...epochOf(v) } });
    } catch (e) {
      if (!keyChanged(e)) throw e;
      // Someone else replaced the key after our sync, and nothing was changed. Show the vault as it is now and let
      // the user decide again. Their new key also finishes a removal this browser still had to secure.
      if (!without) setPendingRotation(vaultId, false);
      await sync().catch(() => {});
      throw new Error(
        without
          ? "Someone else replaced this vault's key just now, so nobody was removed. Check the members, then try again."
          : "Someone else replaced this vault's key just now. If the vault still asks for a new key, replace it again.",
      );
    }
    // Servers from before the vault name moved into the rotation request (they report no key epoch) need it separately.
    if (meta && !without && typeof r?.key_epoch !== "number") await api(`/vaults/${vaultId}`, { method: "PUT", body: { meta } });
  } finally {
    fresh.free();
  }
}

// ---------------------------------------------------- password / Secret Key

/**
 * Change master password and/or Secret Key setting. Returns the new Secret Key, if any. The new keys follow the server's
 * key-derivation minimums, so a change with the same password fixes a `kdf` policy violation.
 */
export async function changeKeys(currentPassword: string, newPassword: string, withSecretKey: boolean): Promise<string | null> {
  if (!account || !bundle) throw new Error("Vault is locked.");
  const reauthToken = await reauth(currentPassword);
  const kdf = await kdfMinimums();
  // Looked up again after the requests: a lock meanwhile frees the keys.
  if (!account || !bundle) throw new Error("Vault is locked.");
  const existing = bundle.secret_key_enabled ? rememberedSecretKey(state.email) : null;
  const next = account.rewrapWithKdf(bundle, newPassword, withSecretKey, existing ?? undefined, kdf.memory, kdf.iterations);
  const master = next.takeMaster();
  try {
    const start = core.opaqueRegisterStart(master);
    const resp = expectStrings(await api("/account/keys/start", { body: { message: start.message } }), "message");
    const upload = core.opaqueRegisterFinish(start.state, master, resp.message);
    await api("/account/keys/finish", { body: { upload, bundle: next.bundle }, headers: { "x-reauth-token": reauthToken } });
    bundle = next.bundle as Bundle;
    if (!withSecretKey) rememberSecretKey(state.email, null);
    else if (next.secretKey) rememberSecretKey(state.email, next.secretKey);
    // New keys may meet policies the old ones didn't (Secret Key, key derivation).
    void refreshPolicyViolations().catch(() => {});
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
