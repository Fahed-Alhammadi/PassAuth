/** HTTP client for the configured PassAuth server, with refresh-token rotation. */

import { oneLine } from "@web/lib/text";
import { AppError, INSUFFICIENT_STORAGE, QUOTA_EXCEEDED, signedOutError, TWO_STEP_REQUIRED, UNREACHABLE } from "../shared/errors";

/** No server address set for the account yet. */
const NO_SERVER = "no_server";

import { knownFeatures, local } from "./storage";

/**
 * A failed API request. `code` is the server's error code (API v2: `{error,
 * message}`); for older servers that only said why in the message text, the
 * known reasons are mapped to the same codes (`errorCode`), so callers check
 * codes, never message text.
 */
export class ApiError extends AppError {
  readonly status: number;
  /** Seconds to wait before trying again (429 Retry-After). */
  readonly retryAfter: number | undefined;
  constructor(status: number, code: string, message: string, retryAfter?: number) {
    super(code, message);
    this.name = "ApiError";
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

export const UNREACHABLE_TEXT = "Can't reach your PassAuth server. Check the server address and your connection.";
const unreachable = () => new AppError(UNREACHABLE, UNREACHABLE_TEXT, true);

/** Sent with every API request (API contract v2): which client and version is talking. */
export const clientHeaders = (): Record<string, string> => ({ "x-passauth-client": `extension/${chrome.runtime.getManifest().version}` });

/** A hung server must not stall the popup, badge, inline menu or passkey flows. */
const TIMEOUT_MS = 15_000;
export const timeoutSignal = (ms = TIMEOUT_MS) => AbortSignal.timeout(ms);

/** Reasons older servers gave only as the message text, and the code newer ones send. */
const LEGACY_MESSAGES: Record<string, string> = {
  email_not_verified: "email_not_verified",
  reauth_required: "reauth_required",
  "item id already exists": "item_exists",
  "item changed on another device; sync and retry": "revision_conflict",
};

/** 403 `quota_exceeded` in plain words: the vault owner's item or storage limit (admin page) would be passed. The same words as the other apps. */
export const QUOTA_TEXT = "You've reached this server's storage limit. Delete items or ask the server's admin.";
/** 507 `insufficient_storage`: the server's disk is down to its admin's reserve; nothing new is stored. The same words as the other apps. */
export const STORAGE_TEXT = "Your server is running out of storage space, so this wasn't saved. Ask the server's admin.";
/** 403 `two_step_required`: the server requires two-step login and the account has no method yet. */
export const TWO_STEP_TEXT = "Your server requires two-step login. Set it up in the web vault, then try again.";

/**
 * Codes PassAuth explains in its own words. Any other code — the generic ones (`bad_request`, `forbidden`,
 * `conflict`, `not_found`, `internal`…) too — gets PassAuth's generic sentence with the request id, and the server's
 * message only as a labelled detail (`unknownError`): a server never puts its own sentences into PassAuth's mouth.
 */
const FRIENDLY: Record<string, string> = {
  email_not_verified: "Confirm your email address first, then sign in.",
  reauth_required: "Enter your master password again to confirm it's you.",
  revision_conflict: "This item was changed on another device. PassAuth has the latest version now; check it and try again.",
  item_exists: "This item was already saved.",
  vault_key_changed: "This vault's key was just replaced. Try again.",
  expired: "This step has expired. Start again.",
  invalid_code: "That code isn't right. Check it and try again.",
  invalid_credentials: "Wrong email, master password or Secret Key.",
  session_expired: "Your session has ended. Sign in again.",
  account_disabled: "This account was turned off by your server's admin.",
  signups_closed: "This server isn't taking new accounts.",
  already_enabled: "This is already turned on.",
  too_large: "That's larger than your server allows.",
  attachments_disabled: "Your server's admin has turned files off.",
  login_with_device_disabled: "Your server's admin has turned off signing in with another device.",
  [QUOTA_EXCEEDED]: QUOTA_TEXT,
  [INSUFFICIENT_STORAGE]: STORAGE_TEXT,
  [TWO_STEP_REQUIRED]: TWO_STEP_TEXT,
};

/** The longest server message shown (as a detail), in characters. */
export const SERVER_MESSAGE_MAX = 200;

/**
 * An error whose code PassAuth has no words for: its generic sentence, the request id (to give the server's admin),
 * and the server's message as a labelled detail: one line without control or format characters, cut short
 * (`oneLine`, the web vault's).
 */
export function unknownError(json: unknown): string {
  const j = (json ?? {}) as { message?: unknown; request_id?: unknown };
  const id = typeof j.request_id === "string" && /^[\w.:-]{1,64}$/.test(j.request_id) ? j.request_id : "";
  const detail = oneLine(j.message, SERVER_MESSAGE_MAX);
  return ["Your PassAuth server couldn't do this.", id ? `Request ID: ${id}.` : "", detail ? `Server message: ${detail}` : ""].filter(Boolean).join(" ");
}

/** The error code of a failed response: the v2 `error` code, else a known reason from the message text, else the generic code. */
export function errorCode(json: unknown): string {
  const j = (json ?? {}) as { error?: unknown; message?: unknown };
  const code = typeof j.error === "string" ? j.error : "";
  const message = typeof j.message === "string" ? j.message : "";
  if (code && !GENERIC.has(code)) return code;
  return LEGACY_MESSAGES[message] ?? (code || "error");
}
/** Codes older servers used for many reasons; the message text says which. */
const GENERIC = new Set(["bad_request", "forbidden", "conflict", "error"]);

/** Retry-After: seconds, or an HTTP date. */
export function retryAfterSeconds(value: string | null, now = Date.now()): number | undefined {
  if (!value) return undefined;
  const v = value.trim();
  if (/^\d+$/.test(v)) return Number(v);
  const at = Date.parse(v);
  return Number.isFinite(at) ? Math.max(0, Math.ceil((at - now) / 1000)) : undefined;
}

const waitText = (s: number) => (s <= 1 ? "a moment" : s < 90 ? `${s} seconds` : `${Math.ceil(s / 60)} minutes`);

/** The ApiError for a failed response (`json`: its parsed body, or null). */
export function apiError(status: number, json: unknown, retryAfter?: number): ApiError {
  const code = errorCode(json);
  if (status === 429) return new ApiError(status, code, `Too many attempts. Try again in ${waitText(retryAfter ?? 60)}.`, retryAfter);
  // A 507 from an older server without the code says the same.
  const words = FRIENDLY[code] ?? (status === 507 ? STORAGE_TEXT : undefined);
  return new ApiError(status, code, words ?? unknownError(json), retryAfter);
}

/**
 * "rejected": the server refused the refresh token (sign in again).
 * "unavailable": network error, timeout, 5xx or 429 — keep the tokens and retry later.
 */
type RefreshResult = "refreshed" | "rejected" | "unavailable";

// One refresh at a time per account.
const refreshing = new Map<string, Promise<RefreshResult>>();
export let onSessionLost: (accountId: string) => void = () => {};
export function setSessionLostHandler(fn: (accountId: string) => void) {
  onSessionLost = fn;
}
/**
 * Called when the server refuses a request with 403 `two_step_required` (servers with the `policies` feature: it
 * requires two-step login and this account has no method yet), before the error is thrown.
 */
let onTwoStepRequired: (accountId: string) => Promise<void> | void = () => {};
export function setTwoStepHandler(fn: (accountId: string) => Promise<void> | void) {
  onTwoStepRequired = fn;
}

async function refresh(accountId: string): Promise<RefreshResult> {
  const running = refreshing.get(accountId);
  if (running !== undefined) return running;
  const p = (async (): Promise<RefreshResult> => {
    const { server, tokens } = (await local.account(accountId)).data ?? {};
    if (!server || !tokens) return "rejected";
    try {
      const r = await fetch(`${server}/api/auth/refresh`, {
        method: "POST",
        headers: { "content-type": "application/json", ...clientHeaders() },
        body: JSON.stringify({ refresh_token: tokens.refresh }),
        signal: timeoutSignal(),
      });
      if (r.status === 400 || r.status === 401 || r.status === 403) return "rejected";
      if (!r.ok) return "unavailable";
      const j = (await r.json()) as { access_token?: unknown; refresh_token?: unknown };
      if (typeof j.access_token !== "string" || typeof j.refresh_token !== "string") return "unavailable";
      await local.set({ tokens: { access: j.access_token, refresh: j.refresh_token } }, accountId);
      return "refreshed";
    } catch {
      return "unavailable";
    } finally {
      refreshing.delete(accountId);
    }
  })();
  refreshing.set(accountId, p);
  return p;
}

/**
 * A new access token for `accountId` now (its last one was refused, e.g. a file download from the popup after 15
 * minutes). The same rules as a request that gets a 401: a refused refresh token signs the account out here.
 */
export async function renewAccess(accountId: string): Promise<void> {
  const r = await refresh(accountId);
  if (r === "refreshed") return;
  if (r === "unavailable") throw unreachable();
  await local.set({ tokens: null }, accountId);
  onSessionLost(accountId);
  throw signedOutError();
}

type Options = {
  method?: string;
  body?: unknown;
  auth?: boolean;
  headers?: Record<string, string>;
  /** Account to use (default: the active one at call time). */
  accountId?: string;
};

/** A request to the account's server. `T`: the response's shape (web/src/lib/types.ts where the web vault has one). */
export async function api<T = unknown>(path: string, opts: Options = {}): Promise<T> {
  const { method = opts.body === undefined ? "GET" : "POST", body, auth = true, headers = {} } = opts;
  // Pin the account for this request, so switching accounts mid-request can't mix them up.
  const accountId = opts.accountId ?? (await local.account()).id;
  // A server too old for this app is never asked for anything (signing out here still ends the session there).
  if (path !== "/auth/logout") await refuseOutdated((await local.account(accountId)).data?.server ?? "");
  const send = async () => {
    const { server, tokens } = (await local.account(accountId)).data ?? { server: "", tokens: null };
    if (!server) throw new AppError(NO_SERVER, "Set your PassAuth server address first.", true);
    return fetch(`${server}/api${path}`, {
      method,
      headers: {
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
        ...(auth && tokens ? { authorization: `Bearer ${tokens.access}` } : {}),
        ...headers,
        ...clientHeaders(),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: timeoutSignal(),
    });
  };
  const reach = async () => {
    try {
      return await send();
    } catch (e) {
      if (e instanceof AppError) throw e;
      throw unreachable();
    }
  };
  let res = await reach();
  if (res.status === 401 && auth) {
    const r = await refresh(accountId);
    if (r === "refreshed") res = await reach();
    else if (r === "unavailable") throw unreachable();
    else {
      await local.set({ tokens: null }, accountId);
      onSessionLost(accountId);
      // Signed out elsewhere (or every other session was revoked): the popup goes back to the sign-in screen.
      throw signedOutError();
    }
  }
  const text = await res.text();
  let json: unknown = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    if (res.status >= 500) throw new ApiError(res.status, "unavailable", `Your PassAuth server isn't responding right now (${res.status}). Try again in a moment.`);
    throw new ApiError(res.status, "not_passauth", "That address doesn't look like a PassAuth server.");
  }
  if (!res.ok) {
    const e = apiError(res.status, json, retryAfterSeconds(res.headers.get("retry-after")));
    if (res.status === 403 && e.code === TWO_STEP_REQUIRED) await onTwoStepRequired(accountId);
    throw e;
  }
  return json as T;
}

/** Best-effort sign-out of an account that isn't active (its own server and tokens). */
export async function logoutRemote(server: string, tokens: { access: string } | null) {
  if (!server || !tokens) return;
  // Best effort: the account is signed out here either way; the server ends the session when the token expires.
  await fetch(`${server}/api/auth/logout`, { method: "POST", headers: { authorization: `Bearer ${tokens.access}`, ...clientHeaders() }, signal: timeoutSignal() }).catch(() => {});
}

/** `GET /api/config` as far as the extension reads it. */
export interface ServerConfig {
  name?: string;
  api?: number;
  features?: unknown;
  /** Servers with the `policies` feature: the admin's account policies (web `readPolicies` reads them). */
  policies?: unknown;
  /** The admin's limits (`max_import_items`, …). */
  limits?: unknown;
}

/** `GET /api/config` of a server (unauthenticated), or null when no PassAuth server answers. */
export async function serverConfig(server: string): Promise<ServerConfig | null> {
  // Unreachable, or not JSON: no PassAuth server answered (null).
  const r = await fetch(`${server}/api/config`, { headers: clientHeaders(), signal: timeoutSignal() }).catch(() => null);
  return r?.ok ? ((await r.json().catch(() => null)) as ServerConfig | null) : null;
}

/**
 * What a server supports (its `features` list), its API contract version (`api`; null for servers from before API 2)
 * and its account policies (`policies`, raw: web `readPolicies` reads them).
 */
export interface ServerInfo {
  features: ReadonlySet<string>;
  api: number | null;
  policies: unknown;
  /** The admin's limits, raw (`max_import_items` for the old-trash batches: manifests.ts `purgeBatch`). */
  limits?: unknown;
}

/** Signed sharing: every server from 0.12.0 lists it, and this app needs it. */
const REQUIRED_FEATURE = "signed_sharing";

export const SERVER_OUTDATED = "server_outdated";
export const SERVER_UPDATE_TEXT = "Update your PassAuth server to keep using this app.";

/**
 * Whether this app refuses the server: its `/api/config` was read and doesn't list `signed_sharing` (a server from
 * before signed sharing, or one that leaves the feature out so that a new browser would skip the checks). Unknown
 * (`null`: the server can't be reached) is never a refusal: the offline copy is used as always, and the next answer
 * decides.
 */
export const serverOutdated = (info: Pick<ServerInfo, "features"> | null): boolean => !!info && !info.features.has(REQUIRED_FEATURE);

export const outdatedError = () => new AppError(SERVER_OUTDATED, SERVER_UPDATE_TEXT, true);

/**
 * Before anything is asked of `server`: fails with "Update your PassAuth server…" when it is one this app refuses
 * (`serverOutdated`), and with "Can't reach your PassAuth server…" when its `/api/config` can't be fetched or read
 * and this browser has never read a feature list with `signed_sharing` from it (`knownFeatures`). So a server can't
 * get around the check by failing `/api/config` while it answers everything else: no sign-in is started and no sync
 * answer is asked for or used. With such a list stored, an unreachable config changes nothing (the next answer
 * decides), which is what working offline needs.
 */
export async function refuseOutdated(server: string): Promise<void> {
  if (!server) return;
  const info = await serverInfo(server);
  if (info) {
    if (serverOutdated(info)) throw outdatedError();
    return;
  }
  const known = await knownFeatures.get(server).catch(() => null);
  if (!known?.includes(REQUIRED_FEATURE)) throw unreachable();
}

/** Whether the active account's server is one this app refuses, as far as known (for the popup's notice). */
export async function outdatedServer(server: string): Promise<boolean> {
  return !!server && serverOutdated(await serverInfo(server).catch(() => null));
}

/** The feature lists already stored in this worker's lifetime (so a config read doesn't write the same list again). */
const storedLists = new Map<string, string>();

/** Keep the feature list just read for `server` (`knownFeatures`); a failure is only logged by the caller's chain. */
async function noteFeatures(server: string, info: ServerInfo): Promise<ServerInfo> {
  const list = [...info.features].sort();
  const text = JSON.stringify(list);
  if (storedLists.get(server) !== text) {
    try {
      await knownFeatures.set(server, list);
      storedLists.set(server, text);
    } catch {
      /* not stored: asked again with the next config answer */
    }
  }
  return info;
}

const readInfo = (cfg: ServerConfig): ServerInfo => ({
  features: new Set(Array.isArray(cfg.features) ? cfg.features.filter((f): f is string => typeof f === "string") : []),
  api: typeof cfg.api === "number" && Number.isFinite(cfg.api) ? cfg.api : null,
  policies: cfg.policies ?? null,
  limits: cfg.limits ?? null,
});

// Feature detection (API contract v2): what a server supports comes from its `features` list, never from its version
// number. Kept per server address for an hour (and asked again at every unlock: `refreshServerInfo`): the live-sync
// socket keeps the worker running for days, and the server can be upgraded or its admin change a policy meanwhile.
const INFO_MS = 60 * 60_000;
const infos = new Map<string, { at: number; p: Promise<ServerInfo | null> }>();

/** The server's features and policies (cached per server address), or null while no PassAuth server answers there. */
export function serverInfo(server: string): Promise<ServerInfo | null> {
  const cached = infos.get(server);
  const now = Date.now();
  if (cached && now - cached.at < INFO_MS && now >= cached.at) return cached.p;
  const p = serverConfig(server).then((cfg) => {
    if (!cfg) {
      // Not reachable right now: ask again next time instead of remembering "no features".
      if (infos.get(server)?.p === p) infos.delete(server);
      return null;
    }
    return noteFeatures(server, readInfo(cfg));
  });
  infos.set(server, { at: now, p });
  return p;
}

/**
 * Ask the server again now (unlock, sign-in): a policy its admin changed (a lower `max_vault_timeout_minutes`) or a
 * feature turned on or off applies from this unlock, not an hour later. Requests meanwhile wait for this answer; while
 * the server can't be reached, what was known before stays.
 */
export function refreshServerInfo(server: string): Promise<ServerInfo | null> {
  if (!server) return Promise.resolve(null);
  const before = infos.get(server);
  const now = Date.now();
  const p: Promise<ServerInfo | null> = serverConfig(server).then(async (cfg) => {
    if (cfg) return noteFeatures(server, readInfo(cfg));
    const old = before ? await before.p : null;
    // Unreachable: keep the earlier answer (with its own age), or ask again next time when there was none.
    if (infos.get(server)?.p === p) {
      if (before && old) infos.set(server, before);
      else infos.delete(server);
    }
    return old;
  });
  infos.set(server, { at: now, p });
  return p;
}

/**
 * Whether website icons are shown: the user wants them (`showIcons`) and the server offers them. API 2 servers say so
 * with the feature `icons` (only while their icon service is on); older servers (no `api`) always had it, and while
 * the server's answer is unknown the setting alone decides (a failed icon falls back to the letter). The same rule as
 * the web vault's `siteIconsShown` (web/src/lib/site-icons.ts).
 */
export function siteIconsShown(wanted: boolean, info: Pick<ServerInfo, "api" | "features"> | null): boolean {
  if (!wanted) return false;
  if (!info || info.api === null || info.api < 2) return true;
  return info.features.has("icons");
}

/** `siteIconsShown` for `server`, from its cached features. */
export async function iconsShown(server: string, wanted: boolean): Promise<boolean> {
  if (!wanted || !server) return false;
  return siteIconsShown(wanted, await serverInfo(server));
}

/** The server's API features (an older server has none; so does one that can't be reached right now). */
export async function serverFeatures(server: string): Promise<ReadonlySet<string>> {
  return (await serverInfo(server))?.features ?? new Set<string>();
}

/** Forget what a server supports (its address changed, or it may have been upgraded). */
export function forgetServerFeatures(server?: string) {
  if (server) {
    infos.delete(server);
    storedLists.delete(server);
  } else {
    infos.clear();
    storedLists.clear();
  }
}
