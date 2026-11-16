/** PassAuth HTTP client: bearer auth, automatic refresh-token rotation shared by every open tab. */
import { useEffect, useState } from "react";
import { clientId, clientName, isDesktop, secretStore } from "./platform";
import { isTwoStepRequired, readPolicies, type Policies } from "./policies";
import { server } from "./server";
import { oneLine } from "./text";

export class ApiError extends Error {
  constructor(
    public status: number,
    /** The server's `error` code, e.g. "vault_key_changed" (older servers send only generic codes such as "conflict"). */
    public code: string,
    message: string,
    /** Seconds from the Retry-After header of a 429. */
    public retryAfter?: number,
    /** The server's id for the request (error body `request_id`, else the `x-request-id` header): names it in the server log. */
    public requestId?: string,
  ) {
    super(message);
  }
}

/** 403 `quota_exceeded`, in plain words: the vault owner's item or storage limit (admin page) would be passed. */
export const QUOTA_EXCEEDED = "You've reached this server's storage limit. Delete items or ask the server's admin.";
/** 403 `quota_exceeded` for files: the owner's attachment storage limit (admin page) would be passed. */
export const ATTACHMENT_QUOTA_EXCEEDED = "You've reached your attachment storage limit. Remove files or ask the server's admin.";
/** 507 `insufficient_storage`: the server's disk is (nearly) full, so it keeps what it has and refuses writes. */
export const OUT_OF_STORAGE = "Your server is running out of storage space, so this wasn't saved. Ask the server's admin.";

/** The server refused a save or import because it would pass the vault owner's item or storage limit. */
export function isQuotaExceeded(e: unknown): boolean {
  return hasErrorCode(e, "quota_exceeded", "storage limit reached");
}

/** The server refused a write because its disk is running out of space (507 `insufficient_storage`): trying again won't help soon. */
export function isOutOfStorage(e: unknown): boolean {
  return e instanceof ApiError && (e.code === "insufficient_storage" || e.status === 507);
}

/**
 * Whether `e` is the server's error `code`. Servers from before the codes sent a generic code with the reason as
 * the message text, so that text (`legacyMessage`, by default the code itself) is recognised too.
 */
export function hasErrorCode(e: unknown, code: string, legacyMessage: string = code): boolean {
  return e instanceof ApiError && (e.code === code || e.message === legacyMessage);
}

/** The server couldn't be reached, or answered with a temporary failure (5xx, 429). The session is kept. */
export class UnreachableError extends Error {
  constructor(
    public status = 0,
    /**
     * The desktop app's own words for what went wrong (its native client's error: a certificate this computer doesn't
     * trust, an answer too large, a timeout), shown instead of the general sentence. Never the server's text.
     */
    public detail?: string,
  ) {
    super("unreachable");
  }
}

/**
 * The desktop app's description of a request that failed in its native client: its commands fail with a sentence of
 * the app's own (the browser's `fetch` fails with a TypeError instead, which says nothing useful). Null otherwise.
 */
export function nativeFailure(e: unknown): string | null {
  return typeof e === "string" && e.trim() ? oneLine(e, 300) : null;
}

export type Tokens = { access: string; refresh: string };

export const SESSION_KEY = "pa.session";
let tokens: Tokens | null = null;
let refreshing: Promise<RefreshResult> | null = null;
const listeners = new Set<() => void>();

function load(): Tokens | null {
  try {
    const raw = secretStore.get(SESSION_KEY);
    return raw ? (JSON.parse(raw) as Tokens) : null;
  } catch {
    return null;
  }
}

/** Read lazily while signed out, so a session stored after start-up (desktop keychain, another server) is seen. */
export function getTokens() {
  return (tokens ??= load());
}

export function setTokens(t: Tokens | null) {
  tokens = t;
  secretStore.set(SESSION_KEY, t ? JSON.stringify(t) : null);
}

/** Called when the session is gone (refresh rejected, revoked, or signed out in another tab). */
export function onSessionLost(fn: () => void) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

const sessionLost = () => listeners.forEach((fn) => fn());

const twoStepListeners = new Set<() => void>();
/**
 * Called when the server refuses a request with 403 `two_step_required` (servers with the `policies` feature): it
 * requires two-step login and the account has no method yet, so only setting one up and signing out work. Runs before
 * the request's error is thrown.
 */
export function onTwoStepRequired(fn: () => void) {
  twoStepListeners.add(fn);
  return () => twoStepListeners.delete(fn);
}

// Another tab rotated the tokens or signed out: follow it, so this tab never sends a used refresh token.
if (typeof window !== "undefined") {
  window.addEventListener("storage", (e) => {
    if (e.key !== SESSION_KEY) return;
    const next = load();
    const had = tokens;
    tokens = next;
    if (had && !next) sessionLost();
  });
}

/** Random v4 UUID. crypto.randomUUID only exists on https and localhost; self-hosted servers may be tried over plain http first. */
function uuid(): string {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export function deviceId(): string {
  try {
    let id = localStorage.getItem("pa.device");
    if (!id) {
      id = uuid();
      localStorage.setItem("pa.device", id);
    }
    return id;
  } catch {
    return uuid();
  }
}

export function deviceInfo() {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /Mac OS X/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Linux/.test(ua) ? "Linux" : "";
  const client = isDesktop() ? "PassAuth desktop" : browser;
  return { id: deviceId(), name: `${client}${os ? ` on ${os}` : ""}`, kind: "web" };
}

export type RefreshResult = "refreshed" | "rejected" | "unavailable";

/** Run `fn` while holding a lock shared by every tab of this origin (navigator.locks needs a secure context). */
async function withTabLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
  const locks = (navigator as Navigator & { locks?: LockManager }).locks;
  if (!locks?.request) return fn();
  return locks.request(name, fn) as Promise<T>;
}

/**
 * Exchange the refresh token for a new pair. Tabs take turns: a tab that finds the stored tokens already
 * rotated by another tab adopts them instead of sending its (now used) refresh token, which the server
 * would treat as token theft and revoke the session.
 */
async function refresh(): Promise<RefreshResult> {
  if (!getTokens()) return "rejected";
  const used = tokens!.refresh;
  refreshing ??= withTabLock("pa.refresh", async (): Promise<RefreshResult> => {
    const stored = load();
    if (stored && stored.refresh !== used) {
      tokens = stored;
      return "refreshed";
    }
    if (!tokens) return "rejected";
    try {
      const r = await server.fetch(server.apiUrl("/auth/refresh"), {
        method: "POST",
        headers: { "content-type": "application/json", "x-passauth-client": clientId() },
        body: JSON.stringify({ refresh_token: tokens.refresh }),
      });
      if (r.status === 400 || r.status === 401 || r.status === 403) return "rejected";
      if (!r.ok) return "unavailable";
      const j = (await r.json()) as { access_token: string; refresh_token: string };
      setTokens({ access: j.access_token, refresh: j.refresh_token });
      return "refreshed";
    } catch {
      return "unavailable";
    }
  }).finally(() => {
    refreshing = null;
  });
  return refreshing;
}

/**
 * For requests made outside `api()` (file transfers, which stream their bodies): renew the session after a 401. "rejected"
 * signs out as `api()` does; "unavailable" means the server couldn't be reached.
 */
export async function renewSession(): Promise<RefreshResult> {
  const r = await refresh();
  if (r === "rejected" && getTokens()) {
    setTokens(null);
    sessionLost();
  }
  return r;
}

type Options = {
  method?: string;
  body?: unknown;
  auth?: boolean;
  headers?: Record<string, string>;
  /**
   * False: a 403 `two_step_required` doesn't bring up the two-step screen (`onTwoStepRequired`). For turning off a
   * two-step method, which the server refuses with that code when it is the account's last one and two-step login is
   * required: the account still has its method then.
   */
  twoStepGate?: boolean;
};

/** Parse a response body that should be JSON; proxies sometimes answer with an HTML error page. */
function parseBody(text: string): unknown {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

export async function api<T = unknown>(path: string, opts: Options = {}): Promise<T> {
  const { method = opts.body === undefined ? "GET" : "POST", body, auth = true, headers = {}, twoStepGate = true } = opts;
  const send = async () => {
    try {
      return await server.fetch(server.apiUrl(path), {
        method,
        headers: {
          "x-passauth-client": clientId(),
          ...(body !== undefined ? { "content-type": "application/json" } : {}),
          ...(auth && getTokens() ? { authorization: `Bearer ${tokens!.access}` } : {}),
          ...headers,
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (e) {
      throw new UnreachableError(0, nativeFailure(e) ?? undefined);
    }
  };

  let res = await send();
  if (res.status === 401 && auth && getTokens()) {
    const r = await refresh();
    if (r === "refreshed") res = await send();
    else if (r === "unavailable") throw new UnreachableError();
    else {
      setTokens(null);
      sessionLost();
    }
  }
  const text = await res.text();
  const json = parseBody(text) as { error?: string; message?: string; request_id?: unknown } | null | undefined;
  if (!res.ok) {
    const requestId = (typeof json?.request_id === "string" ? json.request_id : res.headers.get("x-request-id")) || undefined;
    if (json === undefined && (res.status >= 500 || res.status === 404))
      throw new ApiError(res.status, "bad_response", unexpectedResponse(res.status), undefined, requestId);
    if (res.status >= 502 && res.status <= 504) throw new UnreachableError(res.status);
    if (twoStepGate && isTwoStepRequired(res.status, json?.error)) twoStepListeners.forEach((fn) => fn());
    throw new ApiError(res.status, json?.error ?? "error", json?.message ?? `Request failed (${res.status})`, retryAfter(res), requestId);
  }
  if (json === undefined) throw new ApiError(res.status, "bad_response", unexpectedResponse(res.status));
  return json as T;
}

/** Retry-After in seconds (a number of seconds or an HTTP date), if the response has one. */
function retryAfter(res: Response): number | undefined {
  const value = res.headers.get("retry-after");
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return Math.max(0, seconds);
  const at = Date.parse(value);
  return Number.isNaN(at) ? undefined : Math.max(0, Math.round((at - Date.now()) / 1000));
}

const unexpectedResponse = (status: number) =>
  `The server sent an unexpected response (${status}). If you use a reverse proxy, check that it forwards /api to PassAuth.`;

/** A request id worth showing: what servers make (letters, digits, `-_.:`, at most 64), never other text from the answer. */
const REQUEST_ID = /^[A-Za-z0-9_.:-]{1,64}$/;
/** Longest piece of a server's own message that is shown, in characters. */
const SERVER_MESSAGE_MAX = 200;

/** Server error codes with the app's own wording. A server's `message` is never shown for these. */
const CODE_TEXT = new Map<string, string>([
  ["reauth_required", "Your confirmation expired. Enter your master password again."],
  ["email_not_verified", "Confirm your email address first. Check your inbox for the verification link."],
  ["vault_key_changed", "Someone replaced this vault's key just now. Try again."],
  ["revision_conflict", "This was changed on another device or by someone you share the vault with just now, so nothing was saved. Try again."],
  ["quota_exceeded", QUOTA_EXCEEDED],
  ["insufficient_storage", OUT_OF_STORAGE],
  ["expired", "This took too long and expired. Start again."],
  ["invalid_code", "That code didn't work. Enter the code that's showing now and try again."],
  ["invalid_credentials", "That master password is wrong. Check it and try again."],
  ["unauthorized", "You're signed out. Sign in again, then try again."],
  ["session_expired", "Your session has ended. Sign in again."],
  ["account_disabled", "This account is turned off on this server. Ask the server's admin."],
  ["signups_closed", "This server doesn't take new accounts at the moment. Ask the server's admin."],
  ["account_exists", "An account with this email address already exists. Sign in instead."],
  ["not_found", "Your PassAuth server couldn't find this. It may have been deleted on another device."],
  ["item_exists", "An item with the same id already exists. Try again."],
  ["vault_exists", "A vault with the same id already exists. Try again."],
  ["last_vault", "You can't delete your last vault."],
  ["already_enabled", "This is turned on already."],
  ["too_large", "This is larger than your server allows."],
  ["attachment_exists", "This file is being added already. Wait a moment, then try again."],
  ["already_uploaded", "This file was uploaded already."],
  ["wrong_password", "That password is wrong. Check it and try again."],
  // Policies (servers with `policies`): what the server refused, and what to do about it.
  ["two_step_required", "Your server requires two-step login. Set it up in Settings, under Two-step login, then try again."],
  ["secret_key_required", "Your server requires every account to use a Secret Key. Turn on the Secret Key, then try again."],
  [
    "kdf_too_weak",
    "Your server's admin just raised the encryption settings for account keys. Reload the page, then try again.",
  ],
  // Features the admin can turn off (servers with `sends`, `attachments`, `emergency_access`, `login_with_device`).
  ["sends_disabled", "Send is turned off on this server."],
  ["attachments_disabled", "Adding files is turned off on this server."],
  ["emergency_access_disabled", "Emergency access is turned off on this server."],
  ["emergency_vaults_changed", "Your vaults changed while this was being saved. Try again."],
  ["roster_changed", "Your emergency contacts changed on another device just now. Try again."],
  ["update_required", "This version of PassAuth is too old for your server. Update PassAuth, then try again."],
  ["login_with_device_disabled", "Signing in with another device's approval is turned off on this server. Sign in with your master password."],
  ["upload_in_progress", "This file is being uploaded already. Wait a moment, then try again."],
]);

/**
 * Messages servers send under a generic code (`bad_request`, `forbidden`…) that the app knows, with its own wording.
 * Servers from before the codes sent some coded reasons only this way.
 */
const MESSAGE_TEXT = new Map<string, string>([
  ["invalid code", CODE_TEXT.get("invalid_code")!],
  ["invalid two-factor code", CODE_TEXT.get("invalid_code")!],
  ["start setup first", "The setup expired. Cancel and start setup again."],
  ["invalid or expired link", "This link has expired or was used already."],
  ["reauth_required", CODE_TEXT.get("reauth_required")!],
  ["email_not_verified", CODE_TEXT.get("email_not_verified")!],
  ["storage limit reached", QUOTA_EXCEEDED],
  ["attachment storage limit reached", ATTACHMENT_QUOTA_EXCEEDED],
  ["item changed on another device; sync and retry", CODE_TEXT.get("revision_conflict")!],
  ["email is not configured on this server", "This server isn't set up to send email. Ask the server's admin."],
  ["you can't be your own emergency contact", "You can't be your own emergency contact."],
  ["you can register at most 10 security keys", "You can add at most 10 security keys. Remove one first."],
  ["the owner cannot be removed", "The owner of a vault can't be removed."],
  ["invalid email address", "Enter a valid email address."],
  ["name too long", "That name is too long. Shorten it and try again."],
]);

/**
 * What the app says about an error answer: its own wording for every code (and message) it knows; otherwise a sentence
 * of its own with the request's reference, and the server's message only as a labelled detail, cleaned and shortened.
 * A compromised server can't put instructions of its own into the app's words this way.
 */
function apiErrorText(e: ApiError): string {
  const reference = e.requestId && REQUEST_ID.test(e.requestId) ? e.requestId : null;
  if (e.status === 429) {
    const minutes = e.retryAfter && e.retryAfter > 90 ? Math.ceil(e.retryAfter / 60) : 0;
    return minutes ? `Too many attempts. Wait ${minutes} minutes, then try again.` : "Too many attempts. Wait a minute, then try again.";
  }
  // A failure inside the server: its log has the details under the request's id.
  if (e.status >= 500 && e.code === "internal")
    return `Something went wrong on your PassAuth server. Try again; if it keeps happening, tell the server's admin${reference ? ` and give them this reference: ${reference}` : ""}.`;
  // Made by this app (an answer that isn't JSON): its own words.
  if (e.code === "bad_response") return e.message;
  const known = MESSAGE_TEXT.get(e.message) ?? CODE_TEXT.get(e.code);
  if (known) return known;
  const detail = oneLine(e.message, SERVER_MESSAGE_MAX);
  const lead = e.status >= 500 ? "Something went wrong on your PassAuth server." : "Your PassAuth server refused this request.";
  return [lead, reference ? `Reference: ${reference}.` : "", detail ? `Server message: ${detail}` : ""].filter(Boolean).join(" ");
}

/** Human-readable message for any thrown value. */
export function errorMessage(e: unknown): string {
  if (e instanceof UnreachableError) return e.detail ?? `Can't reach your PassAuth server at ${server.host()}. Check your connection, then try again.`;
  if (e instanceof ApiError) return apiErrorText(e);
  if (e instanceof Error) {
    if (e.message === "decrypt_failed") return "Wrong master password or Secret Key.";
    if (e.message === "invalid secret key") return "That Secret Key isn't valid. Secret Keys start with PA1 and use only the letters A–Z and the digits 2–7.";
    return e.message;
  }
  return String(e);
}

/** One wording for errors across the web vault: says what happened and how to fix it. */
export function friendlyError(e: unknown): string {
  if (e instanceof ApiError) return apiErrorText(e);
  const m = errorMessage(e);
  switch (m) {
    case "secret_key_required":
      return `${clientName(true)} doesn't have your Secret Key saved. Sign out, sign in again with your Secret Key, then retry.`;
    case "Wrong email, master password or Secret Key.":
    case "Wrong master password or Secret Key.":
      return "That master password is wrong. Check it and try again.";
    case "reauth_required":
    case "email_not_verified":
      return CODE_TEXT.get(m)!;
    case "Failed to fetch":
      return errorMessage(new UnreachableError());
  }
  const s = m.charAt(0).toUpperCase() + m.slice(1);
  return /[.!?]$/.test(s) ? s : `${s}.`;
}

export interface PublicConfig {
  name: string;
  version: string;
  signups_allowed: boolean;
  email_enabled: boolean;
  /** API generation (2 and up); older servers omit it. */
  api?: number;
  /** What this server supports, e.g. "revoke_others". Feature-detect with `hasFeature`, never by version number. */
  features?: string[];
  /** Days items stay in the trash before the server deletes them; 0 = never (servers with `trash_retention`). */
  trash_days?: number;
  /**
   * What the server takes (older servers omit it): items per import request, KiB per encrypted item, the longest a
   * Send stays and its largest encrypted text, the largest attachment (encrypted, in MB).
   */
  limits?: {
    max_import_items?: number;
    max_item_kib?: number;
    item_versions_kept?: number;
    send_max_days?: number;
    send_max_bytes?: number;
    max_attachment_mb?: number;
  };
  /** The admin's account policies (servers with `policies`); read them with `readPolicies` in policies.ts. */
  policies?: Record<string, unknown>;
}

let configCache: { base: string; request: Promise<PublicConfig | null> } | null = null;
/** The last answer, by server: kept while a refresh is on its way or fails, so policies and features don't flicker. */
let configKnown: { base: string; config: PublicConfig } | null = null;
const configListeners = new Set<() => void>();

/** The server's public settings, fetched once per server (the desktop app can change server); a failure is retried on the next call. */
export function loadPublicConfig(): Promise<PublicConfig | null> {
  if (configCache && configCache.base === server.base) return configCache.request;
  const base = server.base;
  const request: Promise<PublicConfig | null> = api<PublicConfig>("/config", { auth: false }).then(
    (config) => {
      if (server.base === base) {
        configKnown = { base, config };
        configListeners.forEach((fn) => fn());
      }
      return config;
    },
    () => {
      if (configCache?.request === request) configCache = null;
      return null;
    },
  );
  configCache = { base, request };
  return request;
}

/**
 * Ask the server for its public settings again. Called at sign-in, unlock and start-up, so an admin's change (a policy,
 * a feature turned on or off) reaches an app that stays open. Until the answer arrives the last one stays in use.
 */
export function refreshPublicConfig(): Promise<PublicConfig | null> {
  if (configCache?.base === server.base) configCache = null;
  return loadPublicConfig();
}

/** The settings last received from the current server, without asking it; null before the first answer. */
export function knownPublicConfig(): PublicConfig | null {
  return configKnown?.base === server.base ? configKnown.config : null;
}

/** Run `fn` whenever a new answer from the server's /config arrives; returns the unsubscribe. */
export function onPublicConfig(fn: () => void) {
  configListeners.add(fn);
  return () => {
    configListeners.delete(fn);
  };
}

/** Whether the server announced `feature` in GET /api/config (servers before API 2 announce none). */
export function hasFeature(config: PublicConfig | null, feature: string): boolean {
  return Array.isArray(config?.features) && config.features.includes(feature);
}

/** Server's public settings (cached per server, refreshed at sign-in and unlock). Null while loading or if unreachable. */
export function usePublicConfig() {
  const [config, setConfig] = useState<PublicConfig | null>(knownPublicConfig);
  useEffect(() => {
    let live = true;
    const unsubscribe = onPublicConfig(() => live && setConfig(knownPublicConfig()));
    loadPublicConfig().then((c) => live && setConfig(c ?? knownPublicConfig()));
    return () => {
      live = false;
      unsubscribe();
    };
  }, []);
  return config;
}

/** The server's account policies (`policies.ts`); the defaults, which change nothing, until the server has answered. */
export const usePolicies = (): Policies => readPolicies(usePublicConfig());
