/** PassAuth HTTP client: bearer auth, automatic refresh-token rotation shared by every open tab. */
import { useEffect, useState } from "react";
import { clientName, isDesktop, secretStore } from "./platform";
import { server } from "./server";

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

/** The server couldn't be reached, or answered with a temporary failure (5xx, 429). The session is kept. */
export class UnreachableError extends Error {
  constructor(public status = 0) {
    super("unreachable");
  }
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

type RefreshResult = "refreshed" | "rejected" | "unavailable";

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
        headers: { "content-type": "application/json" },
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

type Options = { method?: string; body?: unknown; auth?: boolean; headers?: Record<string, string> };

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
  const { method = opts.body === undefined ? "GET" : "POST", body, auth = true, headers = {} } = opts;
  const send = async () => {
    try {
      return await server.fetch(server.apiUrl(path), {
        method,
        headers: {
          ...(body !== undefined ? { "content-type": "application/json" } : {}),
          ...(auth && getTokens() ? { authorization: `Bearer ${tokens!.access}` } : {}),
          ...headers,
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch {
      throw new UnreachableError();
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
  const json = parseBody(text) as { error?: string; message?: string } | null | undefined;
  if (!res.ok) {
    if (json === undefined && (res.status >= 500 || res.status === 404)) throw new ApiError(res.status, "bad_response", unexpectedResponse(res.status));
    if (res.status >= 502 && res.status <= 504) throw new UnreachableError(res.status);
    throw new ApiError(res.status, json?.error ?? "error", json?.message ?? `Request failed (${res.status})`);
  }
  if (json === undefined) throw new ApiError(res.status, "bad_response", unexpectedResponse(res.status));
  return json as T;
}

const unexpectedResponse = (status: number) =>
  `The server sent an unexpected response (${status}). If you use a reverse proxy, check that it forwards /api to PassAuth.`;

/** Human-readable message for any thrown value. */
export function errorMessage(e: unknown): string {
  if (e instanceof UnreachableError) return `Can't reach your PassAuth server at ${server.host()}. Check your connection, then try again.`;
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) {
    if (e.message === "decrypt_failed") return "Wrong master password or Secret Key.";
    if (e.message === "invalid secret key") return "That Secret Key isn't valid. Secret Keys start with PA1 and use only the letters A–Z and the digits 2–7.";
    return e.message;
  }
  return String(e);
}

/** One wording for errors across the web vault: says what happened and how to fix it. */
export function friendlyError(e: unknown): string {
  if (e instanceof ApiError && e.status === 429) return "Too many attempts. Wait a minute, then try again.";
  const m = errorMessage(e);
  switch (m) {
    case "secret_key_required":
      return `${clientName(true)} doesn't have your Secret Key saved. Sign out, sign in again with your Secret Key, then retry.`;
    case "Wrong email, master password or Secret Key.":
    case "Wrong master password or Secret Key.":
      return "That master password is wrong. Check it and try again.";
    case "invalid code":
      return "That code didn't work. Enter the code that's showing now and try again.";
    case "start setup first":
      return "The setup expired. Cancel and start setup again.";
    case "reauth_required":
      return "Your confirmation expired. Enter your master password again.";
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
}

let configRequest: Promise<PublicConfig | null> | null = null;

/** Server's public settings (cached per page load). Null while loading or if unreachable. */
export function usePublicConfig() {
  const [config, setConfig] = useState<PublicConfig | null>(null);
  useEffect(() => {
    configRequest ??= api<PublicConfig>("/config", { auth: false }).catch(() => null);
    configRequest.then(setConfig);
  }, []);
  return config;
}
