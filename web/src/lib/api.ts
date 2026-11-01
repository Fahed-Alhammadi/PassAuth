/** PassAuth HTTP client: bearer auth, automatic refresh-token rotation. */
import { useEffect, useState } from "react";

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

export type Tokens = { access: string; refresh: string };

const SESSION_KEY = "pa.session";
let tokens: Tokens | null = load();
let refreshing: Promise<boolean> | null = null;
const listeners = new Set<() => void>();

function load(): Tokens | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    return raw ? (JSON.parse(raw) as Tokens) : null;
  } catch {
    return null;
  }
}

export function getTokens() {
  return tokens;
}

export function setTokens(t: Tokens | null) {
  tokens = t;
  try {
    if (t) localStorage.setItem(SESSION_KEY, JSON.stringify(t));
    else localStorage.removeItem(SESSION_KEY);
  } catch {
    /* storage unavailable: session lasts for this tab only */
  }
}

/** Called when the session is gone (refresh failed or revoked). */
export function onSessionLost(fn: () => void) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function deviceId(): string {
  try {
    let id = localStorage.getItem("pa.device");
    if (!id) {
      id = crypto.randomUUID();
      localStorage.setItem("pa.device", id);
    }
    return id;
  } catch {
    return crypto.randomUUID();
  }
}

export function deviceInfo() {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /Mac OS X/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Linux/.test(ua) ? "Linux" : "";
  return { id: deviceId(), name: `${browser}${os ? ` on ${os}` : ""}`, kind: "web" };
}

async function refresh(): Promise<boolean> {
  if (!tokens) return false;
  refreshing ??= (async () => {
    try {
      const r = await fetch("/api/auth/refresh", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ refresh_token: tokens!.refresh }),
      });
      if (!r.ok) return false;
      const j = await r.json();
      setTokens({ access: j.access_token, refresh: j.refresh_token });
      return true;
    } catch {
      return false;
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
}

type Options = { method?: string; body?: unknown; auth?: boolean; headers?: Record<string, string> };

export async function api<T = any>(path: string, opts: Options = {}): Promise<T> {
  const { method = opts.body === undefined ? "GET" : "POST", body, auth = true, headers = {} } = opts;
  const send = () =>
    fetch(`/api${path}`, {
      method,
      headers: {
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
        ...(auth && tokens ? { authorization: `Bearer ${tokens.access}` } : {}),
        ...headers,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

  let res = await send();
  if (res.status === 401 && auth && tokens) {
    if (await refresh()) {
      res = await send();
    } else {
      setTokens(null);
      listeners.forEach((fn) => fn());
    }
  }
  const text = await res.text();
  const json = text ? JSON.parse(text) : null;
  if (!res.ok) {
    throw new ApiError(res.status, json?.error ?? "error", json?.message ?? `Request failed (${res.status})`);
  }
  return json as T;
}

/** Human-readable message for any thrown value. */
export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) {
    if (e.message === "decrypt_failed") return "Wrong master password or Secret Key.";
    return e.message;
  }
  return String(e);
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
