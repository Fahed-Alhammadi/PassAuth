/** HTTP client for the configured PassAuth server, with refresh-token rotation. */
import { local } from "./storage";

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

export const UNREACHABLE = "Can't reach your PassAuth server. Check the server address and your connection.";

/** A hung server must not stall the popup, badge, inline menu or passkey flows. */
const TIMEOUT_MS = 15_000;
export const timeoutSignal = (ms = TIMEOUT_MS) => AbortSignal.timeout(ms);

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

async function refresh(accountId: string): Promise<RefreshResult> {
  const running = refreshing.get(accountId);
  if (running) return running;
  const p = (async (): Promise<RefreshResult> => {
    const { server, tokens } = (await local.account(accountId)).data ?? {};
    if (!server || !tokens) return "rejected";
    try {
      const r = await fetch(`${server}/api/auth/refresh`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ refresh_token: tokens.refresh }),
        signal: timeoutSignal(),
      });
      if (r.status === 400 || r.status === 401 || r.status === 403) return "rejected";
      if (!r.ok) return "unavailable";
      const j = await r.json();
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

type Options = {
  method?: string;
  body?: unknown;
  auth?: boolean;
  headers?: Record<string, string>;
  /** Account to use (default: the active one at call time). */
  accountId?: string;
};

export async function api<T = any>(path: string, opts: Options = {}): Promise<T> {
  const { method = opts.body === undefined ? "GET" : "POST", body, auth = true, headers = {} } = opts;
  // Pin the account for this request, so switching accounts mid-request can't mix them up.
  const accountId = opts.accountId ?? (await local.account()).id;
  const send = async () => {
    const { server, tokens } = (await local.account(accountId)).data ?? { server: "", tokens: null };
    if (!server) throw new Error("Set your PassAuth server address first.");
    return fetch(`${server}/api${path}`, {
      method,
      headers: {
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
        ...(auth && tokens ? { authorization: `Bearer ${tokens.access}` } : {}),
        ...headers,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: timeoutSignal(),
    });
  };
  const reach = async () => {
    try {
      return await send();
    } catch (e) {
      if (e instanceof Error && e.message.startsWith("Set your")) throw e;
      throw new Error(UNREACHABLE);
    }
  };
  let res = await reach();
  if (res.status === 401 && auth) {
    const r = await refresh(accountId);
    if (r === "refreshed") res = await reach();
    else if (r === "unavailable") throw new Error(UNREACHABLE);
    else {
      await local.set({ tokens: null }, accountId);
      onSessionLost(accountId);
    }
  }
  const text = await res.text();
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    if (res.status >= 500) throw new ApiError(res.status, "unavailable", `Your PassAuth server isn't responding right now (${res.status}). Try again in a moment.`);
    throw new ApiError(res.status, "not_passauth", "That address doesn't look like a PassAuth server.");
  }
  if (!res.ok) throw new ApiError(res.status, json?.error ?? "error", json?.message ?? `Request failed (${res.status})`);
  return json as T;
}

/** Best-effort sign-out of an account that isn't active (its own server and tokens). */
export async function logoutRemote(server: string, tokens: { access: string } | null) {
  if (!server || !tokens) return;
  await fetch(`${server}/api/auth/logout`, { method: "POST", headers: { authorization: `Bearer ${tokens.access}` }, signal: timeoutSignal() }).catch(() => {});
}
