/** HTTP client for the configured PassAuth server, with refresh-token rotation. */
import { local } from "./storage";

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

// One refresh at a time per account.
const refreshing = new Map<string, Promise<boolean>>();
export let onSessionLost: (accountId: string) => void = () => {};
export function setSessionLostHandler(fn: (accountId: string) => void) {
  onSessionLost = fn;
}

async function refresh(accountId: string): Promise<boolean> {
  const running = refreshing.get(accountId);
  if (running) return running;
  const p = (async () => {
    const { accounts } = await local.get();
    const { server, tokens } = accounts[accountId] ?? {};
    if (!server || !tokens) return false;
    try {
      const r = await fetch(`${server}/api/auth/refresh`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ refresh_token: tokens.refresh }),
      });
      if (!r.ok) return false;
      const j = await r.json();
      await local.set({ tokens: { access: j.access_token, refresh: j.refresh_token } }, accountId);
      return true;
    } catch {
      return false;
    } finally {
      refreshing.delete(accountId);
    }
  })();
  refreshing.set(accountId, p);
  return p;
}

type Options = { method?: string; body?: unknown; auth?: boolean; headers?: Record<string, string> };

export async function api<T = any>(path: string, opts: Options = {}): Promise<T> {
  const { method = opts.body === undefined ? "GET" : "POST", body, auth = true, headers = {} } = opts;
  // Pin the account for this request, so switching accounts mid-request can't mix them up.
  const { activeId } = await local.get();
  const send = async () => {
    const { server, tokens } = (await local.get()).accounts[activeId] ?? { server: "", tokens: null };
    if (!server) throw new Error("Set your PassAuth server address first.");
    return fetch(`${server}/api${path}`, {
      method,
      headers: {
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
        ...(auth && tokens ? { authorization: `Bearer ${tokens.access}` } : {}),
        ...headers,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  };
  let res: Response;
  try {
    res = await send();
  } catch (e) {
    if (e instanceof Error && e.message.startsWith("Set your")) throw e;
    throw new Error("Can't reach your PassAuth server. Check the server address and your connection.");
  }
  if (res.status === 401 && auth) {
    if (await refresh(activeId)) res = await send();
    else {
      await local.set({ tokens: null }, activeId);
      onSessionLost(activeId);
    }
  }
  const text = await res.text();
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    throw new ApiError(res.status, "not_passauth", "That address doesn't look like a PassAuth server.");
  }
  if (!res.ok) throw new ApiError(res.status, json?.error ?? "error", json?.message ?? `Request failed (${res.status})`);
  return json as T;
}

/** Best-effort sign-out of an account that isn't active (its own server and tokens). */
export async function logoutRemote(server: string, tokens: { access: string } | null) {
  if (!server || !tokens) return;
  await fetch(`${server}/api/auth/logout`, { method: "POST", headers: { authorization: `Bearer ${tokens.access}` } }).catch(() => {});
}
