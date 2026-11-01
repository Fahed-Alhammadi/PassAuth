/** HTTP client for the configured PassAuth server, with refresh-token rotation. */
import { local } from "./storage";

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

let refreshing: Promise<boolean> | null = null;
export let onSessionLost: () => void = () => {};
export function setSessionLostHandler(fn: () => void) {
  onSessionLost = fn;
}

async function refresh(): Promise<boolean> {
  refreshing ??= (async () => {
    const { server, tokens } = await local.get();
    if (!tokens) return false;
    try {
      const r = await fetch(`${server}/api/auth/refresh`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ refresh_token: tokens.refresh }),
      });
      if (!r.ok) return false;
      const j = await r.json();
      await local.set({ tokens: { access: j.access_token, refresh: j.refresh_token } });
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
  const send = async () => {
    const { server, tokens } = await local.get();
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
    if (await refresh()) res = await send();
    else {
      await local.set({ tokens: null });
      onSessionLost();
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
