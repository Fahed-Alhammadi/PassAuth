/** The saved server address, the check that an address really is a PassAuth server, and requests to it. */
import { invoke } from "@tauri-apps/api/core";
import type { PublicConfig } from "@web/lib/api";
import { configureServer } from "@web/lib/server";

const KEY = "desktop.server";

/** The remembered server, or null when there is none or it no longer passes validation. */
export function savedServer(): string | null {
  try {
    return parseServer(localStorage.getItem(KEY) ?? "");
  } catch {
    return null;
  }
}

export function rememberServer(base: string | null) {
  if (base) localStorage.setItem(KEY, base);
  else localStorage.removeItem(KEY);
}

/** Only the Rust side talks to the network: the web vault's `fetch` becomes an `api_fetch` command. */
const nativeFetch: typeof fetch = async (input, init) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  const path = url.slice(url.indexOf("/api") + 4);
  const headers = Object.fromEntries(new Headers(init?.headers).entries());
  const body = typeof init?.body === "string" ? init.body : undefined;
  const res = await invoke<{ status: number; body: string }>("api_fetch", { path, method: init?.method ?? "GET", headers, body });
  return new Response(res.body, { status: res.status });
};

/** Route the web vault's requests to `base`. */
export async function connectServer(base: string) {
  await invoke("set_server", { base });
  configureServer({ base, fetch: nativeFetch });
}

export class ConnectError extends Error {}

const LOCAL = new Set(["localhost", "127.0.0.1"]);

/** Normalise what the user typed into an origin (a pasted page address is fine). Plain http only for this computer. */
export function parseServer(input: string): string {
  const text = input.trim();
  if (!text) throw new ConnectError("Enter your server address.");
  let url: URL;
  try {
    url = new URL(/^[a-z]+:\/\//i.test(text) ? text : `https://${text}`);
  } catch {
    throw new ConnectError("Enter a full address, such as https://vault.example.com.");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new ConnectError("The address must start with https://.");
  if (url.protocol === "http:" && !LOCAL.has(url.hostname))
    throw new ConnectError("Use https:// so your vault stays private on the way to the server. Plain http:// only works for localhost.");
  return url.origin;
}

/** Ask the server for its public settings; throws a ConnectError that says what to fix. */
export async function probeServer(base: string): Promise<PublicConfig> {
  const host = new URL(base).host;
  await connectServer(base);
  let res: Response;
  try {
    res = await nativeFetch(`${base}/api/config`, { headers: { accept: "application/json" } });
  } catch (e) {
    throw new ConnectError(typeof e === "string" ? e : `Can't reach ${host}. Check the address and your connection, then try again.`);
  }
  let config: Partial<PublicConfig> | null = null;
  try {
    config = (await res.json()) as Partial<PublicConfig>;
  } catch {
    config = null;
  }
  if (!res.ok || typeof config?.version !== "string" || typeof config.signups_allowed !== "boolean")
    throw new ConnectError(`${host} answered, but it isn't a PassAuth server. Check the address.`);
  return config as PublicConfig;
}
