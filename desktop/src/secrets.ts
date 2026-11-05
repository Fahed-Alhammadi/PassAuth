/** Keychain entries for the web vault's secrets, one namespace per server so two servers never share a session. */
import { invoke } from "@tauri-apps/api/core";
import type { DesktopHooks } from "@web/lib/platform";

let host = "";
let useLocalStorage = false;

export function setSecretsHost(h: string) {
  host = h;
}

const name = (key: string) => `${host}|${key}`;

/** Without a keychain (no Secret Service on Linux, say) the app still works, from WebView storage. */
function fallback(error: unknown): boolean {
  if (String(error) !== "unavailable") return false;
  if (!useLocalStorage) console.warn("Keychain unavailable; keeping secrets in WebView storage.");
  useLocalStorage = true;
  return true;
}

async function run<T>(command: string, args: Record<string, string>, local: () => T): Promise<T> {
  if (useLocalStorage) return local();
  try {
    return await invoke<T>(command, args);
  } catch (e) {
    if (fallback(e)) return local();
    throw e;
  }
}

export const secrets: DesktopHooks["secrets"] = {
  get: (key) => run("secret_get", { name: name(key) }, () => localStorage.getItem(name(key))),
  set: (key, value) => run("secret_set", { name: name(key), value }, () => localStorage.setItem(name(key), value)),
  delete: (key) => run("secret_delete", { name: name(key) }, () => localStorage.removeItem(name(key))),
};
