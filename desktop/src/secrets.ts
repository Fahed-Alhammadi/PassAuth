/**
 * Keychain entries for the web vault's secrets, one namespace per server so two servers never share a session.
 * Calls are serialised per entry name: the `secret_*` commands run on a blocking thread pool with no ordering,
 * so a delete issued right after a set must not overtake it (unlock → ⌘L would otherwise leave live keys behind).
 */
import { invoke } from "@tauri-apps/api/core";
import type { DesktopHooks } from "@web/lib/platform";

let host = "";
let useLocalStorage = false;

export function setSecretsHost(h: string) {
  host = h;
}

/** False once the OS keychain turned out to be unavailable and secrets live in WebView storage instead. */
export const keychainAvailable = () => !useLocalStorage;

const name = (key: string) => `${host}|${key}`;

/** Without a keychain (no Secret Service on Linux, say) the app still works, from WebView storage. */
function fallback(error: unknown): boolean {
  if (String(error) !== "unavailable") return false;
  if (!useLocalStorage) console.warn("Keychain unavailable; keeping secrets in WebView storage.");
  useLocalStorage = true;
  return true;
}

const chains = new Map<string, Promise<unknown>>();

/** Run `fn` after every earlier call for the same entry has finished (whatever their outcome). */
function serial<T>(entry: string, fn: () => Promise<T>): Promise<T> {
  const previous = chains.get(entry) ?? Promise.resolve();
  const next = previous.catch(() => {}).then(fn);
  chains.set(entry, next);
  void next.finally(() => {
    if (chains.get(entry) === next) chains.delete(entry);
  });
  return next;
}

function run<T>(command: string, args: { name: string; value?: string }, local: () => T): Promise<T> {
  return serial(args.name, async () => {
    if (useLocalStorage) return local();
    try {
      return await invoke<T>(command, args);
    } catch (e) {
      if (fallback(e)) return local();
      throw e;
    }
  });
}

export const secrets: DesktopHooks["secrets"] = {
  get: (key) => run("secret_get", { name: name(key) }, () => localStorage.getItem(name(key))),
  set: (key, value) => run("secret_set", { name: name(key), value }, () => localStorage.setItem(name(key), value)),
  delete: (key) => run("secret_delete", { name: name(key) }, () => localStorage.removeItem(name(key))),
};
