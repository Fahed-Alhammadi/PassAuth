/**
 * Logging. `warn` and `error` always go to the console of the context that logs (the service worker's own console
 * for the background: chrome://extensions → PassAuth → service worker); `debug` only while debug logging is on:
 * `chrome.storage.local.set({ debugLog: true })` in that console (background/main.ts follows the key).
 *
 * Never log vault data, passwords, keys or tokens: say what failed, with the error's code and message.
 */
import { codeOf, messageOf } from "./errors";

/** Storage key (chrome.storage.local) that switches debug logging on. */
export const DEBUG_KEY = "debugLog";

let debugOn = false;

export function setDebug(on: boolean) {
  debugOn = on;
}

const describe = (e: unknown) => {
  const code = codeOf(e);
  return code ? `${messageOf(e)} [${code}]` : messageOf(e);
};

export const log = {
  debug(what: string, e?: unknown) {
    if (debugOn) console.debug(`PassAuth: ${what}`, ...(e === undefined ? [] : [describe(e)]));
  },
  warn(what: string, e?: unknown) {
    console.warn(`PassAuth: ${what}`, ...(e === undefined ? [] : [describe(e)]));
  },
  error(what: string, e?: unknown) {
    console.error(`PassAuth: ${what}`, ...(e === undefined ? [] : [describe(e)]));
  },
};

/** For a promise whose failure must not stop the caller but should be seen: `.catch(logged("Syncing"))`. */
export const logged =
  (what: string) =>
  (e: unknown): void => {
    log.warn(`${what} failed:`, e);
  };

/** The same, settling with `value` instead: `ensureUnlocked().catch(loggedAs(false, "Restoring the vault"))`. */
export const loggedAs =
  <T>(value: T, what: string) =>
  (e: unknown): T => {
    log.warn(`${what} failed:`, e);
    return value;
  };
