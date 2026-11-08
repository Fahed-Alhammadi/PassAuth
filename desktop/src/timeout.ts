/**
 * Vault timeout for the desktop app, with the extension's options and meaning:
 * - minutes: counted from the last keyboard or mouse activity in the window, also while it's hidden;
 * - "immediately": as soon as the window is closed to the tray or minimised;
 * - "system-lock" (macOS): when the screen locks, the Mac sleeps or the user session is switched;
 * - "restart": only when the app quits (keys live in memory);
 * - "never": the unlocked account keys are kept in the OS keychain (`pa.keys`, scoped to the server like
 *   the other secrets) and the vault opens by itself at launch. They are removed on every lock, sign-out,
 *   server change and when the setting leaves "never"; a server that can't be reached keeps them, so the
 *   vault still opens offline later. Without a keychain (WebView-storage fallback) "Never" isn't offered
 *   and nothing is persisted.
 * The setting is per install (localStorage `desktop.vaultTimeout`), never sent to the server.
 */
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { getTokens } from "@web/lib/api";
import { secretStore, type TimeoutSettings, type VaultTimeout, type VaultTimeoutHook } from "@web/lib/platform";
import { UnreachableError, getState, lock, logout, onVaultChange, restoreUnlocked, sessionKeys, type Status } from "@web/lib/vault";
import { keychainAvailable } from "./secrets";

export const KEYS_KEY = "pa.keys";
const SETTINGS_KEY = "desktop.vaultTimeout";
const TICK_MS = 30_000;
const RETRY_MS = 30_000;
const NO_KEYCHAIN = "Not available: this computer has no keychain service.";
const isMac = navigator.platform.startsWith("Mac");

const defaults: TimeoutSettings = { vaultTimeout: 15, timeoutAction: "lock" };

const OPTIONS: [VaultTimeout, string][] = [
  ["immediately", "Immediately"],
  [1, "1 minute"],
  [5, "5 minutes"],
  [15, "15 minutes"],
  [30, "30 minutes"],
  [60, "1 hour"],
  [240, "4 hours"],
  ...(isMac ? ([["system-lock", "On system lock"]] as [VaultTimeout, string][]) : []),
  ["restart", "On app restart"],
  ["never", "Never"],
];

const MINUTES_HELP = "Counted from your last keyboard or mouse activity in this window, also while it's hidden in the tray.";
const HELP: VaultTimeoutHook["help"] = {
  immediately: "Locks as soon as the window is closed to the tray or minimised.",
  "system-lock": "Locks when you lock the screen, the Mac goes to sleep or you switch to another user.",
  restart: "Stays unlocked until you quit the app.",
  ...Object.fromEntries(OPTIONS.filter(([v]) => typeof v === "number").map(([v]) => [String(v), MINUTES_HELP])),
};

// ---------------------------------------------------------------- settings

let settings = load();
const listeners = new Set<() => void>();

function load(): TimeoutSettings {
  try {
    const raw = JSON.parse(localStorage.getItem(SETTINGS_KEY) ?? "null") as Partial<TimeoutSettings> | null;
    const timeout = raw?.vaultTimeout;
    const known = OPTIONS.some(([v]) => v === timeout);
    return {
      vaultTimeout: known ? (timeout as VaultTimeout) : defaults.vaultTimeout,
      timeoutAction: raw?.timeoutAction === "logout" ? "logout" : "lock",
    };
  } catch {
    return defaults;
  }
}

/** "Never" needs the keychain: with keys in WebView storage anyone with the files could open the vault. */
const neverAllowed = () => keychainAvailable();

function save(next: TimeoutSettings) {
  const previous = settings;
  settings = next;
  try {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(next));
  } catch {
    /* storage unavailable: applies to this run */
  }
  listeners.forEach((fn) => fn());
  if (previous.vaultTimeout === next.vaultTimeout) return;
  if (previous.vaultTimeout === "never") void clearPersistedKeys();
  if (getState().status === "unlocked") {
    if (next.vaultTimeout === "never") persistKeys();
    arm();
  }
}

export const vaultTimeoutHook: VaultTimeoutHook = {
  options: OPTIONS,
  help: HELP,
  disabledReason: (value) => (value === "never" && !neverAllowed() ? NO_KEYCHAIN : null),
  get: () => settings,
  set: (patch) => save({ ...settings, ...patch }),
  subscribe(fn) {
    listeners.add(fn);
    return () => {
      listeners.delete(fn);
    };
  },
};

// ------------------------------------------------------------ persisted keys

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const unb64 = (text: string) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

/** Keychain writes for one entry run in order (`secrets.ts`), so a later delete never overtakes this set. */
function persistKeys() {
  if (!neverAllowed()) return;
  const keys = sessionKeys();
  if (!keys) return;
  const value = JSON.stringify({ accountId: keys.accountId, keys: b64(keys.keys) });
  if (secretStore.get(KEYS_KEY) !== value) void secretStore.set(KEYS_KEY, value);
}

/** Remove the keys kept for "never"; resolves once the keychain entry is gone (no-op when there is none). */
export function clearPersistedKeys(): Promise<void> {
  return secretStore.get(KEYS_KEY) === null ? Promise.resolve() : secretStore.set(KEYS_KEY, null);
}

let restoring: Promise<void> | null = null;
let retry: number | undefined;

/**
 * "Never" and the session is locked: open the vault with the saved keys. A server that can't be reached
 * keeps the keys and tries again later (and after each `boot()`); anything else removes them.
 */
function maybeRestore(): Promise<void> {
  if (restoring) return restoring;
  clearTimeout(retry);
  if (settings.vaultTimeout !== "never" || getState().status !== "locked") return Promise.resolve();
  const raw = secretStore.get(KEYS_KEY);
  if (!raw) return Promise.resolve();
  restoring = (async () => {
    try {
      const saved = JSON.parse(raw) as { accountId: string; keys: string };
      await restoreUnlocked(saved.accountId, unb64(saved.keys));
    } catch (e) {
      if (e instanceof UnreachableError) retry = window.setTimeout(() => void maybeRestore(), RETRY_MS);
      else await clearPersistedKeys();
    } finally {
      restoring = null;
    }
  })();
  return restoring;
}

/**
 * At launch, after `boot()`: waits for the "never" restore the state change started, so the splash stays
 * until the vault is open; a timeout with the "sign out" action signs out (the lock that a restart means
 * for the "lock" action). A server that couldn't be reached changes nothing: the next `boot()` retries.
 */
export async function applyTimeoutAtStart() {
  if (settings.vaultTimeout === "never") return maybeRestore();
  await clearPersistedKeys();
  if (settings.timeoutAction === "logout" && getTokens() && getState().status !== "unreachable") void logout();
}

// ------------------------------------------------------------------- timers

let deadline = 0;
let armedAt = 0;
let timer: number | undefined;
let ticker: number | undefined;

/** The user's timeout action; a no-op while locked. Signing out drops the keys first: the server call may be slow offline. */
export async function timeout() {
  if (getState().status !== "unlocked") return;
  lock(false);
  await clearPersistedKeys();
  if (settings.timeoutAction === "logout") void logout();
}

function minutes(): number | null {
  return typeof settings.vaultTimeout === "number" ? settings.vaultTimeout : null;
}

/** Hidden windows may throttle timers, so the deadline is also checked on a slow tick and when the window comes back. */
function check() {
  if (deadline && Date.now() >= deadline) void timeout();
}

function arm() {
  disarm();
  const m = minutes();
  if (m === null) return;
  armedAt = Date.now();
  deadline = armedAt + m * 60_000;
  timer = window.setTimeout(check, m * 60_000 + 50);
  ticker = window.setInterval(check, TICK_MS);
}

function disarm() {
  clearTimeout(timer);
  clearInterval(ticker);
  timer = ticker = undefined;
  deadline = 0;
}

/** Mouse moves arrive constantly; restarting the timers once a second is plenty. */
const onActivity = () => {
  if (deadline && Date.now() - armedAt >= 1000) arm();
};

function onHidden() {
  if (settings.vaultTimeout === "immediately") void timeout();
  else check();
}

async function onFocusLost() {
  // Minimising doesn't always change the document's visibility; ask the window.
  if (settings.vaultTimeout === "immediately" && (await getCurrentWindow().isMinimized().catch(() => false))) void timeout();
}

/** Follow the vault: persist, restore or wipe the keys and start or stop the idle timer. Call once at start-up. */
export function installVaultTimeout() {
  let previous: Status = getState().status;
  onVaultChange(() => {
    const { status } = getState();
    if (status === previous) return;
    const was = previous;
    previous = status;
    if (status === "unlocked") {
      if (settings.vaultTimeout === "never") persistKeys();
      arm();
      return;
    }
    disarm();
    // Whatever locked an open vault, the saved keys go too; and nothing useful stays without a session
    // (the server rejected it, or the user signed out). A server that can't be reached keeps them.
    if (was === "unlocked" || status === "logged-out") void clearPersistedKeys();
    // A session that just loaded (launch, or "Try again" after the server was unreachable) opens by itself.
    else if (status === "locked") void maybeRestore();
  });

  const events = ["pointerdown", "pointermove", "keydown", "wheel", "touchstart"];
  events.forEach((e) => window.addEventListener(e, onActivity, { passive: true }));
  document.addEventListener("visibilitychange", () => (document.visibilityState === "hidden" ? onHidden() : check()));
  void listen("window-hidden", onHidden);
  void listen("system-lock", () => {
    if (settings.vaultTimeout === "system-lock") void timeout();
  });
  void getCurrentWindow().onFocusChanged(({ payload: focused }) => (focused ? check() : void onFocusLost()));
}
