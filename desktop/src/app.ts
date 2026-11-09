/**
 * Desktop shell settings, shown in Settings → Account → "This app":
 * - start at login: an OS login item through the autostart plugin; the app is launched with `--hidden`, so it
 *   starts in the tray without opening the window;
 * - keep the Dock icon while the window is closed (macOS): kept by the shell in its own settings file, because
 *   the shell applies it before the webview loads (`shell_settings_*` commands);
 * - background sync: while the vault is unlocked the live connection pushes changes, but it can die silently
 *   after sleep or a network change. Every `backgroundSyncMinutes` (default 2 hours), when the computer wakes,
 *   and when the window comes back after a while, the app asks the server for its revision, reconnects the
 *   live connection and syncs if anything changed (`resync`). Nothing runs while the vault is locked: there is
 *   no offline copy on desktop, so there is nothing to refresh.
 * The sync interval is per install (localStorage `desktop.app`), never sent to the server.
 */
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { disable, enable, isEnabled } from "@tauri-apps/plugin-autostart";
import { toast } from "@web/components/ui";
import type { DesktopAppHook, DesktopAppSettings } from "@web/lib/platform";
import { getState, onVaultChange, resync } from "@web/lib/vault";

const SETTINGS_KEY = "desktop.app";
const DEFAULT_SYNC = 120;
const SYNC_OPTIONS: [number, string][] = [
  [0, "Off"],
  [30, "Every 30 minutes"],
  [60, "Every hour"],
  [120, "Every 2 hours"],
  [360, "Every 6 hours"],
  [720, "Every 12 hours"],
];
/** The timer checks once a minute; a tick this late means the computer slept. */
const TICK_MS = 60_000;
const SLEPT_MS = 5 * 60_000;
/** The window coming back triggers a check only if the last one is older than this. */
const FOCUS_MIN_MS = 5 * 60_000;

const platform: DesktopAppHook["platform"] = navigator.platform.startsWith("Mac")
  ? "macos"
  : navigator.platform.startsWith("Win")
    ? "windows"
    : "linux";

let settings: DesktopAppSettings = { startAtLogin: false, keepDock: false, backgroundSyncMinutes: loadInterval() };
const listeners = new Set<() => void>();
const notify = () => listeners.forEach((fn) => fn());

function loadInterval(): number {
  try {
    const raw = JSON.parse(localStorage.getItem(SETTINGS_KEY) ?? "null") as Partial<DesktopAppSettings> | null;
    const m = raw?.backgroundSyncMinutes;
    return SYNC_OPTIONS.some(([v]) => v === m) ? (m as number) : DEFAULT_SYNC;
  } catch {
    return DEFAULT_SYNC;
  }
}

function saveInterval(minutes: number) {
  try {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify({ backgroundSyncMinutes: minutes }));
  } catch {
    /* storage unavailable: applies to this run */
  }
}

/** Read what the OS and the shell hold (login item, Dock setting). Call once before the hooks are registered. */
export async function appHook(): Promise<DesktopAppHook> {
  const [startAtLogin, shell] = await Promise.all([
    isEnabled().catch(() => false),
    invoke<{ keepDock: boolean }>("shell_settings_get").catch(() => ({ keepDock: false })),
  ]);
  // The login item stores this executable's path. Rewrite it once per launch so it follows the app when it was
  // moved (Downloads → Applications) or a new AppImage was downloaded by hand; `isEnabled` only checks existence.
  if (startAtLogin) enable().catch(() => {});
  settings = { ...settings, startAtLogin, keepDock: shell.keepDock };
  return {
    platform,
    syncOptions: SYNC_OPTIONS,
    get: () => settings,
    subscribe(fn) {
      listeners.add(fn);
      return () => {
        listeners.delete(fn);
      };
    },
    async set(patch) {
      if (patch.startAtLogin !== undefined && patch.startAtLogin !== settings.startAtLogin) {
        try {
          await (patch.startAtLogin ? enable() : disable());
          settings = { ...settings, startAtLogin: await isEnabled() };
        } catch {
          toast("Couldn't change the login item.");
        }
      }
      if (patch.keepDock !== undefined && patch.keepDock !== settings.keepDock) {
        try {
          await invoke("shell_settings_set", { keepDock: patch.keepDock });
          settings = { ...settings, keepDock: patch.keepDock };
        } catch {
          toast("Couldn't save the setting.");
        }
      }
      if (patch.backgroundSyncMinutes !== undefined && SYNC_OPTIONS.some(([v]) => v === patch.backgroundSyncMinutes)) {
        settings = { ...settings, backgroundSyncMinutes: patch.backgroundSyncMinutes };
        saveInterval(patch.backgroundSyncMinutes);
        lastCheck = Date.now();
      }
      notify();
    },
  };
}

// ---------------------------------------------------------- background sync

let ticker: number | undefined;
let lastTick = Date.now();
let lastCheck = Date.now();

function check(reason: "timer" | "wake" | "focus") {
  if (getState().status !== "unlocked") return;
  const now = Date.now();
  if (reason === "focus" && now - lastCheck < FOCUS_MIN_MS) return;
  lastCheck = now;
  resync().catch(() => {});
}

function tick() {
  const now = Date.now();
  const slept = now - lastTick > SLEPT_MS;
  lastTick = now;
  const m = settings.backgroundSyncMinutes;
  if (slept) check("wake");
  else if (m > 0 && now - lastCheck >= m * 60_000) check("timer");
}

/** Start the checks while the vault is unlocked. Call once at start-up. */
export function installBackgroundSync() {
  onVaultChange(() => {
    const unlocked = getState().status === "unlocked";
    if (unlocked && ticker === undefined) {
      lastTick = lastCheck = Date.now();
      ticker = window.setInterval(tick, TICK_MS);
    } else if (!unlocked && ticker !== undefined) {
      clearInterval(ticker);
      ticker = undefined;
    }
  });
  void listen("system-wake", () => check("wake"));
  document.addEventListener("visibilitychange", () => document.visibilityState === "visible" && check("focus"));
  void getCurrentWindow().onFocusChanged(({ payload: focused }) => focused && check("focus"));
}
