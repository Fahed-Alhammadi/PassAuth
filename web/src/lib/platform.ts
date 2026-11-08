/** Host hooks. The web vault and the extension run without any; the desktop app registers its own. */
export interface DesktopHooks {
  /** Desktop app version, shown in Settings next to the server version. */
  version: string;
  /** Keyboard shortcut that locks the vault, e.g. "⌘L", shown next to the Lock button. */
  lockShortcut: string;
  /** Sign out, forget the server address and show the connect page. */
  changeServer(): Promise<void>;
  /**
   * Check for an app update. Resolves with the available version, or null when up to date. The app
   * shows the available/error dialogs itself; the "up to date" dialog only when `tellUpToDate`.
   */
  checkForUpdates(tellUpToDate: boolean): Promise<string | null>;
  /** Download and install the update found by the last check, then restart. */
  installUpdate(): Promise<void>;
  /** Save a file through the system save dialog. Resolves false when the user cancels. */
  saveFile(filename: string, content: string): Promise<boolean>;
  /** Copy a secret and clear the clipboard after 30 s if it still holds it. */
  copySecret(value: string): Promise<void>;
  /** Open a web address in the user's browser. */
  openUrl(url: string): Promise<void>;
  /** The OS keychain, one entry per name (already scoped to the connected server). */
  secrets: {
    get(name: string): Promise<string | null>;
    set(name: string, value: string): Promise<void>;
    delete(name: string): Promise<void>;
  };
  /** Vault timeout setting (the extension's options). Settings shows the card only when present. */
  vaultTimeout?: VaultTimeoutHook;
  /** Desktop shell settings (start at login, Dock, background sync). Settings shows the card only when present. */
  app?: DesktopAppHook;
}

export interface DesktopAppSettings {
  /** OS login item; the app then starts in the tray. */
  startAtLogin: boolean;
  /** macOS: keep the Dock icon while the window is closed (the app is always in the menu bar). */
  keepDock: boolean;
  /** Minutes between background checks of the server's revision while unlocked; 0 = off. */
  backgroundSyncMinutes: number;
}
export interface DesktopAppHook {
  platform: "macos" | "windows" | "linux";
  /** Background-sync intervals in minutes (0 = off), in display order, with their labels. */
  syncOptions: [number, string][];
  get(): DesktopAppSettings;
  /** Applies what it can and reports failures itself (toast). */
  set(patch: Partial<DesktopAppSettings>): Promise<void>;
  subscribe(fn: () => void): () => void;
}

/** Minutes, or a moment: the same values as the extension. */
export type VaultTimeout = number | "immediately" | "system-lock" | "restart" | "never";
export type TimeoutAction = "lock" | "logout";
export interface TimeoutSettings {
  vaultTimeout: VaultTimeout;
  timeoutAction: TimeoutAction;
}
export interface VaultTimeoutHook {
  /** The options this platform supports, in display order, with their labels. */
  options: [VaultTimeout, string][];
  /** Plain-language note for each option. */
  help: Partial<Record<string, string>>;
  /** Why an option can't be chosen right now (e.g. "Never" without a keychain), or null when it can. */
  disabledReason(value: VaultTimeout): string | null;
  get(): TimeoutSettings;
  set(patch: Partial<TimeoutSettings>): void;
  subscribe(fn: () => void): () => void;
}

let desktop: DesktopHooks | null = null;

export const isDesktop = () => desktop !== null;
/** Where saved data lives, for user-facing copy: "this browser" or "this app". */
export const clientName = (capital = false) => (capital ? "T" : "t") + (desktop ? "his app" : "his browser");
export const getDesktop = () => desktop;

export function registerDesktop(hooks: DesktopHooks) {
  desktop = hooks;
}

/**
 * Sign-in tokens, remembered Secret Keys and 2FA tokens. Browser and extension: localStorage. Desktop:
 * an in-memory mirror, persisted to the keychain through the hooks and filled by `loadSecrets` before boot.
 */
const mirror = new Map<string, string>();

export const secretStore = {
  get(key: string): string | null {
    if (desktop) return mirror.get(key) ?? null;
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  },
  /** The mirror updates at once; the returned promise settles when the keychain write has finished (desktop). */
  set(key: string, value: string | null): Promise<void> {
    if (desktop) {
      if (value === null) mirror.delete(key);
      else mirror.set(key, value);
      return (value === null ? desktop.secrets.delete(key) : desktop.secrets.set(key, value)).catch(() => {});
    }
    try {
      if (value === null) localStorage.removeItem(key);
      else localStorage.setItem(key, value);
    } catch {
      /* storage unavailable */
    }
    return Promise.resolve();
  },
};

/** Desktop: read `keys` from the keychain into the mirror. Call before `boot()` and after changing server. */
export async function loadSecrets(keys: string[]) {
  if (!desktop) return;
  const values = await Promise.all(keys.map((k) => desktop!.secrets.get(k)));
  keys.forEach((k, i) => (values[i] === null ? mirror.delete(k) : mirror.set(k, values[i])));
}

export function forgetSecrets() {
  mirror.clear();
}
