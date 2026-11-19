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
  /**
   * Save a file's bytes (a downloaded attachment, decrypted) through the system save dialog; the app reads `blob` piece
   * by piece. Resolves false when the user cancels; tells the user "Saved" or what went wrong itself.
   */
  saveBytes(filename: string, blob: Blob): Promise<boolean>;
  /** Copy a secret and clear the clipboard after 30 s if it still holds it. */
  copySecret(value: string): Promise<void>;
  /** Open a web address in the user's browser. */
  openUrl(url: string): Promise<void>;
  /**
   * The app receives `passauth://two-step-key` links and feeds them to `keyPageWaiter` (web/src/lib/key-page.ts), so
   * two-step login with a security key goes through the server's key page in the browser (servers with
   * `two_step_key_page`). Without it the sign-in page hides the method, as the WebView can't run WebAuthn for the server.
   */
  securityKeyHandOff?: boolean;
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
  /** Plain-language note for each option; `minutes` for a number of minutes that isn't an option (the server's limit). */
  help: Partial<Record<string, string>>;
  /** Why an option can't be chosen right now (e.g. "Never" without a keychain), or null when it can. */
  disabledReason(value: VaultTimeout): string | null;
  /**
   * The server's longest vault timeout in minutes (policy `max_vault_timeout_minutes`; 0 = no limit) as the app last
   * learned it, also while offline. `subscribe` tells when it changes. Settings uses /api/config without it.
   */
  maxMinutes?(): number;
  get(): TimeoutSettings;
  set(patch: Partial<TimeoutSettings>): void;
  subscribe(fn: () => void): () => void;
}

let desktop: DesktopHooks | null = null;

/** The web vault's version, set by `define` in web/vite.config.ts (other builds that bundle this file don't set it). */
declare const __PASSAUTH_WEB_VERSION__: string | undefined;

/**
 * `X-PassAuth-Client` value sent with every API request, so the server can name each session's app:
 * `desktop/<app version>` in the desktop app, `web/<web vault version>` in the browser.
 */
export function clientId(): string {
  if (desktop) return `desktop/${desktop.version}`;
  return `web/${typeof __PASSAUTH_WEB_VERSION__ === "string" ? __PASSAUTH_WEB_VERSION__ : "unknown"}`;
}

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
