/**
 * chrome.storage wrappers.
 * - local: settings and session tokens (persist across restarts).
 * - session: unlocked keys; memory-only, extension-private, wiped when the
 *   browser closes. Content scripts cannot read it (TRUSTED_CONTEXTS default).
 */
import type { Settings } from "../shared/messages";

export interface LocalData {
  server: string;
  email: string;
  deviceId: string;
  tokens: { access: string; refresh: string } | null;
  rememberTokens: Record<string, string>;
  secretKeys: Record<string, string>;
  settings: Settings;
  neverSave: string[];
  lastSync: number;
  /** Unlocked keys kept on disk, only while the vault timeout is "never". */
  persistedKeys: SessionData | null;
}

export const defaultSettings: Settings = {
  vaultTimeout: 15,
  timeoutAction: "lock",
  inlineMenu: "focus",
  autoCopyTotp: true,
  clearClipboard: 30,
  showIcons: true,
  defaultMatch: "domain",
  askToSave: true,
};

const defaults: LocalData = {
  server: "",
  email: "",
  deviceId: "",
  tokens: null,
  rememberTokens: {},
  secretKeys: {},
  settings: defaultSettings,
  neverSave: [],
  lastSync: 0,
  persistedKeys: null,
};

export const local = {
  async get(): Promise<LocalData> {
    const v = (await chrome.storage.local.get(null)) as Partial<LocalData> & { autoLockMinutes?: number };
    const data = { ...defaults, ...v, settings: { ...defaultSettings, ...v.settings } };
    if (!data.deviceId) {
      data.deviceId = crypto.randomUUID();
      await chrome.storage.local.set({ deviceId: data.deviceId });
    }
    // Before 0.2 the only setting was autoLockMinutes (0 = when the browser closes).
    if (!v.settings && v.autoLockMinutes !== undefined) {
      data.settings.vaultTimeout = v.autoLockMinutes > 0 ? v.autoLockMinutes : "restart";
      await chrome.storage.local.set({ settings: data.settings });
      await chrome.storage.local.remove("autoLockMinutes");
    }
    return data;
  },
  set: (patch: Partial<LocalData>) => chrome.storage.local.set(patch),
};

export async function getSettings(): Promise<Settings> {
  return (await local.get()).settings;
}

export interface SessionData {
  accountId: string;
  keys: string; // base64 of Account.toSessionBytes()
  bundle: unknown;
}

export const session = {
  async get(): Promise<SessionData | null> {
    const v = await chrome.storage.session.get("unlocked");
    return (v.unlocked as SessionData) ?? null;
  },
  set: (data: SessionData) => chrome.storage.session.set({ unlocked: data }),
  clear: () => chrome.storage.session.remove("unlocked"),
};
