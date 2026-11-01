/**
 * chrome.storage wrappers.
 * - local: settings and session tokens (persist across restarts).
 * - session: unlocked keys; memory-only, extension-private, wiped when the
 *   browser closes. Content scripts cannot read it (TRUSTED_CONTEXTS default).
 */
export interface LocalData {
  server: string;
  email: string;
  deviceId: string;
  tokens: { access: string; refresh: string } | null;
  rememberTokens: Record<string, string>;
  secretKeys: Record<string, string>;
  autoLockMinutes: number;
  neverSave: string[];
}

const defaults: LocalData = {
  server: "",
  email: "",
  deviceId: "",
  tokens: null,
  rememberTokens: {},
  secretKeys: {},
  autoLockMinutes: 15,
  neverSave: [],
};

export const local = {
  async get(): Promise<LocalData> {
    const v = (await chrome.storage.local.get(null)) as Partial<LocalData>;
    const data = { ...defaults, ...v };
    if (!data.deviceId) {
      data.deviceId = crypto.randomUUID();
      await chrome.storage.local.set({ deviceId: data.deviceId });
    }
    return data;
  },
  set: (patch: Partial<LocalData>) => chrome.storage.local.set(patch),
};

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
