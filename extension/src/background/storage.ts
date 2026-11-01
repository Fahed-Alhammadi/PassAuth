/**
 * chrome.storage wrappers.
 * - local: settings and accounts (persist across restarts). Up to
 *   MAX_ACCOUNTS accounts, each with its own server, tokens and unlock state;
 *   one is active. `local.get()` returns the active account's fields merged
 *   with the shared ones, so most code needn't know about accounts.
 * - session: unlocked keys per account; memory-only, extension-private, wiped
 *   when the browser closes. Content scripts cannot read it (TRUSTED_CONTEXTS default).
 */
import type { Settings } from "../shared/messages";

export const MAX_ACCOUNTS = 5;

export interface AccountData {
  server: string;
  email: string;
  /** Profile name, for the account initials. */
  name: string;
  tokens: { access: string; refresh: string } | null;
  lastSync: number;
  /** Unlocked keys kept on disk, only while the vault timeout is "never". */
  persistedKeys: SessionData | null;
}

interface Shared {
  deviceId: string;
  /** Two-step "remember this device" tokens, keyed `server|email`. */
  rememberTokens: Record<string, string>;
  /** Secret Keys typed at sign-in, keyed by email. */
  secretKeys: Record<string, string>;
  settings: Settings;
  neverSave: string[];
}

export interface LocalData extends Shared, AccountData {
  activeId: string;
  accounts: Record<string, AccountData>;
}

const ACCOUNT_FIELDS = ["server", "email", "name", "tokens", "lastSync", "persistedKeys"] as const;

export const defaultSettings: Settings = {
  vaultTimeout: 15,
  timeoutAction: "lock",
  inlineMenu: "focus",
  autoCopyTotp: true,
  clearClipboard: 30,
  showIcons: true,
  defaultMatch: "domain",
  askToSave: true,
  theme: "system",
  badge: true,
};

const emptyAccount: AccountData = { server: "", email: "", name: "", tokens: null, lastSync: 0, persistedKeys: null };

type Stored = Partial<Shared> & { accounts?: Record<string, AccountData>; active?: string } & Partial<AccountData> & { autoLockMinutes?: number };

// Account records are read-modify-written; serialize writes so concurrent updates don't drop each other.
let queue: Promise<unknown> = Promise.resolve();
const serial = <T>(fn: () => Promise<T>): Promise<T> => {
  const next = queue.then(fn, fn);
  queue = next.catch(() => {});
  return next;
};

async function load(): Promise<{ raw: Stored; accounts: Record<string, AccountData>; active: string }> {
  const raw = (await chrome.storage.local.get(null)) as Stored;
  let accounts = raw.accounts;
  let active = raw.active ?? "";
  if (!accounts) {
    // Before 0.3.1 there was one account stored at the top level.
    accounts = {};
    if (raw.server) {
      active = crypto.randomUUID();
      accounts[active] = { ...emptyAccount, ...Object.fromEntries(ACCOUNT_FIELDS.map((k) => [k, raw[k] ?? emptyAccount[k]])) } as AccountData;
    }
    await chrome.storage.local.set({ accounts, active });
    await chrome.storage.local.remove([...ACCOUNT_FIELDS]);
  }
  return { raw, accounts, active };
}

export const local = {
  async get(): Promise<LocalData> {
    const { raw, accounts, active } = await load();
    const settings = { ...defaultSettings, ...raw.settings };
    // Before 0.2 the only setting was autoLockMinutes (0 = when the browser closes).
    if (!raw.settings && raw.autoLockMinutes !== undefined) {
      settings.vaultTimeout = raw.autoLockMinutes > 0 ? raw.autoLockMinutes : "restart";
      await chrome.storage.local.set({ settings });
      await chrome.storage.local.remove("autoLockMinutes");
    }
    let deviceId = raw.deviceId ?? "";
    if (!deviceId) {
      deviceId = crypto.randomUUID();
      await chrome.storage.local.set({ deviceId });
    }
    return {
      deviceId,
      rememberTokens: raw.rememberTokens ?? {},
      secretKeys: raw.secretKeys ?? {},
      neverSave: raw.neverSave ?? [],
      settings,
      ...emptyAccount,
      ...accounts[active],
      activeId: accounts[active] ? active : "",
      accounts,
    };
  },

  /** Update shared fields, and account fields of `accountId` (default: the active account; one is created if none). */
  set: (patch: Partial<Shared & AccountData>, accountId?: string) =>
    serial(async () => {
      const shared: Record<string, unknown> = {};
      const own: Partial<AccountData> = {};
      for (const [k, v] of Object.entries(patch)) {
        if ((ACCOUNT_FIELDS as readonly string[]).includes(k)) (own as Record<string, unknown>)[k] = v;
        else shared[k] = v;
      }
      if (Object.keys(shared).length) await chrome.storage.local.set(shared);
      if (!Object.keys(own).length) return;
      const { accounts, active } = await load();
      let id = accountId ?? active;
      if (!id || !accounts[id]) {
        if (accountId) return; // that account was removed meanwhile
        id = crypto.randomUUID();
        await chrome.storage.local.set({ active: id });
      }
      await chrome.storage.local.set({ accounts: { ...accounts, [id]: { ...emptyAccount, ...accounts[id], ...own } } });
    }),

  /** Start adding an account: an empty record becomes active until it's signed in or cancelled. */
  addAccount: () =>
    serial(async () => {
      const { accounts } = await load();
      const signedIn = Object.values(accounts).filter((a) => a.server);
      if (signedIn.length >= MAX_ACCOUNTS) throw new Error(`PassAuth supports up to ${MAX_ACCOUNTS} accounts. Log out of one first.`);
      const id = crypto.randomUUID();
      // Drop other unfinished records (no server yet).
      const kept = Object.fromEntries(Object.entries(accounts).filter(([, a]) => a.server));
      await chrome.storage.local.set({ accounts: { ...kept, [id]: { ...emptyAccount } }, active: id });
      return id;
    }),

  setActive: (id: string) => serial(() => chrome.storage.local.set({ active: id })),

  /** Remove an account; the next remaining one becomes active. */
  removeAccount: (id: string) =>
    serial(async () => {
      const { accounts, active } = await load();
      const { [id]: _gone, ...rest } = accounts;
      const next = active === id ? (Object.keys(rest).find((k) => rest[k].tokens) ?? Object.keys(rest)[0] ?? "") : active;
      await chrome.storage.local.set({ accounts: rest, active: next });
      await chrome.storage.session.remove(`unlocked:${id}`);
    }),
};

export async function getSettings(): Promise<Settings> {
  return (await local.get()).settings;
}

export interface SessionData {
  accountId: string;
  keys: string; // base64 of Account.toSessionBytes()
  bundle: unknown;
}

async function activeId() {
  return ((await chrome.storage.local.get("active")).active as string | undefined) ?? "";
}

/** Unlocked keys per account (`id` defaults to the active account). */
export const session = {
  async get(id?: string): Promise<SessionData | null> {
    const key = `unlocked:${id ?? (await activeId())}`;
    return ((await chrome.storage.session.get(key))[key] as SessionData) ?? null;
  },
  async set(data: SessionData, id?: string) {
    await chrome.storage.session.set({ [`unlocked:${id ?? (await activeId())}`]: data });
  },
  async clear(id?: string) {
    await chrome.storage.session.remove(`unlocked:${id ?? (await activeId())}`);
  },
};
