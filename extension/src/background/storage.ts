/**
 * chrome.storage wrappers.
 * - local: settings and accounts (persist across restarts). Up to
 *   MAX_ACCOUNTS accounts, each with its own server, tokens and unlock state;
 *   one is active. `local.get()` returns the active account's fields merged
 *   with the shared ones, so most code needn't know about accounts. Writes go
 *   through one queue; `local.update(fn)` reads and writes inside it. Old
 *   layouts are migrated once (migrations.ts, `schemaVersion`), not on reads.
 * - session: unlocked keys per account and short-lived pending state (inline
 *   menus, save prompts, the match index); memory-only, extension-private,
 *   wiped when the browser closes. Content scripts cannot read it
 *   (TRUSTED_CONTEXTS default).
 * - syncCache: the offline copy per account (server ciphertext only, with the
 *   delta-sync cursor and vault numbers in the same record), in the extension
 *   origin's IndexedDB, so the vault opens offline and after a service-worker
 *   restart without downloading everything again. Content scripts can't reach
 *   the extension's IndexedDB.
 * - deviceMemory: what this browser remembers per account to notice a rollback (item edit counters, vault manifest
 *   versions and links, when it first saw items in the trash), in the same IndexedDB store under its own key. It is
 *   NOT part of the offline copy: a vault timeout that signs out removes the copy, never this memory.
 * - knownFeatures: per server address, the feature list of the last `/api/config` this browser read.
 */
import type { Bundle, SyncResponse } from "@web/lib/types";
import { log, logged } from "../shared/log";
import { AVATAR_OPEN_PREFIX, AVATAR_PREFIX } from "../shared/storage-keys";
import type { Settings } from "../shared/types";
import { forgetLastUsed } from "./last-used";
import type { StoredSync } from "./sync-rules";

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
  /** The account bundle says it needs a Secret Key (kept here so the lock screen needn't read the offline copy). Unknown for records from before 0.7. */
  secretKeyEnabled?: boolean;
  /** The account id the core authenticated at unlock (signed sharing: names the trust memory removed with the account). */
  userId?: string;
}

export interface Shared {
  deviceId: string;
  /** Two-step "remember this device" tokens, keyed `accountKey(server, email)`. */
  rememberTokens: Record<string, string>;
  /** Secret Keys typed at sign-in or unlock, keyed `accountKey(server, email)`. */
  secretKeys: Record<string, string>;
  settings: Settings;
  neverSave: string[];
  /** Sites (base domains) where PassAuth hides its inline menu and fill entries. */
  hiddenSites: string[];
}

/**
 * Key for what this browser remembers about one account (Secret Key, "remember
 * this device" token): the server address as stored (origin plus any path) and
 * the email in lower case, so the same email on two servers never shares one.
 */
export const accountKey = (server: string, email: string) => `${server}|${email.trim().toLowerCase()}`;

export interface LocalData extends Shared, AccountData {
  activeId: string;
  accounts: Record<string, AccountData>;
}

/** A change to shared fields and to fields of one account. */
export type LocalPatch = Partial<Shared & AccountData>;

export const ACCOUNT_FIELDS = ["server", "email", "name", "tokens", "lastSync", "persistedKeys", "secretKeyEnabled", "userId"] as const;

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
  contextMenu: true,
  inlineOnSignup: true,
  density: "comfortable",
};

export const emptyAccount: AccountData = { server: "", email: "", name: "", tokens: null, lastSync: 0, persistedKeys: null };

type Stored = Partial<Shared> & { accounts?: Record<string, AccountData>; active?: string };

// Account records are read-modify-written; one queue for every write, so concurrent updates don't drop each other.
let queue: Promise<unknown> = Promise.resolve();
/** Run `fn` in the write queue (after every write queued before it). */
export const serial = <T>(fn: () => Promise<T>): Promise<T> => {
  const next = queue.then(fn, fn);
  queue = next.catch(() => {}); // the caller gets the failure; the queue goes on
  return next;
};

/** Set while the one-time migrations run (migrations.ts): reads wait for them instead of seeing half-moved data. */
let migrating: Promise<unknown> = Promise.resolve();
export function readsWaitFor(p: Promise<unknown>) {
  migrating = p.catch(() => {}); // a failed migration was logged by migrations.ts; reads go on with what is stored
}

// Only these keys are read (not get(null)), so other data in storage never slows down every request.
const LOCAL_KEYS = ["accounts", "active", "deviceId", "rememberTokens", "secretKeys", "settings", "neverSave", "hiddenSites"] as const;

async function read(): Promise<LocalData> {
  const raw = (await chrome.storage.local.get([...LOCAL_KEYS])) as Stored;
  const accounts = raw.accounts ?? {};
  const active = raw.active ?? "";
  const own = accounts[active];
  return {
    deviceId: raw.deviceId ?? "",
    rememberTokens: raw.rememberTokens ?? {},
    secretKeys: raw.secretKeys ?? {},
    neverSave: raw.neverSave ?? [],
    hiddenSites: raw.hiddenSites ?? [],
    settings: { ...defaultSettings, ...raw.settings },
    ...emptyAccount,
    ...own,
    activeId: own ? active : "",
    accounts,
  };
}

/** Write `patch`: shared fields as they are, account fields into `accountId`'s record (default: the active one; one is created if none). */
async function write(patch: LocalPatch, accountId?: string) {
  const shared: Record<string, unknown> = {};
  const own: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(patch)) {
    if ((ACCOUNT_FIELDS as readonly string[]).includes(k)) own[k] = v;
    else shared[k] = v;
  }
  if (Object.keys(shared).length) await chrome.storage.local.set(shared);
  if (!Object.keys(own).length) return;
  const raw = (await chrome.storage.local.get(["accounts", "active"])) as Stored;
  const accounts = raw.accounts ?? {};
  let id = accountId ?? raw.active ?? "";
  if (!id || !accounts[id]) {
    if (accountId) return; // that account was removed meanwhile
    id = crypto.randomUUID();
    await chrome.storage.local.set({ active: id });
  }
  await chrome.storage.local.set({ accounts: { ...accounts, [id]: { ...emptyAccount, ...accounts[id], ...own } } });
}

/** Read-modify-write of one entry of a shared map, in the write queue (concurrent writers don't drop each other's entries). */
const setEntry = (field: "secretKeys" | "rememberTokens", key: string, value: string | null) =>
  serial(async () => {
    const map = { ...(((await chrome.storage.local.get(field)) as Stored)[field] ?? {}) };
    if (value === null) delete map[key];
    else map[key] = value;
    await chrome.storage.local.set({ [field]: map });
  });

export const local = {
  async get(): Promise<LocalData> {
    await migrating;
    return read();
  },

  /** Update shared fields, and account fields of `accountId` (default: the active account; one is created if none). */
  set: (patch: LocalPatch, accountId?: string) => serial(() => write(patch, accountId)),

  /**
   * Read-modify-write inside the write queue: `fn` gets what is stored now and returns the patch to write (for
   * `accountId`'s fields, default the active account), or null to write nothing. Resolves with what was written.
   * `fn` must not wait for other writes (it runs inside the queue).
   */
  update: (fn: (current: LocalData) => LocalPatch | null | Promise<LocalPatch | null>, accountId?: string) =>
    serial(async () => {
      // No wait for `migrating` here: the migrations run in this same queue, so they are done or still to come.
      const patch = await fn(await read());
      if (patch) await write(patch, accountId);
      return patch;
    }),

  /** This browser's device id (sent at sign-in), created the first time it is needed. */
  deviceId: () =>
    serial(async () => {
      const { deviceId } = (await chrome.storage.local.get("deviceId")) as Stored;
      if (deviceId) return deviceId;
      const id = crypto.randomUUID();
      await chrome.storage.local.set({ deviceId: id });
      return id;
    }),

  /** Start adding an account: an empty record becomes active until it's signed in or cancelled. */
  addAccount: () =>
    serial(async () => {
      const { accounts } = await read();
      const signedIn = Object.values(accounts).filter((a) => a.server);
      if (signedIn.length >= MAX_ACCOUNTS) throw new Error(`PassAuth supports up to ${MAX_ACCOUNTS} accounts. Sign out of one first.`);
      const id = crypto.randomUUID();
      // Drop other unfinished records (no server yet).
      const kept = Object.fromEntries(Object.entries(accounts).filter(([, a]) => a.server));
      await chrome.storage.local.set({ accounts: { ...kept, [id]: { ...emptyAccount } }, active: id });
      return id;
    }),

  setActive: (id: string) => serial(() => chrome.storage.local.set({ active: id })),

  /** Store (or with `null` forget) the Secret Key of the account `server|email`. */
  setSecretKey: (server: string, email: string, secretKey: string | null) => setEntry("secretKeys", accountKey(server, email), secretKey),

  /** Store (or with `null` forget) the two-step "remember this device" token of the account `server|email`. */
  setRememberToken: (server: string, email: string, token: string | null) => setEntry("rememberTokens", accountKey(server, email), token),

  /** "Forget this browser" (and sign-out): the account's remember-device token and stored Secret Key go. */
  forgetDevice: (server: string, email: string) =>
    serial(async () => {
      const key = accountKey(server, email);
      const raw = (await chrome.storage.local.get(["secretKeys", "rememberTokens"])) as Stored;
      const { [key]: _sk, ...secretKeys } = raw.secretKeys ?? {};
      const { [key]: _rt, ...rememberTokens } = raw.rememberTokens ?? {};
      await chrome.storage.local.set({ secretKeys, rememberTokens });
    }),

  /** Remove an account (with what this browser remembers for it); the next remaining one becomes active. */
  removeAccount: (id: string) =>
    serial(async () => {
      const raw = (await chrome.storage.local.get(["accounts", "active", "secretKeys", "rememberTokens"])) as Stored;
      const { [id]: gone, ...rest } = raw.accounts ?? {};
      const active = raw.active ?? "";
      const next = active === id ? (Object.keys(rest).find((k) => rest[k]?.tokens) ?? Object.keys(rest)[0] ?? "") : active;
      const patch: Record<string, unknown> = { accounts: rest, active: next };
      if (gone?.server && gone.email) {
        const key = accountKey(gone.server, gone.email);
        const { [key]: _sk, ...secretKeys } = raw.secretKeys ?? {};
        const { [key]: _rt, ...rememberTokens } = raw.rememberTokens ?? {};
        Object.assign(patch, { secretKeys, rememberTokens });
      }
      await chrome.storage.local.set(patch);
      await chrome.storage.local.remove(`${AVATAR_PREFIX}${id}`);
      await chrome.storage.session.remove([`unlocked:${id}`, pinKey(id), `${AVATAR_OPEN_PREFIX}${id}`]);
      await forgetLastUsed(id);
      await syncCache.clear(id);
      if (gone?.server && gone.userId) {
        await trustMemory.clear(gone.server, gone.userId);
        // What this browser remembered to notice a rollback goes only here: with the account, never at a sign-out.
        await deviceMemory.clear(gone.server, gone.userId);
        // Inside the write queue already: the count goes directly.
        await writeUnread(gone.server, gone.userId, () => null).catch(logged("Forgetting the unreadable-memory count"));
      }
    }),

  /** One account's record without reading everything else (hot path: every API request). */
  async account(id?: string): Promise<{ id: string; data: AccountData | undefined }> {
    await migrating;
    const raw = (await chrome.storage.local.get(["accounts", "active"])) as Stored;
    const key = id ?? raw.active ?? "";
    return { id: key, data: raw.accounts?.[key] };
  },
};

export async function getSettings(): Promise<Settings> {
  await migrating;
  const raw = (await chrome.storage.local.get("settings")) as Stored;
  return { ...defaultSettings, ...raw.settings };
}

export interface SessionData {
  accountId: string;
  keys: string; // base64 of Account.toSessionBytes()
  bundle: Bundle;
}

export async function activeId(): Promise<string> {
  await migrating;
  return ((await chrome.storage.local.get("active")).active as string | undefined) ?? "";
}

/** Unlocked keys per account (`id` defaults to the active account). */
export const session = {
  async get(id?: string): Promise<SessionData | null> {
    const key = `unlocked:${id ?? (await activeId())}`;
    return ((await chrome.storage.session.get(key))[key] as SessionData | undefined) ?? null;
  },
  async set(data: SessionData, id?: string) {
    await chrome.storage.session.set({ [`unlocked:${id ?? (await activeId())}`]: data });
  },
  async clear(id?: string) {
    const aid = id ?? (await activeId());
    // With the keys goes what they opened for the popup: the profile picture (a locked account shows its initials).
    await chrome.storage.session.remove([`unlocked:${aid}`, earlierKey(aid), `${AVATAR_OPEN_PREFIX}${aid}`]);
  },
};

const earlierKey = (id: string) => `earlier:${id}`;

/**
 * Signed sharing, grandfathering (docs/ARCHITECTURE.md "Grandfathering", extension re-review M1): the vault ids that
 * were in the account's offline copy when this unlock started (from an earlier session), kept for the unlock in session
 * storage so a worker restart doesn't count this session's own copy as an earlier one. Removed with the session keys.
 */
export const earlierVaults = {
  /** `[{vault_id, key_id}]` as kept for this unlock; anything else (bare ids from before round 5): none. */
  async get(id: string): Promise<{ vault_id: string; key_id: string }[] | null> {
    const v = (await chrome.storage.session.get(earlierKey(id)))[earlierKey(id)];
    if (!Array.isArray(v)) return null;
    return v.flatMap((x) => {
      const c = x as { vault_id?: unknown; key_id?: unknown } | null;
      return c && typeof c === "object" && typeof c.vault_id === "string" && typeof c.key_id === "string" ? [{ vault_id: c.vault_id, key_id: c.key_id }] : [];
    });
  },
  set: (id: string, list: { vault_id: string; key_id: string }[]) => chrome.storage.session.set({ [earlierKey(id)]: list }),
};

const floorKey = (id: string) => `pinsFloor:${id}`;

/**
 * Per account, the highest key pins version this browser session opened or kept (chrome.storage.session, so it outlives
 * a worker restart): while the trust memory can't be read, a server copy below it is never used (review round 5 L).
 */
export const pinsFloor = {
  async get(id: string): Promise<number> {
    const v = (await chrome.storage.session.get(floorKey(id)))[floorKey(id)];
    return typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : 0;
  },
  set: (id: string, seq: number) => chrome.storage.session.set({ [floorKey(id)]: seq }),
};

/**
 * A PIN-wrapped copy of one account's keys (pin.ts). Only ever in chrome.storage.session: memory-only, readable by
 * PassAuth's own pages and worker (not content scripts), gone when the browser session ends; never on disk.
 */
export interface PinCopy {
  /** The account bundle with its Account Key re-wrapped under a key the core derives from the PIN (Argon2id, its own salt). */
  wrapped: Bundle;
  /** The account's own bundle (master password) the copy was made from: when the server's differs, the master password or Secret Key changed and the copy goes. */
  base: Bundle;
  /** Wrong PINs so far (counted before each check). */
  failures: number;
}

const pinKey = (id: string) => `pin:${id}`;

const isPinCopy = (v: unknown): v is PinCopy => {
  const c = v as Partial<PinCopy> | null;
  return !!c && typeof c === "object" && !!c.wrapped && !!c.base && typeof c.failures === "number";
};

/**
 * PIN-wrapped keys per account. Changes go through the storage write queue (`serial`), so a removal (sign-out,
 * account switch) and a write of the try counter never interleave: a removed copy can't come back.
 */
export const pinCopies = {
  async get(id: string): Promise<PinCopy | null> {
    if (!id) return null;
    const v = (await chrome.storage.session.get(pinKey(id)))[pinKey(id)];
    return isPinCopy(v) ? v : null;
  },
  /** Read-modify-write in the queue: `fn` gets the stored copy (or null) and returns the new one, null to delete it, undefined to leave it. Resolves with what is stored afterwards. */
  update: (id: string, fn: (current: PinCopy | null) => PinCopy | null | undefined): Promise<PinCopy | null> =>
    serial(async () => {
      const raw = (await chrome.storage.session.get(pinKey(id)))[pinKey(id)];
      const current = isPinCopy(raw) ? raw : null;
      const next = fn(current);
      if (next === undefined) return current;
      if (next === null) await chrome.storage.session.remove(pinKey(id));
      else await chrome.storage.session.set({ [pinKey(id)]: next });
      return next;
    }),
  remove: (ids: string[]): Promise<void> => serial(() => chrome.storage.session.remove(ids.filter(Boolean).map(pinKey))),
};

/** Short-lived state that must survive a service-worker restart (extension-private, memory-only). */
export const scratch = {
  async get<T>(key: string): Promise<T | undefined> {
    return (await chrome.storage.session.get(key))[key] as T | undefined;
  },
  set: (key: string, value: unknown) => chrome.storage.session.set({ [key]: value }),
  remove: (key: string | string[]) => chrome.storage.session.remove(key),
};

// ------------------------------------------------------------- sync cache

const DB = "passauth";
const STORE = "sync";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await openDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const t = db.transaction(STORE, mode);
      const req = fn(t.objectStore(STORE));
      t.oncomplete = () => resolve(req.result);
      t.onerror = t.onabort = () => reject(t.error);
    });
  } finally {
    db.close();
  }
}

/** Just enough of the /sync shape to use a stored copy (an old or damaged one is ignored). */
const looksLikeSync = (v: unknown): v is StoredSync => {
  const s = v as Partial<SyncResponse> | null;
  return !!s && typeof s.revision === "number" && !!s.bundle && Array.isArray(s.vaults) && Array.isArray(s.items);
};

// One queue for the offline copy: a removal (sign-out) queued after a write always runs after it, so a write that
// was on its way can't bring back the copy of an account that just signed out.
let copyQueue: Promise<unknown> = Promise.resolve();
const inOrder = <T>(fn: () => Promise<T>): Promise<T> => {
  const next = copyQueue.then(fn, fn);
  copyQueue = next.catch(() => {});
  return next;
};

/**
 * The offline copy per account: the last /sync answer with every later change merged in (sync-rules.ts
 * `StoredSync`: server ciphertext only, with its cursor and vault numbers in the same record). Only a cache: a failure
 * is logged and the vault is fetched from the server instead.
 */
export const syncCache = {
  get: (accountId: string): Promise<StoredSync | undefined> =>
    inOrder(() => tx<unknown>("readonly", (s) => s.get(accountId))).then(
      (v) => (looksLikeSync(v) ? v : undefined),
      (e) => {
        log.warn("Reading the offline copy failed:", e);
        return undefined;
      },
    ),
  set: (accountId: string, data: StoredSync): Promise<void> => inOrder(() => tx("readwrite", (s) => s.put(data, accountId))).then(() => {}, logged("Storing the offline copy")),
  clear: (accountId: string): Promise<void> => inOrder(() => tx("readwrite", (s) => s.delete(accountId))).then(() => {}, logged("Removing the offline copy")),
};

/** The trust memory's key: the server's address as stored and the account id the core authenticated (review H1). */
const trustKey = (server: string, userId: string) => `trust:${server}|${userId}`;

/**
 * Signed sharing (signed-sharing.ts `TrustMemory`): what this browser trusted for one account (the highest key pins
 * version it opened and its sealed copy of them, the last trusted roster per vault, the vaults seen signed). In the
 * same IndexedDB store as the offline copies, under its own key: the server's address plus the account id the core
 * authenticated (never the server's `user.id`), so another account can never be handed this one's memory. Kept when
 * the account signs out, removed with the account. Writes go through `update` (read, merge, write in one queued step:
 * signed-sharing.ts `mergeMemory`, never a blind overwrite). `read` rejects when the read fails: the checks never run
 * as on a new device then (cross-client rule 7: shared vaults are refused and nothing is written); `get` answers
 * undefined instead (for callers that only look). Writes that fail are logged. In `update`, a read that fails rejects
 * and nothing is written.
 */
const readTrust = (server: string, userId: string): Promise<unknown> => inOrder(() => tx<unknown>("readonly", (s) => s.get(trustKey(server, userId))));
export const trustMemory = {
  read: readTrust,
  get: (server: string, userId: string): Promise<unknown> =>
    readTrust(server, userId).catch((e) => {
      log.warn("Reading what this browser trusted for signed sharing failed:", e);
      return undefined;
    }),
  /** `fn(stored)` → the record to store, in one queued step; resolves to what was stored (`fn`'s answer even if the write failed); rejects when the read fails. */
  update: <T>(server: string, userId: string, fn: (stored: unknown) => T): Promise<T> =>
    inOrder(async () => {
      const key = trustKey(server, userId);
      // A read that fails aborts the write (review L5): merging into "nothing stored" would overwrite what is there.
      const stored = await tx<unknown>("readonly", (s) => s.get(key));
      const next = fn(stored);
      await tx("readwrite", (s) => s.put(next, key)).catch(logged("Storing what this browser trusted for signed sharing"));
      return next;
    }),
  clear: (server: string, userId: string): Promise<void> =>
    inOrder(() => tx("readwrite", (s) => s.delete(trustKey(server, userId)))).then(() => {}, logged("Removing what this browser trusted for signed sharing")),
};

/** The device memory's key: like the trust memory's, the server's address as stored and the account id the core authenticated. */
const deviceKey = (server: string, userId: string) => `device:${server}|${userId}`;
/** Where a device memory that couldn't be read is put aside by "Reset on this device" (kept, never read again). */
const asideKey = (server: string, userId: string) => `device-unreadable:${server}|${userId}`;

/**
 * What this browser remembers for one account to notice a rollback (device-memory.ts `StoredDeviceMemory`): the
 * highest item edit counters seen, the items marked, per vault the version and link of the last manifest checked, and
 * when each trashed item was first seen in the trash. In the same IndexedDB store as the offline copies, under its
 * own key (never the server's `user.id`), so it outlives the offline copy: a vault timeout with the "log out" action
 * and a sign-out remove the copy, and this stays until the account is removed from the browser
 * (`local.removeAccount`). `read` rejects when the read fails: what can't be read is never taken for "nothing
 * remembered" (the checks wait, nothing is overwritten). `update` reads, merges and writes in one queued step; a read
 * that fails rejects and nothing is written.
 */
export const deviceMemory = {
  read: (server: string, userId: string): Promise<unknown> => inOrder(() => tx<unknown>("readonly", (s) => s.get(deviceKey(server, userId)))),
  update: <T>(server: string, userId: string, fn: (stored: unknown) => T): Promise<T> =>
    inOrder(async () => {
      const key = deviceKey(server, userId);
      const stored = await tx<unknown>("readonly", (s) => s.get(key));
      const next = fn(stored);
      await tx("readwrite", (s) => s.put(next, key));
      return next;
    }),
  /**
   * Move a record that can't be read aside (under its own key, replacing an earlier one put aside) and leave none in
   * its place: the account goes on as on a browser that remembers nothing ("Reset on this device"). `unreadable(stored)`
   * is asked in the same queued step; a record that reads again is left where it is. Rejects when a step fails.
   */
  setAside: (server: string, userId: string, unreadable: (stored: unknown) => boolean): Promise<boolean> =>
    inOrder(async () => {
      const key = deviceKey(server, userId);
      const stored = await tx<unknown>("readonly", (s) => s.get(key));
      if (!unreadable(stored)) return false;
      await tx("readwrite", (s) => s.put(stored, asideKey(server, userId)));
      await tx("readwrite", (s) => s.delete(key));
      return true;
    }),
  clear: (server: string, userId: string): Promise<void> =>
    inOrder(async () => {
      await tx("readwrite", (s) => s.delete(deviceKey(server, userId)));
      await tx("readwrite", (s) => s.delete(asideKey(server, userId)));
    }).then(() => {}, logged("Removing what this browser remembered about the vault's versions")),
};

const UNREAD_KEY = "deviceMemoryUnread";

/** How often in a row an account's device memory couldn't be read, and whether a whole sync was done meanwhile. */
export interface UnreadCount {
  fails: number;
  full: boolean;
}

/**
 * Per account (the device memory's key), how often its device memory failed to read in a row (vault.ts: after three,
 * with a whole sync among them, the popup offers "Reset on this device"). In chrome.storage.local, not beside the
 * record: it must count also when the record's own store can't be read. Gone with the first read that works.
 */
export const memoryUnread = {
  async get(server: string, userId: string): Promise<UnreadCount> {
    const all = ((await chrome.storage.local.get(UNREAD_KEY)) as Record<string, unknown>)[UNREAD_KEY] as Record<string, Partial<UnreadCount>> | undefined;
    const c = all && typeof all === "object" ? all[deviceKey(server, userId)] : undefined;
    return { fails: typeof c?.fails === "number" && Number.isSafeInteger(c.fails) && c.fails > 0 ? c.fails : 0, full: c?.full === true };
  },
  /** `fn(count)` → the count to keep (null: none), read and written in one queued step. */
  update: (server: string, userId: string, fn: (c: UnreadCount) => UnreadCount | null): Promise<UnreadCount | null> => serial(() => writeUnread(server, userId, fn)),
};

async function writeUnread(server: string, userId: string, fn: (c: UnreadCount) => UnreadCount | null): Promise<UnreadCount | null> {
  const all = (((await chrome.storage.local.get(UNREAD_KEY)) as Record<string, unknown>)[UNREAD_KEY] as Record<string, UnreadCount> | undefined) ?? {};
  const key = deviceKey(server, userId);
  const old = all[key];
  const next = fn({ fails: typeof old?.fails === "number" && old.fails > 0 ? old.fails : 0, full: old?.full === true });
  if (!next && !old) return null;
  const { [key]: _gone, ...rest } = all;
  const kept = next ? { ...rest, [key]: next } : rest;
  if (Object.keys(kept).length) await chrome.storage.local.set({ [UNREAD_KEY]: kept });
  else await chrome.storage.local.remove(UNREAD_KEY);
  return next;
}

const FEATURES_KEY = "serverFeatures";

/**
 * Per server address, the feature list of the last `/api/config` this browser read (api.ts). With it, a server whose
 * config can't be fetched right now is still known to be one this app works with (offline use); without it, such a
 * server is not used at all: a server can't dodge the "signed sharing required" check by breaking `/api/config`.
 */
export const knownFeatures = {
  async get(server: string): Promise<string[] | null> {
    const all = ((await chrome.storage.local.get(FEATURES_KEY)) as Record<string, unknown>)[FEATURES_KEY] as Record<string, unknown> | undefined;
    const list = all && typeof all === "object" ? all[server] : undefined;
    return Array.isArray(list) ? list.filter((f): f is string => typeof f === "string") : null;
  },
  set: (server: string, features: string[]): Promise<void> =>
    serial(async () => {
      const all = (((await chrome.storage.local.get(FEATURES_KEY)) as Record<string, unknown>)[FEATURES_KEY] as Record<string, string[]> | undefined) ?? {};
      await chrome.storage.local.set({ [FEATURES_KEY]: { ...all, [server]: features } });
    }),
};
