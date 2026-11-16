/**
 * One-time moves of data stored by older versions (chrome.storage.local), behind `schemaVersion`: each step runs
 * once, in order, inside the storage write queue, and reads wait while they run (storage.ts `readsWaitFor`).
 * `migrate()` runs when the service worker starts (installs, updates and browser starts included); after that it
 * costs one read of `schemaVersion` per worker start. Add a step with the next version number; never change one
 * that has shipped.
 */
import { log } from "../shared/log";
import { ACCOUNT_FIELDS, type AccountData, accountKey, emptyAccount, readsWaitFor, serial } from "./storage";

const VERSION_KEY = "schemaVersion";

/**
 * Secret Keys stored by email only (before 0.7) moved to `server|email`. An
 * entry is moved only when exactly one account on this device has that email:
 * with the same email on two servers it can't be known whose key it was, so it
 * is dropped and PassAuth asks for the Secret Key again.
 */
export function migrateSecretKeys(secretKeys: Record<string, string>, accounts: Record<string, Pick<AccountData, "server" | "email">>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(secretKeys)) if (k.includes("|")) out[k] = v;
  for (const [k, v] of Object.entries(secretKeys)) {
    if (k.includes("|")) continue;
    const email = k.trim().toLowerCase();
    const owners = Object.values(accounts).filter((a) => a.server && a.email.trim().toLowerCase() === email);
    const owner = owners.length === 1 ? owners[0] : undefined;
    if (!owner) continue;
    const key = accountKey(owner.server, email);
    if (!(key in out)) out[key] = v;
  }
  return out;
}

type Raw = Record<string, unknown>;

const STEPS: { version: number; what: string; run: () => Promise<void> }[] = [
  {
    version: 1,
    what: "one account stored at the top level (before 0.3.1) → accounts",
    async run() {
      const raw = (await chrome.storage.local.get(["accounts", ...ACCOUNT_FIELDS])) as Raw;
      if (raw.accounts) return;
      const accounts: Record<string, AccountData> = {};
      let active = "";
      if (raw.server) {
        active = crypto.randomUUID();
        accounts[active] = { ...emptyAccount, ...Object.fromEntries(ACCOUNT_FIELDS.filter((k) => raw[k] !== undefined).map((k) => [k, raw[k]])) } as AccountData;
      }
      await chrome.storage.local.set({ accounts, active });
      await chrome.storage.local.remove([...ACCOUNT_FIELDS]);
    },
  },
  {
    version: 2,
    what: "autoLockMinutes (before 0.2) → settings.vaultTimeout",
    async run() {
      const raw = (await chrome.storage.local.get(["settings", "autoLockMinutes"])) as Raw;
      if (typeof raw.autoLockMinutes !== "number") return;
      // 0 meant "when the browser closes".
      if (!raw.settings) await chrome.storage.local.set({ settings: { vaultTimeout: raw.autoLockMinutes > 0 ? raw.autoLockMinutes : "restart" } });
      await chrome.storage.local.remove("autoLockMinutes");
    },
  },
  {
    version: 3,
    what: "Secret Keys keyed by email (before 0.7) → server|email",
    async run() {
      const raw = (await chrome.storage.local.get(["secretKeys", "accounts"])) as Raw;
      const secretKeys = (raw.secretKeys ?? {}) as Record<string, string>;
      if (!Object.keys(secretKeys).some((k) => !k.includes("|"))) return;
      await chrome.storage.local.set({ secretKeys: migrateSecretKeys(secretKeys, (raw.accounts ?? {}) as Record<string, AccountData>) });
    },
  },
];

/** The schema version this build writes. */
export const SCHEMA_VERSION = Math.max(...STEPS.map((s) => s.version));

let running: Promise<void> | null = null;

/** Bring stored data up to SCHEMA_VERSION (single-flight; a no-op once done). */
export function migrate(): Promise<void> {
  running ??= serial(async () => {
    const stored = (await chrome.storage.local.get(VERSION_KEY))[VERSION_KEY];
    const from = typeof stored === "number" ? stored : 0;
    for (const step of STEPS) {
      if (step.version <= from) continue;
      await step.run();
      await chrome.storage.local.set({ [VERSION_KEY]: step.version });
      log.debug(`Migrated: ${step.what}`);
    }
  }).catch((e: unknown) => {
    log.error("Moving data stored by an older version failed:", e);
    // Tried again the next time the worker starts.
    running = null;
  });
  readsWaitFor(running);
  return running;
}
