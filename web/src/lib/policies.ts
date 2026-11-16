/**
 * Account policies set by the server's admin (servers with the `policies` feature: `GET /api/config` `policies`, and
 * `GET /account` `policy_violations` for what an account still has to change), and what the web vault and the desktop
 * app do with them.
 *
 * Enforced by the server: two-step login (403 `two_step_required` on everything but setting a method up, reading the
 * account and signing out), a Secret Key and the key-derivation minimums for new account keys (400
 * `secret_key_required` / `kdf_too_weak`). Applied by the apps: the master password length, the longest vault timeout
 * and export. Servers without the feature send no policies: every value then has its default, which changes nothing.
 *
 * Pure (no WASM, no network, no React) and unit-tested in `policies.test.ts`.
 */
import type { PublicConfig } from "./api";
import type { VaultTimeout } from "./platform";

export interface Policies {
  /** Every account must use two-step login. */
  requireTwoStep: boolean;
  /** New account keys (registration, master password or Secret Key change) must use a Secret Key. */
  requireSecretKey: boolean;
  /** Least Argon2id memory, in MiB, and passes for new account keys. */
  minKdfMemoryMib: number;
  minKdfIterations: number;
  /** Shortest master password the apps accept for a new one; never below `MIN_MASTER_PASSWORD`. */
  masterPasswordMinLength: number;
  /** Longest vault timeout the apps offer, in minutes; 0 = no limit. */
  maxVaultTimeoutMinutes: number;
  /** The apps don't offer exporting the vault. */
  disableExport: boolean;
}

/** The apps' own minimum master password length; a policy can only raise it. */
export const MIN_MASTER_PASSWORD = 10;
/** The core's own settings for new account keys (`KdfParams::new_default`); a policy can only raise them. */
export const NEW_KEY_KDF = { memoryMib: 128, iterations: 3 } as const;
/** The strongest key-derivation minimums the core follows (`createAccountWithKdf` / `rewrapWithKdf` refuse more). */
export const MAX_KDF = { memoryMib: 1024, iterations: 20 } as const;
/** The web vault's idle lock, in minutes (the desktop app has its own vault timeout setting). */
export const WEB_LOCK_MINUTES = 15;
/** The server's ceiling for `max_vault_timeout_minutes` (30 days). */
const MAX_TIMEOUT_MINUTES = 43_200;

export const DEFAULT_POLICIES: Policies = {
  requireTwoStep: false,
  requireSecretKey: false,
  minKdfMemoryMib: 64,
  minKdfIterations: 3,
  masterPasswordMinLength: MIN_MASTER_PASSWORD,
  maxVaultTimeoutMinutes: 0,
  disableExport: false,
};

/** A whole number from the server, kept within `[min, max]`; anything else (missing, text, a fraction) is `fallback`. */
function whole(value: unknown, min: number, max: number, fallback: number): number {
  if (typeof value !== "number" || !Number.isInteger(value)) return fallback;
  return Math.min(max, Math.max(min, value));
}

/** The server's policies (`GET /api/config`), with the defaults for a server without them or a value it didn't send. */
export function readPolicies(config: PublicConfig | null | undefined): Policies {
  const raw = config?.policies;
  if (!raw || typeof raw !== "object") return DEFAULT_POLICIES;
  const p = raw as Record<string, unknown>;
  const d = DEFAULT_POLICIES;
  return {
    requireTwoStep: p.require_two_step === true,
    requireSecretKey: p.require_secret_key === true,
    minKdfMemoryMib: whole(p.min_kdf_memory_mib, d.minKdfMemoryMib, 1024, d.minKdfMemoryMib),
    minKdfIterations: whole(p.min_kdf_iterations, d.minKdfIterations, 20, d.minKdfIterations),
    masterPasswordMinLength: whole(p.master_password_min_length, MIN_MASTER_PASSWORD, 128, MIN_MASTER_PASSWORD),
    maxVaultTimeoutMinutes: whole(p.max_vault_timeout_minutes, 0, MAX_TIMEOUT_MINUTES, 0),
    disableExport: p.disable_export === true,
  };
}

/** Characters a new master password needs: the server's minimum, never below the apps' own. */
export const minPasswordLength = (p: Policies): number => Math.max(MIN_MASTER_PASSWORD, p.masterPasswordMinLength);

/** Whether the app offers exporting the vault (the server's admin can turn it off). */
export const exportAllowed = (p: Policies): boolean => !p.disableExport;

/**
 * The key-derivation settings this app gives new account keys under the server's policy: memory = max(128 MiB,
 * minimum), passes = max(3, minimum), as the core's `createAccountWithKdf` / `rewrapWithKdf` do with the same minimums.
 */
export const newKeyKdf = (p: Policies): { memoryMib: number; iterations: number } => ({
  memoryMib: Math.max(NEW_KEY_KDF.memoryMib, p.minKdfMemoryMib),
  iterations: Math.max(NEW_KEY_KDF.iterations, p.minKdfIterations),
});

/**
 * Whether this app can create account keys that meet the server's key-derivation minimums (the core follows any
 * minimum up to 1024 MiB and 20 passes, the server's own ceiling). Then registration and a master password change
 * follow the policy, and a change with the same password fixes a `kdf` violation.
 */
export const newKeysMeetKdf = (p: Policies): boolean => p.minKdfMemoryMib <= MAX_KDF.memoryMib && p.minKdfIterations <= MAX_KDF.iterations;

// ------------------------------------------------------------- vault timeout

/** Whether `value` locks the vault within `maxMinutes` of inactivity (0 = no limit: every choice does). */
export function timeoutWithin(value: VaultTimeout, maxMinutes: number): boolean {
  if (maxMinutes <= 0 || value === "immediately") return true;
  return typeof value === "number" && value <= maxMinutes;
}

/**
 * The vault timeout that applies: the saved choice, or the server's longest one when the choice is above it. Moments
 * without a time limit ("On system lock", "On app restart", "Never") are above every limit.
 */
export const clampTimeout = (value: VaultTimeout, maxMinutes: number): VaultTimeout => (timeoutWithin(value, maxMinutes) ? value : maxMinutes);

/** "45 minutes", "1 hour", "4 hours", "30 days": a limit in words. */
export function minutesLabel(minutes: number): string {
  const plural = (n: number, unit: string) => `${n} ${unit}${n === 1 ? "" : "s"}`;
  if (minutes >= 1440 && minutes % 1440 === 0) return plural(minutes / 1440, "day");
  if (minutes >= 60 && minutes % 60 === 0) return plural(minutes / 60, "hour");
  return plural(minutes, "minute");
}

/**
 * The timeout choices to offer under the server's limit: the ones within it, then the limit itself when it isn't one
 * of them (everything left is shorter, so the list still runs from short to long).
 */
export function timeoutOptions(options: [VaultTimeout, string][], maxMinutes: number): [VaultTimeout, string][] {
  if (maxMinutes <= 0) return options;
  const within = options.filter(([v]) => timeoutWithin(v, maxMinutes));
  return within.some(([v]) => v === maxMinutes) ? within : [...within, [maxMinutes, minutesLabel(maxMinutes)]];
}

/** The web vault's idle lock in minutes: its own 15, or the server's longest timeout when that is shorter. */
export const webLockMinutes = (maxMinutes: number): number => (maxMinutes > 0 ? Math.min(WEB_LOCK_MINUTES, maxMinutes) : WEB_LOCK_MINUTES);

// --------------------------------------------------------------- violations

/** What an account still has to change for the server's policies (`GET /account` `policy_violations`). */
export type Violation = "two_step" | "secret_key" | "kdf";
const VIOLATIONS: Violation[] = ["two_step", "secret_key", "kdf"];

/** The known violations in a fixed order; unknown or repeated entries (and servers without the list) give none. */
export function readViolations(value: unknown): Violation[] {
  if (!Array.isArray(value)) return [];
  return VIOLATIONS.filter((v) => value.includes(v));
}

export interface PolicyNotice {
  violation: Violation;
  text: string;
  /** Where the user fixes it, when this app can. */
  action?: { label: string; to: string };
}

/** The banner lines for an account's violations, each with the place that fixes it. */
export function policyNotices(violations: Violation[], p: Policies): PolicyNotice[] {
  return violations.map((violation): PolicyNotice => {
    switch (violation) {
      case "two_step":
        return {
          violation,
          text: "Your server requires two-step login.",
          action: { label: "Set up two-step login", to: "/settings/two-step" },
        };
      case "secret_key":
        return {
          violation,
          text: "Your server asks you to turn on a Secret Key.",
          action: { label: "Turn on a Secret Key", to: "/settings/security" },
        };
      case "kdf":
        return newKeysMeetKdf(p)
          ? {
              violation,
              text: "Your server asks you to update your account's encryption settings. Change your master password to do it; you can keep the same one.",
              action: { label: "Change master password", to: "/settings/security" },
            }
          : {
              violation,
              text: "Your server asks you to update your account's encryption settings, which this app can't do yet. Your vault keeps working meanwhile.",
            };
    }
  });
}

/** Identifies a set of violations, so a dismissed banner comes back when the set changes. */
export const violationsKey = (violations: Violation[]): string => violations.join(",");

// ---------------------------------------------------------- two-step gate

/** Whether an answer is the server's "set up two-step login first" (403 `two_step_required`). */
export const isTwoStepRequired = (status: number, code: unknown): boolean => status === 403 && code === "two_step_required";

/**
 * The same for live sync: the server's `{"type":"two_step_required"}` message, or its close with 1008
 * `two_step_required`, sent when the admin starts requiring two-step login. The app then stops live sync (no
 * reconnecting) and shows the two-step screen.
 */
export const isTwoStepNotice = (msg: unknown): boolean => !!msg && typeof msg === "object" && (msg as { type?: unknown }).type === "two_step_required";
export const isTwoStepClose = (code: number, reason: string): boolean => code === 1008 && reason === "two_step_required";

/**
 * What follows once a method is set up on the "requires two-step login" screen: with the account keys still in memory
 * (the screen came up at sign-in, unlock or while the vault was open) the vault syncs and opens; without them (it came
 * up at start-up, before unlocking) the session loads again and the vault asks to be unlocked.
 */
export const afterTwoStepSetup = (keysInMemory: boolean): "sync" | "boot" => (keysInMemory ? "sync" : "boot");
