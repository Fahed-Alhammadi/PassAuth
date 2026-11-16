/**
 * Unlock with a PIN (Settings → Account security → "Unlock with a PIN"), for this browser session only.
 *
 * Setting it needs the vault unlocked and the master password typed in the same step. The core re-wraps the
 * account's keys under a key it derives from the PIN with its own Argon2id (the account KDF's cost, a new salt, no
 * Secret Key); that copy (storage.ts `PinCopy`) lives only in chrome.storage.session: memory-only, extension-private,
 * gone when the browser session ends, never written to disk or sent anywhere. Locking drops the unwrapped keys and
 * keeps the copy, so the lock screen can offer "Unlock with PIN". Each try is counted before the PIN is checked;
 * MAX_PIN_TRIES wrong ones delete the copy and the master password is needed again. Signing out (also the timeout's
 * "sign out"), switching or removing accounts, a new master password or Secret Key (a different bundle from the
 * server), choosing the timeout "Never" and turning the setting off delete it (vault.ts, storage.ts). A PIN unlock
 * never counts as a master-password entry for passkey user verification.
 */
import { AppError, lockedError, signedOutError } from "../shared/errors";
import type { PinUnlockResult } from "../shared/types";
import { getSettings, local, pinCopies } from "./storage";
import * as vault from "./vault";

export const PIN_MIN_DIGITS = 6;
export const PIN_MAX_DIGITS = 64;
/** Wrong PINs before the copy is deleted. */
export const MAX_PIN_TRIES = 5;

/** No PIN copy for the active account (never set, deleted, or the browser restarted). */
export const PIN_UNAVAILABLE = "pin_unavailable";

export const validPin = (pin: unknown): pin is string => typeof pin === "string" && new RegExp(`^\\d{${PIN_MIN_DIGITS},${PIN_MAX_DIGITS}}$`).test(pin);

// One PIN check at a time in this worker (the counter in session storage also covers a worker restart).
let queue: Promise<unknown> = Promise.resolve();
const serial = <T>(fn: () => Promise<T>): Promise<T> => {
  const next = queue.then(fn, fn);
  queue = next.catch(() => {});
  return next;
};

/** Turn PIN unlock on for the active account, after checking the master password (typed in the same dialog). */
export async function setPin(pin: string, password: string): Promise<void> {
  if (!validPin(pin)) throw new AppError("bad_pin", `Use ${PIN_MIN_DIGITS} or more digits, numbers only.`);
  if ((await getSettings()).vaultTimeout === "never") throw new AppError("bad_pin", 'PIN unlock isn\'t used with the vault timeout "Never".');
  if (!(await vault.ensureUnlocked())) throw lockedError();
  // Throws "Wrong master password or Secret Key." (and records a master-password entry when it is right).
  await vault.verifyMasterPassword(password);
  const { wrapped, base, owner } = await vault.wrapForPin(pin);
  if (!vault.stillOwner(owner)) throw lockedError();
  await pinCopies.update(owner.id, () => ({ wrapped, base, failures: 0 }));
  // Signed out or switched while it was written: take it back.
  if (!vault.stillOwner(owner)) {
    await pinCopies.remove([owner.id]);
    throw lockedError();
  }
}

/** Turn PIN unlock off for the active account. */
export async function removePin(): Promise<void> {
  const { id } = await local.account();
  await pinCopies.remove([id]);
}

/**
 * Unlock the active account with its PIN. A wrong PIN answers how many tries are left; the last one deletes the
 * copy (`triesLeft: 0`). Throws when there is no copy (`pin_unavailable`) or the account is signed out.
 */
export function unlockWithPin(pin: string): Promise<PinUnlockResult> {
  return serial(async () => {
    const { id, data } = await local.account();
    if (!id || !data?.tokens) throw signedOutError();
    // Count the try before checking it: a worker stopped in the middle can't hand out free tries.
    const counted = await pinCopies.update(id, (c) => (c ? { ...c, failures: c.failures + 1 } : undefined));
    if (!counted) throw new AppError(PIN_UNAVAILABLE, "Unlock with your master password.", true);
    const right = validPin(pin) && (await vault.unlockWithPin(counted.wrapped, counted.base, pin, id));
    if (right) {
      // Only the same copy is reset: one deleted meanwhile (sign-out, a new master password) stays deleted.
      await pinCopies.update(id, (c) => (c && JSON.stringify(c.wrapped) === JSON.stringify(counted.wrapped) ? { ...c, failures: 0 } : undefined));
      return { unlocked: true };
    }
    if (counted.failures >= MAX_PIN_TRIES) {
      await pinCopies.remove([id]);
      return { unlocked: false, triesLeft: 0 };
    }
    return { unlocked: false, triesLeft: MAX_PIN_TRIES - counted.failures };
  });
}
