/**
 * The user at work in PassAuth restarts the vault timeout. Which requests count is part of each request's handler
 * (router.ts `activity`); reading (popup state, the item list, an item, its verification code, editor info, a pending
 * passkey request) never does, so an item left open in the popup can't keep the vault unlocked forever. Fills from
 * the inline menu, saves from the save prompt and the keyboard shortcut count too (they call `touch` themselves).
 */
import { getSettings } from "./storage";

/** "restart": restart the timer (at most every 30 s); "force": restart it even if that was moments ago (a new timeout length, unlocking). */
export type Activity = "restart" | "force";

/** The vault-timeout alarm. */
export const AUTOLOCK_ALARM = "autolock";

let lastTouch = 0;

/** Activity in PassAuth restarts the inactivity timer (at most every 30 s unless `force`). */
export async function touch(force = false) {
  if (!force && Date.now() - lastTouch < 30_000) return;
  lastTouch = Date.now();
  const { vaultTimeout } = await getSettings();
  if (typeof vaultTimeout === "number" && vaultTimeout > 0) await chrome.alarms.create(AUTOLOCK_ALARM, { delayInMinutes: vaultTimeout });
  else await chrome.alarms.clear(AUTOLOCK_ALARM);
}
