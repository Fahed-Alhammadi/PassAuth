/**
 * The vault timeout: after the user's chosen minutes without activity (activity.ts), when the system locks, when
 * the browser restarts, or "immediately" when the last PassAuth window closes, run the timeout action: lock every
 * account, or sign every account out. main.ts registers these listeners.
 */
import { AUTOLOCK_ALARM } from "./activity";
import { getSettings, local, scratch } from "./storage";
import * as vault from "./vault";

/** Run the user's timeout action (lock, or sign out which also forgets the vault data). */
export async function timeout() {
  const { settings } = await local.get();
  if (settings.timeoutAction === "logout") await vault.logoutAll();
  else await vault.lockAll();
}

export function onAlarm(alarm: chrome.alarms.Alarm) {
  if (alarm.name === AUTOLOCK_ALARM) void timeout();
}

export async function onIdleState(state: string) {
  if (state === "locked" && (await getSettings()).vaultTimeout === "system-lock") await timeout();
}

/** Keys in session storage are gone after a browser restart (locked); "sign out" also drops the session. */
export async function onBrowserStart() {
  const { vaultTimeout, timeoutAction } = await getSettings();
  if (vaultTimeout !== "never" && timeoutAction === "logout") await timeout();
}

// "Immediately": time out as soon as the last PassAuth window closes. The popup
// keeps a port open and sends a heartbeat (which also keeps this worker awake);
// if the worker was stopped anyway, the popup reconnects. As a backstop, the
// last heartbeat time is kept in session storage and checked before the vault
// is used (`lockCheck`).
const popupPorts = new Set<chrome.runtime.Port>();
const POPUP_SEEN = "popupSeen";

export function onConnect(port: chrome.runtime.Port) {
  if (port.name !== "popup" || port.sender?.id !== chrome.runtime.id || !(port.sender.url ?? "").startsWith(chrome.runtime.getURL(""))) return;
  popupPorts.add(port);
  void scratch.set(POPUP_SEEN, Date.now());
  port.onMessage.addListener(() => void scratch.set(POPUP_SEEN, Date.now()));
  port.onDisconnect.addListener(async () => {
    popupPorts.delete(port);
    if (popupPorts.size) return;
    await scratch.set(POPUP_SEEN, 0);
    if ((await getSettings()).vaultTimeout === "immediately") await timeout();
  });
}

/** Before the vault is used: the "Immediately" timeout, if the popup closed while this worker was asleep. */
export async function lockCheck() {
  if (popupPorts.size || (await getSettings()).vaultTimeout !== "immediately") return;
  const seen = (await scratch.get<number>(POPUP_SEEN)) ?? 0;
  if (Date.now() - seen > 60_000 && (await vault.anyUnlocked())) await timeout();
}
