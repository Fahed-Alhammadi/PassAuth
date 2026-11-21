/**
 * PassAuth's service worker (background.js): wires the modules together and registers every chrome event
 * listener, synchronously at the top level, so events that start the worker reach their listeners. The modules
 * register nothing themselves: importing one has no side effects.
 *
 *   router.ts       messages from PassAuth's pages and content scripts (handler tables in handlers/)
 *   vault.ts        keys, sync (delta sync: sync-rules.ts) and items; storage.ts, migrations.ts, match-index.ts; pin.ts PIN unlock
 *   live-sync.ts    the live-sync socket while unlocked; policies.ts the server admin's account policies
 *   sign-in-requests.ts  sign-ins on other devices waiting for this account's approval
 *   fill.ts         filling logins into pages; save-prompt.ts, inline-menu.ts their in-page UI
 *   timeout.ts      the vault timeout (activity.ts: what restarts it)
 *   badge.ts        the toolbar icon and count; menus.ts the right-click menus; commands.ts the keyboard commands
 *   core.ts         the Rust core (WASM), loaded once; site.ts its site logic (matching, the save rule, passkey targets)
 */
import { DEBUG_KEY, logged, setDebug } from "../shared/log";
import { setReachHandler, setSessionLostHandler, setTwoStepHandler } from "./api";
import { initBadge, pageStateChanged, refreshBadge } from "./badge";
import { onClipboardAlarm } from "./clipboard";
import { onCommand } from "./commands";
import { forgetFillProblem } from "./fill-problems";
import { forgetTab as forgetMenus } from "./inline-menu";
import { ensureLive, LIVE_ALARM, liveAccount, onLiveAlarm, stopLive } from "./live-sync";
import { forgetContextField, onMenuClicked, refreshMenus } from "./menus";
import { migrate } from "./migrations";
import { cancelPasskeysInTab } from "./passkey-handler";
import { noteTwoStepRequired } from "./policies";
import { onMessage } from "./router";
import { dropSavesLogged, forgetTab as forgetSaves, onTabUpdated as showPendingSave } from "./save-prompt";
import { forgetSignInRequests, refreshSignInRequests } from "./sign-in-requests";
import { lockCheck, onAlarm, onBrowserStart, onConnect, onIdleState } from "./timeout";
import { onKeyTabUpdated, onKeyWindowGone, setKeySignInFinisher } from "./two-step-key";
import * as vault from "./vault";

// Local storage holds session tokens, Secret Keys, two-step "remember" tokens and (with the timeout "Never") the
// vault keys: only PassAuth's own pages and this worker may read it, never a content script (they ask the worker
// for what they need and read no storage). Session storage is restricted like this by default. Chrome keeps the
// setting for the browser session, so it is set again at every worker start; a browser that refuses it for local
// storage keeps working as before.
const restrictLocal = () => void chrome.storage.local.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" })?.catch(logged("Restricting local storage to PassAuth's own pages"));
restrictLocal();

// Data stored by older versions is moved once (reads wait for it); after that this is one read per worker start.
void migrate();

vault.setLockCheck(lockCheck);
vault.setKeysDroppedHandler((id) => {
  dropSavesLogged();
  // Lock, sign-out, switch (or this account's session ended): the live-sync socket closes with the keys.
  if (!id || id === liveAccount()) stopLive();
  // Sign-in requests can only be answered while unlocked: they are listed again at the next unlock.
  void forgetSignInRequests(id ? [id] : undefined).catch(logged("Forgetting sign-in requests"));
});
// Unlocked or signed in: sign-ins on other devices waiting for this account's approval are listed.
vault.setUnlockedHandler(() => void refreshSignInRequests(true).catch(logged("Listing sign-in requests")));
// The vault opened or changed: a live-sync socket for it (when the server has delta sync).
vault.setOpenedHandler(() => void ensureLive().catch(logged("Starting live sync")));
// Signed out elsewhere (refresh token refused): this account's keys go too.
setSessionLostHandler((id) => void vault.clearUnlocked(id).catch(logged("Dropping the keys of a signed-out account")));
// A security key's assertion from the server's key page finishes the popup's sign-in here (two-step-key.ts).
setKeySignInFinisher((token, credential, remember) => vault.verifyTwoFactorPasskey(token, credential, remember));
// The server requires two-step login first (403 two_step_required): the popup says so.
setTwoStepHandler(noteTwoStepRequired);
// Offline changes: whether each request reached the server (saves wait while it doesn't; sent when it answers again).
setReachHandler(vault.noteReach);

// Debug logging follows the `debugLog` key (shared/log.ts).
void chrome.storage.local.get(DEBUG_KEY).then((r) => setDebug(r[DEBUG_KEY] === true), logged("Reading the debug setting"));

initBadge();
chrome.idle.setDetectionInterval(60);

/** The toolbar icon, its count and the right-click menu follow the active tab and PassAuth's state. */
function refreshPage() {
  refreshBadge();
  refreshMenus();
}
refreshPage();

chrome.runtime.onMessage.addListener(onMessage);
chrome.runtime.onConnect.addListener(onConnect);
chrome.runtime.onInstalled.addListener((details) => {
  // Again once installing or updating is through (an update while the browser starts could reset it).
  restrictLocal();
  void migrate();
  // Installing or updating clears the extension's menus: build them again.
  refreshMenus(true);
  // A first install opens the short welcome page (popup.html?welcome=1).
  if (details.reason === "install") void chrome.tabs.create({ url: chrome.runtime.getURL("popup.html?welcome=1") }).catch(logged("Opening the welcome page"));
});
chrome.runtime.onStartup.addListener(() => void onBrowserStart().catch(logged("The vault timeout at browser start")));
chrome.alarms.onAlarm.addListener(onAlarm);
chrome.alarms.onAlarm.addListener(onClipboardAlarm);
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === LIVE_ALARM) void onLiveAlarm().catch(logged("The live-sync check"));
  // Offline changes waiting to sync: try again (a sync first, while unlocked).
  if (vault.isOfflineAlarm(alarm.name)) void vault.connectionBack().catch(logged("Sending changes waiting to sync"));
});
// Back online: the same.
(globalThis as { addEventListener?: (type: string, fn: () => void) => void }).addEventListener?.("online", () => void vault.connectionBack().catch(logged("Sending changes waiting to sync")));
chrome.idle.onStateChanged.addListener((state) => void onIdleState(state).catch(logged("The vault timeout on system lock")));
chrome.commands.onCommand.addListener(onCommand);
chrome.contextMenus.onClicked.addListener(onMenuClicked);

chrome.tabs.onActivated.addListener(refreshPage);
chrome.tabs.onUpdated.addListener((_id, change) => {
  if (change.url || change.status === "complete") refreshPage();
});
// Content scripts no longer ask for a pending save on every page load: the worker shows it when the tab finishes loading.
chrome.tabs.onUpdated.addListener((tabId, change, tab) => void showPendingSave(tabId, change, tab).catch(logged("Showing a pending save")));
// A tab that navigates (or reloads) leaves a fill problem of its last page behind.
chrome.tabs.onUpdated.addListener((tabId, change) => {
  if (change.url || change.status === "loading") void forgetFillProblem(tabId).catch(logged("Forgetting a fill problem"));
});
// The security key window reached the server's done page, or was closed (two-step-key.ts).
chrome.tabs.onUpdated.addListener((tabId, change) => void onKeyTabUpdated(tabId, change).catch(logged("Reading the security key result")));
chrome.windows.onRemoved.addListener((windowId) => void onKeyWindowGone({ windowId }).catch(logged("A closed security key window")));
chrome.windows.onFocusChanged.addListener(refreshPage);
chrome.tabs.onRemoved.addListener((tabId) => {
  void forgetSaves(tabId).catch(logged("Forgetting a closed tab's save"));
  void forgetMenus(tabId).catch(logged("Forgetting a closed tab's menu"));
  void forgetFillProblem(tabId).catch(logged("Forgetting a closed tab's fill problem"));
  forgetContextField(tabId);
  cancelPasskeysInTab(tabId);
  void onKeyWindowGone({ tabId }).catch(logged("A closed security key window"));
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (pageStateChanged(changes, area)) refreshPage();
  if (area === "local" && DEBUG_KEY in changes) setDebug(changes[DEBUG_KEY]?.newValue === true);
});

// A worker that starts while the active account is unlocked (it was stopped, or the browser restarted with the
// timeout "never") opens its live-sync socket again.
void ensureLive().catch(logged("Starting live sync"));
