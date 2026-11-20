/** Storage keys shared by the popup and the background (their value shapes are in types.ts or named here). */

/** chrome.storage.session: a page the popup opens once at its next start (`PopupRouteRequest`); the popup removes it. */
export const POPUP_ROUTE_KEY = "popupRoute";

/**
 * chrome.storage.session: where the popup was (route, search, filters, list scroll), so reopening it within
 * VIEW_KEEP_MS comes back to the same place. Removed when PassAuth locks or signs out.
 */
export const POPUP_VIEW_KEY = "popupView";
export const VIEW_KEEP_MS = 2 * 60_000;

/** chrome.storage.local: the generator options (`GeneratorSettings` from @web/lib/generator), written by the popup. */
export const GENERATOR_OPTIONS_KEY = "generatorOptions";

/**
 * chrome.storage.session: why the last fill on a tab's page didn't work (`fillProblem:<tab>`, written by
 * background/fill-problems.ts); the popup removes it when the user dismisses it.
 */
export const FILL_PROBLEM_PREFIX = "fillProblem:";

/** chrome.storage.session: popup notices dismissed for this browser session, by kind (`policy`, `invitations`), each the key of the set dismissed. */
export const DISMISSED_KEY = "popupDismissed";

/**
 * chrome.storage.session: an account's sign-ins on other devices waiting for its approval (`signInRequests:<account>`,
 * written by background/sign-in-requests.ts while it is unlocked); the toolbar badge and an open popup follow it.
 */
export const SIGN_IN_REQUESTS_PREFIX = "signInRequests:";

/** chrome.storage.session: sign-in requests the user put off ("Not now"): the popup doesn't open their sheet again. */
export const SIGN_IN_PUT_OFF_KEY = "signInPutOff";

/**
 * chrome.storage.local: an account's profile picture, sealed as the server sent it (`avatar:<account>`,
 * background/avatar.ts `KeptAvatar`). Removed when the account signs out or is removed.
 */
export const AVATAR_PREFIX = "avatar:";

/**
 * chrome.storage.session: an unlocked account's opened profile picture (`avatarOpen:<account>`, background/avatar.ts
 * `OpenedAvatar`), rebuilt from the sealed copy at unlock. Removed with the account's session keys.
 */
export const AVATAR_OPEN_PREFIX = "avatarOpen:";

/**
 * chrome.storage.local: an account's offline changes waiting to sync (`offlineChanges:<account>`, background/vault.ts
 * section "offline changes"): `{ sealed, count }`, the list sealed with the account key (core `sealOfflineChanges`) and
 * how many changes it holds (shown before Log out while locked). Removed with the account, at Log out and Change server.
 */
export const OFFLINE_CHANGES_PREFIX = "offlineChanges:";
