/**
 * Which browser PassAuth runs in. The same code runs in Chrome (and Edge), Firefox and Safari on a Mac (inside the desktop app);
 * build.mjs gives each its own manifest. Firefox and Safari are told apart by their extension URL schemes
 * (moz-extension:, safari-web-extension:), which a page can't fake.
 */

/** True in Firefox (pages, background and content scripts alike). */
export const isFirefox = (): boolean => chrome.runtime.getURL("").startsWith("moz-extension:");

/** True in Safari (the extension inside the desktop app on macOS). */
export const isSafari = (): boolean => chrome.runtime.getURL("").startsWith("safari-web-extension:");

/** The browser's name for user-facing text. */
export const browserName = (): string => (isFirefox() ? "Firefox" : isSafari() ? "Safari" : globalThis.navigator?.userAgent.includes("Edg/") ? "Edge" : "Chrome");

/** The settings that only some browsers have (Safari has no shortcuts, right-click menu or `privacy` API). */
export const browserFeatures = () => ({
  shortcuts: typeof chrome.commands?.getAll === "function",
  rightClickMenu: !!chrome.contextMenus,
  defaultPasswordManager: !isSafari(),
});

/** The site-access text the popup shows in Safari (needsSiteAccess). */
export const SITE_ACCESS_TEXT =
  "To fill on this website, allow PassAuth on it: click PassAuth in Safari's toolbar and choose to allow it on this website, or set it in Safari → Settings → Websites → PassAuth.";

/** Safari hides a tab's address until the user allows PassAuth on that website: the popup asks for it. */
export const needsSiteAccess = (tab: { id?: number; url?: string } | undefined): boolean => isSafari() && !!tab && !tab.url;
