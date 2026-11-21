/**
 * Which browser PassAuth runs in. The same code runs in Chrome (and Edge), Firefox and Safari (inside the iOS app);
 * build.mjs gives each its own manifest. Firefox and Safari are told apart by their extension URL schemes
 * (moz-extension:, safari-web-extension:), which a page can't fake.
 */

/** True in Firefox (pages, background and content scripts alike). */
export const isFirefox = (): boolean => chrome.runtime.getURL("").startsWith("moz-extension:");

/** True in Safari (the extension inside the PassAuth iOS app). */
export const isSafari = (): boolean => chrome.runtime.getURL("").startsWith("safari-web-extension:");

/** The browser's name for user-facing text. */
export const browserName = (): string => (isFirefox() ? "Firefox" : isSafari() ? "Safari" : globalThis.navigator?.userAgent.includes("Edg/") ? "Edge" : "Chrome");
