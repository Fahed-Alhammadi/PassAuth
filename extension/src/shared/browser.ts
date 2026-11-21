/**
 * Which browser PassAuth runs in. The same code runs in Chrome (and Edge) and Firefox; build.mjs gives each its own
 * manifest. Firefox is told apart by its extension URL scheme (moz-extension:), which a page can't fake.
 */

/** True in Firefox (pages, background and content scripts alike). */
export const isFirefox = (): boolean => chrome.runtime.getURL("").startsWith("moz-extension:");

/** The browser's name for user-facing text. */
export const browserName = (): string => (isFirefox() ? "Firefox" : globalThis.navigator?.userAgent.includes("Edg/") ? "Edge" : "Chrome");
