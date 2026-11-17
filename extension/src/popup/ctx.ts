/** Shared popup types and helpers. */
import type { ItemKind } from "@web/lib/types";
import type { PopupState } from "../shared/types";

/** What a new item starts with (the page's address, a typed user name). */
export interface Prefill {
  url?: string;
  username?: string;
}

export type Route =
  | { tab: "vault"; page: "list" }
  | { tab: "vault"; page: "item"; id: string }
  | { tab: "vault"; page: "history"; id: string }
  | { tab: "vault"; page: "edit"; id: string }
  | { tab: "vault"; page: "new"; kind: ItemKind; prefill?: Prefill }
  /** Add the page at `url` to one of the user's logins. */
  | { tab: "vault"; page: "addSite"; url: string }
  | { tab: "generator" }
  | { tab: "settings"; section?: string };

export type CopyRequest = { text: string } | { id: string; field: "username" | "password" | "totp" };

export interface Ctx {
  state: PopupState;
  /** Copy through the background (cleared after the user's delay); resolves true when it worked. */
  copy: (req: CopyRequest, label: string) => Promise<boolean>;
  /** A short note in the popup's one live region. */
  notify: (text: string) => void;
  go: (route: Route) => void;
  /** Reload popup state (after lock, log out, settings changes). */
  reload: () => void;
  /** Ask before signing out of the active account (says what signing in again needs). */
  signOut: () => void;
  /** Sign-ins on other devices put off with "Not now" (a notice above the list offers them again). */
  signIns?: { putOff: number; review: () => void };
}

/** The text to show for a failed request (the background already words its errors for people). */
export const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));

/**
 * The host of a saved website address, or "" when it isn't a valid address
 * ("https://my site"): item data is whatever was typed or imported, and must
 * never break the page that shows it.
 */
export function hostOf(url: string): string {
  return parseUrl(url)?.hostname ?? "";
}

/** `new URL(url)`, or null for an address that doesn't parse (URL.parse needs Chrome 126; PassAuth supports 120). */
export function parseUrl(url: string): URL | null {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

export const seconds = (s: number) => (s < 60 ? `${s} seconds` : `${s / 60} minute${s > 60 ? "s" : ""}`);

/** The page the user is on: the popup's window, or (when popped out) the last focused browser window. */
export async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url?.startsWith("http") || !new URLSearchParams(location.search).has("popout")) return tab;
  const win = await chrome.windows.getLastFocused({ windowTypes: ["normal"] }).catch(() => null);
  if (!win?.id) return tab;
  const [other] = await chrome.tabs.query({ active: true, windowId: win.id });
  return other ?? tab;
}

export function formatDate(unixSeconds: number) {
  return new Date(unixSeconds * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

/** A one-time code in two halves for reading ("123 456", "1234 5678"). */
export function splitCode(code: string): [string, string] {
  const half = Math.ceil(code.length / 2);
  return [code.slice(0, half), code.slice(half)];
}

export const isMac = () => /mac/i.test(navigator.platform) || /Mac OS X/.test(navigator.userAgent);
