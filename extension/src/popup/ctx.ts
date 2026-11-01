/** Shared popup types and helpers. */
import type { ItemKind } from "@web/lib/types";
import type { PopupState } from "../shared/messages";

export type Route =
  | { tab: "vault"; page: "list" }
  | { tab: "vault"; page: "item"; id: string }
  | { tab: "vault"; page: "edit"; id: string }
  | { tab: "vault"; page: "new"; kind: ItemKind }
  | { tab: "generator" }
  | { tab: "settings"; section?: string };

export type CopyRequest = { text: string } | { id: string; field: "username" | "password" | "totp" };

export interface Ctx {
  state: PopupState;
  copy: (req: CopyRequest, label: string) => Promise<void>;
  notify: (text: string) => void;
  go: (route: Route) => void;
  /** Reload popup state (after lock, log out, settings changes). */
  reload: () => void;
}

export const msg = (e: unknown) => {
  const m = e instanceof Error ? e.message : String(e);
  return m === "secret_key_required" ? "This account uses a Secret Key. Enter it from your Emergency Kit." : m === "email_not_verified" ? "Confirm your email address first, then sign in." : m;
};

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
