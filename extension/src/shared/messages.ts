/** Messages between popup, content scripts and the background service worker. */
import type { Item, ItemKind, UrlMatch } from "@web/lib/types";

export type Status = "setup" | "logged-out" | "locked" | "unlocked";

/** Minutes of inactivity, or a special trigger. */
export type VaultTimeout = number | "immediately" | "system-lock" | "restart" | "never";

export interface Settings {
  vaultTimeout: VaultTimeout;
  timeoutAction: "lock" | "logout";
  /** Inline autofill menu on login fields. */
  inlineMenu: "focus" | "click" | "off";
  autoCopyTotp: boolean;
  /** Seconds; 0 = never. */
  clearClipboard: number;
  showIcons: boolean;
  defaultMatch: Exclude<UrlMatch, "default">;
  askToSave: boolean;
  theme: "system" | "light" | "dark";
}

export interface PopupState {
  status: Status;
  server: string;
  email: string;
  secretKeyRequired: boolean;
  secretKeyStored: boolean;
  settings: Settings;
  lastSync: number;
  neverSave: string[];
}

export interface ItemSummary {
  id: string;
  name: string;
  subtitle: string;
  /** Host of the first website, for the site icon. */
  host: string;
  /** Website to open from the list (first http(s) address), or "". */
  url: string;
  folder: string;
  kind: ItemKind;
  favorite: boolean;
  hasPassword: boolean;
  hasTotp: boolean;
  passkeys: number;
  vaultName: string;
}

export type TwoFactorChallenge = { token: string; providers: string[] };

export type Request =
  | { type: "state" }
  | { type: "setServer"; url: string }
  | { type: "login"; email: string; password: string; secretKey?: string }
  | { type: "verify2fa"; token: string; provider: string; code: string; remember: boolean }
  | { type: "email2fa"; token: string }
  | { type: "unlock"; password: string; secretKey?: string }
  | { type: "lock" }
  | { type: "logout" }
  | { type: "sync" }
  | { type: "items"; url?: string }
  | { type: "item"; id: string }
  | { type: "totp"; id: string }
  | { type: "fill"; id: string; tabId: number }
  | { type: "generate"; mode: "password" | "passphrase"; options?: Record<string, unknown> }
  | { type: "createItem"; item: Item; vaultId?: string }
  | { type: "updateItem"; id: string; item: Item }
  | { type: "trashItem"; id: string }
  | { type: "editorInfo" }
  | { type: "settings"; patch: Partial<Settings> }
  | { type: "neverSave:remove"; domain: string }
  | { type: "copy"; text: string }
  | { type: "copyField"; id: string; field: "username" | "password" | "totp" }
  | { type: "openPopup" }
  // inline autofill menu (extension frame) → background
  | { type: "inline:items"; nonce: string }
  | { type: "inline:fill"; nonce: string; id: string }
  | { type: "inline:close"; nonce: string }
  | { type: "passkey:pending"; requestId: string }
  | { type: "passkey:decide"; requestId: string; accept: boolean; credentialId?: string; fallback?: boolean }
  // content script → background
  | { type: "page:submitted"; url: string; username: string; password: string }
  | { type: "page:pendingSave" }
  | { type: "page:save"; accept: "save" | "never" | "dismiss" }
  | { type: "page:fillRequest" }
  | { type: "page:inlineInfo" }
  | { type: "page:inlineOpen" };

export interface InlineInfo {
  mode: Settings["inlineMenu"];
  status: "locked" | "unlocked";
  count: number;
}

export interface InlineItems {
  server: string;
  theme: Settings["theme"];
  showIcons: boolean;
  locked: boolean;
  items: ItemSummary[];
}

/** background → content script (chrome.tabs.sendMessage). */
export type ContentCommand =
  /** `site`: base domain of the verified top page; only same-site frames fill. */
  | { type: "fill"; username: string; password: string; totp?: string; site: string }
  | { type: "toast"; text: string }
  | { type: "inline:close" }
  | { type: "showSave"; host: string; update: boolean }
  | { type: "probe" };

export type Reply<T = unknown> = { ok: true; data: T } | { ok: false; error: string };

export async function send<T = any>(req: Request): Promise<T> {
  const r: Reply<T> | undefined = await chrome.runtime.sendMessage(req);
  if (!r) throw new Error("PassAuth is not responding. Reload the extension.");
  if (!r.ok) throw new Error(r.error);
  return r.data;
}
