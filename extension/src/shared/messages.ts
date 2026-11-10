/** Messages between popup, content scripts and the background service worker. */
import type { Item, ItemKind, LoginUrl, UrlMatch } from "@web/lib/types";
import type { SaveTarget } from "../background/save-plan";

export type { SaveTarget };

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
  /** Number of matching logins on the toolbar icon. */
  badge: boolean;
}

export interface AccountSummary {
  id: string;
  email: string;
  name: string;
  server: string;
  status: Status;
}

export interface PopupState {
  status: Status;
  activeId: string;
  /** Signed-in (or signed-out but remembered) accounts on this device. */
  accounts: AccountSummary[];
  /** Profile name of the active account ("" if not set). */
  name: string;
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

/** A security key / passkey registered for two-step login (not a passkey saved in a login). */
export interface SecurityKey {
  id: string;
  name: string;
  created_at: number;
  last_used_at: number | null;
}

export interface SecurityKeys {
  keys: SecurityKey[];
  /** Enabled two-step methods besides recovery codes (`totp`, `email`, `passkey`). */
  methods: string[];
}

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
  | { type: "account:add" }
  | { type: "account:switch"; id: string }
  | { type: "account:cancelAdd" }
  /** Two-step login security keys of the active account (`GET /account`). */
  | { type: "securityKeys" }
  /** Remove one, after the master password (fresh reauth token). */
  | { type: "securityKeys:remove"; id: string; password: string }
  // inline autofill menu (extension frame) → background
  | { type: "inline:items"; nonce: string }
  | { type: "inline:fill"; nonce: string; id: string }
  | { type: "inline:close"; nonce: string }
  | { type: "passkey:pending"; requestId: string }
  /** `password`: master password, when the site requires user verification and PassAuth wasn't unlocked recently. */
  | { type: "passkey:decide"; requestId: string; accept: boolean; credentialId?: string; fallback?: boolean; password?: string }
  // content script → background
  | { type: "page:submitted"; username: string; password: string }
  /** First step of an identifier-first login (username only). */
  | { type: "page:identifier"; username: string }
  /** The submitted login form disappeared without a page load. */
  | { type: "page:formDone" }
  | { type: "page:pendingSave" }
  /** The save prompt was dismissed from the page side (Escape): the only thing a page-side script can do to a pending save. */
  | { type: "page:saveDismiss"; nonce: string }
  // save prompt (extension frame inside the page) → background
  | { type: "save:offer"; nonce: string }
  /** `target`: the login shown as selected under "Save in" (an id from the offer's `targets`, or "new"). */
  | { type: "save:answer"; nonce: string; accept: "save" | "never" | "dismiss"; target?: string }
  /** The prompt's content changed height. */
  | { type: "save:resize"; nonce: string; height: number }
  /** This frame has a login form for a fill offer. */
  | { type: "page:fillClaim"; token: string }
  | { type: "page:inlineInfo" }
  | { type: "page:inlineOpen" };

/**
 * All the page side ever learns about a save prompt: the nonce that binds the
 * prompt frame to the pending save, and how tall to make the frame.
 */
export interface SavePrompt {
  nonce: string;
  height: number;
}

/** What the save prompt shows. Only the prompt frame (an extension page) gets it, never the content script. */
export interface SaveOffer {
  host: string;
  /** The user name that was typed ("" when the page had no user-name field). */
  username: string;
  /** The choices under "Save in", besides "New login": the user's own logins for this site (see save-plan.ts). */
  targets: SaveTarget[];
  /** Preselected: one of `targets` (update it) or "new" (save a new login). */
  selected: string;
  theme: Settings["theme"];
}

/** The background's reply to the prompt's answer. */
export type SaveAnswer =
  /** Applied or dismissed: the prompt closes. */
  | { done: true }
  /** Nothing was saved. `retry`: the user can try again from the same prompt. */
  | { error: string; retry: boolean }
  /** The login that was shown as the target is gone or read-only now: show these choices and ask again. */
  | { again: SaveOffer; notice: string };

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
  /**
   * Sent to one frame only. `site`: base domain of the verified top page;
   * `urls`: the item's websites, checked again against the frame's own URL.
   * `focused`: fill the field the inline menu was opened on.
   */
  | { type: "fill"; username: string; password: string; totp?: string; site: string; urls: LoginUrl[]; defaultMatch: Exclude<UrlMatch, "default">; focused: boolean }
  /** No secrets: frames with a matching login form answer with page:fillClaim. */
  | { type: "fill:offer"; token: string; site: string; urls: LoginUrl[]; defaultMatch: Exclude<UrlMatch, "default"> }
  /** `text` is shown inside the page: generic wording and the site's own host only, never vault data. */
  | { type: "toast"; text: string; theme?: Settings["theme"] }
  | { type: "inline:close" }
  | ({ type: "showSave" } & SavePrompt)
  | { type: "save:size"; height: number }
  | { type: "save:close" };

export type Reply<T = unknown> = { ok: true; data: T } | { ok: false; error: string };

export async function send<T = any>(req: Request): Promise<T> {
  const r: Reply<T> | undefined = await chrome.runtime.sendMessage(req);
  if (!r) throw new Error("PassAuth is not responding. Reload the extension.");
  if (!r.ok) throw new Error(r.error);
  return r.data;
}
