/** Messages between popup, content scripts and the background service worker. */
import type { Item, ItemKind } from "@web/lib/types";

export type Status = "setup" | "logged-out" | "locked" | "unlocked";

export interface PopupState {
  status: Status;
  server: string;
  email: string;
  secretKeyRequired: boolean;
  secretKeyStored: boolean;
  autoLockMinutes: number;
}

export interface ItemSummary {
  id: string;
  name: string;
  subtitle: string;
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
  | { type: "createItem"; item: Item }
  | { type: "settings"; autoLockMinutes: number }
  | { type: "passkey:pending"; requestId: string }
  | { type: "passkey:decide"; requestId: string; accept: boolean; credentialId?: string; fallback?: boolean }
  // content script → background
  | { type: "page:submitted"; url: string; username: string; password: string }
  | { type: "page:pendingSave" }
  | { type: "page:save"; accept: "save" | "never" | "dismiss" }
  | { type: "page:fillRequest" };

/** background → content script (chrome.tabs.sendMessage). */
export type ContentCommand =
  | { type: "fill"; username: string; password: string; totp?: string; itemUrls: string[] }
  | { type: "showSave"; host: string; update: boolean }
  | { type: "probe" };

export type Reply<T = unknown> = { ok: true; data: T } | { ok: false; error: string };

export async function send<T = any>(req: Request): Promise<T> {
  const r: Reply<T> | undefined = await chrome.runtime.sendMessage(req);
  if (!r) throw new Error("PassAuth is not responding. Reload the extension.");
  if (!r.ok) throw new Error(r.error);
  return r.data;
}
