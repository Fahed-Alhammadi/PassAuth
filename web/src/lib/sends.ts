/**
 * Send (servers with the `sends` feature): text shared through a link, `<server>/send/<id>#<key>`. The app encrypts the
 * name and the text with a random send key that exists only in the link's fragment (browsers never send it anywhere)
 * and keeps the key wrapped by the account key (`owner_key`), so the owner can copy the link and edit the Send later.
 * The server stores ciphertext only and decides who may open it, how often and until when; an optional password is
 * checked by the server with a verifier the visitor's app derives from it (`access_salt`), not used for encryption.
 *
 * Pure (no WASM, no network, no React) and unit-tested in `sends.test.ts`; the pages encrypt and talk to the server.
 */

/** A Send id: 128 random bits in base64url, chosen by the server. */
const SEND_ID = /^[A-Za-z0-9_-]{22}$/;
/** A send key: 32 bytes in unpadded base64url. */
const SEND_KEY = /^[A-Za-z0-9_-]{43}$/;

/** The link to share: the server's address, the Send's id and, after `#`, its key. */
export function sendLink(origin: string, id: string, key: string): string {
  return `${origin.replace(/\/+$/, "")}/send/${encodeURIComponent(id)}#${key}`;
}

/** The link with its key (everything after `#`) hidden, for showing it on screen; copying uses the whole link. */
export function maskedSendLink(link: string): string {
  const at = link.indexOf("#");
  return at < 0 ? link : `${link.slice(0, at + 1)}${"\u2022".repeat(12)}`;
}

/** Whether a path is the public Send page (`/send/<anything>`), which works without an account or a session. */
export const isSendPage = (pathname: string): boolean => /^\/send\/[^/]+\/?$/.test(pathname);

/**
 * The Send's id from the page's path and its key from the fragment; each is null when missing or malformed (an id the
 * server can't have made, a key of the wrong length). Only the fragment's first value counts: some apps append more.
 */
export function parseSendLocation(pathname: string, hash: string): { id: string | null; key: string | null } {
  const m = /^\/send\/([^/]+)\/?$/.exec(pathname);
  let id: string | null = null;
  if (m) {
    try {
      id = decodeURIComponent(m[1]);
    } catch {
      id = null;
    }
  }
  const key = hash.replace(/^#/, "").split(/[&?#\s]/)[0];
  return { id: id && SEND_ID.test(id) ? id : null, key: SEND_KEY.test(key) ? key : null };
}

// ------------------------------------------------------------------ sizes

/** Bytes the core adds when it encrypts a field: a version byte, the 24-byte nonce and the 16-byte tag. */
const OVERHEAD = 1 + 24 + 16;

/** UTF-8 bytes of `text`. */
export const utf8Length = (text: string): number => new TextEncoder().encode(text).length;

/** Characters of the encrypted field (unpadded base64url) for `plainBytes` bytes of text: what the server limits. */
export const encryptedFieldLength = (plainBytes: number): number => Math.ceil(((plainBytes + OVERHEAD) * 4) / 3);

/** The most text (UTF-8 bytes) that fits the server's limit on the encrypted text (`limits.send_max_bytes`). */
export const maxTextBytes = (maxEncrypted: number): number => Math.max(0, Math.floor((maxEncrypted * 3) / 4) - OVERHEAD);

/** The server's limit on a Send's encrypted text when `/api/config` doesn't say (1 MiB). */
export const DEFAULT_SEND_MAX_BYTES = 1024 * 1024;
/** The longest a Send may stay when `/api/config` doesn't say: the server's default `send_max_days`. */
export const DEFAULT_SEND_MAX_DAYS = 30;
/** Longest name accepted in the form (its ciphertext stays far below the server's 8 KiB). */
export const SEND_NAME_MAX = 200;

/** `send_max_days` and `send_max_bytes` from `/api/config` `limits`, with the server's defaults when missing. */
export function sendLimits(limits: unknown): { maxDays: number; maxBytes: number } {
  const l = limits && typeof limits === "object" ? (limits as Record<string, unknown>) : {};
  const whole = (v: unknown, min: number, fallback: number) => (typeof v === "number" && Number.isFinite(v) && v >= min ? Math.floor(v) : fallback);
  return { maxDays: whole(l.send_max_days, 1, DEFAULT_SEND_MAX_DAYS), maxBytes: whole(l.send_max_bytes, 1024, DEFAULT_SEND_MAX_BYTES) };
}

// ------------------------------------------------------------- durations

const HOUR = 3600;
const DAY = 24 * HOUR;

/** Durations offered for a Send's deletion and expiry, in seconds, with their labels. */
const PRESETS: [number, string][] = [
  [HOUR, "1 hour"],
  [DAY, "1 day"],
  [2 * DAY, "2 days"],
  [3 * DAY, "3 days"],
  [7 * DAY, "7 days"],
  [14 * DAY, "14 days"],
  [30 * DAY, "30 days"],
  [90 * DAY, "90 days"],
  [180 * DAY, "180 days"],
  [365 * DAY, "365 days"],
];

const dayLabel = (days: number) => `${days} ${days === 1 ? "day" : "days"}`;

/** The durations within `maxDays` (the server's `send_max_days`), and the limit itself when it isn't one of them. */
export function durationChoices(maxDays: number): [number, string][] {
  const max = Math.max(1, Math.floor(maxDays)) * DAY;
  const within = PRESETS.filter(([s]) => s <= max);
  return within.some(([s]) => s === max) ? within : [...within, [max, dayLabel(max / DAY)]];
}

/** The deletion offered first: 7 days, or the server's limit when that is shorter. */
export const defaultDeletion = (maxDays: number): number => Math.min(7 * DAY, Math.max(1, Math.floor(maxDays)) * DAY);

// ---------------------------------------------------------------- owner

/** A Send as its owner's list shows it (`GET /sends`); `name` and `ownerKey` are encrypted. */
export interface OwnedSend {
  id: string;
  /** Encrypted with the send key. */
  name: string;
  /** The send key wrapped by the account key. */
  ownerKey: string;
  hasPassword: boolean;
  accessSalt: string | null;
  maxViews: number | null;
  views: number;
  expiresAt: number | null;
  deleteAt: number;
  disabled: boolean;
  hideEmail: boolean;
  /** Whether a visitor can open it right now (the server's answer, which also knows if Send is turned off). */
  available: boolean;
  createdAt: number;
  updatedAt: number;
  /** Encrypted text: only in `GET /sends/{id}`. */
  data: string | null;
}

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const text = (v: unknown): string | null => (typeof v === "string" && v ? v : null);

/** One Send from the owner's API, or null when malformed. */
export function readSend(value: unknown): OwnedSend | null {
  if (!value || typeof value !== "object") return null;
  const s = value as Record<string, unknown>;
  const id = text(s.id);
  const name = text(s.name);
  const ownerKey = text(s.owner_key);
  const deleteAt = num(s.delete_at);
  if (!id || !name || !ownerKey || deleteAt === null) return null;
  const maxViews = num(s.max_views);
  const views = num(s.views) ?? 0;
  const expiresAt = num(s.expires_at);
  return {
    id,
    name,
    ownerKey,
    hasPassword: s.has_password === true,
    accessSalt: text(s.access_salt),
    maxViews,
    views,
    expiresAt,
    deleteAt,
    disabled: s.disabled === true,
    hideEmail: s.hide_email === true,
    available: typeof s.available === "boolean" ? s.available : true,
    createdAt: num(s.created_at) ?? 0,
    updatedAt: num(s.updated_at) ?? 0,
    data: text(s.data),
  };
}

/** `GET /sends`: the owner's Sends, newest first as the server sends them; malformed entries left out. */
export function readSends(value: unknown): OwnedSend[] {
  const list = value && typeof value === "object" ? (value as Record<string, unknown>).sends : null;
  if (!Array.isArray(list)) return [];
  return list.map(readSend).filter((s): s is OwnedSend => s !== null);
}

export type SendState = "available" | "disabled" | "used-up" | "expired" | "deleted" | "unavailable";

/** Why a Send can or can't be opened right now (its own settings first, then the server's say). */
export function sendState(s: OwnedSend, now: number): SendState {
  if (s.deleteAt <= now) return "deleted";
  if (s.disabled) return "disabled";
  if (s.expiresAt !== null && s.expiresAt <= now) return "expired";
  if (s.maxViews !== null && s.views >= s.maxViews) return "used-up";
  return s.available ? "available" : "unavailable";
}

export const SEND_STATE_LABEL: Record<SendState, string> = {
  available: "Active",
  disabled: "Turned off",
  "used-up": "Used up",
  expired: "Expired",
  deleted: "Deleted",
  unavailable: "Unavailable",
};

/** "Not opened yet", "Opened 3 times", "Opened 2 of 5 times". */
export function viewsText(s: { views: number; maxViews: number | null }): string {
  if (s.maxViews !== null) return `Opened ${s.views} of ${s.maxViews} ${s.maxViews === 1 ? "time" : "times"}`;
  if (s.views === 0) return "Not opened yet";
  return `Opened ${s.views} ${s.views === 1 ? "time" : "times"}`;
}

/**
 * What a change of a Send sends (`PUT /sends/{id}` takes only what changed). `password`: undefined keeps the current
 * one, null removes it, `{salt, verifier}` sets a new one.
 */
export interface SendChanges {
  name?: string;
  data?: string;
  password?: { salt: string; verifier: string } | null;
  maxViews?: number | null;
  expiresAt?: number | null;
  deleteAt?: number;
  disabled?: boolean;
  hideEmail?: boolean;
}

/** The `PUT /sends/{id}` body for `changes` (null clears `max_views` / `expires_at`; `access_verifier: null` removes the password). */
export function changesBody(changes: SendChanges): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  if (changes.name !== undefined) body.name = changes.name;
  if (changes.data !== undefined) body.data = changes.data;
  if (changes.password === null) body.access_verifier = null;
  else if (changes.password) {
    body.access_salt = changes.password.salt;
    body.access_verifier = changes.password.verifier;
  }
  if (changes.maxViews !== undefined) body.max_views = changes.maxViews;
  if (changes.expiresAt !== undefined) body.expires_at = changes.expiresAt;
  if (changes.deleteAt !== undefined) body.delete_at = changes.deleteAt;
  if (changes.disabled !== undefined) body.disabled = changes.disabled;
  if (changes.hideEmail !== undefined) body.hide_email = changes.hideEmail;
  return body;
}

// --------------------------------------------------------------- visitor

/** `GET /api/public/sends/{id}`: what the page shows before opening a Send (never the text). */
export interface PublicSend {
  id: string;
  /** Encrypted; null while a password is needed. */
  name: string | null;
  needsPassword: boolean;
  accessSalt: string | null;
  expiresAt: number | null;
  deleteAt: number | null;
  /** The sender's email address, unless they chose to hide it. */
  sender: string | null;
}

export function readPublicSend(value: unknown): PublicSend | null {
  if (!value || typeof value !== "object") return null;
  const s = value as Record<string, unknown>;
  const id = text(s.id);
  if (!id) return null;
  const needsPassword = s.needs_password === true;
  const accessSalt = text(s.access_salt);
  if (needsPassword && !accessSalt) return null;
  return { id, name: text(s.name), needsPassword, accessSalt, expiresAt: num(s.expires_at), deleteAt: num(s.delete_at), sender: text(s.sender) };
}

/** `POST /api/public/sends/{id}/access`: the encrypted name and text. */
export function readOpenedSend(value: unknown): { name: string; data: string } | null {
  if (!value || typeof value !== "object") return null;
  const s = value as Record<string, unknown>;
  const name = text(s.name);
  const data = typeof s.data === "string" ? s.data : null;
  return name && data !== null ? { name, data } : null;
}

/** The visitor's page in words, by what went wrong (HTTP status and error code of the public API). */
export function visitorError(status: number, code: string | null): string {
  if (status === 404) return "This Send doesn't exist, has expired or was used up. Ask the person who sent it for a new link.";
  if (status === 401 || code === "wrong_password") return "That password isn't right. Check it and try again.";
  if (status === 429) return "Too many attempts. Wait a minute, then try again.";
  return "PassAuth couldn't open this Send. Check your connection, then try again.";
}
