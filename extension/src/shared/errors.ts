/**
 * Errors with a machine-readable code that crosses the message boundary: a failed request is answered
 * `{ ok: false, code, message }` (shared/protocol.ts), so pages check codes, never the text of a message.
 */
import type { PageSafeText } from "./page-text";

/**
 * A failure PassAuth explains. `pageSafe`: the message names no vault data (no item names, user names or saved
 * websites), so it may also be shown inside a web page (see page-text.ts). Messages that do name vault data are
 * fine in PassAuth's own pages and frames, never in a toast.
 */
export class AppError extends Error {
  readonly code: string;
  readonly pageSafe: boolean;
  constructor(code: string, message: string, pageSafe = false) {
    super(message);
    this.name = "AppError";
    this.code = code;
    this.pageSafe = pageSafe;
  }
}

/** The vault this request needs is locked (timeout, Lock, browser restart). */
export const LOCKED = "locked";
/** The server ended the session (signed out elsewhere, sessions revoked, refresh token rejected). */
export const SIGNED_OUT = "signed_out";
/** User verification is required and the master password wasn't entered recently. */
export const PASSWORD_REQUIRED = "password_required";
/** The account needs its Secret Key and none is stored in this browser. */
export const SECRET_KEY_REQUIRED = "secret_key_required";
/** This sender may not make this request, or the request is malformed. */
export const NOT_ALLOWED = "not_allowed";
/** The inline menu or save prompt this request belongs to is gone (used up, timed out, another page). */
export const EXPIRED = "expired";
/** The item (or what was asked of it) doesn't exist. */
export const NOT_FOUND = "not_found";
/** The login isn't saved for the page or frame it was to be filled into (the message names its websites). */
export const NOT_FOR_SITE = "not_for_site";
/** Filling didn't happen: no login form, a page PassAuth can't fill. */
export const CANT_FILL = "cant_fill";
/** The PassAuth server can't be reached. */
export const UNREACHABLE = "unreachable";
/** The server requires two-step login and the account has no method yet (403, servers with the `policies` feature). */
export const TWO_STEP_REQUIRED = "two_step_required";
/** A save would pass the vault owner's item or storage limit (403, the server's quotas). */
export const QUOTA_EXCEEDED = "quota_exceeded";
/** The server is almost out of disk space and stores nothing new (507); reading, syncing and deleting still work. */
export const INSUFFICIENT_STORAGE = "insufficient_storage";
/** A sign-in request changed (another key or challenge under the same id) after the approval sheet showed it. */
export const REQUEST_CHANGED = "request_changed";
/** The background didn't answer at all (extension reloaded or stopped). */
export const NO_ANSWER = "no_answer";
/** Anything else (an unexpected exception). */
export const FAILED = "error";

export const lockedError = () => new AppError(LOCKED, "PassAuth is locked. Unlock it to continue.", true);
export const signedOutError = () => new AppError(SIGNED_OUT, "You were signed out of PassAuth. Sign in again.", true);
export const notAllowed = () => new AppError(NOT_ALLOWED, "Not allowed.", true);

export const codeOf = (e: unknown): string | undefined => (e && typeof e === "object" && typeof (e as { code?: unknown }).code === "string" ? (e as { code: string }).code : undefined);

export const messageOf = (e: unknown): string => (e instanceof Error ? e.message : String(e));

/** What to show inside a web page for `e`: its message when it is page-safe, else `fallback`. */
export function pageMessage(e: unknown, fallback: PageSafeText): PageSafeText {
  return e instanceof AppError && e.pageSafe ? (e.message as PageSafeText) : fallback;
}
