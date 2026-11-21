/**
 * Two-step login with a security key or passkey (servers with `two_step_key_page`; docs/ARCHITECTURE.md "Security
 * keys"). The extension can't run WebAuthn for the server's relying party (it can only assert its own id), so it opens
 * the server's own key page (`key_page` from `POST /auth/2fa/passkey/start`, https and host = the options' `rpId` only)
 * in a small PassAuth window with the request options in the fragment and `return=page`. The page runs the ceremony in
 * the browser and navigates to `<same origin>/two-step/key/done#v=1&credential=…` (or `…&error=cancelled`); this worker
 * reads that address from `chrome.tabs.onUpdated` for THAT tab only, closes the window and calls
 * `/auth/2fa/passkey/finish` with the two-step token, which never leaves the worker.
 *
 * One hand-off at a time. A result counts only while waiting, only once, only from the window's own tab and only when
 * the assertion signed the challenge of the options this worker opened. Closing the window is "cancelled". The window
 * moves focus away, which closes the toolbar popup: the wait and the sign-in run here; the popup asks for the outcome
 * when it opens again (`keySignInStatus`). The record of the open window is kept in session storage, so a worker that
 * restarted meanwhile still closes the window and reports "Sign-in expired" (the derived keys were in its memory);
 * while waiting a heartbeat keeps the worker awake.
 */
import { b64urlToBytes, KEY_DONE_PATH, KEY_PAGE_FEATURE, KEY_PAGE_MISMATCH, keyPageUrl, parseReturnFragment, publicKeyOf, signedChallenge } from "@web/lib/key-page";
import { AppError, EXPIRED, FAILED, messageOf } from "../shared/errors";
import { logged } from "../shared/log";
import type { KeySignInStatus, TwoFactorChallenge } from "../shared/types";
import { canUseWindows, openCentered } from "../shared/windows";
import { api, serverFeatures } from "./api";
import { local } from "./storage";

type Json = Record<string, unknown>;

/** Session-storage key of the open key window (`Waiting`). */
export const KEY_WAIT_KEY = "twoStepKeyWait";
/** Page size of the key window: the server's page with one button. */
const KEY_WINDOW = { width: 480, height: 600 };
/** The server keeps a sign-in challenge for 5 minutes: the window doesn't wait longer. */
export const KEY_WAIT_MS = 5 * 60_000;
/** An extension API call more often than every 30 s keeps the service worker running. */
const BEAT_MS = 20_000;

export const EXPIRED_TEXT = "Sign-in expired. Start again.";
const TIMED_OUT_TEXT = "Your security key wasn't used in time. Try again.";
const NO_WINDOW_TEXT = "PassAuth couldn't open a window for your security key. Try again.";

/** The open key window, as kept in session storage. */
/** `Waiting.windowId` of a key page opened as a tab. */
const NO_WINDOW = -1;

interface Waiting {
  /** Random id of this hand-off. */
  id: string;
  tabId: number;
  /** The key window; NO_WINDOW when the key page is a tab (Safari on iPhone and iPad has no windows). */
  windowId: number;
  /** The done page's address (`<key page origin>/two-step/key/done`), without a fragment. */
  done: string;
  /** The options' challenge, base64url. */
  challenge: string;
  /** The random `state` put in the key page's fragment; a result counts only when the page echoes it. */
  state: string;
  /** Who waits: the popup's sign-in (finished in this worker) or the device sign-in window. */
  purpose: "login" | "device";
}

export type KeyOutcome = { credential: Json } | { cancelled: true } | { expired: true };

/** This worker's side of the open hand-off (gone after a restart; the session record stays). */
let current: { w: Waiting; resolve: (o: KeyOutcome) => void; beat: ReturnType<typeof setInterval>; timer: ReturnType<typeof setTimeout> } | null = null;

async function storedWaiting(): Promise<Waiting | null> {
  if (current) return current.w;
  const got = await chrome.storage.session.get(KEY_WAIT_KEY).catch(() => ({}) as Record<string, unknown>);
  const w = (got as Record<string, unknown>)[KEY_WAIT_KEY] as Partial<Waiting> | undefined;
  return w &&
    typeof w.id === "string" &&
    typeof w.tabId === "number" &&
    typeof w.windowId === "number" &&
    typeof w.done === "string" &&
    typeof w.challenge === "string" &&
    typeof w.state === "string" &&
    (w.purpose === "login" || w.purpose === "device")
    ? (w as Waiting)
    : null;
}

/**
 * Whether a WebAuthn request comes from the key page in the key window: its tab, its top-level frame, and the key
 * page's origin. PassAuth's own passkeys stay out of that ceremony (passkey-handler.ts); any other page or frame, also in
 * that window, is handled as usual.
 */
export async function isKeyPageRequest(r: { tabId?: number; frameId?: number; topLevel: boolean; origin: string }): Promise<boolean> {
  if (r.tabId === undefined || r.frameId !== 0 || !r.topLevel) return false;
  const w = await storedWaiting();
  return !!w && w.tabId === r.tabId && new URL(w.done).origin === r.origin;
}

/** Whether the server of `accountId` (default: the active account) offers the key page. */
export async function keyPageOffered(accountId?: string): Promise<boolean> {
  const server = (await local.account(accountId)).data?.server ?? "";
  return !!server && (await serverFeatures(server)).has(KEY_PAGE_FEATURE);
}

/**
 * End the open hand-off (if it is `w`): forget it, close its window (unless it is gone already) and hand `outcome` to
 * whoever waits in this worker. Returns false when nobody here waited for it (the worker restarted meanwhile).
 */
async function settle(w: Waiting, outcome: KeyOutcome, closeWindow = true): Promise<boolean> {
  const mine = current?.w.id === w.id ? current : null;
  if (mine) {
    current = null;
    clearInterval(mine.beat);
    clearTimeout(mine.timer);
  }
  const stored = await storedWaiting();
  if (stored?.id === w.id) await chrome.storage.session.remove(KEY_WAIT_KEY).catch(logged("Forgetting the security key window"));
  if (closeWindow) {
    if (w.windowId === NO_WINDOW) await chrome.tabs.remove(w.tabId).catch(() => {});
    else await chrome.windows.remove(w.windowId).catch(() => {});
  }
  if (mine) mine.resolve(outcome);
  else if (w.purpose === "login") orphaned();
  return !!mine;
}

/** The key page in its own window: its window and tab. */
async function openKeyWindow(url: string): Promise<{ windowId: number; tabId: number }> {
  const win = await openCentered(url, KEY_WINDOW).catch(() => undefined);
  const tabId = win?.tabs?.[0]?.id ?? (win?.id !== undefined ? (await chrome.tabs.query({ windowId: win.id }).catch(() => []))[0]?.id : undefined);
  if (win?.id === undefined || tabId === undefined) {
    if (win?.id !== undefined) await chrome.windows.remove(win.id).catch(() => {});
    throw new AppError(FAILED, NO_WINDOW_TEXT);
  }
  return { windowId: win.id, tabId };
}

/** The key page as a tab (no windows: Safari on iPhone and iPad). */
async function openKeyTab(url: string): Promise<{ windowId: number; tabId: number }> {
  const tab = await chrome.tabs.create({ url, active: true }).catch(() => undefined);
  if (tab?.id === undefined) throw new AppError(FAILED, NO_WINDOW_TEXT);
  return { windowId: NO_WINDOW, tabId: tab.id };
}

/**
 * Start a hand-off for `token`: `POST /auth/2fa/passkey/start`, then the key window. Resolves once the window is open,
 * with the outcome to wait for. An earlier hand-off still open ends as cancelled. Refuses (KEY_PAGE_MISMATCH) a key
 * page that isn't https on the options' `rpId` host and the connected server's host, before anything opens.
 */
export async function openKeyPage(token: string, purpose: "login" | "device", accountId?: string): Promise<{ outcome: Promise<KeyOutcome> }> {
  const start = await api<{ options?: unknown; key_page?: unknown } | null>("/auth/2fa/passkey/start", {
    body: { two_factor_token: token },
    auth: false,
    ...(accountId ? { accountId } : {}),
  });
  const options = start?.options;
  const server = (await local.account(accountId)).data?.server ?? "";
  // https, host = the options' rpId = the connected server's host; the fragment gets a fresh random `state`.
  const page = keyPageUrl(start?.key_page, options, "page", server);
  const url = page?.url;
  const challenge = publicKeyOf(options)?.challenge;
  if (!page || !url || typeof challenge !== "string") throw new AppError(FAILED, KEY_PAGE_MISMATCH);
  await cancelKeyPage();
  const opened = canUseWindows() ? await openKeyWindow(url) : await openKeyTab(url);
  const w: Waiting = { id: crypto.randomUUID(), ...opened, done: new URL(KEY_DONE_PATH, url).href, challenge, state: page.state, purpose };
  await chrome.storage.session.set({ [KEY_WAIT_KEY]: w });
  // Wrapped: an async function would otherwise wait for the outcome itself.
  const outcome = new Promise<KeyOutcome>((resolve) => {
    current = {
      w,
      resolve,
      beat: setInterval(() => void chrome.runtime.getPlatformInfo().catch(() => {}), BEAT_MS),
      timer: setTimeout(() => void settle(w, { expired: true }).catch(logged("Ending a security key wait")), KEY_WAIT_MS),
    };
  });
  return { outcome };
}

/** Cancel the open hand-off (the popup's Cancel, a new hand-off): its window closes. */
export async function cancelKeyPage(): Promise<void> {
  const w = await storedWaiting();
  if (w) await settle(w, { cancelled: true });
}

const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/** The result in `url` if it is the done page of `w` with a valid result for its challenge; null for anything else. */
function readDone(w: Waiting, url: string): KeyOutcome | null {
  const at = url.indexOf("#");
  if (at < 0) return null;
  let page: URL;
  try {
    page = new URL(url.slice(0, at));
  } catch {
    return null;
  }
  const done = new URL(w.done);
  if (page.origin !== done.origin || page.search || (page.pathname.replace(/\/+$/, "") || "/") !== done.pathname) return null;
  // Only with the `state` this worker opened; only `error=cancelled` is a cancel.
  const result = parseReturnFragment(url.slice(at));
  if (!result || result.state !== w.state) return null;
  if (!("credential" in result)) return { cancelled: true };
  const signed = signedChallenge(result.credential);
  const expected = b64urlToBytes(w.challenge);
  return signed && expected && sameBytes(signed, expected) ? { credential: result.credential } : null;
}

/** `chrome.tabs.onUpdated`: the key window's tab reached the done page. */
export async function onKeyTabUpdated(tabId: number, change: { url?: string }): Promise<void> {
  if (!change.url) return;
  const w = await storedWaiting();
  if (!w || w.tabId !== tabId) return;
  const outcome = readDone(w, change.url);
  if (outcome) await settle(w, outcome);
}

/** `chrome.windows.onRemoved` / `chrome.tabs.onRemoved`: the user closed the key window (cancelled). */
export async function onKeyWindowGone(ids: { windowId?: number; tabId?: number }): Promise<void> {
  const w = await storedWaiting();
  if (w && (w.windowId === ids.windowId || w.tabId === ids.tabId)) await settle(w, { cancelled: true }, false);
}

// ------------------------------------------------------------ the popup's sign-in

/** The popup's sign-in waiting on the key window (the popup closes meanwhile): its challenge to show again, and how it went. */
let signIn: { email: string; challenge: TwoFactorChallenge; status: "waiting" | "cancelled" | "failed"; error?: string } | null = null;
/** Finishes a sign-in with the assertion (vault.ts `verifyTwoFactorPasskey`); set by the worker, so this module doesn't import the vault. */
let finishSignIn: (token: string, credential: Json, remember: boolean) => Promise<void> = async () => {
  throw new AppError(EXPIRED, EXPIRED_TEXT);
};
export function setKeySignInFinisher(fn: typeof finishSignIn) {
  finishSignIn = fn;
}

/** A hand-off whose waiter was lost with a restarted worker ended: the popup says the sign-in expired. */
function orphaned() {
  signIn = { email: signIn?.email ?? "", challenge: signIn?.challenge ?? { token: "", providers: [] }, status: "failed", error: EXPIRED_TEXT };
}

/** "Use security key" in the popup's two-step login: opens the key window and finishes the sign-in here. */
export async function startKeySignIn(email: string, challenge: TwoFactorChallenge, remember: boolean): Promise<void> {
  const { outcome: waitFor } = await openKeyPage(challenge.token, "login");
  const mine = { email, challenge, status: "waiting" as const };
  signIn = mine;
  void waitFor.then(async (outcome) => {
    if (signIn !== mine) return;
    if ("credential" in outcome) {
      try {
        await finishSignIn(challenge.token, outcome.credential, remember);
        if (signIn === mine) signIn = null;
      } catch (e) {
        if (signIn === mine) signIn = { ...mine, status: "failed", error: messageOf(e) };
      }
    } else if ("expired" in outcome) signIn = { ...mine, status: "failed", error: TIMED_OUT_TEXT };
    else signIn = { ...mine, status: "cancelled" };
  });
}

/**
 * Where the popup's security-key sign-in stands: waiting, or how it ended (told once; null = nothing to show: none
 * started, or it finished and the account is signed in). A key window left by a restarted worker is closed here.
 */
export async function keySignInStatus(): Promise<KeySignInStatus | null> {
  if (!current) {
    const w = await storedWaiting();
    if (w) await settle(w, { cancelled: true });
  }
  const s = signIn;
  if (!s) return null;
  if (s.status !== "waiting") signIn = null;
  // A sign-in that ended without its challenge (worker restart) has nothing to go back to.
  const challenge = s.challenge.token ? { challenge: s.challenge } : {};
  return { status: s.status, email: s.email, ...challenge, ...(s.error ? { error: s.error } : {}) };
}

/** A new sign-in starts (vault.ts `login`): any open key window closes and the earlier sign-in's outcome is forgotten. */
export async function resetKeySignIn(): Promise<void> {
  signIn = null;
  await cancelKeyPage();
  signIn = null;
}

/** The popup's Cancel while waiting: the window closes, back to the choice. */
export async function cancelKeySignIn(): Promise<void> {
  await cancelKeyPage();
  if (signIn?.status === "cancelled") signIn = null;
}

/** For tests: forget this worker's memory, as a restarted worker would. */
export function _restartForTests() {
  if (current) {
    clearInterval(current.beat);
    clearTimeout(current.timer);
  }
  current = null;
  signIn = null;
}
