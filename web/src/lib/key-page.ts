/**
 * Security-key "key page" hand-off: apps that can't run WebAuthn for the server's relying party themselves (the desktop
 * app's WebView, the extension, the phone apps) open the server's own page `/two-step/key` in a real browser, whose
 * origin is the relying party. The page gets the request options in the address's fragment (never sent to the server):
 *
 *   <key_page>#v=1&options=<base64url(JSON of the start answer's `options`)>&return=app|page
 *
 *   …&state=<16 random bytes, base64url>
 *
 * and hands the assertion back with the fragment `v=1&state=…&credential=<base64url(JSON)>` (or
 * `v=1&state=…&error=cancelled`) to one of a FIXED list of targets: `app` = `passauth://two-step-key`, `page` =
 * `<same origin>/two-step/key/done`. Nothing in the fragment ever names where to go. The two-step token never leaves
 * the app: an assertion alone can't finish a sign-in, and the app accepts a result only while it waits, only once, only
 * with the `state` it opened, and a credential only for the challenge of the options it opened.
 */

export const KEY_PAGE_PATH = "/two-step/key";
export const KEY_DONE_PATH = "/two-step/key/done";
/** Where `return=app` hands the result back (the apps register or catch the `passauth` scheme). */
export const APP_RETURN = "passauth://two-step-key";
/** Server feature (GET /api/config `features`): the start answer has `key_page` and the page exists. */
export const KEY_PAGE_FEATURE = "two_step_key_page";

export type ReturnKind = "app" | "page";
const RETURN_KINDS: readonly ReturnKind[] = ["app", "page"];

/** A fragment longer than this isn't one of ours (options with 10 keys are ~2 KB). */
const MAX_FRAGMENT = 32 * 1024;

export const KEY_PAGE_MISMATCH = "This server's address for security keys doesn't match. Use another method.";
/** Shown under "Waiting for your security key…" in every app. */
export const KEY_PAGE_WARNING = "PassAuth never asks for your master password or Secret Key in the browser.";

/** `state`: 22–64 base64url characters (the apps send 16 random bytes = 22). */
const STATE_RE = /^[A-Za-z0-9_-]{22,64}$/;
export const validState = (s: unknown): s is string => typeof s === "string" && STATE_RE.test(s);

/** A fresh `state` for one hand-off: 16 bytes from the CSPRNG. */
export function newState(): string {
  return bytesToB64url(crypto.getRandomValues(new Uint8Array(16)));
}

type Json = Record<string, unknown>;

export function isKeyPagePath(path: string): boolean {
  const p = path.replace(/\/+$/, "") || "/";
  return p === KEY_PAGE_PATH || p === KEY_DONE_PATH;
}

// ------------------------------------------------------------------------------------------------ base64url

export function bytesToB64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Strict base64url (no padding, no other characters); null when it isn't. */
export function b64urlToBytes(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  try {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export const jsonToB64url = (value: unknown) => bytesToB64url(new TextEncoder().encode(JSON.stringify(value)));

/** A base64url-encoded JSON object; null for anything else. */
export function b64urlToJson(s: string): Json | null {
  const bytes = b64urlToBytes(s);
  if (!bytes) return null;
  try {
    const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    return value && typeof value === "object" && !Array.isArray(value) ? (value as Json) : null;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------------------------------------ options

/**
 * The `publicKey` request options inside the start answer's `options` (`{publicKey: {...}}`); a bare publicKey object
 * is accepted too. Null without a base64url `challenge`.
 */
export function publicKeyOf(options: unknown): Json | null {
  if (!options || typeof options !== "object" || Array.isArray(options)) return null;
  const o = options as Json;
  const pk = o.publicKey && typeof o.publicKey === "object" && !Array.isArray(o.publicKey) ? (o.publicKey as Json) : o;
  if (typeof pk.challenge !== "string" || !b64urlToBytes(pk.challenge)?.length) return null;
  if (pk.rpId !== undefined && typeof pk.rpId !== "string") return null;
  if (pk.allowCredentials !== undefined && !Array.isArray(pk.allowCredentials)) return null;
  return pk;
}

/** The options' challenge, decoded; null when the options have none. */
export function challengeOf(options: unknown): Uint8Array | null {
  const pk = publicKeyOf(options);
  return pk ? b64urlToBytes(pk.challenge as string) : null;
}

function hostOf(address: string): string | null {
  try {
    return new URL(address).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * The key page's address for these options with a fresh `state`, or null when it must not be opened: only an `https:`
 * address whose host is exactly the options' `rpId` AND the host of the server the app is signing in to (`server`, its
 * URL); a server could otherwise send the app's user to a page of its choosing.
 */
export function keyPageUrl(keyPage: unknown, options: unknown, ret: ReturnKind, server: string): { url: string; state: string } | null {
  const pk = publicKeyOf(options);
  if (!pk || typeof pk.rpId !== "string" || typeof keyPage !== "string") return null;
  let url: URL;
  try {
    url = new URL(keyPage);
  } catch {
    return null;
  }
  const host = url.hostname.toLowerCase();
  if (url.protocol !== "https:" || url.username || url.password || host !== pk.rpId.toLowerCase() || host !== hostOf(server)) return null;
  url.hash = "";
  const state = newState();
  const fragment = new URLSearchParams({ v: "1", options: jsonToB64url(options), return: ret, state });
  return { url: `${url.href}#${fragment}`, state };
}

// ------------------------------------------------------------------------------------------------ the page's side

export interface KeyPageRequest {
  /** The request options rebuilt from an allowlist (what `getCredential` takes: `{publicKey}`). */
  options: { publicKey: Json };
  ret: ReturnKind;
  state: string;
}

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

/**
 * The request options the page passes to the browser, rebuilt from an allowlist: `challenge`, `rpId` (must be this
 * page's host), `allowCredentials` (non-empty `{type: "public-key", id, transports?}`), `timeout`, `userVerification`.
 * Everything else (`extensions`, …) is dropped; null when something required is missing or malformed.
 */
export function allowedRequest(raw: Json, pageHost: string): Json | null {
  if (typeof raw.challenge !== "string" || !b64urlToBytes(raw.challenge)?.length) return null;
  if (typeof raw.rpId !== "string" || raw.rpId.toLowerCase() !== pageHost.toLowerCase()) return null;
  const list = raw.allowCredentials;
  if (!Array.isArray(list) || list.length === 0 || list.length > 64) return null;
  const allowCredentials: Json[] = [];
  for (const d of list) {
    if (!d || typeof d !== "object" || Array.isArray(d)) return null;
    const { type, id, transports } = d as Json;
    if (type !== "public-key" || typeof id !== "string" || !B64URL_RE.test(id) || !b64urlToBytes(id)) return null;
    const entry: Json = { type, id };
    if (transports !== undefined) {
      if (!Array.isArray(transports) || !transports.every((t) => typeof t === "string" && /^[a-z-]{1,32}$/.test(t))) return null;
      entry.transports = [...transports];
    }
    allowCredentials.push(entry);
  }
  const out: Json = { challenge: raw.challenge, rpId: raw.rpId, allowCredentials };
  if (raw.timeout !== undefined) {
    if (typeof raw.timeout !== "number" || !Number.isFinite(raw.timeout) || raw.timeout <= 0) return null;
    out.timeout = Math.min(Math.floor(raw.timeout), 600_000);
  }
  if (raw.userVerification !== undefined) {
    if (!["required", "preferred", "discouraged"].includes(raw.userVerification as string)) return null;
    out.userVerification = raw.userVerification;
  }
  return out;
}

/** Each key exactly once; null when one is missing, repeated or empty. */
function single(params: URLSearchParams, key: string): string | null {
  const all = params.getAll(key);
  return all.length === 1 && all[0] ? all[0] : null;
}

function fragmentParams(hash: string): URLSearchParams | null {
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  if (!raw || raw.length > MAX_FRAGMENT) return null;
  return new URLSearchParams(raw);
}

/**
 * The key page's fragment; null when it is missing, damaged, of another version, names a return off the list, has no
 * valid `state`, or its options don't pass `allowedRequest` for this page's host.
 */
export function parseKeyPageFragment(hash: string, pageHost: string): KeyPageRequest | null {
  const params = fragmentParams(hash);
  if (!params || single(params, "v") !== "1") return null;
  const ret = single(params, "return");
  if (!ret || !(RETURN_KINDS as readonly string[]).includes(ret)) return null;
  const state = single(params, "state");
  if (!validState(state)) return null;
  const encoded = single(params, "options");
  const options = encoded ? b64urlToJson(encoded) : null;
  const raw = options ? publicKeyOf(options) : null;
  const publicKey = raw ? allowedRequest(raw, pageHost) : null;
  if (!publicKey) return null;
  return { options: { publicKey }, ret: ret as ReturnKind, state };
}

export type KeyPageResult = { credential: Json } | { cancelled: true };
export type ReturnedResult = KeyPageResult & { state: string };

/**
 * Where the page sends the result: `passauth://two-step-key#…` or this origin's done page. `origin` is the page's own
 * (`location.origin`); nothing from the fragment is used.
 */
export function returnTarget(ret: ReturnKind, origin: string, state: string, result: KeyPageResult): string {
  const fragment = `v=1&state=${state}&` + ("credential" in result ? `credential=${jsonToB64url(result.credential)}` : "error=cancelled");
  const base = ret === "app" ? APP_RETURN : `${origin}${KEY_DONE_PATH}`;
  return `${base}#${fragment}`;
}

// ------------------------------------------------------------------------------------------------ the app's side

/** The result in a return address's fragment (`v=1&state=…&credential=…` or `…&error=cancelled`); null for anything else. */
export function parseReturnFragment(hash: string): ReturnedResult | null {
  const params = fragmentParams(hash);
  if (!params || single(params, "v") !== "1") return null;
  const state = single(params, "state");
  if (!validState(state)) return null;
  const hasCredential = params.has("credential");
  const hasError = params.has("error");
  if (hasCredential === hasError) return null;
  if (hasError) return single(params, "error") === "cancelled" ? { cancelled: true, state } : null;
  const encoded = single(params, "credential");
  const credential = encoded ? b64urlToJson(encoded) : null;
  return credential ? { credential, state } : null;
}

/** The challenge the authenticator signed (from the assertion's `clientDataJSON`), decoded; null when unreadable. */
export function signedChallenge(credential: Json): Uint8Array | null {
  const response = credential.response;
  if (!response || typeof response !== "object") return null;
  const clientData = (response as Json).clientDataJSON;
  if (typeof clientData !== "string") return null;
  const data = b64urlToJson(clientData);
  return data && data.type === "webauthn.get" && typeof data.challenge === "string" ? b64urlToBytes(data.challenge) : null;
}

const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * One hand-off at a time: `expect(options)` starts waiting for the result of these options; `deliver(url)` is fed every
 * `passauth://two-step-key…` (or done-page) address the app sees. A result counts only while waiting, only once, only
 * with the `state` the app opened, and a credential only when it signed this start's challenge; anything else is
 * ignored and the wait goes on. `cancel()` ends the wait (null).
 */
export class KeyPageWaiter {
  private waiting: { challenge: Uint8Array; state: string; resolve: (r: Json | null) => void } | null = null;

  get isWaiting() {
    return this.waiting !== null;
  }

  /** Resolves with the credential to send to `/finish`, or null when the user cancelled (there or in the app). */
  expect(options: unknown, state: string): Promise<Json | null> {
    const challenge = challengeOf(options);
    if (!challenge || !validState(state)) return Promise.reject(new Error(KEY_PAGE_MISMATCH));
    this.cancel();
    return new Promise((resolve) => {
      this.waiting = { challenge, state, resolve };
    });
  }

  /** Handles one returned address (`base` = where results arrive). Returns true when it ended the wait. */
  deliver(url: string, base = APP_RETURN): boolean {
    const w = this.waiting;
    if (!w) return false;
    const hashAt = url.indexOf("#");
    if (hashAt < 0 || url.slice(0, hashAt).replace(/\/+$/, "").toLowerCase() !== base.toLowerCase()) return false;
    const result = parseReturnFragment(url.slice(hashAt));
    if (!result || result.state !== w.state) return false;
    if ("credential" in result) {
      const signed = signedChallenge(result.credential);
      if (!signed || !sameBytes(signed, w.challenge)) return false;
    }
    this.waiting = null;
    w.resolve("credential" in result ? result.credential : null);
    return true;
  }

  cancel() {
    const w = this.waiting;
    this.waiting = null;
    w?.resolve(null);
  }
}

/** The app's one waiter (desktop: fed by the deep-link listener). */
export const keyPageWaiter = new KeyPageWaiter();

// ------------------------------------------------------------------------------------------------ sign-in context

/** What the server knows about the sign-in waiting for this challenge (`GET /auth/2fa/passkey/context`). */
export interface KeyPageContext {
  client: string | null;
  deviceName: string | null;
  ip: string | null;
  startedAt: number;
}

export const CONTEXT_ENDED = "This sign-in has ended or wasn't started from PassAuth. Go back to the app and try again.";
export const CONTEXT_WARNING = "If you didn't just start signing in to PassAuth, press Cancel and change your master password.";

const CLIENT_NAMES: Record<string, string> = {
  android: "PassAuth for Android",
  ios: "PassAuth for iPhone",
  extension: "PassAuth extension",
  desktop: "PassAuth desktop app",
  web: "web vault",
  "macos-autofill": "PassAuth AutoFill on Mac",
};

const shortText = (v: unknown, max: number) =>
  typeof v === "string" && v.trim() ? v.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, "").trim().slice(0, max) || null : null;

/** The context answer, checked; null when it isn't one. */
export function readContext(value: unknown): KeyPageContext | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const v = value as Json;
  if (typeof v.started_at !== "number" || !Number.isFinite(v.started_at)) return null;
  return { client: shortText(v.client, 32), deviceName: shortText(v.device_name, 80), ip: shortText(v.ip, 64), startedAt: v.started_at };
}

function ago(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return s <= 1 ? "1 second" : `${s} seconds`;
  const m = Math.round(s / 60);
  if (m < 60) return m === 1 ? "1 minute" : `${m} minutes`;
  const h = Math.round(m / 60);
  return h === 1 ? "1 hour" : `${h} hours`;
}

/** "Signing in on <device or app> from <ip>, <time> ago." (plain text). */
export function contextLine(ctx: KeyPageContext, nowSeconds: number): string {
  const who = ctx.deviceName ?? (ctx.client ? (CLIENT_NAMES[ctx.client] ?? "an unknown app") : "an unknown app");
  const where = ctx.ip ? ` from ${ctx.ip}` : "";
  return `Signing in on ${who}${where}, ${ago(nowSeconds - ctx.startedAt)} ago.`;
}

/** Ask the page's own server about the sign-in waiting for `challenge`; null when it has ended or can't be read. */
export async function fetchContext(challenge: string, fetchFn: typeof fetch = fetch): Promise<KeyPageContext | null> {
  try {
    const r = await fetchFn(`/api/auth/2fa/passkey/context?challenge=${encodeURIComponent(challenge)}`, {
      credentials: "omit",
      cache: "no-store",
      headers: { accept: "application/json" },
    });
    if (!r.ok) return null;
    return readContext(await r.json());
  } catch {
    return null;
  }
}
