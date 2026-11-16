/**
 * Approve a sign-in from another device (servers with the `login_with_device` feature; the server's side is
 * crates/server/src/auth_requests.rs, the keys are crates/core/src/device_login.rs).
 *
 * New device: it makes a key for one request (core `LoginRequestKey`, memory only), sends the key's public half and a
 * random access code it keeps (`POST /auth/requests`), shows the five words of its own key (`phrase()`) and polls
 * `GET /auth/requests/{id}` with the code in `X-PassAuth-Access-Code` until the request is denied, expires, or is
 * approved: for a session that carries the account key sealed to the request's key, or for two-step login first (the
 * sealed key then comes with the session from the two-step answer). `runDeviceLogin` is that state machine.
 *
 * Approving app (signed in and unlocked): it lists the account's requests (`GET /account/auth-requests`) and asks which
 * words the new device shows, offering the request key's own words among decoys (`loginPhraseChoices`, worked out
 * here). The words picked go to the core (`Account.approveLoginRequest`), which seals the account key to that key only
 * when they are the key's own (else the request is denied); the request's challenge, opened, comes along as proof
 * (`POST /account/auth-requests/{id}`). The core also gives a 6-digit code, shown until the user is done.
 *
 * New device, after the approval: the sealed key opens (`LoginRequestKey.open`) but stays unusable until the user types
 * the approving app's code (`ApprovedLogin.confirm`; 3 wrong codes end the sign-in): a server can't make that code, so it
 * can't hand this device an account key of its own choosing.
 *
 * Neither side ever shows the server's `fingerprint_phrase`: a server that swapped the public key would pass a
 * comparison of words it chose itself. The readers below leave that field out, so nothing can show it by mistake.
 *
 * The approval sheet shows one request at a time, frozen as it was when the sheet opened (`settleQueue`): the words and
 * the approval always use that copy (its challenge too: the server seals it again for every listing, so its text changes
 * while what it opens to doesn't). A listing that gives the shown request another public key, or drops it, closes
 * the sheet instead of updating it, and a newer request waits until the shown one is answered or put off. What the new
 * device says about itself (its name, its app) is shown as its own claim, cleaned and shortened (`claimedText`).
 *
 * Pure (no WASM, no network, no React): the core and the server come in as arguments. Unit-tested in
 * `device-login.test.ts`; `device-login-client.ts` wires it to the app.
 */
import { oneLine } from "./text";
import { isBundle, type Bundle } from "./types";

/** The server feature (GET /api/config `features`). */
export const DEVICE_LOGIN_FEATURE = "login_with_device";
/** Header that carries the access code when polling; never in the URL (proxies log query strings). */
export const ACCESS_CODE_HEADER = "x-passauth-access-code";
/** How long the server keeps a request open (15 minutes); the countdown never shows more. */
export const REQUEST_TTL_MS = 15 * 60_000;
/** Polling goes on this long past the request's lifetime when the server can't say it expired (unreachable). */
const GIVE_UP_GRACE_MS = 60_000;
/** Random bytes in an access code: 256 bits, 43 base64url characters (the server wants 22 to 128). */
export const ACCESS_CODE_BYTES = 32;
export const UNEXPECTED_ANSWER = "The server sent an unexpected response. Try again.";

const str = (v: unknown): string | null => (typeof v === "string" && v ? v : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

// ------------------------------------------------------------ new device

/** The key a request is made with: core `LoginRequestKey` (its private half never leaves the core). */
export interface RequestKey {
  publicKey(): string;
  /** The words this device shows, from its own key. */
  phrase(): string;
  free(): void;
}

/** `POST /auth/requests`. */
export interface NewRequestBody {
  email: string;
  public_key: string;
  access_code: string;
  device_id: string;
  device_name: string;
  device_kind: string;
  /** This device's "remember this device" token for the account, if it has one: it skips two-step login. */
  remember_token?: string;
}

/** An approved request exchanged for a session: a password sign-in's session answer plus the sealed account key. */
export interface DeviceSession {
  user_id: string;
  email: string;
  access_token: string;
  refresh_token: string;
  bundle: Bundle;
  remember_token?: string;
  /** The account key (and maybe the Secret Key) sealed to this request's key. */
  sealed_key: string;
}

/** What a poll says about the request. */
export type PollAnswer =
  | { status: "pending" | "denied" | "expired" | "used" }
  | { status: "session"; session: DeviceSession }
  | { status: "two-step"; token: string; providers: string[] };

/** One poll as the app's server client reports it: an answer, the request gone (404), or worth asking again later. */
export type PollOutcome = { kind: "answer"; body: unknown } | { kind: "gone" } | { kind: "retry"; afterMs?: number };

/** An approved request, handed to the app to finish the sign-in. */
export type Approval = { kind: "session"; session: DeviceSession } | { kind: "two-step"; token: string; providers: string[] };

/**
 * Where a sign-in request stands. `waiting.deadline` is when it expires by this device's clock (ms). The run ends in
 * `two-step` (the sign-in continues on the two-step screens), `done`, `denied`, `expired`, `used`, `cancelled` or
 * `failed`.
 */
export type DeviceLoginState =
  | { step: "asking" }
  | { step: "waiting"; id: string; phrase: string; deadline: number }
  | { step: "signing-in" }
  | { step: "two-step"; token: string; providers: string[] }
  /** The approval arrived: the sign-in waits for the code the approving app shows (`finish` answered "confirm"). */
  | { step: "confirm"; email: string }
  | { step: "done"; email: string }
  | { step: "denied" | "expired" | "used" | "cancelled" }
  | { step: "failed"; error: unknown };

const FINAL = new Set<DeviceLoginState["step"]>(["two-step", "confirm", "done", "denied", "expired", "used", "cancelled", "failed"]);
export const isFinal = (s: DeviceLoginState) => FINAL.has(s.step);

/** base64url without padding. */
export function base64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The secret the new device keeps to poll its request: random bytes in base64url (at least 128 bits). */
export function accessCode(random: Uint8Array): string {
  if (random.length < 16) throw new Error("an access code needs at least 128 random bits");
  return base64url(random);
}

/** `{id, expires_at}` of a new request. The server's `fingerprint_phrase` is left out on purpose (see the top). */
export function readCreated(body: unknown): { id: string; expiresAt: number } | null {
  if (!body || typeof body !== "object") return null;
  const b = body as Record<string, unknown>;
  const id = str(b.id);
  const expiresAt = num(b.expires_at);
  return id && expiresAt !== null ? { id, expiresAt } : null;
}

function readSession(b: Record<string, unknown>): DeviceSession | null {
  const [user_id, email, access_token, refresh_token, sealed_key] = [b.user_id, b.email, b.access_token, b.refresh_token, b.sealed_key].map(str);
  const bundle = isBundle(b.bundle) ? b.bundle : null;
  if (!user_id || !email || !access_token || !refresh_token || !sealed_key || !bundle) return null;
  const remember = str(b.remember_token);
  return { user_id, email, access_token, refresh_token, bundle, sealed_key, ...(remember ? { remember_token: remember } : {}) };
}

/** A `GET /auth/requests/{id}` answer; null when it isn't one. */
export function readPollAnswer(body: unknown): PollAnswer | null {
  if (!body || typeof body !== "object") return null;
  const b = body as Record<string, unknown>;
  switch (b.status) {
    case "pending":
    case "denied":
    case "expired":
    case "used":
      return { status: b.status };
    case "approved": {
      if (b.two_factor_required === true) {
        const token = str(b.two_factor_token);
        const providers = Array.isArray(b.providers) ? b.providers.filter((p): p is string => typeof p === "string") : [];
        return token ? { status: "two-step", token, providers } : null;
      }
      const session = readSession(b);
      return session ? { status: "session", session } : null;
    }
  }
  return null;
}

/**
 * When the request expires by this device's clock: the server's `expires_at`, unless this device's clock disagrees by
 * more than a request lasts (it is then taken as the full 15 minutes from now). Only the countdown uses it; the
 * server says when the request has expired.
 */
export function requestDeadline(expiresAtSec: number, nowMs: number): number {
  const left = expiresAtSec * 1000 - nowMs;
  return nowMs + (left > 0 && left <= REQUEST_TTL_MS ? left : REQUEST_TTL_MS);
}

/**
 * Wait before the next poll: every 3 s for the first 2 minutes, every 5 s until 5 minutes, then every 10 s. After a
 * poll that failed (no connection, a server error, too many requests) the wait doubles from 6 s up to 30 s, and is at
 * least the server's Retry-After (up to a minute).
 */
export function pollDelay(elapsedMs: number, failures: number, retryAfterMs?: number): number {
  const steady = elapsedMs < 2 * 60_000 ? 3000 : elapsedMs < 5 * 60_000 ? 5000 : 10_000;
  if (failures <= 0) return steady;
  const backoff = Math.min(30_000, 3000 * 2 ** Math.min(failures, 10));
  return Math.max(steady, backoff, Math.min(retryAfterMs ?? 0, 60_000));
}

/** "4:05": what is left of a request, rounded up to the second. */
export function countdown(ms: number): string {
  const s = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

/** Resolves after `ms`, or as soon as `signal` aborts (never rejects). */
export function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const done = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal.addEventListener("abort", done, { once: true });
  });
}

export interface DeviceLoginDeps<K extends RequestKey> {
  /** A fresh key for this request (core `LoginRequestKey.generate()`). */
  newKey(): K;
  /** Cryptographically random bytes (`crypto.getRandomValues`). */
  randomBytes(length: number): Uint8Array;
  device: { id: string; name: string; kind: string };
  rememberToken?: string | null;
  /** `POST /auth/requests`; throws when the server refuses it. */
  create(body: NewRequestBody): Promise<unknown>;
  /** `GET /auth/requests/{id}` with the access code; throws for answers not worth asking again. */
  poll(id: string, accessCode: string): Promise<PollOutcome>;
  /**
   * Finish an approved request. Takes over `key` (and frees it): opens the sealed key and signs in (`session`), or
   * keeps the key for the two-step answer (`two-step`). "confirm": the sealed key opened but waits for the approving
   * app's code, so the run ends in `confirm` instead of `done`.
   */
  finish(approval: Approval, key: K, requestId: string): Promise<void | "confirm">;
  /** A session that arrived after the run was cancelled: sign it out again (best effort), so it doesn't stay behind. */
  discard(session: DeviceSession): void;
  now(): number;
  /** As `sleep` above; tests pass a fake clock. */
  sleep(ms: number, signal: AbortSignal): Promise<void>;
}

export interface DeviceLoginRun {
  /** Stop asking and drop the key. Leaving the page must call it. */
  cancel(): void;
  /** Poll now instead of at the next turn (e.g. when the page is shown again). */
  pollNow(): void;
  /** The state the run ended in. */
  readonly done: Promise<DeviceLoginState>;
}

/**
 * Ask to sign in to `email` with another device's approval, and wait for the answer. The run starts in `asking` (not
 * reported); `onChange` gets every later state, never before this function has returned. The words shown while
 * waiting are always the request key's own (`key.phrase()`), never the server's. The key lives only in this run (and,
 * once approved, in `finish`); every end frees it.
 */
export function runDeviceLogin<K extends RequestKey>(email: string, deps: DeviceLoginDeps<K>, onChange: (state: DeviceLoginState) => void): DeviceLoginRun {
  const stop = new AbortController();
  let nap: AbortController | null = null;
  let key: K | null = null;
  let last: DeviceLoginState = { step: "asking" };
  const stopped = () => stop.signal.aborted;
  const show = (s: DeviceLoginState): DeviceLoginState => {
    last = s;
    onChange(s);
    return s;
  };
  const release = () => {
    const k = key;
    key = null;
    k?.free();
  };
  /** The key, now owned by the caller. */
  const handOver = (): K => {
    const k = key;
    key = null;
    if (!k) throw new Error("Sign-in expired, start again.");
    return k;
  };

  async function rest(ms: number) {
    const wake = new AbortController();
    nap = wake;
    const onStop = () => wake.abort();
    stop.signal.addEventListener("abort", onStop, { once: true });
    try {
      await deps.sleep(ms, wake.signal);
    } finally {
      stop.signal.removeEventListener("abort", onStop);
      if (nap === wake) nap = null;
    }
  }

  async function run(): Promise<DeviceLoginState> {
    // Nothing is reported before the first await: the caller may not hold the run yet.
    key = deps.newKey();
    const code = accessCode(deps.randomBytes(ACCESS_CODE_BYTES));
    const body: NewRequestBody = {
      email,
      public_key: key.publicKey(),
      access_code: code,
      device_id: deps.device.id,
      device_name: deps.device.name,
      device_kind: deps.device.kind,
      ...(deps.rememberToken ? { remember_token: deps.rememberToken } : {}),
    };
    const created = readCreated(await deps.create(body));
    if (stopped()) return last;
    if (!created || !key) throw new Error(UNEXPECTED_ANSWER);
    const startedAt = deps.now();
    const giveUpAt = startedAt + REQUEST_TTL_MS + GIVE_UP_GRACE_MS;
    show({ step: "waiting", id: created.id, phrase: key.phrase(), deadline: requestDeadline(created.expiresAt, startedAt) });
    let failures = 0;
    let retryAfter: number | undefined;
    for (;;) {
      await rest(pollDelay(deps.now() - startedAt, failures, retryAfter));
      if (stopped()) return last;
      if (deps.now() >= giveUpAt) {
        release();
        return show({ step: "expired" });
      }
      const outcome = await deps.poll(created.id, code);
      const answer = outcome.kind === "answer" ? readPollAnswer(outcome.body) : null;
      if (stopped()) {
        // Answered just as it was cancelled: nobody will use that session.
        if (answer?.status === "session") deps.discard(answer.session);
        return last;
      }
      if (outcome.kind === "gone") {
        release();
        return show({ step: "expired" });
      }
      if (outcome.kind === "retry") {
        failures++;
        retryAfter = outcome.afterMs;
        continue;
      }
      if (!answer) throw new Error(UNEXPECTED_ANSWER);
      failures = 0;
      retryAfter = undefined;
      switch (answer.status) {
        case "pending":
          continue;
        case "denied":
        case "expired":
        case "used":
          release();
          return show({ step: answer.status });
        case "session": {
          show({ step: "signing-in" });
          const next = await deps.finish({ kind: "session", session: answer.session }, handOver(), created.id);
          if (stopped()) return last;
          return show(next === "confirm" ? { step: "confirm", email: answer.session.email } : { step: "done", email: answer.session.email });
        }
        case "two-step":
          await deps.finish({ kind: "two-step", token: answer.token, providers: answer.providers }, handOver(), created.id);
          return stopped() ? last : show({ step: "two-step", token: answer.token, providers: answer.providers });
      }
    }
  }

  const done = run().catch((error: unknown) => {
    release();
    return stopped() ? last : show({ step: "failed", error });
  });

  return {
    cancel() {
      if (stopped()) return;
      stop.abort();
      release();
      if (!isFinal(last)) show({ step: "cancelled" });
    },
    pollNow() {
      nap?.abort();
    },
    done,
  };
}

// ------------------------------------------------------- approving apps

/** A sign-in request waiting for the account's answer (`GET /account/auth-requests`). */
export interface SignInRequest {
  id: string;
  /** The new device's key for this request (base64url): the words come from it, worked out on this device. */
  publicKey: string;
  /**
   * Sealed by the server to the account's key; opened, it proves the approval comes from an unlocked app. Sealed again
   * for every listing: its text changes while what it opens to doesn't, so it is never compared.
   */
  challenge: string;
  deviceName: string;
  deviceKind: string;
  /** The new device's app (`X-PassAuth-Client`), when it said. */
  client: string | null;
  /** Its address, when the server keeps addresses. */
  ip: string | null;
  /** Unix seconds (the server's clock). */
  createdAt: number;
  expiresAt: number;
}

/** Longest device name, app or address shown for a request, in characters. */
export const CLAIM_MAX = 64;

/**
 * What a requesting device says about itself (its name, its app, as it sent them), made safe to show: one line without
 * control or format characters (no bidi overrides, no zero-width marks), at most `CLAIM_MAX` characters. "" for
 * anything but a string.
 */
export const claimedText = (v: unknown): string => oneLine(v, CLAIM_MAX);

function readSignInRequest(v: unknown): SignInRequest | null {
  if (!v || typeof v !== "object") return null;
  const r = v as Record<string, unknown>;
  const id = str(r.id);
  const publicKey = str(r.public_key);
  const challenge = str(r.challenge);
  const createdAt = num(r.created_at);
  const expiresAt = num(r.expires_at);
  if (!id || !publicKey || !challenge || createdAt === null || expiresAt === null) return null;
  // The server's `fingerprint_phrase` is not read: the words shown are always worked out here (see the top).
  return {
    id,
    publicKey,
    challenge,
    deviceName: claimedText(r.device_name),
    deviceKind: claimedText(r.device_kind) || "web",
    client: claimedText(r.client) || null,
    ip: claimedText(r.ip) || null,
    createdAt,
    expiresAt,
  };
}

/** The requests of a `GET /account/auth-requests` answer, newest first as the server sends them; malformed ones are left out. */
export function readSignInRequests(body: unknown): SignInRequest[] {
  const list = body && typeof body === "object" ? (body as { requests?: unknown }).requests : null;
  return Array.isArray(list) ? list.map(readSignInRequest).filter((r): r is SignInRequest => r !== null) : [];
}

/** The words to compare, from the request's own public key (core `loginPhrase`); null when the key can't be read. */
export function requestPhrase(req: Pick<SignInRequest, "publicKey">, loginPhrase: (publicKey: string) => string): string | null {
  try {
    const phrase = loginPhrase(req.publicKey).trim();
    return phrase || null;
  } catch {
    return null;
  }
}

/** The words of a phrase, for showing them one by one. */
export const phraseWords = (phrase: string): string[] => phrase.split(/\s+/).filter(Boolean);

/** How many sets of words the approval sheet offers: the request key's own among decoys. */
export const PHRASE_CHOICES = 3;

/**
 * The words to choose from for `req`, worked out here from its own key (core `loginPhraseChoices`: its words among
 * decoys, in random order); none when its key can't be read (the request can then only be denied).
 */
export function phraseChoices(req: Pick<SignInRequest, "publicKey">, loginPhraseChoices: (publicKey: string, count: number) => string[]): string[] {
  try {
    const list = loginPhraseChoices(req.publicKey, PHRASE_CHOICES);
    return Array.isArray(list) && list.length > 1 && list.every((c) => typeof c === "string" && c.trim() !== "") ? list : [];
  } catch {
    return [];
  }
}

/** The core's answer when the words picked aren't the request key's own (`Account.approveLoginRequest`). */
export const PHRASE_MISMATCH = "phrase_mismatch";
export const isPhraseMismatch = (e: unknown): boolean => e instanceof Error && e.message === PHRASE_MISMATCH;

/** What approving needs of the unlocked account (core `Account`). */
export interface ApprovingAccount {
  approveLoginRequest(requesterPublicKey: string, requestId: string, chosenPhrase: string, secretKey?: string | null): { sealed: string; code: string };
  openLoginChallenge(challenge: string, requestId: string): string;
}

export type AnswerBody = { approve: true; sealed_key: string; proof: string } | { approve: false };
export const DENY_BODY: AnswerBody = { approve: false };

/**
 * Approve `req` for the words the user picked (`chosen`). The core refuses with `PHRASE_MISMATCH` unless they are the
 * request key's own; otherwise the body carries the account key sealed to that key, with the Secret Key when this app
 * knows it (so the new device can unlock with the master password later), and the challenge opened as proof, and
 * `code` is the 6-digit code to show for the new device. A saved Secret Key the core can't read is left out rather
 * than failing the approval: the new device then asks for it at its first unlock with the master password.
 */
export function approval(
  account: ApprovingAccount,
  req: Pick<SignInRequest, "id" | "publicKey" | "challenge">,
  chosen: string,
  secretKey: string | null,
): { body: AnswerBody; code: string } {
  let answer: { sealed: string; code: string };
  try {
    answer = account.approveLoginRequest(req.publicKey, req.id, chosen, secretKey || undefined);
  } catch (e) {
    if (isPhraseMismatch(e) || !secretKey) throw e;
    answer = account.approveLoginRequest(req.publicKey, req.id, chosen, undefined);
  }
  if (typeof answer?.sealed !== "string" || !/^\d{6}$/.test(answer.code ?? "")) throw new Error("unexpected approval");
  return { body: { approve: true, sealed_key: answer.sealed, proof: account.openLoginChallenge(req.challenge, req.id) }, code: answer.code };
}

/** "123 456": a 6-digit code in two groups, to read and type. */
export const groupedCode = (code: string): string => (code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code);

/** Shown when the words picked aren't the request's: it was denied. */
export const WORDS_MISMATCH = "Those aren't the words for this request, so it was denied.";

// ------------------------------------------------- new device: the code

/** What confirming needs of the opened approval (core `ApprovedLogin`). */
export interface ConfirmableApproval {
  confirm(code: string): void;
  readonly attemptsLeft: number;
}

/** The core's answers to a code (`ApprovedLogin.confirm`). */
export const WRONG_CODE = "wrong_code";
export const TOO_MANY_WRONG_CODES = "too_many_wrong_codes";

/** Shown when the third wrong code ended the sign-in. */
export const CODE_STOPPED =
  "Too many wrong codes, so this sign-in was stopped. If you didn't approve it on your other device, change your master password.";
/** Shown for anything but 6 digits (not counted as a try). */
export const CODE_FORMAT = "Enter the 6 digits your other device shows.";

/** The digits of a typed code (spaces and hyphens allowed between them); null unless there are exactly 6. */
export function codeDigits(typed: string): string | null {
  const digits = typed.replace(/[\s-]/g, "");
  return /^\d{6}$/.test(digits) ? digits : null;
}

export type CodeOutcome = { kind: "confirmed" } | { kind: "wrong"; attemptsLeft: number } | { kind: "stopped" };

/**
 * Check `typed` against the approval (core `confirm`): confirmed, wrong (with the tries left), or stopped (the third
 * wrong code: the approval is refused for good). Throws `CODE_FORMAT` for anything but 6 digits, which isn't counted.
 */
export function checkCode(approval: ConfirmableApproval, typed: string): CodeOutcome {
  const digits = codeDigits(typed);
  if (!digits) throw new Error(CODE_FORMAT);
  try {
    approval.confirm(digits);
    return { kind: "confirmed" };
  } catch (e) {
    const code = e instanceof Error ? e.message : "";
    if (code === TOO_MANY_WRONG_CODES) return { kind: "stopped" };
    if (code === WRONG_CODE) return approval.attemptsLeft > 0 ? { kind: "wrong", attemptsLeft: approval.attemptsLeft } : { kind: "stopped" };
    throw e;
  }
}

/** "That code doesn't match. 2 tries left." */
export const wrongCodeText = (attemptsLeft: number): string =>
  `That code doesn't match. ${attemptsLeft === 1 ? "1 try left" : `${attemptsLeft} tries left`}.`;

/**
 * The Secret Key to keep from a confirmed approval, or null to keep nothing: only for the email the user typed on this
 * device (the session's must be the same), and never in place of a different Secret Key already kept for it.
 */
export function secretKeyToKeep(typedEmail: string, sessionEmail: string, received: string | null | undefined, kept: string | null): string | null {
  const same = typedEmail.trim().toLowerCase() === sessionEmail.trim().toLowerCase();
  if (!received || !same) return null;
  return kept && kept !== received ? null : received;
}

/** How an answer ended: given, or not needed any more (expired, answered elsewhere first, or gone). */
export type AnswerOutcome = "done" | "expired" | "answered" | "gone";

/** An error answer to `POST /account/auth-requests/{id}` that means the request is over; null for real errors. */
export function answerErrorOutcome(status: number, code: string): Exclude<AnswerOutcome, "done"> | null {
  if (status === 409) return "answered";
  if (status === 400 && code === "expired") return "expired";
  if (status === 404) return "gone";
  return null;
}

/**
 * The request the approval sheet shows: the one the user asked to review, else the newest one they haven't put off
 * ("Not now"); null when none.
 */
export function requestToShow(requests: readonly SignInRequest[], putOff: ReadonlySet<string>, preferred: string | null): SignInRequest | null {
  const wanted = preferred ? requests.find((r) => r.id === preferred && !putOff.has(r.id)) : undefined;
  return wanted ?? requests.find((r) => !putOff.has(r.id)) ?? null;
}

/** A copy of `req` as it is now, which later listings can't change. */
export const freezeRequest = (req: SignInRequest): SignInRequest => Object.freeze({ ...req });

/** Shown when the request on screen changed (another public key for its id) or left the list early. */
export const REQUEST_CHANGED = "This request changed, so it was closed. If you're signing in on a new device, start again there.";
/** Shown when the request on screen expired while it was shown. */
export const REQUEST_EXPIRED = "This sign-in request expired before it was answered.";

/**
 * What stays on screen after a request's sheet closed, until the user dismisses it (nothing else comes up meanwhile):
 * the request changed under the sheet, the words picked weren't its own (it was denied), or the code to enter on the
 * new device after approving it.
 */
export type ApprovalNotice = { kind: "changed" } | { kind: "mismatch" } | { kind: "code"; code: string };

/** What the approval sheet works from: the listed requests and the one request on screen. */
export interface ApprovalQueue {
  /** Waiting requests, newest first, as last listed. */
  requests: SignInRequest[];
  /** Requests put off with "Not now" (or closed because they changed): listed in Settings, not brought up again. */
  putOff: ReadonlySet<string>;
  /** The request the user chose to review in Settings. */
  preferred: string | null;
  /** The request on screen, exactly as it was when its sheet opened (`freezeRequest`); never updated in place. */
  shown: SignInRequest | null;
  /** A note that stays up until dismissed; nothing else comes up meanwhile. */
  notice: ApprovalNotice | null;
}

export const EMPTY_QUEUE: ApprovalQueue = { requests: [], putOff: new Set(), preferred: null, shown: null, notice: null };

/**
 * The queue after its list (or what was put off or preferred) changed. The shown request stays exactly as it was
 * while the list still has it with the same public key, whatever else changed (a newer request waits behind it). Its
 * challenge is never compared: the server seals it again for every listing (new ciphertext, same content), and the
 * frozen one is what the approval opens. It closes when the list has another public key for its id (the "changed"
 * note, and it is put off: it comes up again only when the user reviews it) or no longer has it: expired by this
 * device's clock, or else "changed" too, unless `quiet(id)` (this app answered it). Only when nothing is on screen and no
 * note is up does the next request come up: the one the user asked to review, else the newest one not put off.
 */
export function settleQueue(q: ApprovalQueue, nowSeconds: number, quiet: (id: string) => boolean = () => false): { queue: ApprovalQueue; ended: "expired" | null } {
  let { shown, putOff, notice } = q;
  let ended: "expired" | null = null;
  if (shown) {
    const id = shown.id;
    const listed = q.requests.find((r) => r.id === id);
    if (!listed) {
      if (!quiet(id)) {
        if (nowSeconds >= shown.expiresAt) ended = "expired";
        else notice = { kind: "changed" };
      }
      shown = null;
    } else if (listed.publicKey !== shown.publicKey) {
      notice = { kind: "changed" };
      putOff = new Set([...putOff, id]);
      shown = null;
    }
  }
  if (!shown && !notice) {
    const next = requestToShow(q.requests, putOff, q.preferred);
    shown = next ? freezeRequest(next) : null;
  }
  return { queue: { ...q, shown, putOff, notice }, ended };
}

/** "Chrome on macOS (Web), 203.0.113.7, 9:14 PM": who asks, from where and when. */
export function requestOrigin(req: Pick<SignInRequest, "deviceName" | "ip">, app: string | null, time: string): string {
  const name = req.deviceName || "Unknown device";
  return [app ? `${name} (${app})` : name, req.ip, time].filter(Boolean).join(", ");
}
