/**
 * Approve a sign-in from another device (servers with `login_with_device`; docs/ARCHITECTURE.md "Approve a sign-in
 * from another device"), the approving side. While the active account is unlocked the worker lists its waiting
 * requests (`GET /account/auth-requests`): at unlock and sign-in, at every live-sync (re)connect, when the socket says
 * one arrived (`auth_request`), when the popup opens (at most every 30 s) and when the first one should have expired.
 * The list is kept in session storage (`signInRequests:<account>`: memory only, gone with the keys; public keys, the
 * server's challenge, device, app, address and times — nothing secret), which the toolbar badge (a dot) and an open
 * popup follow. Nothing opens by itself: the popup shows the newest request in a sheet when the user opens it.
 *
 * The popup gets each request with the five words worked out here from the request's own public key (core
 * `loginPhrase`), never the server's `fingerprint_phrase`, which a server that swapped the key would choose, and with
 * that key and the server's challenge, which the popup freezes when its sheet opens. An approval names the frozen
 * key, challenge and the words the user picked: it is refused when the listing has another key for that id since
 * (`REQUEST_CHANGED`: a server swapping the key under the user's eyes), and the request is denied when the words
 * aren't the key's. The challenge's text is never compared — the server seals it to the account again, with a fresh
 * ephemeral key, at every listing (the same plaintext) — and the frozen one is what is opened as proof. It seals the
 * account key (and the Secret Key this browser keeps, if any) to the frozen key with the frozen challenge opened as
 * proof (vault.ts `approveSignIn`); "None of these" denies. A request answered elsewhere
 * (`auth_request_answered`), expired or gone leaves the list. Rules and readers are the web vault's
 * (`@web/lib/device-login`).
 */
import {
  answerErrorOutcome,
  REQUEST_CHANGED as CHANGED_TEXT,
  DENY_BODY,
  DEVICE_LOGIN_FEATURE,
  isPhraseMismatch,
  phraseChoices,
  readSignInRequests,
  requestPhrase,
  type SignInRequest,
} from "@web/lib/device-login";
import { AppError, EXPIRED, REQUEST_CHANGED } from "../shared/errors";
import { log, logged } from "../shared/log";
import { SIGN_IN_REQUESTS_PREFIX } from "../shared/storage-keys";
import type { SignInAnswer, SignInApproval, SignInRequestList } from "../shared/types";
import { loginPhrase, loginPhraseChoices } from "../wasm/passauth_core";
import { ApiError, api, serverInfo } from "./api";
import { initCore } from "./core";
import { activeId, local, scratch } from "./storage";
import * as vault from "./vault";

export { SIGN_IN_REQUESTS_PREFIX };

const key = (accountId: string) => `${SIGN_IN_REQUESTS_PREFIX}${accountId}`;

/** Without a reason to ask (a socket message, an unlock), the list is asked for at most this often. */
const RELIST_MS = 30_000;
const listedAt = new Map<string, number>();
const listing = new Map<string, Promise<void>>();
let expiryTimer: ReturnType<typeof setTimeout> | undefined;
/**
 * Requests answered lately, here or (said by the socket) elsewhere: a listing that was already on its way when the
 * answer came doesn't bring one back (found in a real browser: the dot stayed after "answered elsewhere").
 */
const answered = new Map<string, number>();
function noteAnswered(requestId: string) {
  const now = Date.now();
  for (const [id, at] of answered) if (now - at > 20 * 60_000 || now < at) answered.delete(id);
  answered.set(requestId, now);
}

const isRequest = (v: unknown): v is SignInRequest => {
  const r = v as Partial<SignInRequest> | null;
  return !!r && typeof r.id === "string" && typeof r.publicKey === "string" && typeof r.challenge === "string" && typeof r.expiresAt === "number";
};

/** The waiting requests kept for `accountId` (newest first, as the server lists them). */
export async function storedRequests(accountId: string): Promise<SignInRequest[]> {
  if (!accountId) return [];
  const v = await scratch.get<unknown>(key(accountId));
  return Array.isArray(v) ? v.filter(isRequest) : [];
}

async function store(accountId: string, list: SignInRequest[]) {
  if (list.length) await scratch.set(key(accountId), list);
  else await scratch.remove(key(accountId));
}

/** Whether a sign-in waits for the active account's answer (the toolbar badge shows a dot then). */
export async function signInWaiting(): Promise<boolean> {
  return (await storedRequests(await activeId())).length > 0;
}

/** The keys went (lock, sign-out, switch, a lost session): what was listed for those accounts goes too. */
export async function forgetSignInRequests(accountIds?: string[]) {
  const ids = accountIds ?? Object.keys((await local.get()).accounts);
  for (const id of ids) listedAt.delete(id);
  answered.clear();
  await scratch.remove(ids.map(key));
}

/** Ask the server again shortly after the first request should have expired, so its dot doesn't stay. */
function scheduleExpiry(list: SignInRequest[]) {
  clearTimeout(expiryTimer);
  expiryTimer = undefined;
  const first = Math.min(...list.map((r) => r.expiresAt * 1000));
  if (!Number.isFinite(first)) return;
  const wait = Math.min(Math.max(first - Date.now(), 0) + 5_000, 16 * 60_000);
  expiryTimer = setTimeout(() => void refreshSignInRequests(true).catch(logged("Listing sign-in requests")), wait);
}

/**
 * List the active account's waiting sign-in requests (`force`: now, else at most every RELIST_MS). Only while it is
 * unlocked and its server has `login_with_device`; otherwise anything kept for it goes. One listing per account at
 * a time; a failure leaves the list as it was.
 */
export function refreshSignInRequests(force = false): Promise<void> {
  return (async () => {
    const { id, data } = await local.account();
    if (!id) return;
    const running = listing.get(id);
    if (running !== undefined) return running;
    const p = list(id, data?.server ?? "", !!data?.tokens, force).finally(() => listing.delete(id));
    listing.set(id, p);
    return p;
  })();
}

async function list(id: string, server: string, signedIn: boolean, force: boolean) {
  if (!server || !signedIn || (await vault.lockStatus()) !== "unlocked") return forgetSignInRequests([id]);
  const now = Date.now();
  const last = listedAt.get(id) ?? 0;
  if (!force && now - last < RELIST_MS && now >= last) return;
  const info = await serverInfo(server);
  if (!info) return; // unreachable now: keep what was listed
  if (!info.features.has(DEVICE_LOGIN_FEATURE)) return forgetSignInRequests([id]);
  listedAt.set(id, now);
  let requests: SignInRequest[];
  try {
    requests = readSignInRequests(await api<unknown>("/account/auth-requests", { accountId: id })).filter((r) => !answered.has(r.id));
  } catch (e) {
    listedAt.delete(id);
    log.debug("Listing sign-in requests failed:", e);
    return;
  }
  // Locked, signed out or switched meanwhile: nothing is kept for an account that isn't open.
  if ((await activeId()) !== id || (await vault.lockStatus()) !== "unlocked") return;
  await store(id, requests);
  if ((await activeId()) === id) scheduleExpiry(requests);
}

/** The socket said a request was answered (here, by another app, or denied): it leaves the list at once. */
export async function signInAnswered(requestId: string) {
  noteAnswered(requestId);
  const id = await activeId();
  const list = await storedRequests(id);
  const rest = list.filter((r) => r.id !== requestId);
  if (rest.length !== list.length) await store(id, rest);
}

/**
 * What the popup shows of the active account's requests: device, app, address and times as the new device and the
 * server state them, the request's key and challenge (to freeze), and the words worked out here; with the ids
 * answered lately (here or on another device), so a sheet that loses its request can say why.
 */
export async function signInRequests(): Promise<SignInRequestList> {
  await initCore();
  const requests = (await storedRequests(await activeId())).map((r) => {
    // From the key this browser holds, never the server's `fingerprint_phrase`; null when the key can't be read.
    const phrase = requestPhrase(r, loginPhrase);
    return {
      id: r.id,
      publicKey: r.publicKey,
      challenge: r.challenge,
      phrase,
      // Its words among decoys (`PHRASE_CHOICES`), new ones in a new order at every listing: the popup keeps those of
      // the moment its sheet opened.
      choices: phrase ? phraseChoices(r, loginPhraseChoices) : [],
      deviceName: r.deviceName,
      deviceKind: r.deviceKind,
      client: r.client,
      ip: r.ip,
      createdAt: r.createdAt,
      expiresAt: r.expiresAt,
    };
  });
  return { requests, answered: [...answered.keys()] };
}

/** "This request changed": the popup closes its sheet and says so (the web vault's words). */
const changed = () => new AppError(REQUEST_CHANGED, CHANGED_TEXT);

/**
 * Answer a request of the active account (unlocked): approve or deny ("None of these"). An approval carries the request
 * as the popup froze it when its sheet opened (key, challenge) and the words the user picked:
 * - the listing has another key under that id since: refused, nothing is sent (`REQUEST_CHANGED`); a challenge with
 *   other text is no change (the server seals it again at every listing) and the frozen one is used;
 * - the words aren't the frozen key's (the core says `phrase_mismatch`): the request is denied (outcome "mismatch");
 * - otherwise the account key is sealed to the frozen key, with the challenge opened as proof, and the answer carries
 *   the 6-digit code the user enters on the new device (it unlocks nothing there without it).
 * A request that was answered elsewhere, expired or is gone isn't an error: the answer says so, and it leaves the list
 * in every case.
 */
export async function answerSignIn(requestId: string, approve: boolean, frozen?: SignInApproval): Promise<SignInAnswer> {
  await initCore();
  const id = await activeId();
  const req = (await storedRequests(id)).find((r) => r.id === requestId);
  if (!req) throw new AppError(EXPIRED, "This sign-in request isn't waiting any more.");
  let body: { approve: false } | vault.ApprovalBody = DENY_BODY as { approve: false };
  let code: string | undefined;
  let outcome: SignInAnswer["outcome"] = "done";
  if (approve) {
    // Only the request the user looked at: frozen when its sheet opened, and still the same key now (never the
    // challenge's text: it is sealed again at every listing; the frozen one opens to the same proof).
    if (!frozen || frozen.publicKey !== req.publicKey) throw changed();
    // An approval needs a request whose words this browser can show: one it can't read is only ever denied.
    if (!requestPhrase({ publicKey: frozen.publicKey }, loginPhrase)) {
      throw new AppError(EXPIRED, "This request can't be checked, so it can't be approved. Choose None of these, then start again on the new device.");
    }
    try {
      ({ body, code } = await vault.approveSignIn({ id: req.id, publicKey: frozen.publicKey, challenge: frozen.challenge }, frozen.phrase));
    } catch (e) {
      // The words picked aren't the request's: it is denied.
      if (!isPhraseMismatch(e)) throw e;
      outcome = "mismatch";
    }
  }
  try {
    await api(`/account/auth-requests/${encodeURIComponent(req.id)}`, { body, accountId: id });
  } catch (e) {
    const ended = e instanceof ApiError ? answerErrorOutcome(e.status, e.code) : null;
    if (!ended) throw e;
    // The words didn't match, and it ended meanwhile anyway: say what the user did.
    if (outcome !== "mismatch") outcome = ended;
  }
  noteAnswered(req.id);
  const rest = (await storedRequests(id)).filter((r) => r.id !== req.id);
  await store(id, rest);
  return outcome === "done" && code ? { outcome, code } : { outcome };
}
