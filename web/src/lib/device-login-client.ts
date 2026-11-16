/**
 * Sign-ins approved from another device, wired to the app (the rules and the request's state machine are in
 * `device-login.ts`, unit-tested).
 *
 * New device: `startDeviceLogin` runs one request from the sign-in page; its key lives only in that run, and leaving
 * the page cancels it.
 *
 * Approving app: the account's waiting requests, kept while the vault is unlocked. They are listed when a live-sync
 * connection opens (each unlock, sign-in and reconnect), when the server announces one (`auth_request`), when the app
 * opens after unlocking and when Settings → Sessions is shown, and every minute while any is waiting; a request answered
 * by another app (`auth_request_answered`) is dropped at once. The approval sheet shows one request at a time, frozen
 * when it came up (`settleQueue` in device-login.ts decides what is on screen after every change).
 */
import { useSyncExternalStore } from "react";
import * as core from "../wasm/passauth_core";
import { ApiError, UnreachableError, api, deviceInfo, hasErrorCode, hasFeature, knownPublicConfig, loadPublicConfig } from "./api";
import {
  ACCESS_CODE_HEADER,
  DENY_BODY,
  DEVICE_LOGIN_FEATURE,
  EMPTY_QUEUE,
  answerErrorOutcome,
  approval,
  isPhraseMismatch,
  readSignInRequests,
  runDeviceLogin,
  settleQueue,
  sleep,
  type AnswerOutcome,
  type ApprovalNotice,
  type ApprovalQueue,
  type DeviceLoginRun,
  type DeviceLoginState,
  type PollOutcome,
  type SignInRequest,
} from "./device-login";
import { secretStore } from "./platform";
import {
  endSession,
  getAccount,
  getBundle,
  getState,
  holdDeviceSignIn,
  onLiveNotice,
  onVaultChange,
  openDeviceApproval,
  rememberKey,
  rememberedSecretKey,
} from "./vault";

// ------------------------------------------------------------ new device

/** `GET /auth/requests/{id}` with the access code, sorted into what the run does next. */
async function pollRequest(id: string, accessCode: string): Promise<PollOutcome> {
  try {
    return { kind: "answer", body: await api(`/auth/requests/${encodeURIComponent(id)}`, { auth: false, headers: { [ACCESS_CODE_HEADER]: accessCode } }) };
  } catch (e) {
    // Unknown id or code: the server deleted the request a day after it expired.
    if (e instanceof ApiError && e.status === 404) return { kind: "gone" };
    if (e instanceof UnreachableError) return { kind: "retry" };
    if (e instanceof ApiError && (e.status === 429 || e.status >= 500)) return { kind: "retry", afterMs: e.retryAfter === undefined ? undefined : e.retryAfter * 1000 };
    throw e;
  }
}

/**
 * Ask to sign in to `email` with the approval of a device where the account is signed in. `onChange` gets each state
 * (see `DeviceLoginState`); an approved request opens its sealed key and ends in `confirm`, where the page asks for
 * the approving app's code (`confirmDeviceLogin` then signs in and unlocks), or hands over to the two-step screens
 * (`verifyTwoFactor`, which then also asks for the code).
 */
export function startDeviceLogin(email: string, onChange: (state: DeviceLoginState) => void): DeviceLoginRun {
  const device = deviceInfo();
  const run = runDeviceLogin(
    email,
    {
      newKey: () => core.LoginRequestKey.generate(),
      randomBytes: (n) => crypto.getRandomValues(new Uint8Array(n)),
      device,
      rememberToken: secretStore.get(rememberKey(email)),
      create: (body) => api("/auth/requests", { body, auth: false }),
      poll: pollRequest,
      finish: async (answer, key, requestId) => {
        if (answer.kind === "two-step") return holdDeviceSignIn(key, requestId, email);
        // Opened, not usable yet: the approving app's code comes first.
        openDeviceApproval(key, requestId, answer.session, email);
        return "confirm";
      },
      discard: (session) => endSession(session.access_token),
      now: Date.now,
      sleep,
    },
    onChange,
  );
  // A hidden page's timers may be slowed down a lot: ask at once when it is shown again.
  if (typeof document !== "undefined") {
    const onVisible = () => {
      if (document.visibilityState === "visible") run.pollNow();
    };
    document.addEventListener("visibilitychange", onVisible);
    void run.done.finally(() => document.removeEventListener("visibilitychange", onVisible));
  }
  return run;
}

// ------------------------------------------------------- approving apps

/**
 * The account's waiting requests and the one on screen (`ApprovalQueue`): `requests` newest first, `putOff` the ones put
 * off with "Not now" (still listed in Settings → Sessions, not brought up again), `preferred` the one the user chose to
 * review in Settings, `shown` the request on screen, frozen as it was when its sheet opened, and `changed` while the
 * note that the shown request changed is up.
 */
export type SignInRequests = ApprovalQueue;

let store: ApprovalQueue = EMPTY_QUEUE;
const subs = new Set<() => void>();
/** Requests this app answered (its own answer's `auth_request_answered` isn't news, nor the request leaving the list). */
const answeredHere = new Set<string>();
const endedListeners = new Set<(why: "answered" | "expired") => void>();

function update(next: ApprovalQueue) {
  store = next;
  subs.forEach((fn) => fn());
  keepFresh();
}

/** `next` with the request on screen worked out again (`settleQueue`): it stays, closes, or the next one comes up. */
function apply(next: ApprovalQueue) {
  const { queue, ended } = settleQueue(next, Date.now() / 1000, (id) => answeredHere.has(id));
  update(queue);
  if (ended) endedListeners.forEach((fn) => fn(ended));
}

const subscribe = (fn: () => void) => {
  subs.add(fn);
  return () => {
    subs.delete(fn);
  };
};

/** The account's waiting sign-in requests and the one on screen (empty while locked or on servers without the feature). */
export function useSignInRequests(): SignInRequests {
  return useSyncExternalStore(subscribe, () => store);
}

/**
 * Called when the request on screen ended without this app's answer: answered by another app or window, or expired
 * (the sheet then closes with a note). A request that changed under the sheet sets `changed` instead.
 */
export function onShownRequestEnded(fn: (why: "answered" | "expired") => void) {
  endedListeners.add(fn);
  return () => {
    endedListeners.delete(fn);
  };
}

/**
 * `id` gone from the list (answered here or elsewhere): its sheet closes, with `notice` if given (the code to enter, or
 * that the words didn't match), and otherwise the next request may come up.
 */
function remove(id: string, notice: ApprovalNotice | null = null) {
  if (!notice && !store.requests.some((r) => r.id === id) && store.shown?.id !== id) return;
  apply({
    ...store,
    requests: store.requests.filter((r) => r.id !== id),
    preferred: store.preferred === id ? null : store.preferred,
    shown: store.shown?.id === id ? null : store.shown,
    notice: notice ?? store.notice,
  });
}

/** Don't bring this request up again (it stays listed in Settings → Sessions until it is answered or expires). */
export function putOffSignInRequest(id: string) {
  apply({
    ...store,
    putOff: new Set([...store.putOff, id]),
    preferred: store.preferred === id ? null : store.preferred,
    shown: store.shown?.id === id ? null : store.shown,
  });
}

/** Bring a request up for review (Settings → Sessions); it waits while another one is on screen. */
export function reviewSignInRequest(id: string) {
  const putOff = new Set(store.putOff);
  putOff.delete(id);
  apply({ ...store, putOff, preferred: id });
}

/** The note on screen (changed, words that didn't match, the code to enter) was read: the next waiting request may come up. */
export function dismissApprovalNotice() {
  if (store.notice) apply({ ...store, notice: null });
}

let listing: Promise<void> | null = null;
let listAgain = false;

/**
 * List the account's waiting requests. One list at a time: a call made while one runs shares it, and with `fresh`
 * (the server just announced a request the running list may have missed) another list follows it.
 */
export function refreshSignInRequests(fresh = false): Promise<void> {
  if (listing) {
    if (fresh) listAgain = true;
    return listing;
  }
  listing = (async () => {
    do {
      listAgain = false;
      await listOnce();
    } while (listAgain);
  })().finally(() => {
    listing = null;
  });
  return listing;
}

async function listOnce() {
  const { status, userId } = getState();
  if (status !== "unlocked") return;
  if (!hasFeature((await loadPublicConfig()) ?? knownPublicConfig(), DEVICE_LOGIN_FEATURE)) return clearRequests();
  let body: unknown;
  try {
    body = await api("/account/auth-requests");
  } catch (e) {
    // Turned off on the admin page since this app learned the server's features.
    if (hasErrorCode(e, "login_with_device_disabled")) clearRequests();
    // Otherwise keep what is shown: the next connection, notice or minute lists again.
    return;
  }
  // Locked, or another account, while the list was on its way.
  if (getState().status !== "unlocked" || getState().userId !== userId) return;
  const requests = readSignInRequests(body);
  const ids = new Set(requests.map((r) => r.id));
  apply({
    ...store,
    requests,
    putOff: new Set([...store.putOff].filter((id) => ids.has(id))),
    preferred: store.preferred && ids.has(store.preferred) ? store.preferred : null,
  });
}

function clearRequests() {
  answeredHere.clear();
  if (store !== EMPTY_QUEUE) update(EMPTY_QUEUE);
}

/** While any request waits, list again every minute: expired ones go, without trusting this device's clock. */
let freshTimer: ReturnType<typeof setInterval> | null = null;
function keepFresh() {
  const want = store.requests.length > 0;
  if (want && !freshTimer) freshTimer = setInterval(() => void refreshSignInRequests(), 60_000);
  if (!want && freshTimer) {
    clearInterval(freshTimer);
    freshTimer = null;
  }
}

onLiveNotice((n) => {
  if (n.type === "connected") void refreshSignInRequests();
  else if (n.type === "auth_request") void refreshSignInRequests(true);
  else if (!answeredHere.has(n.id) && (store.requests.some((r) => r.id === n.id) || store.shown?.id === n.id)) {
    // Answered in another app or window: first tell the sheet that shows it, then drop it.
    const onScreen = store.shown?.id === n.id;
    remove(n.id);
    if (onScreen) endedListeners.forEach((fn) => fn("answered"));
  }
});

// Locking or signing out forgets the requests (they are listed again after unlocking).
onVaultChange(() => {
  if (getState().status !== "unlocked" && store !== EMPTY_QUEUE) clearRequests();
});

const LOCKED = "The vault is locked. Unlock it and try again.";
const CANT_APPROVE = "This request can't be approved from this app. Deny it, then start again on the new device.";

/** The request can't be approved here (its key or its frozen challenge doesn't work with this account): it was put off. */
export class CantApproveError extends Error {
  constructor() {
    super(CANT_APPROVE);
  }
}

/**
 * The Secret Key to send along with an approval, when the account uses one and this app has it saved (it was checked
 * at this app's last sign-in or unlock with the master password). The new device can then unlock with the master
 * password later; without it, it asks for the Secret Key at that first unlock.
 */
function secretKeyToShare(): string | null {
  return getBundle()?.secret_key_enabled ? rememberedSecretKey(getState().email) : null;
}

/** What answering a request came to: given, ended meanwhile, or denied because the words picked weren't its own. */
export type AnswerResult = AnswerOutcome | "mismatch";

/**
 * Answer `req` (the request as its sheet froze it): `chosen` = the words the user says the new device shows, or null
 * for "None of these" (deny). Approving goes through the core (`approval`): words that aren't the request key's own
 * deny the request instead ("mismatch", with a note on screen); otherwise the account key is sealed to the frozen key
 * with the challenge opened as proof, and the code to enter on the new device stays on screen until dismissed. Nothing
 * else is asked, the vault being unlocked. Resolves how it went, or how the request ended meanwhile (expired, answered
 * elsewhere first, gone); in every case it leaves the list.
 */
export async function answerSignInRequest(req: SignInRequest, chosen: string | null): Promise<AnswerResult> {
  let body = DENY_BODY;
  let code: string | null = null;
  let mismatch = false;
  if (chosen !== null) {
    const acct = getAccount();
    if (!acct || getState().status !== "unlocked") throw new Error(LOCKED);
    try {
      ({ body, code } = approval(acct, req, chosen, secretKeyToShare()));
    } catch (e) {
      // Not the request's words: deny it. A key the core refuses, or a (frozen) challenge that doesn't open with this
      // account's keys: nothing to approve with, so the request is put off (it stays listed in Settings → Sessions).
      if (!isPhraseMismatch(e)) {
        putOffSignInRequest(req.id);
        throw new CantApproveError();
      }
      mismatch = true;
    }
  }
  answeredHere.add(req.id);
  const notice: ApprovalNotice | null = mismatch ? { kind: "mismatch" } : code ? { kind: "code", code } : null;
  try {
    await api(`/account/auth-requests/${encodeURIComponent(req.id)}`, { body });
  } catch (e) {
    const ended = e instanceof ApiError ? answerErrorOutcome(e.status, e.code) : null;
    if (!ended) {
      // The words didn't match but the denial didn't get through: say so anyway, and keep it out of the way.
      if (mismatch) {
        apply({
          ...store,
          putOff: new Set([...store.putOff, req.id]),
          preferred: store.preferred === req.id ? null : store.preferred,
          shown: store.shown?.id === req.id ? null : store.shown,
          notice: { kind: "mismatch" },
        });
        return "mismatch";
      }
      throw e;
    }
    remove(req.id, mismatch ? { kind: "mismatch" } : null);
    return mismatch ? "mismatch" : ended;
  }
  remove(req.id, notice);
  return mismatch ? "mismatch" : "done";
}
