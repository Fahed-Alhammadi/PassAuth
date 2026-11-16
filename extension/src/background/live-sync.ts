/**
 * Live sync in the service worker. While the active account is unlocked and its server has delta sync, a WebSocket to
 * the server's `/api/ws` says when something changed elsewhere; vault.ts then syncs only what the copy lacks
 * (`liveNotice`; the `hello` origin is kept but never a reason to skip a message). A `logout` message makes vault.ts
 * check the session; `auth_request` / `auth_request_answered` keep the sign-in requests waiting for an answer
 * current (sign-in-requests.ts), which are also listed at every (re)connect.
 *
 * Chrome (116 and later) keeps an extension's service worker running while a WebSocket in it exchanges messages, so
 * a small text frame goes out every 20 seconds (the server counts any frame as a sign of life and accepts at most
 * 4 KiB). The socket closes on lock, sign-out and account switch. A socket that drops is opened again after 1 s, 2 s,
 * 4 s … up to a minute (±20%), each time after a `GET /sync/revision` check, which refreshes an expired access token
 * and brings what was missed meanwhile. Where no socket can be kept (the worker was stopped, a proxy refuses it, the
 * server is down), an alarm every 5 minutes checks for changes and tries again while the account is unlocked.
 * Servers without delta sync keep the behaviour from before: no socket and no alarm.
 *
 * When the server requires two-step login of the account (its admin turned the policy on), it says
 * `{"type":"two_step_required"}` and closes the socket with 1008 `two_step_required`: then live sync stops for the
 * account (no reconnect, no alarm) and the popup shows the two-step notice, as after a 403 `two_step_required`
 * (policies.ts). It starts again when the vault opens or a sync gets through.
 */
import { logged } from "../shared/log";
import { noteTwoStepRequired } from "./policies";
import { refreshSignInRequests, signInAnswered } from "./sign-in-requests";
import { activeId, local } from "./storage";
import { backoffMs, closedFor, readLiveMessage, socketUrl } from "./sync-rules";
import * as vault from "./vault";

export const LIVE_ALARM = "liveSync";
/** Under Chrome's 30-second idle limit for service workers. */
export const KEEPALIVE_MS = 20_000;
const KEEPALIVE_TEXT = '{"type":"ping"}';
const OPEN = 1;
const CONNECTING = 0;

let socket: WebSocket | null = null;
/** The account the socket belongs to ("" without one). */
let socketAccount = "";
let keepalive: ReturnType<typeof setInterval> | undefined;
let retry: ReturnType<typeof setTimeout> | undefined;
let attempt = 0;
/** The session's live-sync origin, from the socket's `hello`. */
let origin: string | null = null;
/** Bumped by `stopLive`: a connection still on its way gives up. */
let epoch = 0;
let connecting: { epoch: number; p: Promise<void> } | null = null;

/** The session's live-sync origin while connected (kept, never used to skip a message). */
export const liveOrigin = () => origin;
/** The account whose socket is open or opening ("" for none). */
export const liveAccount = () => socketAccount;
export const liveConnected = () => socket?.readyState === OPEN;

/** Keep a socket for the active account while it is unlocked (cheap when one is open or on its way). */
export function ensureLive(): Promise<void> {
  if (connecting?.epoch === epoch) return connecting.p;
  const before = connecting?.p ?? Promise.resolve();
  const p: Promise<void> = before
    .catch(() => {})
    .then(connect)
    .finally(() => {
      if (connecting?.p === p) connecting = null;
    });
  connecting = { epoch, p };
  return p;
}

async function connect() {
  const run = epoch;
  const stale = () => run !== epoch;
  if ((await vault.lockStatus()) !== "unlocked") return stopLive();
  const { id, data } = await local.account();
  if (stale()) return;
  if (!id || !data?.server || !data.tokens) return stopLive();
  if (socket && socketAccount === id && (socket.readyState === OPEN || socket.readyState === CONNECTING)) return;
  const check = await vault.checkForChanges();
  if (stale()) return;
  // An older server, a session that ended, or two-step login still to be set up: no socket and no alarm.
  if (check === "unsupported" || check === "signed_out" || check === "two_step") return stopLive();
  scheduleAlarm();
  if (check === "offline") return scheduleRetry();
  // The tokens after the check (it may have refreshed them), for the account still active.
  const now = await local.account(id);
  if (stale() || (await activeId()) !== id || !now.data?.tokens) return;
  open(socketUrl(now.data.server, now.data.tokens.access), id);
}

function open(url: string, account: string) {
  closeSocket();
  let ws: WebSocket;
  try {
    ws = new WebSocket(url);
  } catch {
    scheduleRetry();
    return;
  }
  socket = ws;
  socketAccount = account;
  ws.onopen = () => {
    if (socket !== ws) return;
    attempt = 0;
    // Every (re)connect: sign-in requests that arrived while there was no socket are listed.
    void refreshSignInRequests(true).catch(logged("Listing sign-in requests"));
    clearInterval(keepalive);
    keepalive = setInterval(() => {
      if (socket === ws && ws.readyState === OPEN) ws.send(KEEPALIVE_TEXT);
    }, KEEPALIVE_MS);
  };
  ws.onmessage = (e: MessageEvent) => {
    if (socket !== ws) return;
    const msg = readLiveMessage(e.data);
    if (!msg) return;
    if (msg.type === "hello") origin = msg.origin;
    else if (msg.type === "two_step_required") twoStepRequired(account);
    else if (msg.type === "sync") void vault.liveNotice(msg).catch(logged("A live-sync update"));
    // A sign-in on another device asks for this account's approval, or one was answered (here or elsewhere).
    else if (msg.type === "auth_request") void refreshSignInRequests(true).catch(logged("Listing sign-in requests"));
    else if (msg.type === "auth_request_answered") void signInAnswered(msg.id).catch(logged("Dropping an answered sign-in request"));
    else void vault.checkSession().catch(logged("Checking the session"));
  };
  // An error is always followed by a close.
  ws.onclose = (e: CloseEvent) => {
    if (socket !== ws) return;
    if (closedFor(e.code, e.reason) === "two_step") return twoStepRequired(account);
    closeSocket();
    scheduleRetry();
  };
}

/**
 * The server requires two-step login of `account` first: like a 403 `two_step_required`, the popup says what to do,
 * and live sync stops for the account — no reconnect and no alarm, so nothing asks the server again and again.
 */
function twoStepRequired(account: string) {
  stopLive();
  void noteTwoStepRequired(account).catch(logged("Noting the two-step requirement"));
}

function closeSocket() {
  clearInterval(keepalive);
  keepalive = undefined;
  const ws = socket;
  socket = null;
  socketAccount = "";
  origin = null;
  if (!ws) return;
  ws.onopen = null;
  ws.onmessage = null;
  ws.onclose = null;
  try {
    ws.close(1000);
  } catch {
    /* already closed */
  }
}

/** Open again after the backoff (a timer lost with a stopped worker is made up for by the alarm). */
function scheduleRetry() {
  clearTimeout(retry);
  const run = epoch;
  retry = setTimeout(
    () => {
      retry = undefined;
      if (run === epoch) void ensureLive().catch(logged("Reconnecting live sync"));
    },
    backoffMs(attempt++, Math.random()),
  );
}

function scheduleAlarm() {
  void chrome.alarms
    .get(LIVE_ALARM)
    .then((a) => (a ? undefined : chrome.alarms.create(LIVE_ALARM, { periodInMinutes: 5 })))
    .catch(logged("Scheduling the live-sync check"));
}

/** Lock, sign-out, account switch: the socket closes and nothing reconnects until the vault is open again. */
export function stopLive() {
  epoch++;
  clearTimeout(retry);
  retry = undefined;
  attempt = 0;
  closeSocket();
  void chrome.alarms.clear(LIVE_ALARM).catch(logged("Clearing the live-sync check"));
}

/** The fallback alarm: while unlocked and without a socket, check for changes and try to connect again. */
export async function onLiveAlarm() {
  if ((await vault.lockStatus()) !== "unlocked") return stopLive();
  if (liveConnected()) return;
  await ensureLive();
}
