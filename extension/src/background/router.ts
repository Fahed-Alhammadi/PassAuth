/**
 * The service worker's message router: one table of handlers, `{ type → who may send it, whether it needs the
 * vault unlocked, whether it counts as activity, a check of the message, the handler }` (handlers/). Who sent a
 * message comes from the browser (`senderKind`), never from the message. Anything not in the table, or from a
 * sender the entry doesn't list, is refused before anything runs. Replies are `Reply` (shared/protocol.ts); the
 * passkey bridge's requests are answered in their own shape (`bridge`).
 */
import { codeOf, FAILED, lockedError, messageOf, notAllowed } from "../shared/errors";
import { log } from "../shared/log";
import type { Fields, Reply, ResOf } from "../shared/protocol";
import { type Activity, touch } from "./activity";
import { isRecord } from "./checks";
import { initCore } from "./core";
import { type BridgeFrom, bridgeHandlers, contentHandlers } from "./handlers/content";
import { inlineHandlers, saveHandlers } from "./handlers/frames";
import { passkeyWindowHandlers, popupHandlers } from "./handlers/popup";
import { extensionOrigin, type SenderKind, senderKind } from "./senders";
import * as vault from "./vault";

export type Sender = chrome.runtime.MessageSender;

export interface Handler<Req, Res> {
  /** Who may send it (senders.ts `senderKind`); anyone else is refused before anything runs. */
  from: readonly SenderKind[];
  /** Needs the vault unlocked: refused with the code "locked" otherwise. */
  unlock?: true;
  /** Counts as the user at work in PassAuth (activity.ts): the vault timeout restarts first. */
  activity?: Activity;
  /** Builds the typed request from a message a web page could have shaped, or null to refuse it. */
  parse?(msg: Record<string, unknown>): Req | null;
  run(req: Req, sender: Sender): Res | Promise<Res>;
}

/** A handler for every request type of channel `C`: checked with `satisfies`, so a missing or mistyped one doesn't compile. */
export type Handlers<C> = { [K in keyof C]-?: Handler<Fields<C, K>, ResOf<C, K>> };

/** The same for a channel web pages can reach (content scripts, framed pages): every handler checks its message. */
export type CheckedHandlers<C> = { [K in keyof C]-?: Handler<Fields<C, K>, ResOf<C, K>> & { parse(msg: Record<string, unknown>): Fields<C, K> | null } };

/** A handler with its types erased: what the dispatcher works with. */
interface Route {
  from: readonly SenderKind[];
  unlock?: true;
  activity?: Activity;
  parse?(msg: Record<string, unknown>): unknown;
  run(req: unknown, sender: Sender): unknown;
}

function table(...channels: Record<string, Route>[]): Map<string, Route> {
  const all = new Map<string, Route>();
  for (const channel of channels) {
    for (const [type, route] of Object.entries(channel)) {
      // Two channels with the same request type would make one of them unreachable.
      if (all.has(type)) throw new Error(`Request type ${type} is handled twice.`);
      all.set(type, route);
    }
  }
  return all;
}

const ROUTES = table(popupHandlers, passkeyWindowHandlers, inlineHandlers, saveHandlers, contentHandlers);

/** Every request type the router answers, with who may send it (for tests and documentation). */
export function routes(): ReadonlyMap<string, { from: readonly SenderKind[]; unlock: boolean; activity: Activity | null }> {
  return new Map([...ROUTES].map(([type, r]) => [type, { from: r.from, unlock: !!r.unlock, activity: r.activity ?? null }]));
}

/** Origins of PassAuth's own pages: the extension's, and the per-session one of pages loaded through a dynamic URL. */
let ownOrigins: string[] | null = null;
const origins = () => (ownOrigins ??= [...new Set(["", "inline-menu.html", "save-prompt.html"].map((p) => extensionOrigin(chrome.runtime.getURL(p))))]);

/** Who sent a message, from what the browser says about the sender. */
export const kindOf = (sender: Sender): SenderKind => senderKind(sender, chrome.runtime.id, origins());

const failure = (e: unknown): Extract<Reply<never>, { ok: false }> => ({ ok: false, code: codeOf(e) ?? FAILED, message: messageOf(e) });

/** Answer one request (never rejects: a failure is a reply). */
export async function dispatch(msg: unknown, sender: Sender): Promise<Reply<unknown>> {
  try {
    const route = isRecord(msg) && typeof msg.type === "string" ? ROUTES.get(msg.type) : undefined;
    if (!route || !isRecord(msg) || !route.from.includes(kindOf(sender))) throw notAllowed();
    const req = route.parse ? route.parse(msg) : msg;
    if (req === null) throw notAllowed();
    // Only what the user does restarts the vault timeout; reading (an open item, its code) doesn't.
    if (route.activity) await touch(route.activity === "force");
    if (route.unlock && !(await vault.ensureUnlocked())) throw lockedError();
    // The handlers use the core's site logic synchronously: it is loaded first (once per worker).
    await initCore();
    return { ok: true, data: (await route.run(req, sender)) ?? null };
  } catch (e) {
    const reply = failure(e);
    if (reply.code === FAILED) log.warn(`Request ${isRecord(msg) ? String(msg.type) : "?"} failed:`, e);
    return reply;
  }
}

/** A bridge handler with its types erased (handlers/content.ts `bridgeHandlers`). */
interface BridgeRoute {
  parse(msg: Record<string, unknown>): unknown;
  run(req: unknown, from: BridgeFrom): Promise<unknown> | undefined;
}

const BRIDGE: Record<string, BridgeRoute> = bridgeHandlers;

/**
 * Requests from the passkey bridge, answered in the authenticator's reply shape. Only from a frame of a tab (the
 * bridge is a content script); anything else gets no answer. A creation or sign-in PassAuth can't read goes to the
 * browser's own authenticators (`{fallback: true}`).
 */
function bridge(route: BridgeRoute, msg: Record<string, unknown>, sender: Sender, respond: (reply: unknown) => void): boolean {
  const tabId = sender.tab?.id;
  const frameId = sender.frameId;
  if (!tabId || frameId === undefined || sender.id !== chrome.runtime.id) return false;
  const req = route.parse(msg);
  const reply = req === null ? undefined : route.run(req, { tabId, frameId, sender });
  if (!reply) {
    if (req === null && msg.type !== "passkey:cancel") respond({ fallback: true });
    return false;
  }
  reply.then(respond, (e: unknown) => {
    log.warn("A passkey request failed:", e);
    respond({ fallback: true });
  });
  return true;
}

/** The chrome.runtime.onMessage listener (main.ts). */
export function onMessage(msg: unknown, sender: Sender, respond: (reply: unknown) => void): boolean {
  const bridged = isRecord(msg) && typeof msg.type === "string" && Object.hasOwn(BRIDGE, msg.type) ? BRIDGE[msg.type] : undefined;
  if (bridged && isRecord(msg)) return bridge(bridged, msg, sender, respond);
  void dispatch(msg, sender).then(respond);
  return true;
}
