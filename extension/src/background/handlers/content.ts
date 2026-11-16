/**
 * Requests from content scripts. They run inside web pages, so everything they send is checked (`parse`), and
 * every handler checks the sender's real origin (senders.ts) before it acts: a cross-site or sandboxed frame gets
 * nothing.
 */
import { MAX_USERNAME } from "../../shared/limits";
import type { CreateRequest, GetRequest, PasskeyRuntimeReply } from "../../shared/passkey-types";
import type { BridgeApi, ContentApi, Fields, InlineOpen, ResOf } from "../../shared/protocol";
import type { InlineKind } from "../../shared/types";
import { all, isRecord, none, optional, text, token, whole, yesNo } from "../checks";
import { claimFill } from "../fill";
import { inlineInfo, openInline } from "../inline-menu";
import { noteContextField } from "../menus";
import { cancelPasskey, handlePasskey } from "../passkey-handler";
import type { CheckedHandlers, Sender } from "../router";
import { formDone, onSubmitted, rememberUser } from "../save-prompt";
import { type SenderKind, senderOrigin } from "../senders";

const CONTENT: readonly SenderKind[] = ["content"];

const INLINE_KINDS: readonly InlineKind[] = ["login", "new-password", "otp", "card", "identity"];

/** page:inlineOpen: every field optional; a user name longer than the cap is left out, never cut. */
function inlineOpen(m: Record<string, unknown>): InlineOpen | null {
  const kind = optional(m.kind, (v) => (typeof v === "string" && (INLINE_KINDS as readonly string[]).includes(v) ? (v as InlineKind) : null));
  const username = optional(m.username, (v) => text(v));
  const minLength = optional(m.minLength, (v) => whole(v, 1, 4096));
  const maxLength = optional(m.maxLength, (v) => whole(v, 1, 4096));
  if (kind === null || username === null || minLength === null || maxLength === null) return null;
  return {
    ...(kind !== undefined ? { kind } : {}),
    ...(username !== undefined && username.length <= MAX_USERNAME ? { username } : {}),
    ...(minLength !== undefined ? { minLength } : {}),
    ...(maxLength !== undefined ? { maxLength } : {}),
  };
}

export const contentHandlers = {
  "page:submitted": {
    from: CONTENT,
    parse(m) {
      const req = all({ username: text(m.username), password: text(m.password) });
      const keyboard = optional(m.keyboard, yesNo);
      return req && keyboard !== null ? { ...req, ...(keyboard ? { keyboard } : {}) } : null;
    },
    run: ({ username, password, keyboard }, sender) => onSubmitted(sender, username, password, keyboard === true),
  },
  "page:identifier": {
    from: CONTENT,
    parse: (m) => all({ username: text(m.username) }),
    run: ({ username }, sender) => rememberUser(sender, username),
  },
  "page:formDone": { from: CONTENT, parse: none, run: (_req, sender) => formDone(sender) },
  "page:fillClaim": {
    from: CONTENT,
    parse: (m) => all({ token: token(m.token) }),
    run: ({ token }, sender) => claimFill(token, sender),
  },
  "page:inlineInfo": { from: CONTENT, parse: none, run: (_req, sender) => inlineInfo(sender) },
  "page:inlineOpen": { from: CONTENT, parse: inlineOpen, run: (req, sender) => openInline(sender, req) },
  "page:contextField": { from: CONTENT, parse: (m) => all({ password: yesNo(m.password) }), run: ({ password }, sender) => noteContextField(sender, password) },
} satisfies CheckedHandlers<ContentApi>;

/** Where a bridge request came from: a frame of a tab (router.ts checks that before a handler runs). */
export interface BridgeFrom {
  tabId: number;
  frameId: number;
  sender: Sender;
}

type BridgeHandlers = {
  [K in keyof BridgeApi]-?: {
    /** The request, or null: then create/get go to the browser's own authenticators (`{fallback: true}`) and a cancel is ignored. */
    parse(msg: Record<string, unknown>): Fields<BridgeApi, K> | null;
    /** The answer, or undefined for none. */
    run(req: Fields<BridgeApi, K>, from: BridgeFrom): Promise<ResOf<BridgeApi, K>> | undefined;
  };
};

const FALLBACK: PasskeyRuntimeReply = { fallback: true };

/** The bridge's own request id: at most 100 characters (the page chose it). */
const bridgeId = (v: unknown) => (typeof v === "string" ? v.slice(0, 100) : "");

function passkeyRequest(type: "passkey:create" | "passkey:get", req: { options: CreateRequest | GetRequest; bridgeId: string; activated?: boolean }, from: BridgeFrom): Promise<PasskeyRuntimeReply> {
  // The document's real origin, from the browser (never from the message): a sandboxed or borrowed origin is left to the browser.
  const origin = senderOrigin(from.sender);
  if (!origin) return Promise.resolve(FALLBACK);
  return handlePasskey({
    type,
    options: req.options,
    bridgeId: req.bridgeId,
    origin,
    topLevel: from.frameId === 0,
    tabId: from.tabId,
    frameId: from.frameId,
    documentId: from.sender.documentId,
    // Creation always comes with a user gesture (the bridge refuses it without one).
    activated: type === "passkey:create" || req.activated === true,
  });
}

/**
 * WebAuthn requests from the page bridge (content/passkey-bridge.ts), answered in the authenticator's reply shape.
 * The options are checked in detail by background/passkeys.ts; here only that they are an object.
 */
export const bridgeHandlers = {
  "passkey:create": {
    parse: (m) => (isRecord(m.options) ? { options: m.options as unknown as CreateRequest, bridgeId: bridgeId(m.bridgeId) } : null),
    run: (req, from) => passkeyRequest("passkey:create", req, from),
  },
  "passkey:get": {
    parse: (m) => (isRecord(m.options) ? { options: m.options as unknown as GetRequest, bridgeId: bridgeId(m.bridgeId), activated: m.activated === true } : null),
    run: (req, from) => passkeyRequest("passkey:get", req, from),
  },
  "passkey:cancel": {
    parse: (m) => ({ bridgeId: typeof m.bridgeId === "string" ? m.bridgeId : String(m.bridgeId ?? ""), gone: m.gone === true }),
    run({ bridgeId, gone }, from) {
      // The page aborted or timed out its request (or went away): close the window without creating or using anything.
      cancelPasskey(from.tabId, from.frameId, bridgeId, gone);
      return undefined;
    },
  },
} satisfies BridgeHandlers;
