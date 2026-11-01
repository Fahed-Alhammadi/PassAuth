// PassAuth passkey bridge — isolated-world content script part.
//
// Relays WebAuthn requests from the MAIN-world shim (page/webauthn.ts) to the
// background service worker and posts the reply back to the page.
//
// Why a page forging "passauth-page" messages gains nothing:
//   - The origin sent to the background is always `location.origin` of the
//     frame this content script runs in; nothing origin-related is read from
//     the message. The background derives and checks the RP ID from that
//     origin, so a page can only ever request passkeys for its own origin.
//   - Any script on the page can already call navigator.credentials.create/get
//     for that same origin; a forged message is exactly equivalent to doing so
//     and still requires the user's confirmation in PassAuth's UI.
//   - Replies go only to this window, which the requesting page already owns.

import type {
  BridgeToPageMessage,
  CreateRequest,
  GetRequest,
  PasskeyErrorJSON,
  PasskeyRuntimeMessage,
} from "../shared/passkey-types";

// Minimal local typing so this file does not depend on @types/chrome.
declare const chrome: { runtime: { sendMessage(message: unknown): Promise<unknown> } };

type Reply = Omit<BridgeToPageMessage, "source" | "id">;

let installed = false;

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Accept only the documented reply shapes from the background; anything else → fallback. */
function sanitizeReply(r: unknown): Reply {
  if (isObj(r)) {
    if (isObj(r.result)) return { result: r.result as unknown as NonNullable<Reply["result"]> };
    if (isObj(r.error)) {
      const error: PasskeyErrorJSON = { name: String(r.error.name ?? "NotAllowedError"), message: String(r.error.message ?? "") };
      return { error };
    }
  }
  return { fallback: true };
}

async function forward(message: PasskeyRuntimeMessage): Promise<Reply> {
  try {
    return sanitizeReply(await chrome.runtime.sendMessage(message));
  } catch {
    // No listener, service worker unavailable, or extension context invalidated.
    return { fallback: true };
  }
}

export function installPasskeyBridge(): void {
  if (installed) return;
  installed = true;

  window.addEventListener("message", (event: MessageEvent) => {
    if (event.source !== window) return;
    const data: unknown = event.data;
    if (!isObj(data) || data.source !== "passauth-page") return;
    const { id, kind, options } = data;
    if (typeof id !== "string" || id.length === 0 || id.length > 100) return;
    if (kind !== "create" && kind !== "get") return;

    const targetOrigin = location.origin === "null" ? "*" : location.origin;
    const reply = (msg: Reply): void => {
      const out: BridgeToPageMessage = { source: "passauth-bridge", id, ...msg };
      window.postMessage(out, targetOrigin);
    };
    reply({ ack: true });

    // Origin comes from this frame, never from the page's message.
    const origin = location.origin;
    if (!isObj(options) || origin === "null") {
      reply({ fallback: true });
      return;
    }
    // Options are passed through as-is; background/passkeys.ts validates them.
    const topLevel = window.top === window;
    const message: PasskeyRuntimeMessage =
      kind === "create"
        ? { type: "passkey:create", options: options as unknown as CreateRequest, origin, topLevel }
        : { type: "passkey:get", options: options as unknown as GetRequest, origin, topLevel };
    void forward(message).then(reply);
  });
}
