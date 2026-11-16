// PassAuth passkey bridge — isolated-world content script part.
//
// Relays WebAuthn requests from the MAIN-world shim (page/webauthn.ts) to the
// background service worker and posts the reply back to the page.
//
// Why a page forging "passauth-page" messages gains nothing:
//   - The origin is never read from the message. The background takes it from
//     the browser (`sender.origin`) and checks the RP ID against it, so a page
//     can only ever request passkeys for its own origin. A frame whose document
//     origin is opaque ("null": sandboxed) or differs from its URL is refused.
//   - Any script on the page can already call navigator.credentials.create/get
//     for that same origin; a forged message is exactly equivalent to doing so
//     and still requires the user's confirmation in PassAuth's UI.
//   - Replies go only to this window, which the requesting page already owns.

import { capPasskeyNames } from "../shared/limits";
import type { BridgeToPageMessage, CreateRequest, GetRequest, PasskeyErrorJSON, PasskeyRuntimeMessage } from "../shared/passkey-types";

// Minimal local typing so this file does not depend on @types/chrome.
declare const chrome: { runtime: { sendMessage(message: unknown): Promise<unknown> } };

type Reply = Omit<BridgeToPageMessage, "source" | "id">;

let installed = false;
/** Requests sent to PassAuth and not answered yet: when the page goes away they are cancelled (their window closes). */
const inFlight = new Set<string>();

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

  // The page is going away (navigation, reload, closing): nobody waits for its confirmation windows any more.
  window.addEventListener("pagehide", () => {
    for (const id of inFlight) void chrome.runtime.sendMessage({ type: "passkey:cancel", bridgeId: id, gone: true } satisfies PasskeyRuntimeMessage).catch(() => {});
    inFlight.clear();
  });

  window.addEventListener("message", (event: MessageEvent) => {
    if (event.source !== window) return;
    const data: unknown = event.data;
    if (!isObj(data) || data.source !== "passauth-page") return;
    const { id, kind, options } = data;
    if (typeof id !== "string" || id.length === 0 || id.length > 100) return;
    if (kind === "cancel") {
      // Nothing to do if the extension can't be reached: then no confirmation window is open either.
      void chrome.runtime.sendMessage({ type: "passkey:cancel", bridgeId: id } satisfies PasskeyRuntimeMessage).catch(() => {});
      return;
    }
    if (kind !== "create" && kind !== "get") return;

    // The document's own origin (`self.origin`): "null" for a sandboxed frame even when its URL looks like the site's.
    const origin = self.origin;
    const targetOrigin = origin === "null" ? "*" : origin;
    const reply = (msg: Reply): void => {
      const out: BridgeToPageMessage = { source: "passauth-bridge", id, ...msg };
      window.postMessage(out, targetOrigin);
    };
    reply({ ack: true });

    // Origin comes from this frame, never from the page's message; an opaque or borrowed origin is left to the browser.
    if (!isObj(options) || origin === "null" || origin !== location.origin) {
      reply({ fallback: true });
      return;
    }
    // Options are passed through as-is; background/passkeys.ts validates them.
    // Creating a passkey needs a recent click or key press on the page (read in
    // this isolated world, which the page can't tamper with), so a page can't
    // pop PassAuth windows up on its own. Signing in may come without one (a
    // two-step page asks as it loads); the background then holds a tab back
    // whose user just cancelled (`activated`: whether there was one).
    const activated = navigator.userActivation?.isActive === true;
    if (kind === "create" && !activated) {
      reply({ fallback: true });
      return;
    }
    const topLevel = window.top === window;
    // Names the page supplies are cut to 256 characters here and again in the background.
    const message: PasskeyRuntimeMessage =
      kind === "create"
        ? { type: "passkey:create", options: capPasskeyNames(options as unknown as CreateRequest), origin, topLevel, bridgeId: id }
        : { type: "passkey:get", options: options as unknown as GetRequest, origin, topLevel, bridgeId: id, activated };
    inFlight.add(id);
    void forward(message).then((r) => {
      inFlight.delete(id);
      reply(r);
    });
  });
}
