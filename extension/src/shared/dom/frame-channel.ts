/**
 * How a content script talks to the PassAuth page it framed (inline menu, save prompt): by postMessage, addressed
 * to the extension's origin only, so a frame the website navigated elsewhere never receives anything. The nonce
 * that ties the frame to its menu or pending save travels this way after the frame has loaded, never in the
 * frame's URL. The website can post to the frame as well (it is the same parent window), so the frame accepts a
 * well-formed nonce only once, "moved" (which can only make it more careful), and "focus" only with its own nonce
 * (which the page never sees): the page can't move the keyboard focus into PassAuth's list.
 *
 * The other way, the frame never posts to the parent window: the page would receive the message too, and with it
 * `e.source`, a handle on the frame's window (enough to focus it without a user gesture, or to navigate it to a
 * page of its own). What the frame has to tell the content script — "return" (give the focus back to the field)
 * and "touch" (the user touched the frame with a finger or pen) — goes to the worker as a request carrying the
 * frame's nonce, and the worker sends it on to the field's document only (background/inline-menu.ts,
 * background/save-prompt.ts).
 */

export type FrameMessage = { passauth: "nonce"; nonce: string } | { passauth: "moved" } | { passauth: "focus"; nonce: string };

const NONCE = /^[\w-]{8,64}$/;

/** The origins the framed page can have: the one in its URL (per session with a dynamic URL) and the extension's own. */
export function frameOrigins(src: string): string[] {
  const origin = (url: string) => {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  };
  return [...new Set([origin(src), origin(chrome.runtime.getURL(""))])];
}

/** Content script side. */
export function postToFrame(frame: HTMLIFrameElement, src: string, msg: FrameMessage) {
  const w = frame.contentWindow;
  if (!w) return;
  for (const origin of frameOrigins(src)) w.postMessage(msg, origin);
}

/** Framed page side: resolves with the first well-formed nonce from the parent window. */
export function receiveNonce(): Promise<string> {
  return new Promise((resolve) => {
    const onMessage = (e: MessageEvent) => {
      const d = e.data as Partial<{ passauth: string; nonce: unknown }> | null;
      if (e.source !== window.parent || !d || d.passauth !== "nonce" || typeof d.nonce !== "string" || !NONCE.test(d.nonce)) return;
      window.removeEventListener("message", onMessage);
      resolve(d.nonce);
    };
    window.addEventListener("message", onMessage);
  });
}

/** Framed page side: `fn` runs when the parent says the frame was moved or resized. */
export function onMoved(fn: () => void) {
  window.addEventListener("message", (e: MessageEvent) => {
    const d = e.data as Partial<{ passauth: string }> | null;
    if (e.source === window.parent && d?.passauth === "moved") fn();
  });
}

/** Framed page side: `fn` runs when the content script asks for the focus with this frame's nonce (`current()`, "" before it arrived). */
export function onFocusRequest(current: () => string, fn: () => void) {
  window.addEventListener("message", (e: MessageEvent) => {
    const d = e.data as Partial<{ passauth: string; nonce: unknown }> | null;
    const nonce = current();
    if (e.source === window.parent && d?.passauth === "focus" && nonce && d.nonce === nonce) fn();
  });
}

/**
 * Framed page side: the first trusted press of a finger or pen in this frame calls `report` once (it sends "touch"
 * through the worker), so the content script checks the frame in every animation frame from then on (content/guard.ts:
 * confirm taps). Mouse users never send it: a page producing frames for that check delays the browser's own
 * visibility reports (IntersectionObserver v2) that the gate relies on against a page covering the frame — found in
 * a real browser.
 */
export function reportTouch(report: () => void) {
  const onDown = (e: PointerEvent) => {
    if (!e.isTrusted || (e.pointerType !== "touch" && e.pointerType !== "pen")) return;
    window.removeEventListener("pointerdown", onDown, true);
    report();
  };
  window.addEventListener("pointerdown", onDown, true);
}
