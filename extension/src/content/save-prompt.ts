/**
 * "Save login?" / "Update login?" in the top-right corner of the page. The prompt itself is an extension page in a
 * frame (save-prompt.html, like the inline menu): this script only places and sizes the frame. It never gets the
 * logins listed in the prompt or the user's choice — just the nonce that ties the frame to the pending save
 * (handed to the frame by postMessage once it has loaded, never in its URL) and a height — and it can neither
 * accept nor dismiss a save: only the prompt itself does (Esc pressed inside it, its buttons, its timer).
 *
 * Focus: the frame takes the keyboard focus only when the form was submitted from the keyboard (`focus`), and then
 * says so to the frame with its nonce (only then do key presses count there); otherwise the prompt announces itself
 * politely and the focus stays where the user is. The frame is out of the page's tab order.
 *
 * The frame never posts anything to this window (the page would get a handle on the frame's window). Its "touch"
 * comes through the worker (`savePromptTouched`). A second document loaded in the frame closes the prompt.
 */
import { postToFrame } from "../shared/dom/frame-channel";
import { clampPromptHeight, SAVE_PROMPT } from "../shared/save-layout";
import type { SavePrompt } from "../shared/types";
import { panelShadow } from "./brand";
import { Scan } from "./fields";
import { type Placement, placementDiffers, shadowHost, tampered } from "./guard";

let prompt: { nonce: string; host: HTMLElement; frame: HTMLIFrameElement; src: string; at: Placement | null; close: () => void; touched: () => void } | null = null;
/** A prompt waiting to be shown after a page load (see showSavePrompt). */
let waiting: ReturnType<typeof setTimeout> | undefined;

/** Where the prompt frame sits: the top-right corner of the viewport (scroll bar excluded), at its width and the height last set. */
function promptPlacement(frame: HTMLIFrameElement): Placement {
  const vw = document.compatMode === "BackCompat" ? (document.body?.clientWidth ?? innerWidth) : document.documentElement.clientWidth;
  const width = Math.min(SAVE_PROMPT.width, innerWidth - 2 * SAVE_PROMPT.edge);
  return { left: vw - SAVE_PROMPT.edge - width, top: SAVE_PROMPT.edge, width, height: parseFloat(frame.style.height) || 0 };
}

/** The same, measured as if the vertical scroll bar were on the left (right-to-left pages): either is where PassAuth put it. */
const promptPlacements = (at: Placement): Placement[] => [at, { ...at, left: innerWidth - SAVE_PROMPT.edge - at.width }];

function setPromptHeight(frame: HTMLIFrameElement, height: number) {
  frame.style.height = `${Math.max(0, Math.min(clampPromptHeight(height), innerHeight - 2 * SAVE_PROMPT.edge))}px`;
  if (!prompt || prompt.frame !== frame) return;
  // A new size: the frame waits again before it takes a click.
  const at = promptPlacement(frame);
  if (prompt.at && placementDiffers(prompt.at, at)) postToFrame(frame, prompt.src, { passauth: "moved" });
  prompt.at = at;
}

/** save:size: the prompt's content changed height. */
export function resizeSavePrompt(height: number) {
  if (prompt) setPromptHeight(prompt.frame, height);
}

/** save:close. */
export function closeSavePrompt() {
  prompt?.close();
}

/** The prompt's bottom edge (viewport pixels) while it is open, for notes shown beneath it. */
export function savePromptBottom(): number | null {
  return prompt ? prompt.host.getBoundingClientRect().bottom : null;
}

/**
 * showSave. `afterLoad`: the background shows a pending save once a page has loaded; a page that asks for a
 * password again (the sign-in most likely failed) doesn't get it. The check waits a moment for pages that draw
 * their form after loading.
 */
export function showSavePrompt(p: SavePrompt & { afterLoad?: boolean }) {
  if (window.top !== window || prompt || typeof p.nonce !== "string" || !/^[\w-]{8,64}$/.test(p.nonce)) return;
  if (!p.afterLoad) return open(p);
  clearTimeout(waiting);
  waiting = setTimeout(() => {
    if (!new Scan().passwords().length) open(p);
  }, 600);
}

function open({ nonce, height, focus }: SavePrompt) {
  if (prompt) return;
  // Static markup only. The page can restyle the host element; the frame checks that it is really visible before it accepts a click.
  const { el: hostEl, shadow } = shadowHost(`:host { top: ${SAVE_PROMPT.edge}px !important; right: ${SAVE_PROMPT.edge}px !important; left: auto !important;
      width: auto !important; height: auto !important; }
      iframe { display: block; border: 0; outline: 0; width: ${SAVE_PROMPT.width}px; max-width: calc(100vw - ${2 * SAVE_PROMPT.edge}px); border-radius: 16px; color-scheme: normal;
               background: transparent; box-shadow: ${panelShadow}; }`);
  const frame = document.createElement("iframe");
  const src = chrome.runtime.getURL("save-prompt.html");
  // The nonce goes to the frame once it has loaded, addressed to the extension only (a document the page
  // navigated the frame to never gets it; the background lets only the first frame that uses it have it).
  // PassAuth's page loads once: a second load is another document in PassAuth's frame, so the prompt goes.
  let loaded = false;
  frame.addEventListener("load", () => {
    if (loaded) return close();
    loaded = true;
    postToFrame(frame, src, { passauth: "nonce", nonce });
    // After a keyboard submit the focus goes to the prompt (to its dialog container, never a button: a key press
    // already on its way can't accept anything), and the frame is told so with its nonce: key presses count there
    // only after that (or after a click in it).
    if (focus) {
      frame.focus({ preventScroll: true });
      postToFrame(frame, src, { passauth: "focus", nonce });
    }
  });
  frame.src = src;
  frame.title = "PassAuth: save login";
  // Not in the page's tab order: the prompt takes the focus only after a keyboard submit.
  frame.tabIndex = -1;
  frame.setAttribute("allowtransparency", "true");
  setPromptHeight(frame, height);
  shadow.append(frame);

  // The page hid, restyled or moved the prompt: take it away rather than leave it to be clicked blind. Where it
  // should be is worked out each time from the viewport, so resizing the window moves it legitimately (and the
  // frame then waits again before it takes a click).
  const check = () => {
    if (!prompt || prompt.host !== hostEl) return;
    const at = promptPlacement(frame);
    if (tampered(hostEl, frame, promptPlacements(at))) return close();
    if (prompt.at && placementDiffers(prompt.at, at)) postToFrame(frame, src, { passauth: "moved" });
    prompt.at = at;
  };
  // Every 250 ms; once the user touched the prompt with a finger or pen ("touch" from the frame), also in every
  // animation frame: its gate then waits for a confirm tap (content/guard.ts), and between the two taps the page
  // must not restyle or move the prompt unseen. Not for the mouse (frame-channel.ts says why).
  const watch = setInterval(check, 250);
  let raf = 0;
  const tick = () => {
    check();
    raf = prompt?.host === hostEl ? requestAnimationFrame(tick) : 0;
  };
  // "touch" from the worker (savePromptTouched): the frame was touched with a finger or pen.
  const touched = () => {
    if (!raf && prompt?.host === hostEl) raf = requestAnimationFrame(tick);
  };
  // Whatever happens to the frame, it never outlives the pending save (2 minutes; a generated password's save
  // stays longer and is shown again on the next page).
  const expire = setTimeout(() => close(), 125_000);
  function close() {
    clearInterval(watch);
    cancelAnimationFrame(raf);
    raf = 0;
    clearTimeout(expire);
    hostEl.remove();
    if (prompt?.host === hostEl) prompt = null;
  }
  (document.body ?? document.documentElement).appendChild(hostEl);
  prompt = { nonce, host: hostEl, frame, src, at: null, close, touched };
  prompt.at = promptPlacement(frame);
}

/**
 * save:touch (from the worker, which checked the prompt frame's nonce): the user touched the prompt with a finger or
 * pen, so its gate waits for a confirm tap (content/guard.ts), and between the two taps the page must not restyle or
 * move the prompt unseen: it is checked in every animation frame from now on.
 */
export function savePromptTouched(nonce: string) {
  if (prompt?.nonce === nonce) prompt.touched();
}
