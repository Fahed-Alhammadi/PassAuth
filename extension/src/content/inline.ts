/**
 * Inline autofill menu, page side. When a login, sign-up, one-time-code, card or identity field (fields.ts) gets
 * the focus while PassAuth is signed in — unless the inline menu is off or the site is hidden — a PassAuth icon
 * appears at the field's right edge (a 24 px hit area left of the site's own controls: place.ts). The list is an
 * extension page in an iframe (inline-menu.html), so the website can't read the names, user names or codes in it.
 *
 * What the page can learn: the icon shows on every such field whether PassAuth is locked or not and whatever it
 * has for the site, and the list's frame always has the same size, so neither tells the page the lock state or
 * how many logins match.
 *
 * Clickjacking: the list opens by itself only right after the user clicked the field (or its label) or tabbed into
 * it — never on a focus() call from the page, even right after an unrelated click — closes when the page restyles it
 * or moves it away from where PassAuth put it (checked every 250 ms — once touched with a finger or pen, in every
 * animation frame — and on every scroll, resize and size change) and when its frame loads a second document, and the
 * menu frame ignores clicks until it has been fully visible, with the pointer inside it, for a moment (a touch: a
 * confirm tap). The host is a plain <div> (a page can't predefine it as a custom element) whose styles are pinned
 * (guard.ts `HOST_CSS`), and the nonce reaches the frame by postMessage, never in its URL.
 *
 * The frame never posts anything to this window (the page would get a handle on the frame's window from the message:
 * enough to focus it or navigate it). What it tells this script — "return" and "touch" — goes through the worker,
 * which checks the frame's nonce and sends it here, to this document only.
 *
 * Keyboard: Alt+↓ in the field opens the list with the focus in it; ↓ (or Alt+↓) moves the focus into an open
 * list, by a "focus" message that carries the menu's nonce (the page never sees it, so it can't move the focus
 * there itself); Esc and Tab in the list give the focus back to the field ("inline:return" and "inline:close" from
 * the worker). Otherwise the list never takes the focus, and the frame is out of the page's tab order.
 */

import { postToFrame } from "../shared/dom/frame-channel";
import { INLINE_MENU_HEIGHT } from "../shared/inline-layout";
import { MAX_USERNAME } from "../shared/limits";
import { callContent, type InlineOpen } from "../shared/protocol";
import type { InlineInfo } from "../shared/types";
import { logoSvg, panelShadow } from "./brand";
import { composedContains, deepActiveElement, eventTarget, type FieldKind, fieldKind, isPasswordField, Scan, shadowOf, usernameFieldFor } from "./fields";
import { type Placement, placeHost, placementDiffers, shadowHost, tampered } from "./guard";
import { pageUrl } from "./origin";
import { type IconSpot, iconPlacement, iconSpot } from "./place";

interface Icon {
  el: HTMLDivElement;
  button: HTMLButtonElement;
  at: Placement | null;
  spot: IconSpot | null;
}

interface Menu {
  el: HTMLDivElement;
  frame: HTMLIFrameElement;
  src: string;
  at: Placement | null;
  nonce: string;
  /** The frame has loaded (and has its nonce). */
  loaded: boolean;
  /** Move the focus into the list once it has loaded (opened from the keyboard, or ↓ before it loaded). */
  focusOnLoad: boolean;
}

let info: { value: InlineInfo | null; at: number } = { value: null, at: 0 };
/** The field the icon is in, and what it is for. */
let field: HTMLInputElement | null = null;
let kind: FieldKind = "login";
/** The field the open (or last) menu was opened on: fills from the menu go there. */
let lastMenuField: HTMLInputElement | null = null;
let icon: Icon | null = null;
let menu: Menu | null = null;
/** The menu that closed last: its "return" (Esc in the list closes it too) still brings the focus back. */
let closedMenu: Menu | null = null;
let opening = false;
let suppressUntil = 0;
/** The last trusted pointer or key press in this frame: when, on what element (deepest, shadow roots included), whether it was Tab. */
let lastInput: LastInput = { at: 0, target: null, tab: false };
let observer: ResizeObserver | null = null;
let watch: ReturnType<typeof setInterval> | undefined;
let frameRequest = 0;
/** While the menu is open: the check in every animation frame (see `watchMenu`). */
let menuFrame = 0;

/** The field the inline menu was opened on, while it is in the page ("Use a strong password" goes only there). */
export const menuField = (): HTMLInputElement | null => (lastMenuField?.isConnected ? lastMenuField : null);

const isOurs = (el: unknown) => (!!icon && el === icon.el) || (!!menu && el === menu.el);

/**
 * The field a fill "at the focused field" goes into: the field that has the focus (the right-click menu), else the
 * one the inline menu was opened on (the focus was in the menu, which has closed).
 */
export function targetField(): HTMLInputElement | null {
  const active = deepActiveElement();
  if (active instanceof HTMLInputElement && !isOurs(active)) return active;
  return menuField();
}

async function getInfo(): Promise<InlineInfo | null> {
  if (Date.now() - info.at < 3000) return info.value;
  // No answer (extension reloaded) or refused: no icon.
  const value = await callContent("page:inlineInfo").catch(() => null);
  info = { value, at: Date.now() };
  return info.value;
}

/** Called while PassAuth fills the page, so its own focus changes don't reopen the menu. */
export function suppressInlineMenu(ms = 800) {
  suppressUntil = Date.now() + ms;
  info.at = 0;
  closeInlineMenu();
}

export function closeInlineMenu() {
  if (menu) closedMenu = menu;
  menu?.el.remove();
  menu = null;
  cancelAnimationFrame(menuFrame);
  menuFrame = 0;
  icon?.button.setAttribute("aria-expanded", "false");
}

/**
 * Once the user has touched the open menu with a finger or pen (the frame says "touch"), its frame is checked (and
 * kept in place) in every animation frame, not only every 250 ms: a touch user confirms with a second tap
 * (content/guard.ts), and between the two taps the page must not be able to restyle or move the frame unseen. Any
 * change closes the menu (`place`), or tells the frame it moved. Not for the mouse (frame-channel.ts says why).
 */
function watchMenu() {
  if (menuFrame) return;
  cancelAnimationFrame(menuFrame);
  const tick = () => {
    menuFrame = 0;
    if (!menu) return;
    place();
    if (menu) menuFrame = requestAnimationFrame(tick);
  };
  menuFrame = requestAnimationFrame(tick);
}

function hideAll() {
  closeInlineMenu();
  icon?.el.remove();
  icon = null;
  field = null;
  observer?.disconnect();
  observer = null;
  clearInterval(watch);
  watch = undefined;
}

/** inline:off: the user hid PassAuth's menu on this site; the next focus asks the background again (and gets "off"). */
export function inlineMenuOff() {
  hideAll();
  info = { value: null, at: 0 };
}

/** Where the icon goes in the field: measured when it appears and when the field changes size. */
function measure() {
  if (icon && field) icon.spot = iconSpot(field, isOurs);
}

function place() {
  frameRequest = 0;
  if (!field) return;
  if (!field.isConnected || !field.getClientRects().length) return hideAll();
  // The page restyled or moved our UI: close the list rather than let it be clicked blind.
  if (menu && tampered(menu.el, menu.frame, menu.at)) closeInlineMenu();
  if (icon && tampered(icon.el, icon.el, icon.at, { cover: false })) return hideAll();
  const r = field.getBoundingClientRect();
  if (icon) {
    icon.spot ??= iconSpot(field, isOurs);
    const at = iconPlacement(r, icon.spot, document.documentElement.clientWidth || innerWidth);
    placeHost(icon.el, at);
    icon.at = at;
  }
  if (menu) {
    const width = Math.min(Math.max(r.width, 300), innerWidth - 16);
    const height = INLINE_MENU_HEIGHT;
    const below = r.bottom + 4 + height <= innerHeight || r.top - 4 - height < 0;
    const at = { left: Math.max(8, Math.min(r.left, innerWidth - width - 8)), top: below ? r.bottom + 4 : r.top - 4 - height, width, height };
    placeHost(menu.el, at);
    // Moved (it follows the field): the frame waits again before it takes a click.
    if (menu.at && placementDiffers(menu.at, at)) postToFrame(menu.frame, menu.src, { passauth: "moved" });
    menu.at = at;
  }
}

/** One placement in the next frame, however many scroll, resize and size events come before it. */
function schedule() {
  if (!frameRequest) frameRequest = requestAnimationFrame(place);
}

function showIcon(target: HTMLInputElement, k: FieldKind, locked: boolean) {
  field = target;
  kind = k;
  observer?.disconnect();
  observer = new ResizeObserver(() => {
    measure();
    schedule();
  });
  observer.observe(target);
  if (target.form) observer.observe(target.form);
  if (!icon) {
    const { el, shadow } = shadowHost(
      `button { all: unset; cursor: pointer; display: grid; place-items: center; width: 100%; height: 100%; border-radius: 6px; }
       button:hover { background: rgb(8 102 237 / .12); } button:focus-visible { outline: 2px solid #0866ed; }
       svg { display: block; width: auto; height: 18px; }`,
    );
    const button = document.createElement("button");
    button.type = "button";
    // Not in the page's tab order (the host sits at the end of <body>): Alt+↓ in the field opens the list from the keyboard.
    button.tabIndex = -1;
    button.setAttribute("aria-haspopup", "listbox");
    button.setAttribute("aria-expanded", "false");
    button.innerHTML = logoSvg(18);
    // Keep focus in the field while clicking the icon.
    button.addEventListener("pointerdown", (e) => e.preventDefault());
    button.addEventListener("click", (e) => {
      if (!e.isTrusted) return;
      if (menu) closeInlineMenu();
      else void openMenu(false);
    });
    shadow.append(button);
    (document.body ?? document.documentElement).appendChild(el);
    icon = { el, button, at: null, spot: null };
  }
  // Inside a closed shadow root: the page can't read which one it is.
  icon.button.title = locked ? "PassAuth is locked" : "PassAuth";
  icon.button.setAttribute("aria-label", icon.button.title);
  icon.spot = null;
  place();
  clearInterval(watch);
  watch = setInterval(place, 250);
}

/** What the background needs to know about the field the menu opens on (protocol.ts `InlineOpen`). */
function openRequest(target: HTMLInputElement, k: FieldKind): InlineOpen {
  const req: InlineOpen = { kind: k };
  if (k === "login" || k === "new-password") {
    const scan = new Scan();
    const user = isPasswordField(target, scan) ? usernameFieldFor(target, scan) : target;
    if (user?.value && user.value.length <= MAX_USERNAME) req.username = user.value;
  }
  if (k === "new-password") {
    if (target.minLength > 0) req.minLength = target.minLength;
    if (target.maxLength > 0) req.maxLength = target.maxLength;
  }
  return req;
}

/** Open the list under the field. `focus`: opened from the keyboard, so the focus moves into it once it has loaded. */
async function openMenu(focus: boolean) {
  if (!field || menu || opening) return;
  const target = field;
  opening = true;
  try {
    // No answer (extension reloaded) or refused: no menu.
    const nonce = await callContent("page:inlineOpen", openRequest(target, kind)).catch(() => null);
    if (typeof nonce !== "string" || field !== target || menu) return;
    const { el, shadow } = shadowHost(
      `iframe { border: 0; width: 100%; height: 100%; display: block; border-radius: 12px; color-scheme: normal;
                box-shadow: ${panelShadow}; background: transparent; }`,
    );
    const iframe = document.createElement("iframe");
    const src = chrome.runtime.getURL("inline-menu.html");
    const opened: Menu = { el, frame: iframe, src, at: null, nonce, loaded: false, focusOnLoad: focus };
    // The nonce goes to the frame once it has loaded, addressed to the extension only (a document the page
    // navigated the frame to never gets it; the background lets only the first frame that uses it have it).
    // PassAuth's page loads once: a second load is another document in PassAuth's frame, so the menu goes.
    iframe.addEventListener("load", () => {
      if (opened.loaded) {
        if (menu === opened) closeInlineMenu();
        return;
      }
      postToFrame(iframe, src, { passauth: "nonce", nonce });
      opened.loaded = true;
      if (opened.focusOnLoad && menu === opened) focusMenu();
      opened.focusOnLoad = false;
    });
    iframe.src = src;
    iframe.title = "PassAuth";
    // Not in the page's tab order: the list takes the focus only when the field asks for it (↓, Alt+↓).
    iframe.tabIndex = -1;
    iframe.setAttribute("allowtransparency", "true");
    shadow.append(iframe);
    (document.body ?? document.documentElement).appendChild(el);
    lastMenuField = target;
    menu = opened;
    icon?.button.setAttribute("aria-expanded", "true");
    place();
  } finally {
    opening = false;
  }
}

/** Move the keyboard focus into the open list (its first row); before the frame has loaded, once it has. */
function focusMenu() {
  if (!menu) return;
  if (!menu.loaded) {
    menu.focusOnLoad = true;
    return;
  }
  menu.frame.focus({ preventScroll: true });
  postToFrame(menu.frame, menu.src, { passauth: "focus", nonce: menu.nonce });
}

/** The menu `nonce` belongs to: the open one, or the one that closed last ("return" after Esc). */
const menuOf = (nonce: string): Menu | null => [menu, closedMenu].find((m) => m?.nonce === nonce) ?? null;

/** inline:return (from the worker: Esc or Tab in the list of menu `nonce`): the focus goes back to the field. */
export function returnFocus(nonce: string) {
  if (!menuOf(nonce)) return;
  const back = field?.isConnected ? field : menuField();
  back?.focus({ preventScroll: true });
}

/**
 * inline:touch (from the worker): the user touched the open menu `nonce` with a finger or pen, so its gate waits for
 * a confirm tap: it is checked in every animation frame from now on.
 */
export function menuTouched(nonce: string) {
  if (menu?.nonce === nonce) watchMenu();
}

/** The last trusted pointer or key press, as `inputAimedAt` reads it. */
export interface LastInput {
  at: number;
  /** The element it landed on (for a press of the pointer, the deepest one under it, shadow roots included). */
  target: Element | null;
  /** It was the Tab key (Shift+Tab too). */
  tab: boolean;
}

/**
 * Whether `last` — the last trusted input, less than a second before `now` — put the focus into `field` itself: a
 * click or tap on the field or one of its labels, or Tab. A page that focuses a field from its own script — even
 * right after an unrelated click, say on its cookie banner — never opens the list. Pure.
 */
export function inputAimedAt(last: LastInput, field: HTMLInputElement, now = Date.now()): boolean {
  if (now - last.at >= 1000 || now < last.at) return false;
  if (last.tab) return true;
  const t = last.target;
  if (!t) return false;
  if (t === field) return true;
  const label = t.closest("label");
  return !!label && (label.control === field || composedContains(label, field));
}

/** The element under a point, inside open shadow roots and the closed ones of custom elements (where a click landed). */
function deepElementAt(x: number, y: number): Element | null {
  let el = document.elementFromPoint(x, y);
  for (let s = el ? shadowOf(el) : null; el && s; s = shadowOf(el)) {
    const inner = s.elementFromPoint(x, y);
    if (!inner || inner === el) break;
    el = inner;
  }
  return el;
}

/** A field got the focus: show the icon if PassAuth has something for it, and open the list if the user just put the focus there. */
async function consider(target: Element | null, byUser: boolean) {
  if (Date.now() < suppressUntil || target === field || isOurs(target)) return;
  if (!(target instanceof HTMLInputElement)) return;
  const k = fieldKind(target, new Scan());
  // Cards only on https pages (PassAuth never fills one into an http page).
  if (!k || (k === "card" && !pageUrl()?.startsWith("https:"))) {
    if (field) hideAll();
    return;
  }
  const i = await getInfo();
  // Off, hidden on this site, signed out, refused — or the focus has moved on meanwhile.
  if (!i || i.mode === "off" || deepActiveElement() !== target) {
    if (deepActiveElement() === target) hideAll();
    return;
  }
  closeInlineMenu();
  showIcon(target, k, i.status === "locked");
  if (i.mode === "focus" && byUser) await openMenu(false);
}

/**
 * Listeners go on the window in the capture phase (content.js runs at document_idle; a field already focused by
 * then is picked up at once, without opening the list).
 */
export function installInlineMenu() {
  window.addEventListener(
    "pointerdown",
    (e) => {
      if (!e.isTrusted) return;
      const path = e.composedPath()[0];
      lastInput = { at: Date.now(), target: deepElementAt(e.clientX, e.clientY) ?? (path instanceof Element ? path : null), tab: false };
    },
    true,
  );
  window.addEventListener(
    "keydown",
    (e) => {
      if (e.isTrusted) lastInput = { at: Date.now(), target: eventTarget(e), tab: e.key === "Tab" };
    },
    true,
  );
  window.addEventListener(
    "focusin",
    (e) => {
      const t = eventTarget(e);
      void consider(t, t instanceof HTMLInputElement && inputAimedAt(lastInput, t));
    },
    true,
  );
  window.addEventListener(
    "focusout",
    () =>
      setTimeout(() => {
        const active = deepActiveElement();
        if (field && active !== field && !isOurs(active)) hideAll();
      }, 200),
    true,
  );
  window.addEventListener(
    "pointerdown",
    (e) => {
      const t = eventTarget(e);
      if (menu && t !== field && !isOurs(t)) closeInlineMenu();
      // Clicking the field again reopens a list closed with Esc or by typing.
      else if (!menu && t === field && e.isTrusted && info.value?.mode === "focus") void openMenu(false);
    },
    true,
  );
  window.addEventListener(
    "keydown",
    (e) => {
      if (!e.isTrusted) return;
      const inField = !!field && eventTarget(e) === field;
      if (e.key === "Escape" && menu) closeInlineMenu();
      else if (inField && e.key === "ArrowDown" && (menu || e.altKey)) {
        // ↓ into an open list, Alt+↓ opens it: the page's own handling of the key stops here.
        e.preventDefault();
        e.stopPropagation();
        if (menu) focusMenu();
        else void openMenu(true);
      }
      // Typing hides the list so it doesn't cover what the user is doing.
      else if (menu && inField && e.key.length === 1 && !e.ctrlKey && !e.metaKey) closeInlineMenu();
    },
    true,
  );
  window.addEventListener("scroll", schedule, { capture: true, passive: true });
  window.addEventListener("resize", schedule, { passive: true });
  const active = deepActiveElement();
  if (active) void consider(active, false);
}
