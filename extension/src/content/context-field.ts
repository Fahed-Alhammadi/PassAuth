/**
 * What the right-click menu (background/menus.ts) needs from the page: whether the field the user is in is a password
 * field, so "Fill a strong password" shows only there, and which field the menu was opened on (with its length
 * limits) when it is chosen. Chrome builds its menu while the click happens and has no "menu shown" event, so the
 * state is sent ahead of it: when the focus moves to another field, and when the right button goes down on one. Only
 * changes are sent (per frame while it has the focus). No values, names or anything typed ever leave the page here.
 */
import { callContent } from "../shared/protocol";
import { deepActiveElement, eventTarget, isPasswordField, Scan } from "./fields";

/** The field the last right-click in this frame was on, and when. */
let lastContext: { el: HTMLInputElement; at: number } | null = null;
/** What this frame said last (null: nothing since it got the focus). */
let reported: boolean | null = null;

/** A right-click this long ago still names the field "Fill a strong password" goes into. */
const CONTEXT_MS = 2 * 60_000;

function report(el: Element | null) {
  const password = !!el && isPasswordField(el, new Scan());
  if (password === reported) return;
  reported = password;
  // No answer (the extension was reloaded) changes nothing here.
  callContent("page:contextField", { password }).catch(() => {});
}

export function installContextField() {
  window.addEventListener("focusin", (e) => report(eventTarget(e)), true);
  window.addEventListener(
    "pointerdown",
    (e) => {
      if (e.isTrusted && e.button === 2) report(eventTarget(e));
    },
    true,
  );
  window.addEventListener(
    "contextmenu",
    (e) => {
      if (!e.isTrusted) return;
      const t = eventTarget(e);
      lastContext = t instanceof HTMLInputElement ? { el: t, at: Date.now() } : null;
    },
    true,
  );
  // Another frame (or window) has the focus now: the next field here reports again.
  window.addEventListener("blur", () => {
    reported = null;
  });
}

/** The field the right-click menu was opened on in this frame (recently), else the focused one. */
export function contextField(): HTMLInputElement | null {
  const now = Date.now();
  if (lastContext?.el.isConnected && now - lastContext.at < CONTEXT_MS && now >= lastContext.at) return lastContext.el;
  const active = deepActiveElement();
  return active instanceof HTMLInputElement ? active : null;
}

/** context:field: whether that field is a password field, with its length limits. */
export function contextFieldInfo(): { password: boolean; minLength?: number; maxLength?: number } {
  const el = contextField();
  if (!el || !isPasswordField(el, new Scan())) return { password: false };
  return { password: true, ...(el.minLength > 0 ? { minLength: el.minLength } : {}), ...(el.maxLength > 0 ? { maxLength: el.maxLength } : {}) };
}
