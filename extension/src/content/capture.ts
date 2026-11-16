/**
 * Offering to save what the user typed. After a submit — a form's submit event, Enter in a login field, or a click
 * on a button in the same form or container as a typed password (found by the page's structure, so it works in
 * any language; buttons worded like "Sign in" count too) — the typed user name and password go to the background
 * (page:submitted), which decides whether there is something to offer. The prompt follows only once the login
 * seems to have worked: the page navigates (the background shows it on the next page) or, in single-page apps, the
 * form goes away. A form that stays (wrong password) never prompts.
 *
 * Only a real action by the user counts, with values the user typed (all read here in the isolated world, which the
 * page can't tamper with):
 * - the submit must follow a trusted click, tap or key press inside that form (or on its button) within about a
 *   second — a page's own `form.requestSubmit()` right after an unrelated click doesn't count, although the browser
 *   marks that submit event trusted and the click leaves the page's user activation on for seconds;
 * - the password offered must be what trusted `input` events left in its field: typed, pasted or dropped by the
 *   user. A value the page set itself (or changed after the user typed) is never offered, so a page can't put its
 *   own password into an "Update login?" prompt.
 * So a page can't make PassAuth offer to save — and show its prompt — by itself.
 */
import { credentialsFit, MAX_USERNAME } from "../shared/limits";
import { callContent } from "../shared/protocol";
import { composedContains, composedParent, eventTarget, fieldKind, isPasswordField, Scan, scopeOf, usernameFieldFor, visible } from "./fields";
import { pageUrl } from "./origin";
import { submittedPassword } from "./pick";

const ignore = () => {};

let lastSent = "";
/** The kind of the last trusted press: a submit event doesn't say whether a key press or a click made it. */
let lastInput: "key" | "pointer" | "" = "";
/** The last trusted input of any kind (press, release, typing): when, and on which element. */
let lastTouch: { at: number; target: Element | null } = { at: 0, target: null };
/** How soon after a trusted input inside the form a submit must come to count. */
export const SUBMIT_AFTER_INPUT_MS = 1000;
/** What each field held after its last trusted `input` event: its value counts as typed only while it is still that. */
const typed = new WeakMap<Element, string>();

/** Whether `field`'s current value is what the user's own typing (or pasting) left there. */
const typedNow = (field: HTMLInputElement) => typed.get(field) === field.value;

/** The form a control belongs to (its `form` attribute counts), else null. */
function formOf(el: Element): HTMLFormElement | null {
  const control = el.closest("button, input, select, textarea");
  return control instanceof HTMLButtonElement || control instanceof HTMLInputElement || control instanceof HTMLSelectElement || control instanceof HTMLTextAreaElement
    ? control.form
    : el.closest("form");
}

/** The last trusted input was inside `region` (or a control of that form) within the last second or so. */
function inputJustNow(region: Element | null): boolean {
  const { at, target } = lastTouch;
  if (Date.now() - at > SUBMIT_AFTER_INPUT_MS || !target) return false;
  if (!region) return true;
  return composedContains(region, target) || (region instanceof HTMLFormElement && formOf(target) === region);
}

const BUTTONS = 'button, input[type="submit"], input[type="button"], input[type="image"], [role="button"]';
/** Buttons worded like a submit, for buttons with no typed password near them (identifier-first steps). */
const SUBMIT_WORDS = /log ?in|sign ?in|continue|next|submit|save|update|register|sign ?up|create|join/i;
/** Buttons next to a password field that aren't a submit: show/hide toggles, "Forgot password?", "Cancel". */
const NOT_SUBMIT = /\b(show|hide|reveal|toggle|visib\w*|eye|forgot|reset|cancel|back|clear|close)\b/i;

/** What a button says (its text, value, label, title), cut short. */
function buttonText(btn: Element): string {
  const value = btn instanceof HTMLInputElement ? btn.value : "";
  return `${(btn.textContent ?? "").slice(0, 200)} ${value} ${btn.getAttribute("aria-label") ?? ""} ${btn.getAttribute("title") ?? ""}`;
}

/** A show-password eye and the like: a toggle, worded like one, or drawn over a password field. */
function toggleLike(btn: Element, scan: Scan): boolean {
  if (btn.hasAttribute("aria-pressed") || NOT_SUBMIT.test(buttonText(btn))) return true;
  const b = btn.getBoundingClientRect();
  const x = b.left + b.width / 2;
  const y = b.top + b.height / 2;
  return scan.passwords().some((p) => {
    const r = p.getBoundingClientRect();
    return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom;
  });
}

/**
 * The form or container a submit button belongs to, by structure: its form when that holds a typed password (or,
 * with no password field at all, a typed user name: an identifier-first step); else the nearest element a few
 * levels up that holds a typed password. `undefined`: no login form near it.
 */
function submitScope(btn: Element, scan: Scan): Element | null | undefined {
  const form = btn instanceof HTMLButtonElement || btn instanceof HTMLInputElement ? btn.form : btn.closest("form");
  if (form) {
    const passwords = scan.passwords(form);
    if (passwords.some((p) => p.value)) return form;
    if (!passwords.length && usernameFieldFor(null, scan, form)?.value) return form;
  }
  let n = composedParent(btn);
  for (let depth = 0; n instanceof Element && n !== document.body && n !== document.documentElement && depth < 6; depth++, n = composedParent(n)) {
    if (scan.passwords(n).some((p) => p.value)) return n;
  }
  return undefined;
}

/**
 * `scope`: the form or container whose fields are read; `region`: where the user's input must have been just now (the
 * form, or the button clicked).
 */
function capture(scope: Element | null, event: Event, keyboard: boolean, scan = new Scan(), region: Element | null = scope) {
  if (!event.isTrusted || !navigator.userActivation?.isActive || !pageUrl() || !inputJustNow(region)) return;
  const fields = scan.passwords(scope);
  const password = submittedPassword(fields.map((f) => ({ value: f.value, autocomplete: f.getAttribute("autocomplete") ?? "" })));
  if (!password) {
    // First step of an identifier-first login: remember the user name for the password step.
    const user = usernameFieldFor(null, scan, scope);
    if (user?.value && user.value.length <= MAX_USERNAME) callContent("page:identifier", { username: user.value }).catch(ignore);
    return;
  }
  const pw = fields.find((f) => f.value === password);
  // Only a password the user typed (or pasted) into its field, and that nothing changed since.
  if (!pw || !typedNow(pw)) return;
  const user = usernameFieldFor(pw, scan);
  // At most 1 KiB of user name and 4 KiB of password are offered; longer values aren't sent at all (the background checks again).
  if (!credentialsFit(user?.value ?? "", password)) return;
  const key = `${user?.value}\u0000${password}`;
  if (key === lastSent) return;
  lastSent = key;
  callContent("page:submitted", { username: user?.value ?? "", password, keyboard })
    .then((offered) => offered && watchForm(pw))
    .catch(ignore);
}

/**
 * Ask to save only once the login seems to have worked: in single-page apps the URL changes or the password field
 * goes away (page:formDone; after a page load the background shows the prompt itself). `ms`: how long to watch; a
 * generated password's form is watched for minutes (a sign-up takes longer than a sign-in).
 */
export function watchForm(pw: HTMLInputElement, ms = 8_000) {
  const start = location.href;
  const every = ms > 60_000 ? 1_000 : 400;
  const until = Date.now() + ms;
  const timer = setInterval(() => {
    if (location.href !== start || !pw.isConnected || !visible(pw)) {
      clearInterval(timer);
      callContent("page:formDone").catch(ignore);
    } else if (Date.now() > until) {
      clearInterval(timer);
      // Still there: the sign-in most likely failed; trying the same values again is sent again.
      lastSent = "";
    }
  }, every);
}

/** The submit, click and Enter listeners: on the window in the capture phase, so a page's own handlers can't hide a submit first. */
export function installCapture() {
  const note = (e: Event) => {
    if (!e.isTrusted) return;
    const path = e.composedPath()[0];
    lastTouch = { at: Date.now(), target: eventTarget(e) ?? (path instanceof Element ? path : null) };
  };
  for (const type of ["pointerup", "keyup"]) window.addEventListener(type, note, true);
  // Trusted typing, pasting and dropping: what it leaves in the field is what the user typed.
  window.addEventListener(
    "input",
    (e) => {
      if (!e.isTrusted) return;
      note(e);
      const t = eventTarget(e);
      if (t instanceof HTMLInputElement) typed.set(t, t.value);
    },
    true,
  );
  window.addEventListener(
    "pointerdown",
    (e) => {
      if (!e.isTrusted) return;
      lastInput = "pointer";
      note(e);
    },
    true,
  );
  window.addEventListener(
    "keydown",
    (e) => {
      if (!e.isTrusted) return;
      lastInput = "key";
      note(e);
      if (e.key !== "Enter") return;
      const t = eventTarget(e);
      if (!(t instanceof HTMLInputElement)) return;
      const scan = new Scan();
      if (isPasswordField(t, scan) || fieldKind(t, scan) === "login") capture(scopeOf(t), e, true, scan);
    },
    true,
  );
  window.addEventListener("submit", (e) => capture(e.target instanceof HTMLFormElement ? e.target : null, e, lastInput === "key"), true);
  window.addEventListener(
    "click",
    (e) => {
      if (!e.isTrusted) return;
      const t = e.composedPath()[0];
      const btn = t instanceof Element ? t.closest(BUTTONS) : null;
      if (!btn) return;
      const scan = new Scan();
      if (toggleLike(btn, scan)) return;
      // A click with no pointer behind it (detail 0) is Enter or Space on the focused button.
      const keyboard = e.detail === 0;
      // The click itself is the user's input on this button.
      lastTouch = { at: Date.now(), target: btn };
      const scope = submitScope(btn, scan);
      if (scope !== undefined) capture(scope, e, keyboard, scan, btn);
      else if (SUBMIT_WORDS.test(buttonText(btn))) capture(btn instanceof HTMLButtonElement || btn instanceof HTMLInputElement ? btn.form : btn.closest("form"), e, keyboard, scan, btn);
    },
    true,
  );
}
