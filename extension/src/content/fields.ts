/**
 * Field detection shared by filling, save prompts and the inline menu: login fields (user name, current
 * password), new-password, one-time-code, card and identity fields. Each event handler takes one `Scan` of the
 * page: the fields are walked once (open shadow roots, and the closed ones of custom elements through
 * chrome.dom.openOrClosedShadowRoot), and each field's visibility and hint text (name, id, placeholder,
 * aria-label, aria-labelledby, <label>s, title) are worked out at most once. Unit-tested in test/fields.test.ts.
 */
import { autofillToken, type CardPart, cardPart, type Field, hasCardNumber, type IdentityPart, identityPart, identityPartCount } from "./forms";

export type { Field };

/** What a field is for: what the inline menu lists there and what a fill puts in. */
export type FieldKind = "login" | "new-password" | "otp" | "card" | "identity";

/**
 * Whether the user can actually see the field. Fields that are tiny, placed off the page, transparent or hidden
 * by an ancestor are never filled or offered (a page could otherwise collect filled credentials from invisible
 * fields).
 */
export function visible(el: HTMLElement): boolean {
  const r = el.getBoundingClientRect();
  if (r.width < 4 || r.height < 4) return false;
  if (r.right + scrollX <= 0 || r.bottom + scrollY <= 0) return false;
  const s = getComputedStyle(el);
  if (s.visibility === "hidden" || s.visibility === "collapse" || s.display === "none" || parseFloat(s.opacity) < 0.1) return false;
  // Transparent or hidden ancestors (checkVisibility covers the whole flat tree).
  return el.checkVisibility?.({ opacityProperty: true, visibilityProperty: true, checkOpacity: true, checkVisibilityCSS: true } as CheckVisibilityOptions) ?? true;
}

const USER_HINT = /user|e-?mail|login|account|identifier|username|mail/;
const OTP_HINT = /otp|totp|2fa|mfa|one.?time|verification|auth.?code|security.?code|passcode|sms.?code/;
const SEARCH_HINT = /search|query/;
const PASSWORD_HINT = /pass|pwd|kennwort|contrase|mot.?de.?passe|senha/;
const NEW_PASSWORD_HINT = /\bnew|confirm|repeat|retype|re-?enter|again|create|choose/;
const CURRENT_PASSWORD_HINT = /current|\bold|existing/;
const TEXT_TYPES = new Set(["text", "email", "tel", ""]);
const OTP_TYPES = new Set(["text", "tel", "number", ""]);

/**
 * The shadow root of `el`, open or closed. Closed ones are looked up (chrome.dom) only on custom elements: web
 * components are where closed roots with form fields live, and the lookup on every element of a page would cost.
 */
export function shadowOf(el: Element): ShadowRoot | null {
  if (el.shadowRoot) return el.shadowRoot;
  if (!el.localName.includes("-")) return null;
  try {
    return chrome.dom?.openOrClosedShadowRoot?.(el as HTMLElement) ?? null;
  } catch {
    return null;
  }
}

/** The parent in the flat tree: the parent node, or a shadow root's host. */
export const composedParent = (n: Node): Node | null => n.parentNode ?? (n as Partial<ShadowRoot>).host ?? null;

/** Whether `node` is `container` or inside it, across shadow roots. */
export function composedContains(container: Node, node: Node): boolean {
  for (let n: Node | null = node; n; n = composedParent(n)) if (n === container) return true;
  return false;
}

/** The focused element, looking inside open shadow roots and the closed ones of custom elements. */
export function deepActiveElement(): Element | null {
  let a = document.activeElement;
  for (let s = a ? shadowOf(a) : null; a && s?.activeElement; s = shadowOf(a)) a = s.activeElement;
  return a;
}

/** The element an event really happened on: inside a closed shadow root the event's path stops at the host. */
export function eventTarget(e: Event): Element | null {
  const t = e.composedPath()[0];
  if (!(t instanceof Element)) return null;
  let a: Element = t;
  for (let s = shadowOf(a); s?.activeElement; s = shadowOf(a)) a = s.activeElement;
  return a;
}

const isField = (el: Element): el is Field => el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement;

/** Every form field under `root` in document order, shadow roots included. */
function allFields(root: Node): Field[] {
  const out: Field[] = [];
  const visit = (node: Node) => {
    const walker = document.createTreeWalker(node, NodeFilter.SHOW_ELEMENT);
    for (let el = walker.nextNode() as Element | null; el; el = walker.nextNode() as Element | null) {
      if (isField(el)) out.push(el);
      const shadow = shadowOf(el);
      if (shadow) visit(shadow);
    }
  };
  visit(root);
  return out;
}

/** A label's own words, without the options or values of fields inside it. */
function labelText(label: Element): string {
  let out = "";
  const walker = document.createTreeWalker(label, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n && out.length < 120; n = walker.nextNode()) {
    if (n.parentElement?.closest("select, textarea, option, button")) continue;
    out += ` ${n.nodeValue ?? ""}`;
  }
  return out;
}

/** Name, id, placeholder, aria-label, aria-labelledby, <label>s and title, in lower case. */
function hintText(el: Field): string {
  const parts = [el.name, el.id, el.getAttribute("placeholder"), el.getAttribute("aria-label"), el.getAttribute("title")];
  const ids = el.getAttribute("aria-labelledby");
  if (ids) {
    const root = el.getRootNode() as Document | ShadowRoot;
    for (const id of ids.split(/\s+/).slice(0, 4)) {
      const label = id ? root.getElementById?.(id) : null;
      if (label) parts.push(labelText(label));
    }
  }
  for (const label of Array.from(el.labels ?? []).slice(0, 3)) parts.push(labelText(label));
  return parts
    .map((p) => (p ?? "").replace(/\s+/g, " ").trim().slice(0, 120))
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

/** The form of `el` (null: the whole document is its scope). */
export const scopeOf = (el: Field): HTMLFormElement | null => el.form;

/** A password field: type "password", or one shown as text (a "show password" button) that still says so. */
export function isPasswordField(el: Element, scan?: Scan): boolean {
  if (!(el instanceof HTMLInputElement)) return false;
  if (el.type === "password") return true;
  if (el.type !== "text" || !/^(current|new)-password$/.test(autofillToken(el))) return false;
  return PASSWORD_HINT.test(scan ? scan.hint(el) : hintText(el));
}

/** One look at the page's fields for one event (see the file comment). Cheap to make: nothing is read before it is asked for. */
export class Scan {
  #fields: Field[] | null = null;
  readonly #usable = new Map<Field, boolean>();
  readonly #hints = new Map<Field, string>();
  readonly #scopes = new Map<Element | null, Field[]>();
  readonly #cardForms = new Map<Element | null, boolean>();
  readonly #identityForms = new Map<Element | null, boolean>();

  /** Every form field of the document (and its shadow roots), in document order. */
  get fields(): readonly Field[] {
    this.#fields ??= allFields(document);
    return this.#fields;
  }

  /** The fields inside `scope` (a form or another element; null: all of them), in document order. */
  in(scope: Element | null): Field[] {
    let list = this.#scopes.get(scope);
    if (!list) {
      list = scope ? this.fields.filter((f) => (scope instanceof HTMLFormElement && f.form === scope) || composedContains(scope, f)) : [...this.fields];
      this.#scopes.set(scope, list);
    }
    return list;
  }

  inputs(scope: Element | null = null): HTMLInputElement[] {
    return this.in(scope).filter((f): f is HTMLInputElement => f instanceof HTMLInputElement);
  }

  /** Visible, enabled and editable. */
  usable(el: Field): boolean {
    let ok = this.#usable.get(el);
    if (ok === undefined) {
      ok = !el.disabled && !(el instanceof HTMLSelectElement ? false : el.readOnly) && visible(el);
      this.#usable.set(el, ok);
    }
    return ok;
  }

  hint(el: Field): string {
    let h = this.#hints.get(el);
    if (h === undefined) {
      h = hintText(el);
      this.#hints.set(el, h);
    }
    return h;
  }

  /** Usable password fields inside `scope` (null: the whole document). */
  passwords(scope: Element | null = null): HTMLInputElement[] {
    return this.inputs(scope).filter((i) => isPasswordField(i, this) && this.usable(i));
  }

  /** The card part `el` asks for (hint-text matches count only in a form with a card number field). */
  cardPart(el: Field): CardPart | null {
    return cardPart(el, this.hint(el), () => this.cardForm(scopeOf(el)));
  }

  /** Whether `scope` has a card number field. */
  cardForm(scope: Element | null): boolean {
    let yes = this.#cardForms.get(scope);
    if (yes === undefined) {
      yes = hasCardNumber(
        this.in(scope).filter((f) => this.usable(f)),
        (f) => this.hint(f),
      );
      this.#cardForms.set(scope, yes);
    }
    return yes;
  }

  /** Whether `scope` asks for two or more identity parts (name, address, phone, …). */
  identityForm(scope: Element | null): boolean {
    let yes = this.#identityForms.get(scope);
    if (yes === undefined) {
      yes =
        identityPartCount(
          this.in(scope).filter((f) => this.usable(f)),
          (f) => this.hint(f),
        ) >= 2;
      this.#identityForms.set(scope, yes);
    }
    return yes;
  }

  /** The identity part `el` asks for (hint-text matches count only in an identity form). */
  identityPart(el: Field): IdentityPart | null {
    return identityPart(el, this.hint(el), () => this.identityForm(scopeOf(el)));
  }
}

/** "new": a sign-up or new-password field (never filled from a saved login); "current": a sign-in password. */
export function passwordRole(pw: HTMLInputElement, scan: Scan): "new" | "current" {
  const token = autofillToken(pw);
  if (token === "new-password") return "new";
  if (token === "current-password") return "current";
  const hint = scan.hint(pw);
  if (CURRENT_PASSWORD_HINT.test(hint)) return "current";
  if (NEW_PASSWORD_HINT.test(hint)) return "new";
  // Without hints: two password fields are a password and its confirmation; with three, the first is the current one.
  const all = scan.passwords(scopeOf(pw));
  if (all.length === 2) return "new";
  if (all.length >= 3) return all.indexOf(pw) === 0 ? "current" : "new";
  return "current";
}

/** The password field a saved login goes into: a current-password field, never a new-password one. */
export function loginPasswordField(scan: Scan, scope: Element | null = null): HTMLInputElement | null {
  const all = scan.passwords(scope);
  return all.find((p) => autofillToken(p) === "current-password") ?? all.find((p) => passwordRole(p, scan) === "current") ?? null;
}

/** The username field for `pw` (or, without one, a likely username field in `scope`). */
export function usernameFieldFor(pw: HTMLInputElement | null, scan: Scan, scope: Element | null = pw ? scopeOf(pw) : null): HTMLInputElement | null {
  const inputs = scan.inputs(scope);
  const candidates = inputs.filter((i) => TEXT_TYPES.has(i.type) && !isPasswordField(i, scan) && scan.usable(i) && !OTP_HINT.test(scan.hint(i)) && !SEARCH_HINT.test(scan.hint(i)));
  const byAutocomplete = candidates.find((i) => /^(username|email)$/.test(autofillToken(i)));
  if (byAutocomplete) return byAutocomplete;
  if (pw) {
    // The closest text field before the password field.
    const at = inputs.indexOf(pw);
    return candidates.filter((i) => at < 0 || inputs.indexOf(i) < at).at(-1) ?? null;
  }
  return candidates.find((i) => USER_HINT.test(scan.hint(i))) ?? null;
}

/** Single-character boxes in a row (four to eight): a one-time code typed one digit per box. */
function boxGroup(el: HTMLInputElement, scan: Scan): HTMLInputElement[] {
  const isBox = (i: HTMLInputElement | undefined): i is HTMLInputElement => !!i && i.maxLength === 1 && OTP_TYPES.has(i.type) && scan.usable(i);
  if (!isBox(el)) return [];
  const row = scan.inputs(scopeOf(el));
  let start = row.indexOf(el);
  if (start < 0) return [];
  while (start > 0 && isBox(row[start - 1])) start--;
  const group: HTMLInputElement[] = [];
  for (let i = start; i < row.length && isBox(row[i]) && group.length < 8; i++) group.push(row[i]!);
  return group.length >= 4 ? group : [];
}

/** The one-time-code boxes starting at the group `el` belongs to, or just `el` when it is a single field. */
export function otpBoxes(el: HTMLInputElement, scan: Scan): HTMLInputElement[] {
  const group = boxGroup(el, scan);
  return group.length ? group : [el];
}

function isOtpField(el: HTMLInputElement, scan: Scan): boolean {
  if (autofillToken(el) === "one-time-code") return true;
  if (!OTP_TYPES.has(el.type)) return false;
  return OTP_HINT.test(scan.hint(el)) || boxGroup(el, scan).length > 0;
}

/** The first one-time-code field on the page. */
export function otpField(scan: Scan): HTMLInputElement | null {
  return scan.inputs().find((i) => scan.usable(i) && !scan.cardPart(i) && isOtpField(i, scan)) ?? null;
}

/** What `el` is for, or null when PassAuth has nothing for it (see FieldKind). */
export function fieldKind(el: Element | null, scan: Scan): FieldKind | null {
  if (!(el instanceof HTMLInputElement) || !scan.usable(el)) return null;
  const token = autofillToken(el);
  if (token === "one-time-code") return "otp";
  // A card field, a security code typed into a password field included.
  if (scan.cardPart(el)) return "card";
  if (isPasswordField(el, scan)) return passwordRole(el, scan) === "new" ? "new-password" : "login";
  if (token === "username") return "login";
  const hint = scan.hint(el);
  if (!OTP_TYPES.has(el.type) && !TEXT_TYPES.has(el.type)) return null;
  if (SEARCH_HINT.test(hint)) return null;
  if (isOtpField(el, scan)) return "otp";
  if (!TEXT_TYPES.has(el.type)) return null;
  const scope = scopeOf(el);
  const identity = scan.identityPart(el);
  const pw = scan.passwords(scope)[0];
  if (pw) {
    // A sign-in or sign-up form: its user name field is a login field; its name or address fields are identity fields.
    if (usernameFieldFor(pw, scan) === el) return "login";
    return identity ? "identity" : null;
  }
  // E-mail and user name fields are the first step of a sign-in, unless the form asks for a name and address too.
  if (identity && ((identity !== "email" && identity !== "username") || scan.identityForm(scope))) return "identity";
  if (/^(username|email)$/.test(token) || USER_HINT.test(hint)) return "login";
  return null;
}

/** The kinds of fill a frame can take (for fill offers): whether it has a login, card or identity form. */
export function hasFields(scan: Scan, what: "login" | "card" | "identity"): boolean {
  if (what === "login") return scan.passwords().length > 0 || !!otpField(scan);
  if (what === "card") return scan.fields.some((f) => scan.usable(f) && !!scan.cardPart(f));
  return scan.fields.some((f) => scan.usable(f) && !!scan.identityPart(f));
}
