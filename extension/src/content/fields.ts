/** Login field detection shared by autofill, save prompts and the inline menu. Open shadow roots are searched too. */

/**
 * Whether the user can actually see the field. Fields that are tiny, placed
 * off the page, transparent or hidden by an ancestor are never filled or
 * offered (a page could otherwise collect filled credentials from invisible fields).
 */
export function visible(el: HTMLElement) {
  const r = el.getBoundingClientRect();
  if (r.width < 4 || r.height < 4) return false;
  if (r.right + scrollX <= 0 || r.bottom + scrollY <= 0) return false;
  const s = getComputedStyle(el);
  if (s.visibility !== "visible" || s.display === "none" || parseFloat(s.opacity) < 0.1) return false;
  // Transparent or hidden ancestors (checkVisibility covers the whole flat tree).
  return el.checkVisibility?.({ opacityProperty: true, visibilityProperty: true, checkOpacity: true, checkVisibilityCSS: true } as CheckVisibilityOptions) ?? true;
}

const USER_HINT = /user|email|login|account|identifier|mail|e-mail|username/i;
const OTP_HINT = /otp|totp|2fa|mfa|one.?time|verification|auth.?code|security.?code/i;
const TEXT_TYPES = ["text", "email", "tel", ""];

export function attrs(i: HTMLInputElement) {
  return `${i.name} ${i.id} ${i.autocomplete} ${i.placeholder} ${i.getAttribute("aria-label") ?? ""}`;
}

/** Every <input> under `root` in document order, including those inside open shadow roots (web components). */
export function allInputs(root: ParentNode = document): HTMLInputElement[] {
  const out: HTMLInputElement[] = [];
  const visit = (node: ParentNode) => {
    const walker = document.createTreeWalker(node, NodeFilter.SHOW_ELEMENT);
    for (let el = walker.nextNode() as Element | null; el; el = walker.nextNode() as Element | null) {
      if (el instanceof HTMLInputElement) out.push(el);
      if (el.shadowRoot) visit(el.shadowRoot);
    }
  };
  visit(root);
  return out;
}

const usable = (i: HTMLInputElement) => visible(i) && !i.disabled && !i.readOnly;

export function passwordFields(root: ParentNode = document) {
  return allInputs(root).filter((i) => i.type === "password" && usable(i));
}

/** The username field for `pw` (or, without one, a likely username field in `scope`). */
export function usernameFieldFor(pw: HTMLInputElement | null, scope: ParentNode = pw?.form ?? document): HTMLInputElement | null {
  const inputs = allInputs(scope);
  const candidates = inputs.filter((i) => usable(i) && TEXT_TYPES.includes(i.type) && !OTP_HINT.test(attrs(i)));
  const byAutocomplete = candidates.find((i) => /username|email/.test(i.autocomplete));
  if (byAutocomplete) return byAutocomplete;
  if (pw) {
    // The closest text field before the password field.
    const at = inputs.indexOf(pw);
    const before = candidates.filter((i) => at < 0 || inputs.indexOf(i) < at);
    return before.at(-1) ?? null;
  }
  return candidates.find((i) => USER_HINT.test(attrs(i))) ?? null;
}

export function otpField(): HTMLInputElement | null {
  return allInputs().find((i) => usable(i) && (i.autocomplete === "one-time-code" || (OTP_HINT.test(attrs(i)) && i.type !== "password"))) ?? null;
}

/** A password field, the username field of a login form, or the first step of an identifier-first login. */
export function isLoginField(el: EventTarget | null): el is HTMLInputElement {
  if (!(el instanceof HTMLInputElement) || el.disabled || el.readOnly || !visible(el)) return false;
  if (el.type === "password") return true;
  if (!TEXT_TYPES.includes(el.type) || OTP_HINT.test(attrs(el)) || /search/i.test(attrs(el))) return false;
  const pw = passwordFields(el.form ?? document)[0];
  if (pw) return usernameFieldFor(pw) === el;
  return /username|email/.test(el.autocomplete) || USER_HINT.test(`${el.name} ${el.id} ${el.getAttribute("aria-label") ?? ""}`);
}

/** The focused element, looking inside open shadow roots. */
export function deepActiveElement(): Element | null {
  let a = document.activeElement;
  while (a?.shadowRoot?.activeElement) a = a.shadowRoot.activeElement;
  return a;
}

export function setValue(el: HTMLInputElement, value: string) {
  el.focus();
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(el, value);
  el.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  el.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
  el.blur();
}
