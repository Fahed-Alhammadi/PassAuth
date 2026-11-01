/** Login field detection shared by autofill, save prompts and the inline menu. */

export function visible(el: HTMLElement) {
  const r = el.getBoundingClientRect();
  const s = getComputedStyle(el);
  return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none";
}

const USER_HINT = /user|email|login|account|identifier|mail|e-mail|username/i;
const OTP_HINT = /otp|totp|2fa|mfa|one.?time|verification|auth.?code|security.?code/i;
const TEXT_TYPES = ["text", "email", "tel", ""];

export function attrs(i: HTMLInputElement) {
  return `${i.name} ${i.id} ${i.autocomplete} ${i.placeholder} ${i.getAttribute("aria-label") ?? ""}`;
}

export function passwordFields(root: ParentNode = document) {
  return [...root.querySelectorAll<HTMLInputElement>('input[type="password"]')].filter((i) => visible(i) && !i.disabled && !i.readOnly);
}

export function usernameFieldFor(pw: HTMLInputElement | null): HTMLInputElement | null {
  const scope: ParentNode = pw?.form ?? document;
  const candidates = [...scope.querySelectorAll<HTMLInputElement>("input")].filter(
    (i) => visible(i) && !i.disabled && TEXT_TYPES.includes(i.type) && !OTP_HINT.test(attrs(i)),
  );
  const byAutocomplete = candidates.find((i) => /username|email/.test(i.autocomplete));
  if (byAutocomplete) return byAutocomplete;
  if (pw) {
    // The closest text field before the password field.
    const before = candidates.filter((i) => i.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING);
    return before.at(-1) ?? null;
  }
  return candidates.find((i) => USER_HINT.test(attrs(i))) ?? null;
}

export function otpField(): HTMLInputElement | null {
  return (
    [...document.querySelectorAll<HTMLInputElement>("input")].find(
      (i) => visible(i) && !i.disabled && (i.autocomplete === "one-time-code" || (OTP_HINT.test(attrs(i)) && i.type !== "password")),
    ) ?? null
  );
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

export function setValue(el: HTMLInputElement, value: string) {
  el.focus();
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(el, value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
  el.blur();
}
