/**
 * Filling, page side: what the background sends to this one document (shared/protocol.ts `ContentCommandApi`).
 * The background decides with the core's site logic (a login's websites against this document's address, no
 * https → http downgrade, cards only on https pages, cards and identities only on the tab's site) and sends the
 * origin it checked; this document fills only while it still has exactly that origin (origin.ts), so a frame that
 * navigated in between gets nothing. A saved login never goes into a new-password field. Values are set the way
 * typing leaves them (input and change events), and the focus stays in the last field filled.
 */
import { MAX_USERNAME } from "../shared/limits";
import type { CardFillCommand, FillCommand, IdentityFillCommand } from "../shared/protocol";
import { watchForm } from "./capture";
import { contextField } from "./context-field";
import { fieldKind, isPasswordField, loginPasswordField, otpBoxes, otpField, passwordRole, Scan, scopeOf, usernameFieldFor } from "./fields";
import { cardValue, type Field, identityValue } from "./forms";
import { menuField, suppressInlineMenu, targetField } from "./inline";
import { pageUrl } from "./origin";

/** The browser's own value setter (frameworks that wrap `value` on the element still see the change). */
function nativeSetter(el: Field): (v: string) => void {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const set = Object.getOwnPropertyDescriptor(proto, "value")?.set;
  return (v) => {
    if (set) set.call(el, v);
    else el.value = v;
  };
}

/** Set a field's value the way typing leaves it: focus, the native setter, input and change. The focus stays in it. */
export function setValue(el: Field, value: string) {
  el.focus();
  nativeSetter(el)(value);
  el.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  el.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
}

/**
 * Whether this document is still at `origin`, the web origin the background checked before it sent a command (an
 * https one when `https`). No second copy of the site rules: an equality check of the origin this document has.
 */
export function atOrigin(origin: unknown, https = false): boolean {
  const url = pageUrl();
  if (!url || typeof origin !== "string") return false;
  const here = new URL(url).origin;
  return here === origin && (!https || here.startsWith("https:"));
}

/** A one-time code into `el`, or across the single-character boxes it starts. */
function fillCode(el: HTMLInputElement, code: string, scan: Scan): boolean {
  const boxes = otpBoxes(el, scan);
  if (boxes.length === 1) {
    setValue(el, code);
    return true;
  }
  const chars = [...code];
  for (const [i, box] of boxes.slice(0, chars.length).entries()) setValue(box, chars[i]!);
  return true;
}

/** fill: a login into this document. `focused`: at the focused field or the one the inline menu was opened on (and its form). */
export function fillLogin(cmd: FillCommand): boolean {
  if (!atOrigin(cmd.origin)) return false;
  const scan = new Scan();
  const focused = cmd.focused ? targetField() : null;
  suppressInlineMenu();
  // Only a code: the inline menu on a one-time-code field.
  if (!cmd.username && !cmd.password) {
    const target = focused?.isConnected ? focused : otpField(scan);
    return !!cmd.totp && !!target && fillCode(target, cmd.totp, scan);
  }
  let pw: HTMLInputElement | null;
  let user: HTMLInputElement | null;
  if (focused?.isConnected) {
    const scope = scopeOf(focused);
    const kind = fieldKind(focused, scan);
    // A one-time-code field: the code, nothing else.
    if (kind === "otp") return !!cmd.totp && fillCode(focused, cmd.totp, scan);
    if (isPasswordField(focused, scan)) {
      // A new-password field: the form's current-password field, if it has one, never that field.
      pw = passwordRole(focused, scan) === "current" ? focused : loginPasswordField(scan, scope);
      user = usernameFieldFor(pw ?? focused, scan);
    } else {
      pw = loginPasswordField(scan, scope);
      // The user name goes into the focused field only when it is the form's user name field.
      user = kind === "login" ? focused : usernameFieldFor(pw, scan, scope);
    }
  } else {
    pw = loginPasswordField(scan);
    user = usernameFieldFor(pw, scan);
  }
  let filled = false;
  if (user && cmd.username && !isPasswordField(user, scan)) {
    setValue(user, cmd.username);
    filled = true;
  }
  if (pw && cmd.password) {
    setValue(pw, cmd.password);
    filled = true;
  }
  const otp = pw ? null : otpField(scan);
  if (otp && cmd.totp) filled = fillCode(otp, cmd.totp, scan) || filled;
  return filled;
}

/** The form with the most fields `wanted` takes (null: fields outside any form, the document). */
function bestScope(scan: Scan, wanted: (f: Field) => boolean): HTMLFormElement | null {
  const counts = new Map<HTMLFormElement | null, number>();
  for (const f of scan.fields) if (scan.usable(f) && wanted(f)) counts.set(f.form, (counts.get(f.form) ?? 0) + 1);
  return [...counts].sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;
}

/** Fill every usable field of `scope` that `valueFor` has a value for; true if any was. */
function fillParts(scan: Scan, scope: HTMLFormElement | null, valueFor: (f: Field) => string | null): boolean {
  let filled = false;
  for (const f of scan.in(scope)) {
    if (!scan.usable(f)) continue;
    const v = valueFor(f);
    if (v === null) continue;
    setValue(f, v);
    filled = true;
  }
  return filled;
}

/** fill:card: only on https pages, only into fields that ask for a card part (the security code only into a security-code field). */
export function fillCard(cmd: CardFillCommand): boolean {
  if (!atOrigin(cmd.origin, true)) return false;
  const scan = new Scan();
  const focused = cmd.focused ? targetField() : null;
  const scope = focused?.isConnected ? scopeOf(focused) : bestScope(scan, (f) => !!scan.cardPart(f));
  suppressInlineMenu();
  return fillParts(scan, scope, (f) => {
    const part = scan.cardPart(f);
    return part ? cardValue(part, cmd.card, f, scan.hint(f)) : null;
  });
}

/** fill:identity: name, contact and address fields. */
export function fillIdentity(cmd: IdentityFillCommand): boolean {
  if (!atOrigin(cmd.origin)) return false;
  const scan = new Scan();
  const focused = cmd.focused ? targetField() : null;
  const scope = focused?.isConnected ? scopeOf(focused) : bestScope(scan, (f) => !!scan.identityPart(f));
  suppressInlineMenu();
  return fillParts(scan, scope, (f) => {
    const part = scan.identityPart(f);
    return part ? identityValue(part, cmd.identity, f) : null;
  });
}

/**
 * fill:generated: a generated password into the new-password field the inline menu was opened on (`field` "menu"),
 * or into the password field the right-click menu was opened on (`field` "context": any password field, the user
 * asked for it there), and the field's confirmation: when the field is a new password, the form's other
 * new-password fields (never its current password). The form is then watched for minutes, so the save prompt follows
 * the sign-up even when the submit wasn't seen.
 */
export function fillGenerated(password: string, origin: string, field: "menu" | "context" = "menu"): { filled: boolean; username: string } {
  const none = { filled: false, username: "" };
  if (!atOrigin(origin) || !password) return none;
  const scan = new Scan();
  const target = field === "context" ? contextField() : menuField();
  if (!target?.isConnected || !isPasswordField(target, scan)) return none;
  const role = passwordRole(target, scan);
  if (field === "menu" && role !== "new") return none;
  suppressInlineMenu();
  const targets = role === "new" ? scan.passwords(scopeOf(target)).filter((p) => p === target || passwordRole(p, scan) === "new") : [target];
  for (const p of targets) setValue(p, password);
  watchForm(target, 10 * 60_000);
  const username = usernameFieldFor(target, scan)?.value ?? "";
  return { filled: true, username: username.length <= MAX_USERNAME ? username : "" };
}
