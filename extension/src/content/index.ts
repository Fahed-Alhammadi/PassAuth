/**
 * PassAuth content script (isolated world, every frame).
 * - Fills logins only on explicit request from the background, and only in
 *   frames whose own origin matches the item's websites.
 * - Offers to save credentials after a form is submitted.
 * - Relays WebAuthn requests (passkey bridge).
 */
import type { ContentCommand } from "../shared/messages";
import { matchesUrl } from "../background/urls";
import { installPasskeyBridge } from "./passkey-bridge";

installPasskeyBridge();

// ------------------------------------------------------------------ fields

function visible(el: HTMLElement) {
  const r = el.getBoundingClientRect();
  const s = getComputedStyle(el);
  return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none";
}

const USER_HINT = /user|email|login|account|identifier|mail|e-mail|username/i;
const OTP_HINT = /otp|totp|2fa|mfa|one.?time|verification|auth.?code|security.?code/i;

function passwordFields(root: ParentNode = document) {
  return [...root.querySelectorAll<HTMLInputElement>('input[type="password"]')].filter((i) => visible(i) && !i.disabled && !i.readOnly);
}

function usernameFieldFor(pw: HTMLInputElement | null): HTMLInputElement | null {
  const scope: ParentNode = pw?.form ?? document;
  const candidates = [...scope.querySelectorAll<HTMLInputElement>("input")].filter(
    (i) => visible(i) && !i.disabled && ["text", "email", "tel", ""].includes(i.type) && !OTP_HINT.test(attrs(i)),
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

function otpField(): HTMLInputElement | null {
  return (
    [...document.querySelectorAll<HTMLInputElement>("input")].find(
      (i) => visible(i) && !i.disabled && (i.autocomplete === "one-time-code" || (OTP_HINT.test(attrs(i)) && i.type !== "password")),
    ) ?? null
  );
}

function attrs(i: HTMLInputElement) {
  return `${i.name} ${i.id} ${i.autocomplete} ${i.placeholder} ${i.getAttribute("aria-label") ?? ""}`;
}

function setValue(el: HTMLInputElement, value: string) {
  el.focus();
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(el, value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
  el.blur();
}

function fill(cmd: Extract<ContentCommand, { type: "fill" }>): boolean {
  // Never fill a frame that isn't the saved website (e.g. a third-party iframe).
  if (cmd.itemUrls.length && !cmd.itemUrls.some((url) => matchesUrl(location.href, { url, match: "domain" }))) return false;
  const pw = passwordFields()[0] ?? null;
  const user = usernameFieldFor(pw);
  let filled = false;
  if (user && cmd.username) (setValue(user, cmd.username), (filled = true));
  if (pw && cmd.password) (setValue(pw, cmd.password), (filled = true));
  const otp = otpField();
  if (!pw && otp && cmd.totp) (setValue(otp, cmd.totp), (filled = true));
  return filled;
}

chrome.runtime.onMessage.addListener((cmd: ContentCommand, _sender, respond) => {
  if (cmd.type === "fill") respond({ filled: fill(cmd) });
  else if (cmd.type === "showSave") showSaveBanner(cmd.host, cmd.update);
  else if (cmd.type === "probe") respond({ hasLogin: passwordFields().length > 0 });
});

// ---------------------------------------------------------------- capture

let lastSent = "";

function capture(form: HTMLFormElement | null) {
  const pw = (form ? passwordFields(form) : passwordFields()).find((p) => p.value);
  if (!pw) return;
  const user = usernameFieldFor(pw);
  const key = `${user?.value}\u0000${pw.value}`;
  if (key === lastSent) return;
  lastSent = key;
  chrome.runtime
    .sendMessage({ type: "page:submitted", url: location.href, username: user?.value ?? "", password: pw.value })
    .then((r) => r?.ok && r.data && showSaveBanner(r.data.host, r.data.update))
    .catch(() => {});
}

document.addEventListener("submit", (e) => capture(e.target as HTMLFormElement), true);
document.addEventListener(
  "click",
  (e) => {
    const btn = (e.target as HTMLElement).closest?.('button, input[type="submit"], [role="button"]');
    if (btn && /log ?in|sign ?in|continue|next|submit|save|update|register|sign ?up/i.test(btn.textContent + " " + (btn as HTMLInputElement).value)) {
      capture((btn as HTMLButtonElement).form ?? btn.closest("form"));
    }
  },
  true,
);
document.addEventListener(
  "keydown",
  (e) => {
    if (e.key === "Enter" && (e.target as HTMLInputElement).type === "password") capture((e.target as HTMLInputElement).form);
  },
  true,
);

// After a navigation (the form page is gone), show any pending prompt here.
if (window.top === window) {
  const ask = () =>
    chrome.runtime
      .sendMessage({ type: "page:pendingSave" })
      .then((r) => r?.ok && r.data && showSaveBanner(r.data.host, r.data.update))
      .catch(() => {});
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", ask, { once: true });
  else ask();
}

// ------------------------------------------------------------- save banner

let banner: HTMLElement | null = null;

function showSaveBanner(host: string, update: boolean) {
  if (window.top !== window || banner) return;
  const hostEl = document.createElement("passauth-save");
  const shadow = hostEl.attachShadow({ mode: "closed" });
  shadow.innerHTML = `
    <style>
      :host { all: initial; position: fixed; top: 16px; right: 16px; z-index: 2147483647; }
      .b { font: 14px/1.45 system-ui, sans-serif; width: 320px; background: #1b2a41; color: #e6ebf2; border-radius: 12px;
           box-shadow: 0 12px 32px rgb(0 0 0 / .3); padding: 16px; display: grid; gap: 12px; }
      .t { display: flex; gap: 10px; align-items: center; font-weight: 600; }
      .t svg { flex: none; }
      p { margin: 0; color: #b4bfcd; overflow-wrap: anywhere; }
      .a { display: flex; gap: 8px; flex-wrap: wrap; }
      button { font: inherit; border-radius: 6px; padding: 7px 12px; cursor: pointer; border: 1px solid #44546b; background: transparent; color: #e6ebf2; }
      button.p { background: #c99a3e; border-color: #c99a3e; color: #1b2a41; font-weight: 600; }
      button:focus-visible { outline: 2px solid #6fb3b6; outline-offset: 2px; }
    </style>
    <div class="b" role="dialog" aria-label="PassAuth">
      <div class="t">
        <svg width="22" height="22" viewBox="0 0 64 64" aria-hidden="true"><rect width="64" height="64" rx="14" fill="#0e1622"/><g fill="#c99a3e"><path d="M34 8.5a15.5 15.5 0 1 1 0 31 15.5 15.5 0 0 1 0-31zm0 7a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17z"/><rect x="17" y="10" width="7.5" height="45" rx="3.75"/><rect x="23" y="41" width="9" height="5" rx="1.5"/><rect x="23" y="49" width="6" height="5" rx="1.5"/></g></svg>
        <span>${update ? "Update saved password?" : "Save this login?"}</span>
      </div>
      <p></p>
      <div class="a">
        <button class="p" data-a="save">${update ? "Update" : "Save"}</button>
        <button data-a="dismiss">Not now</button>
        ${update ? "" : '<button data-a="never">Never for this site</button>'}
      </div>
    </div>`;
  shadow.querySelector("p")!.textContent = update
    ? `PassAuth has a different password for this account on ${host}.`
    : `Save the username and password for ${host} to your PassAuth vault.`;
  shadow.querySelectorAll<HTMLButtonElement>("button").forEach((b) =>
    b.addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "page:save", accept: b.dataset.a }).catch(() => {});
      hostEl.remove();
      banner = null;
    }),
  );
  (document.body ?? document.documentElement).appendChild(hostEl);
  banner = hostEl;
  setTimeout(() => {
    if (banner === hostEl) (hostEl.remove(), (banner = null));
  }, 30_000);
}
