/**
 * PassAuth content script (isolated world, every frame).
 * - Fills logins only on explicit request from the background, and only in
 *   frames whose own origin matches the item's websites.
 * - Offers to save credentials after a form is submitted.
 * - Relays WebAuthn requests (passkey bridge).
 */
import type { ContentCommand } from "../shared/messages";
import { baseDomain } from "../background/urls";
import { otpField, passwordFields, setValue, usernameFieldFor } from "./fields";
import { closeInlineMenu, installInlineMenu, suppressInlineMenu } from "./inline";
import { installPasskeyBridge } from "./passkey-bridge";
import { logoSvg, panelCss } from "./brand";

installPasskeyBridge();
installInlineMenu();

// ------------------------------------------------------------------ fill

function fill(cmd: Extract<ContentCommand, { type: "fill" }>): boolean {
  // Never fill a frame from another site (e.g. a third-party iframe); the background verified the tab's URL.
  if (!/^https?:$/.test(location.protocol) || baseDomain(location.hostname) !== cmd.site) return false;
  suppressInlineMenu();
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
  else if (cmd.type === "toast") showToast(cmd.text);
  else if (cmd.type === "inline:close") closeInlineMenu();
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
      .b { width: 320px; }
      .a { display: flex; gap: 8px; flex-wrap: wrap; }
      ${panelCss}
    </style>
    <div class="b" role="dialog" aria-label="PassAuth">
      <div class="t">
        ${logoSvg(22)}
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

// ------------------------------------------------------------------ toast

function showToast(text: string) {
  if (window.top !== window) return;
  const hostEl = document.createElement("passauth-toast");
  const shadow = hostEl.attachShadow({ mode: "closed" });
  shadow.innerHTML = `
    <style>
      :host { all: initial; position: fixed; top: 16px; right: 16px; z-index: 2147483647; }
      ${panelCss}
      .b { padding: 12px 14px; max-width: 320px; }
    </style>
    <div class="b" role="status"><div class="t">${logoSvg(20)}<span></span></div></div>`;
  shadow.querySelector("span")!.textContent = text;
  (document.body ?? document.documentElement).appendChild(hostEl);
  setTimeout(() => hostEl.remove(), 4000);
}
