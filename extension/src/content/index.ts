/**
 * PassAuth content script (isolated world, every frame).
 * - Fills logins only on explicit request from the background, sent to this
 *   frame alone, and only if the item's websites match this frame's own URL.
 * - Offers to save credentials after a successful submit (the page changed or
 *   the form went away).
 * - Relays WebAuthn requests (passkey bridge).
 */
import type { ContentCommand, SaveOffer } from "../shared/messages";
import type { LoginUrl, UrlMatch } from "@web/lib/types";
import { baseDomain, downgrade, matchesUrl } from "../background/urls";
import { isLoginField, otpField, passwordFields, setValue, usernameFieldFor, visible } from "./fields";
import { submittedPassword } from "./pick";
import { closeInlineMenu, currentField, installInlineMenu, suppressInlineMenu } from "./inline";
import { installPasskeyBridge } from "./passkey-bridge";
import { logoSvg, panelCss } from "./brand";
import { tampered, visibilityGate } from "./guard";

installPasskeyBridge();
installInlineMenu();

// ------------------------------------------------------------------ fill

/** The item's websites must match this frame (not just the tab), and no https → http downgrade. */
function frameAllowed(urls: LoginUrl[], defaultMatch: Exclude<UrlMatch, "default">, site: string) {
  if (!/^https?:$/.test(location.protocol)) return false;
  if (!urls.length) return baseDomain(location.hostname) === site;
  return urls.some((u) => matchesUrl(location.href, u, defaultMatch)) && !urls.some((u) => downgrade(location.href, u));
}

function fill(cmd: Extract<ContentCommand, { type: "fill" }>): boolean {
  if (!frameAllowed(cmd.urls, cmd.defaultMatch, cmd.site)) return false;
  const focused = cmd.focused ? currentField() : null;
  suppressInlineMenu();
  let pw: HTMLInputElement | null;
  let user: HTMLInputElement | null;
  if (focused?.isConnected) {
    // The field the inline menu was opened on, and its partner in the same form.
    pw = focused.type === "password" ? focused : (passwordFields(focused.form ?? document)[0] ?? null);
    user = focused.type === "password" ? usernameFieldFor(focused) : focused;
  } else {
    pw = passwordFields()[0] ?? null;
    user = usernameFieldFor(pw);
  }
  let filled = false;
  if (user && cmd.username) (setValue(user, cmd.username), (filled = true));
  if (pw && cmd.password) (setValue(pw, cmd.password), (filled = true));
  const otp = otpField();
  if (!pw && otp && cmd.totp) (setValue(otp, cmd.totp), (filled = true));
  return filled;
}

chrome.runtime.onMessage.addListener((cmd: ContentCommand, _sender, respond) => {
  if (cmd.type === "fill") respond({ filled: fill(cmd) });
  else if (cmd.type === "fill:offer") {
    // No secrets in an offer: claim it only if this frame has a login form for the item.
    if (frameAllowed(cmd.urls, cmd.defaultMatch, cmd.site) && (passwordFields().length || otpField())) {
      chrome.runtime.sendMessage({ type: "page:fillClaim", token: cmd.token }).catch(() => {});
    }
  } else if (cmd.type === "showSave") showSaveBanner(cmd);
  else if (cmd.type === "toast") showToast(cmd.text);
  else if (cmd.type === "inline:close") closeInlineMenu();
});

// ---------------------------------------------------------------- capture

let lastSent = "";

function capture(form: HTMLFormElement | null) {
  const fields = form ? passwordFields(form) : passwordFields();
  const password = submittedPassword(fields.map((f) => ({ value: f.value, autocomplete: f.autocomplete })));
  if (!password) {
    // First step of an identifier-first login: remember the username for the password step.
    const user = usernameFieldFor(null, form ?? document);
    if (user?.value) chrome.runtime.sendMessage({ type: "page:identifier", username: user.value }).catch(() => {});
    return;
  }
  const pw = fields.find((f) => f.value === password)!;
  const user = usernameFieldFor(pw);
  const key = `${user?.value}\u0000${password}`;
  if (key === lastSent) return;
  lastSent = key;
  chrome.runtime
    .sendMessage({ type: "page:submitted", username: user?.value ?? "", password })
    .then((r) => r?.ok && r.data && watchForm(pw))
    .catch(() => {});
}

/**
 * Ask to save only once the login seems to have worked: the page navigates
 * (the next page asks, see below) or, in single-page apps, the URL changes or
 * the password field goes away. A form that stays (wrong password) never prompts.
 */
function watchForm(pw: HTMLInputElement) {
  const start = location.href;
  let tries = 0;
  const timer = setInterval(() => {
    tries++;
    if (location.href !== start || !pw.isConnected || !visible(pw)) {
      clearInterval(timer);
      chrome.runtime.sendMessage({ type: "page:formDone" }).catch(() => {});
    } else if (tries > 20) clearInterval(timer);
  }, 400);
}

document.addEventListener("submit", (e) => capture(e.target as HTMLFormElement), true);
document.addEventListener(
  "click",
  (e) => {
    const btn = (e.composedPath()[0] as HTMLElement).closest?.('button, input[type="submit"], [role="button"]');
    if (btn && /log ?in|sign ?in|continue|next|submit|save|update|register|sign ?up/i.test(btn.textContent + " " + (btn as HTMLInputElement).value)) {
      capture((btn as HTMLButtonElement).form ?? btn.closest("form"));
    }
  },
  true,
);
document.addEventListener(
  "keydown",
  (e) => {
    const t = e.composedPath()[0] as HTMLInputElement;
    if (e.key === "Enter" && t instanceof HTMLInputElement && (t.type === "password" || isLoginField(t))) capture(t.form);
  },
  true,
);

// After a navigation (the form page is gone), show any pending prompt here —
// unless this page shows a password field again (the sign-in most likely failed).
if (window.top === window) {
  const ask = () =>
    setTimeout(() => {
      if (passwordFields().length) return;
      chrome.runtime
        .sendMessage({ type: "page:pendingSave" })
        .then((r) => r?.ok && r.data && showSaveBanner(r.data))
        .catch(() => {});
    }, 600);
  if (document.readyState === "complete") ask();
  else addEventListener("load", ask, { once: true });
}

// ------------------------------------------------------------- save banner

let banner: HTMLElement | null = null;

function showSaveBanner(offer: SaveOffer) {
  if (window.top !== window || banner) return;
  const { host, update, username, nonce } = offer;
  const hostEl = document.createElement("passauth-save");
  const shadow = hostEl.attachShadow({ mode: "closed" });
  shadow.innerHTML = `
    <style>
      :host { all: initial; position: fixed !important; top: 16px !important; right: 16px !important; z-index: 2147483647 !important;
              opacity: 1 !important; filter: none !important; clip-path: none !important; visibility: visible !important; }
      .b { width: 320px; }
      .a { display: flex; gap: 8px; flex-wrap: wrap; }
      strong { color: #fff; font-weight: 600; }
      ${panelCss}
    </style>
    <div class="b" role="dialog" aria-labelledby="t" aria-describedby="d">
      <div class="t">
        ${logoSvg(22)}
        <span id="t">${update ? "Update saved password?" : "Save this login?"}</span>
      </div>
      <p id="d"></p>
      <div class="a">
        <button class="p" data-a="save">${update ? "Update" : "Save"}</button>
        <button data-a="dismiss">Not now</button>
        ${update ? "" : '<button data-a="never">Never for this site</button>'}
      </div>
    </div>`;
  // Name the account, so the user can check what will be saved.
  const p = shadow.querySelector("p")!;
  const who = document.createElement("strong");
  who.textContent = username || "this account";
  p.append(update ? "PassAuth has a different password for " : "Save the password for ", who, ` on ${host} ${update ? "" : "to your PassAuth vault"}`.trimEnd() + ".");
  const box = shadow.querySelector<HTMLElement>(".b")!;
  const gate = visibilityGate(box);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const close = () => {
    clearTimeout(timer);
    gate.stop();
    removeEventListener("keydown", onKey, true);
    hostEl.remove();
    if (banner === hostEl) banner = null;
  };
  const answer = (accept: string) => {
    chrome.runtime.sendMessage({ type: "page:save", accept, nonce }).catch(() => {});
    close();
  };
  // Disappears after 30 s, but not while the pointer or focus is on it.
  const arm = () => {
    clearTimeout(timer);
    timer = setTimeout(close, 30_000);
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Escape" && e.isTrusted) answer("dismiss");
  };
  shadow.querySelectorAll<HTMLButtonElement>("button").forEach((b) =>
    b.addEventListener("click", (e) => {
      // Only real clicks on a banner the user can see (not hidden or covered by the page).
      if (!e.isTrusted || !gate.ok() || tampered(hostEl)) return;
      answer(b.dataset.a!);
    }),
  );
  box.addEventListener("pointerenter", () => clearTimeout(timer));
  box.addEventListener("pointerleave", arm);
  box.addEventListener("focusin", () => clearTimeout(timer));
  box.addEventListener("focusout", arm);
  addEventListener("keydown", onKey, true);
  (document.body ?? document.documentElement).appendChild(hostEl);
  banner = hostEl;
  shadow.querySelector<HTMLButtonElement>("button.p")?.focus({ preventScroll: true });
  arm();
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
  setTimeout(() => hostEl.remove(), 5000);
}
