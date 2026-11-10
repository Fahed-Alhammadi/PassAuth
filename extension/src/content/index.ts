/**
 * PassAuth content script (isolated world, every frame).
 * - Fills logins only on explicit request from the background, sent to this
 *   frame alone, and only if the item's websites match this frame's own URL.
 * - Offers to save credentials after a successful submit (the page changed or
 *   the form went away).
 * - Relays WebAuthn requests (passkey bridge).
 */
import type { ContentCommand, SavePrompt, Settings } from "../shared/messages";
import type { LoginUrl, UrlMatch } from "@web/lib/types";
import { baseDomain, downgrade, matchesUrl } from "../background/urls";
import { isLoginField, otpField, passwordFields, setValue, usernameFieldFor, visible } from "./fields";
import { submittedPassword } from "./pick";
import { closeInlineMenu, currentField, installInlineMenu, suppressInlineMenu } from "./inline";
import { installPasskeyBridge } from "./passkey-bridge";
import { clampPromptHeight, SAVE_PROMPT } from "../shared/save-layout";
import { logoSvg, panelShadow, toastCss } from "./brand";
import { tampered } from "./guard";

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
  } else if (cmd.type === "showSave") showSavePrompt(cmd);
  else if (cmd.type === "save:size") prompt && setPromptHeight(prompt.frame, cmd.height);
  else if (cmd.type === "save:close") prompt?.close();
  else if (cmd.type === "toast") showToast(cmd.text, cmd.theme);
  else if (cmd.type === "inline:close") closeInlineMenu();
});

// ---------------------------------------------------------------- capture

let lastSent = "";

/**
 * Called from the submit / click / Enter listeners below. Only a real action
 * by the user counts: the event must be one the browser made (not one a script
 * dispatched), and the page must have a recent click or key press behind it
 * (read here in the isolated world, which the page can't tamper with). So a
 * page can't make PassAuth offer to save — and show its prompt — by itself.
 */
function capture(form: HTMLFormElement | null, event: Event) {
  if (!event.isTrusted || !navigator.userActivation?.isActive) return;
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

document.addEventListener("submit", (e) => capture(e.target as HTMLFormElement, e), true);
document.addEventListener(
  "click",
  (e) => {
    const btn = (e.composedPath()[0] as HTMLElement).closest?.('button, input[type="submit"], [role="button"]');
    if (btn && /log ?in|sign ?in|continue|next|submit|save|update|register|sign ?up/i.test(btn.textContent + " " + (btn as HTMLInputElement).value)) {
      capture((btn as HTMLButtonElement).form ?? btn.closest("form"), e);
    }
  },
  true,
);
document.addEventListener(
  "keydown",
  (e) => {
    const t = e.composedPath()[0] as HTMLInputElement;
    if (e.key === "Enter" && t instanceof HTMLInputElement && (t.type === "password" || isLoginField(t))) capture(t.form, e);
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
        .then((r) => r?.ok && r.data && showSavePrompt(r.data))
        .catch(() => {});
    }, 600);
  if (document.readyState === "complete") ask();
  else addEventListener("load", ask, { once: true });
}

// ------------------------------------------------------------- save prompt

/**
 * "Save login?" / "Update login?" in the top-right corner of the page. The
 * prompt itself is an extension page in a frame (save-prompt.html, like the
 * inline menu): this script only places and sizes the frame. It never gets the
 * logins listed in the prompt or the user's choice — just the nonce that ties
 * the frame to the pending save, and a height — and it cannot accept a save.
 */
let prompt: { nonce: string; host: HTMLElement; frame: HTMLIFrameElement; close: () => void } | null = null;

function setPromptHeight(frame: HTMLIFrameElement, height: number) {
  frame.style.height = `${Math.max(0, Math.min(clampPromptHeight(height), innerHeight - 2 * SAVE_PROMPT.edge))}px`;
}

function showSavePrompt({ nonce, height }: SavePrompt) {
  if (window.top !== window || prompt || typeof nonce !== "string" || !/^[\w-]{8,64}$/.test(nonce)) return;
  const hostEl = document.createElement("passauth-save");
  const shadow = hostEl.attachShadow({ mode: "closed" });
  // Static markup only. The page can restyle the host element; the frame checks that it is really visible before it accepts a click.
  shadow.innerHTML = `<style>
      :host { all: initial; position: fixed !important; top: ${SAVE_PROMPT.edge}px !important; right: ${SAVE_PROMPT.edge}px !important; z-index: 2147483647 !important;
              opacity: 1 !important; filter: none !important; clip-path: none !important; visibility: visible !important; }
      iframe { display: block; border: 0; outline: 0; width: ${SAVE_PROMPT.width}px; max-width: calc(100vw - ${2 * SAVE_PROMPT.edge}px); border-radius: 16px; color-scheme: normal;
               background: transparent; box-shadow: ${panelShadow}; }
    </style>`;
  const frame = document.createElement("iframe");
  frame.src = `${chrome.runtime.getURL("save-prompt.html")}#${nonce}`;
  frame.title = "PassAuth: save login";
  frame.setAttribute("allowtransparency", "true");
  setPromptHeight(frame, height);
  shadow.append(frame);

  // The page hid or moved the prompt: take it away rather than leave it to be clicked blind.
  const watch = setInterval(() => tampered(hostEl) && close(), 250);
  // Whatever happens to the frame, it never outlives the pending save (2 minutes).
  const expire = setTimeout(() => close(), 125_000);
  const onKey = (e: KeyboardEvent) => {
    // Escape in the page dismisses (the frame handles Escape itself while focus is inside it).
    if (e.key !== "Escape" || !e.isTrusted) return;
    chrome.runtime.sendMessage({ type: "page:saveDismiss", nonce }).catch(() => {});
    close();
  };
  function close() {
    clearInterval(watch);
    clearTimeout(expire);
    removeEventListener("keydown", onKey, true);
    hostEl.remove();
    if (prompt?.host === hostEl) prompt = null;
  }
  addEventListener("keydown", onKey, true);
  // Focus goes to the prompt (its dialog container, never a button: a key press already on its way can't accept it).
  frame.addEventListener("load", () => frame.focus({ preventScroll: true }), { once: true });
  (document.body ?? document.documentElement).appendChild(hostEl);
  prompt = { nonce, host: hostEl, frame, close };
}

// ------------------------------------------------------------------ toast

let toast: HTMLElement | null = null;

/** A short note in the page. `text` comes from the background and never contains vault data (see ContentCommand). */
function showToast(text: string, theme?: Settings["theme"]) {
  if (window.top !== window) return;
  toast?.remove();
  const hostEl = document.createElement("passauth-toast");
  const shadow = hostEl.attachShadow({ mode: "closed" });
  shadow.innerHTML = `
    <style>
      :host { all: initial; position: fixed; top: 16px; right: 16px; z-index: 2147483647; }
      ${toastCss}
    </style>
    <div class="b" role="status">${logoSvg(20)}<span></span></div>`;
  const box = shadow.querySelector<HTMLElement>(".b")!;
  if (theme === "light" || theme === "dark") box.dataset.theme = theme;
  shadow.querySelector("span")!.textContent = text;
  // Below the save prompt when that is open, never on top of it.
  if (prompt) hostEl.style.top = `${Math.round(prompt.host.getBoundingClientRect().bottom) + 8}px`;
  (document.body ?? document.documentElement).appendChild(hostEl);
  toast = hostEl;
  setTimeout(() => {
    hostEl.remove();
    if (toast === hostEl) toast = null;
  }, 5000);
}
