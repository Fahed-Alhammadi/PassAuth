/**
 * Inline autofill menu. When a login field gets focus and PassAuth has logins
 * for this site (or is locked), a PassAuth icon appears inside the field.
 * The list itself is an extension page in an iframe (inline-menu.html), so the
 * website can't read the names and usernames shown in it.
 */
import type { InlineInfo } from "../shared/messages";
import { logoSvg } from "./brand";
import { isLoginField } from "./fields";

const ROW = 52;
let info: { value: InlineInfo | null; at: number } = { value: null, at: 0 };
let field: HTMLInputElement | null = null;
let icon: HTMLElement | null = null;
let menu: HTMLElement | null = null;
let suppressUntil = 0;
let frame = 0;

async function getInfo(): Promise<InlineInfo | null> {
  if (Date.now() - info.at < 3000) return info.value;
  const r = await chrome.runtime.sendMessage({ type: "page:inlineInfo" }).catch(() => null);
  info = { value: r?.ok ? r.data : null, at: Date.now() };
  return info.value;
}

/** Called while PassAuth fills the page, so its own focus changes don't reopen the menu. */
export function suppressInlineMenu(ms = 800) {
  suppressUntil = Date.now() + ms;
  info.at = 0;
  closeInlineMenu();
}

export function closeInlineMenu() {
  menu?.remove();
  menu = null;
}

function hideAll() {
  closeInlineMenu();
  icon?.remove();
  icon = null;
  field = null;
}

function host(tag: string, css: string) {
  const el = document.createElement(tag);
  const shadow = el.attachShadow({ mode: "closed" });
  shadow.innerHTML = `<style>:host { all: initial; position: fixed; z-index: 2147483647; } ${css}</style>`;
  (document.body ?? document.documentElement).appendChild(el);
  return { el, shadow };
}

function place() {
  frame = 0;
  if (!field) return;
  if (!field.isConnected || !field.getClientRects().length) return hideAll();
  const r = field.getBoundingClientRect();
  if (icon) {
    const size = Math.max(14, Math.min(20, r.height - 8));
    Object.assign(icon.style, { left: `${r.right - size - 8}px`, top: `${r.top + (r.height - size) / 2}px`, width: `${size}px`, height: `${size}px` });
  }
  if (menu) {
    const width = Math.min(Math.max(r.width, 300), innerWidth - 16);
    const height = parseFloat(menu.dataset.height ?? "0");
    const below = r.bottom + 4 + height <= innerHeight || r.top - 4 - height < 0;
    Object.assign(menu.style, {
      left: `${Math.max(8, Math.min(r.left, innerWidth - width - 8))}px`,
      top: `${below ? r.bottom + 4 : r.top - 4 - height}px`,
      width: `${width}px`,
      height: `${height}px`,
    });
  }
}
const schedule = () => (frame ||= requestAnimationFrame(place));

function showIcon(target: HTMLInputElement, i: InlineInfo) {
  field = target;
  if (!icon) {
    const { el, shadow } = host(
      "passauth-inline-icon",
      `button { all: unset; cursor: pointer; display: grid; place-items: center; width: 100%; height: 100%; border-radius: 4px; }
       button:hover { background: rgb(8 102 237 / .12); } button:focus-visible { outline: 2px solid #0866ed; }
       svg { width: 100%; height: 100%; }`,
    );
    const btn = document.createElement("button");
    btn.type = "button";
    btn.title = i.status === "locked" ? "PassAuth is locked" : "Fill with PassAuth";
    btn.setAttribute("aria-label", btn.title);
    btn.innerHTML = logoSvg(20);
    // Keep focus in the field while clicking the icon.
    btn.addEventListener("pointerdown", (e) => e.preventDefault());
    btn.addEventListener("click", () => (menu ? closeInlineMenu() : void openMenu(i)));
    shadow.append(btn);
    icon = el;
  }
  place();
}

async function openMenu(i: InlineInfo) {
  if (!field || menu) return;
  const r = await chrome.runtime.sendMessage({ type: "page:inlineOpen" }).catch(() => null);
  if (!r?.ok || !r.data || !field || menu) return;
  const { el, shadow } = host(
    "passauth-inline-menu",
    `iframe { border: 0; width: 100%; height: 100%; display: block; border-radius: 10px; color-scheme: normal;
              box-shadow: 0 2px 6px rgb(0 0 0 / .12), 0 12px 32px rgb(0 0 0 / .2); background: transparent; }`,
  );
  const iframe = document.createElement("iframe");
  iframe.src = `${chrome.runtime.getURL("inline-menu.html")}#${r.data}`;
  iframe.title = "PassAuth";
  iframe.setAttribute("allowtransparency", "true");
  shadow.append(iframe);
  el.dataset.height = String(i.status === "locked" ? 112 : Math.min(i.count, 4) * ROW + 12);
  menu = el;
  place();
}

async function onFocus(e: FocusEvent) {
  const target = e.composedPath()[0];
  if (Date.now() < suppressUntil || target === field || !isLoginField(target)) return;
  const i = await getInfo();
  if (!i || i.mode === "off" || (i.status === "unlocked" && i.count === 0)) return hideAll();
  closeInlineMenu();
  showIcon(target, i);
  if (i.mode === "focus") await openMenu(i);
}

export function installInlineMenu() {
  document.addEventListener("focusin", (e) => void onFocus(e), true);
  document.addEventListener(
    "focusout",
    () =>
      setTimeout(() => {
        const active = document.activeElement;
        if (field && active !== field && active !== menu && active !== icon) hideAll();
      }, 200),
    true,
  );
  document.addEventListener(
    "pointerdown",
    (e) => {
      const t = e.composedPath()[0];
      if (menu && t !== field && t !== menu && t !== icon) closeInlineMenu();
      // Clicking the field again reopens a list closed with Esc.
      else if (!menu && t === field && info.value?.mode === "focus") void openMenu(info.value);
    },
    true,
  );
  document.addEventListener(
    "keydown",
    (e) => {
      if (e.key === "Escape" && menu) closeInlineMenu();
      // Typing hides the list so it doesn't cover what the user is doing.
      else if (menu && e.target === field && e.key.length === 1) closeInlineMenu();
    },
    true,
  );
  addEventListener("scroll", schedule, { capture: true, passive: true });
  addEventListener("resize", schedule, { passive: true });
}
