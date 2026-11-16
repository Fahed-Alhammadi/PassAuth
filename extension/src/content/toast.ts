/** A short note in the page (top frame). `text` comes from the background and is page-safe: never vault data (shared/page-text.ts). */
import type { PageSafeText } from "../shared/page-text";
import type { Settings } from "../shared/types";
import { logoSvg, toastCss } from "./brand";
import { savePromptBottom } from "./save-prompt";

let toast: HTMLElement | null = null;

export function showToast(text: PageSafeText, theme?: Settings["theme"]) {
  if (window.top !== window) return;
  toast?.remove();
  // A plain <div> host like the other PassAuth UI in pages (never a custom element name a page could predefine).
  const hostEl = document.createElement("div");
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
  const below = savePromptBottom();
  if (below !== null) hostEl.style.top = `${Math.round(below) + 8}px`;
  (document.body ?? document.documentElement).appendChild(hostEl);
  toast = hostEl;
  setTimeout(() => {
    hostEl.remove();
    if (toast === hostEl) toast = null;
  }, 5000);
}
