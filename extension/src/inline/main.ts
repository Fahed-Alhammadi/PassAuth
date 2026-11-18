/**
 * Inline autofill menu (inside the page, in an extension frame): the logins for the page — on one-time-code fields
 * those with a code, with the current code; on card and identity fields the cards and identities — then a quiet
 * footer ("New login", and "Use a strong password" on sign-up fields) and "⋯" ("Hide on this site", "Open
 * PassAuth"). The rows are a listbox: ↑/↓/Home/End move, Enter fills, Esc and Tab give the focus back to the field.
 * The frame takes the focus only when the content script asks with this menu's nonce (the user pressed ↓ in the
 * field); it never does by itself.
 *
 * Clickjacking: every action counts only once the frame has been fully visible (not covered or made transparent
 * by the page around it) for half a second and, for a click, the pointer has rested inside it for half a second
 * since it last moved (content/guard.ts); a touch or pen tap needs a confirm tap on the same control. A click that
 * comes too early gets "Click again" ("Tap again", "Press Enter again") instead of nothing. Keys count only after
 * the content script gave this frame the focus with its nonce, or after a click here that passed those checks.
 *
 * This frame never posts to the page around it (that would hand the page a handle on this window): "return" and
 * "touch" go to the worker with the nonce, which tells the content script that placed the frame.
 */
import "@fontsource/ibm-plex-mono/500.css";
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@web/styles/app.css";
import "./inline.css";
import { cardSvg, keySvg, logoSvg, moreSvg, personSvg, plusSvg } from "../content/brand";
import { againHint, clickGate, inputKind } from "../content/guard";
import { onFocusRequest, onMoved, receiveNonce, reportTouch } from "../shared/dom/frame-channel";
import { callInline, type InlineFrameApi } from "../shared/protocol";
import type { InlineItems, InlineKind, ItemSummary } from "../shared/types";
import { siteIcon } from "./site-icon";

/** Set once the content script that placed this frame has handed it over (frame-channel.ts). */
let nonce = "";
let data: InlineItems | null = null;
/** The content script asked for the focus (↓ in the field) before the rows were there. */
let wantFocus = false;
let ticker: ReturnType<typeof setInterval> | undefined;
let refreshing = false;
let hintTimer: ReturnType<typeof setTimeout> | undefined;

const menu = document.getElementById("menu")!;
// Clicks count only once this frame has been fully visible (not covered or made transparent by the page around it)
// for half a second, and the pointer has been inside it for half a second since it last moved.
const gate = clickGate(document.documentElement);
onMoved(gate.moved);
/** A finger or pen touched the frame before the nonce arrived: said once it has. */
let touchPending = false;
const sendTouch = () => void callInline("inline:touch", { nonce }).catch(() => {});
// A finger or pen: the content script then checks this frame in every animation frame (confirm taps).
reportTouch(() => {
  if (nonce) sendTouch();
  else touchPending = true;
});

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> = {}, ...children: (Node | string)[]) {
  const e = Object.assign(document.createElement(tag), props);
  e.append(...children);
  return e;
}

/** A button the frame moves the focus to itself (the list keeps its own order: Tab goes back to the field). */
function button(className: string, content: string | (Node | string)[], label?: string) {
  const b = el("button", { className, type: "button", tabIndex: -1 });
  if (typeof content === "string") b.textContent = content;
  else b.append(...content);
  if (label) b.setAttribute("aria-label", label);
  return b;
}

const svg = (markup: string) => {
  const span = el("span", { className: "ico" });
  span.setAttribute("aria-hidden", "true");
  span.innerHTML = markup;
  return span;
};

// Brand line with "⋯"; the rows (or a message) below it; the footer; the "⋯" menu and the hint on top.
const head = el("div", { className: "head" });
const brand = el("span", { className: "brand" });
brand.innerHTML = logoSvg(16);
brand.append("PassAuth");
const more = button("btn btn-icon more", [svg(moreSvg)], "More");
more.setAttribute("aria-haspopup", "menu");
more.setAttribute("aria-expanded", "false");
head.append(brand, more);
const body = el("div", { className: "body" });
const foot = el("div", { className: "foot" });
const popover = el("div", { className: "popover", hidden: true });
popover.setAttribute("role", "menu");
popover.setAttribute("aria-label", "More");
const hint = el("p", { className: "hint" });
hint.setAttribute("role", "status");
menu.append(head, body, foot, popover, hint);

/** "Click again" ("Tap again", "Press Enter again") for a moment, over the footer. */
function showHint(text: string) {
  hint.textContent = text;
  hint.classList.add("show");
  clearTimeout(hintTimer);
  hintTimer = setTimeout(() => hint.classList.remove("show"), 2000);
}

/**
 * `fn` for real clicks and key presses on a frame the user can see, with the pointer resting on it (a touch: a confirm
 * tap). A key press while the keyboard isn't armed (the frame got the focus some other way than from PassAuth) does
 * nothing, and says nothing: pressing again wouldn't help.
 */
function guarded(fn: () => void) {
  return (e: Event) => {
    if (!e.isTrusted) return;
    if (!gate.ok(e)) {
      if (inputKind(e) !== "key" || gate.keysArmed()) showHint(againHint(e));
      return;
    }
    fn();
  };
}

/** The menu's requests that carry only the nonce (and use it up). */
type NonceRequest = Extract<keyof InlineFrameApi, "inline:unlock" | "inline:generate" | "inline:new" | "inline:hide">;

/** A request that needs only the nonce. A failure is shown in the menu (when it closed meanwhile, there is nothing to show). */
const call = (type: NonceRequest) => void callInline(type, { nonce }).catch(showError);

function showError(e: unknown) {
  const text = e instanceof Error ? e.message : String(e);
  const close = button("btn", "Close");
  // The menu is gone already if this fails (expired): the page side removes the frame either way.
  close.addEventListener("click", () => void callInline("inline:close", { nonce }).catch(() => {}));
  const box = el("div", { className: "message" }, el("p", { className: "error" }, text), close);
  box.setAttribute("role", "alert");
  clearInterval(ticker);
  body.replaceChildren(box);
  foot.replaceChildren();
  // Only a frame that has the focus already keeps it.
  if (document.hasFocus()) close.focus();
}

const tile = (markup: string) => {
  const t = el("span", { className: "tile" });
  t.setAttribute("aria-hidden", "true");
  t.innerHTML = markup;
  return t;
};

const secondsLeft = (expires: number) => Math.max(0, Math.ceil((expires - Date.now()) / 1000));
const spaced = (code: string) => (code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code);

function option(item: ItemSummary, d: InlineItems, kind: InlineKind): HTMLElement {
  const icon = kind === "card" ? tile(cardSvg) : kind === "identity" ? tile(personSvg) : siteIcon(item, d);
  const text = el("span", { className: "txt" }, el("span", { className: "name", textContent: item.name }), el("span", { className: "user", textContent: item.subtitle }));
  const row = el("div", { className: "row", tabIndex: -1 }, icon, text);
  row.setAttribute("role", "option");
  row.setAttribute("aria-selected", "false");
  row.dataset.id = item.id;
  const code = d.codes?.find((c) => c.id === item.id);
  if (code) {
    const left = el("span", { className: "left", textContent: `${secondsLeft(code.expires)}s` });
    left.dataset.expires = String(code.expires);
    left.setAttribute("aria-hidden", "true");
    row.append(el("span", { className: "code" }, el("span", { className: "digits", textContent: spaced(code.code) }), left));
  }
  const fill = guarded(() => void callInline("inline:fill", { nonce, id: item.id }).catch(showError));
  row.addEventListener("click", fill);
  row.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    e.preventDefault();
    fill(e);
  });
  row.addEventListener("focus", () => {
    for (const o of body.querySelectorAll("[role=option]")) o.setAttribute("aria-selected", String(o === row));
  });
  return row;
}

const NOUNS: Record<InlineKind, [string, string]> = {
  login: ["login", "logins"],
  "new-password": ["login", "logins"],
  otp: ["verification code", "verification codes"],
  card: ["card", "cards"],
  identity: ["identity", "identities"],
};

function emptyText(kind: InlineKind, site: string): string {
  if (kind === "card") return "No cards saved in PassAuth.";
  if (kind === "identity") return "No identities saved in PassAuth.";
  const where = site ? ` for ${site}` : " for this site";
  return kind === "otp" ? `No verification codes${where}.` : `No logins${where}.`;
}

function footer(kind: InlineKind, d: InlineItems): HTMLElement[] {
  const label = kind === "card" ? "New card" : kind === "identity" ? "New identity" : "New login";
  const add = button("btn btn-text", [svg(plusSvg), label]);
  add.addEventListener(
    "click",
    guarded(() => call("inline:new")),
  );
  if (!d.strongPassword) return [add];
  const strong = button("btn btn-text", [svg(keySvg), "Use a strong password"]);
  strong.addEventListener(
    "click",
    guarded(() => call("inline:generate")),
  );
  return [add, strong];
}

/** Count the codes down every second; when one changes, ask for the new ones (the focus stays on its row). */
function startTicker() {
  clearInterval(ticker);
  ticker = setInterval(() => {
    let expired = false;
    for (const left of body.querySelectorAll<HTMLElement>(".left")) {
      const s = secondsLeft(Number(left.dataset.expires));
      left.textContent = `${s}s`;
      if (s === 0) expired = true;
    }
    if (!expired || refreshing) return;
    refreshing = true;
    const focused = document.activeElement instanceof HTMLElement ? document.activeElement.dataset.id : undefined;
    callInline("inline:items", { nonce })
      .then((d) => {
        render(d);
        if (focused) body.querySelector<HTMLElement>(`[data-id="${CSS.escape(focused)}"]`)?.focus();
      })
      .catch(() => clearInterval(ticker))
      .finally(() => (refreshing = false));
  }, 1000);
}

function render(d: InlineItems) {
  data = d;
  if (d.theme !== "system") document.documentElement.dataset.theme = d.theme;
  clearInterval(ticker);
  const kind = d.kind ?? "login";
  if (d.locked) {
    const unlock = button("btn btn-accent", "Unlock PassAuth");
    unlock.addEventListener(
      "click",
      guarded(() => call("inline:unlock")),
    );
    body.replaceChildren(el("div", { className: "message" }, el("p", {}, "PassAuth is locked. Unlock it to fill this page."), unlock));
    foot.replaceChildren();
  } else {
    const [one, many] = NOUNS[kind];
    const perSite = kind !== "card" && kind !== "identity";
    const count = d.items.length;
    if (count) {
      const list = el("div", { className: "rows" }, ...d.items.map((item) => option(item, d, kind)));
      list.setAttribute("role", "listbox");
      list.setAttribute("aria-label", `${count} ${count === 1 ? one : many}${perSite && d.site ? ` for ${d.site}` : ""}`);
      body.replaceChildren(list);
    } else {
      body.replaceChildren(el("div", { className: "message muted" }, el("p", {}, emptyText(kind, d.site ?? ""))));
    }
    foot.replaceChildren(...footer(kind, d));
    if (d.codes?.length) startTicker();
  }
  if (wantFocus) {
    wantFocus = false;
    focusFirst();
  }
}

// ------------------------------------------------------------------ keyboard

/** What ↑/↓ move through, top to bottom: "⋯", the rows (or the message's button), the footer. In the open "⋯" menu, its items. */
function navItems(): HTMLElement[] {
  if (!popover.hidden) return [...popover.querySelectorAll<HTMLElement>("[role=menuitem]")];
  return [more, ...body.querySelectorAll<HTMLElement>("[role=option], button"), ...foot.querySelectorAll<HTMLElement>("button")];
}

function focusFirst() {
  (body.querySelector<HTMLElement>("[role=option], button") ?? foot.querySelector<HTMLElement>("button") ?? more).focus();
}

// The content script gave this frame the focus (↓ or Alt+↓ in the field), asking with the nonce: keys count from now
// until the frame loses the focus.
onFocusRequest(
  () => nonce,
  () => {
    gate.armKeys();
    if (data) focusFirst();
    else wantFocus = true;
  },
);

function openPopover(fromKeyboard: boolean) {
  const item = (text: string, type: NonceRequest) => {
    const b = button("menuitem", text);
    b.setAttribute("role", "menuitem");
    b.addEventListener(
      "click",
      guarded(() => call(type)),
    );
    return b;
  };
  // Hiding covers the whole site (its base domain): the item says which, e.g. "Hide on example.com".
  popover.replaceChildren(item(data?.hides ? `Hide on ${data.hides}` : "Hide on this site", "inline:hide"), item("Open PassAuth", "inline:unlock"));
  popover.hidden = false;
  more.setAttribute("aria-expanded", "true");
  if (fromKeyboard) popover.querySelector<HTMLElement>("[role=menuitem]")?.focus();
}

function closePopover(refocus: boolean) {
  if (popover.hidden) return;
  popover.hidden = true;
  more.setAttribute("aria-expanded", "false");
  if (refocus) more.focus();
}

more.addEventListener("click", (e) => {
  if (!e.isTrusted) return;
  if (popover.hidden) openPopover(e.detail === 0);
  else closePopover(false);
});
document.addEventListener("pointerdown", (e) => {
  const t = e.target as Node | null;
  if (!popover.hidden && t && !popover.contains(t) && !more.contains(t)) closePopover(false);
});

document.addEventListener("keydown", (e) => {
  if (!e.isTrusted || !nonce) return;
  if (e.key === "Escape") {
    e.preventDefault();
    if (!popover.hidden) return closePopover(true);
    // The menu closes (the nonce is used up) and the focus goes back to the field.
    void callInline("inline:close", { nonce, refocus: true }).catch(() => {});
    return;
  }
  if (e.key === "Tab") {
    e.preventDefault();
    closePopover(false);
    // Back to the field (the worker tells the content script that placed this frame).
    void callInline("inline:return", { nonce }).catch(() => {});
    return;
  }
  if (e.key !== "ArrowDown" && e.key !== "ArrowUp" && e.key !== "Home" && e.key !== "End") return;
  e.preventDefault();
  const items = navItems();
  if (!items.length) return;
  const i = items.indexOf(document.activeElement as HTMLElement);
  const firstRow = Math.max(
    0,
    items.findIndex((x) => x.getAttribute("role") === "option"),
  );
  const next = e.key === "Home" ? 0 : e.key === "End" ? items.length - 1 : e.key === "ArrowDown" ? (i < 0 ? firstRow : Math.min(i + 1, items.length - 1)) : Math.max(i - 1, 0);
  items[next]?.focus();
});

// Only as a frame inside a page (where the content script put it); nothing is asked before the nonce arrives.
if (window.top !== window) {
  void receiveNonce().then((n) => {
    nonce = n;
    if (touchPending) sendTouch();
    return callInline("inline:items", { nonce }).then(render, showError);
  });
}
