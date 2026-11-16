/**
 * Save prompt (inside the page, in an extension frame): "Save login?" /
 * "Update login?" with the "Save in" choice. The website can't read this
 * frame, so the logins listed here and the user's pick never reach the page;
 * the content script that placed the frame only knows its nonce and height.
 *
 * Clickjacking: buttons and choices only react to real (trusted) events, and
 * only once the frame has been fully visible — not covered, transparent or
 * filtered by the page around it — for half a second (content/guard.ts; a tap
 * needs a confirm tap on the same button). Keys count only after the content
 * script gave this frame the focus with its nonce, or after a click here that
 * passed those checks. This frame never posts to the page around it: "touch"
 * goes to the worker with the nonce.
 *
 * Focus: the prompt has the keyboard focus only when the content script gave it
 * (the form was submitted from the keyboard); otherwise it announces itself
 * politely and leaves the focus where the user is. It goes away after 30 s, but
 * not while the pointer or the focus is in it, and only Esc pressed inside it
 * (or its own buttons) dismisses it: the page can't.
 */
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@web/styles/app.css";
import "./save.css";
import { closeSvg, logoSvg, plusSvg } from "../content/brand";
import { againHint, clickGate, inputKind } from "../content/guard";
import { onFocusRequest, onMoved, receiveNonce, reportTouch } from "../shared/dom/frame-channel";
import { callSave } from "../shared/protocol";
import { describeSave, NEW_LOGIN, sharedWarning, type TextPart } from "../shared/save-text";
import type { SaveAnswer, SaveOffer } from "../shared/types";

/** Set once the content script that placed this frame has handed it over (frame-channel.ts). */
let nonce = "";
const root = document.getElementById("prompt")!;
const gate = clickGate(document.documentElement);
onMoved(gate.moved);
/** A finger or pen touched the frame before the nonce arrived: said once it has. */
let touchPending = false;
const sendTouch = () => void callSave("save:touch", { nonce }).catch(() => {});
// A finger or pen: the content script then checks this frame in every animation frame (confirm taps).
reportTouch(() => {
  if (nonce) sendTouch();
  else touchPending = true;
});
// After a keyboard submit the content script gives this frame the focus and says so with the nonce: keys count from
// now until the frame loses the focus. The dialog takes the focus, never a button.
onFocusRequest(
  () => nonce,
  () => {
    gate.armKeys();
    if (!root.contains(document.activeElement) || document.activeElement === document.body) root.focus({ preventScroll: true });
  },
);

/** Element with text set through `textContent`; markup is only ever the static icons. */
function el<K extends keyof HTMLElementTagNameMap>(tag: K, className = "", text = ""): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text) e.textContent = text;
  return e;
}

function tile(content: string, svg = false) {
  const t = el("span", "tile");
  t.setAttribute("aria-hidden", "true");
  if (svg) t.innerHTML = content;
  else t.textContent = (content.trim()[0] ?? "?").toUpperCase();
  return t;
}

/**
 * "Click again", "Tap again" or "Press Enter again" for a moment, over the bottom of the prompt: it never changes
 * the prompt's height (a new size would make the frame wait again, and a touch user's confirm tap would never count).
 */
const hint = el("p", "hint");
hint.setAttribute("role", "status");
document.body.append(hint);
let hintTimer: ReturnType<typeof setTimeout> | undefined;
function showHint(text: string) {
  hint.textContent = text;
  hint.classList.add("show");
  clearTimeout(hintTimer);
  hintTimer = setTimeout(() => hint.classList.remove("show"), 2000);
}

function button(className: string, text: string, onClick: () => void) {
  const b = el("button", className, text);
  b.type = "button";
  b.addEventListener("click", (e) => {
    // Only real clicks (or key presses) on a prompt the user can see, with the pointer resting on it (a touch: a confirm tap).
    if (!e.isTrusted || busy) return;
    if (!gate.ok(e)) {
      // A key press while the keyboard isn't armed (the frame got the focus some other way) does nothing, silently.
      if (inputKind(e) !== "key" || gate.keysArmed()) showHint(againHint(e));
      return;
    }
    onClick();
  });
  return b;
}

let busy = false;
let selected = NEW_LOGIN;
let timer: ReturnType<typeof setTimeout> | undefined;
let pointerInside = false;
let focusInside = document.hasFocus();
let announced = false;
/** Says the prompt is there when it opens without the focus (a screen reader reads it out; nothing moves). */
const live = el("div", "sr-only");
live.setAttribute("role", "status");
document.body.append(live);

async function answer(accept: "save" | "never" | "dismiss") {
  if (busy || !nonce) return;
  busy = true;
  clearTimeout(timer);
  root.setAttribute("aria-busy", "true");
  let reply: SaveAnswer;
  try {
    reply = await callSave("save:answer", { nonce, accept, target: selected });
  } catch (e) {
    // The pending save is gone (expired, locked, another account): nothing more to do here.
    reply = { error: e instanceof Error ? e.message : String(e), retry: false };
  }
  busy = false;
  root.removeAttribute("aria-busy");
  if ("done" in reply) return; // the content script removes the frame
  if ("again" in reply) render(reply.again, { notice: reply.notice });
  else if (last) render({ ...last, selected }, { error: reply.error, closed: !reply.retry });
}

let last: SaveOffer | null = null;

function render(offer: SaveOffer, state: { notice?: string; error?: string; closed?: boolean } = {}) {
  last = offer;
  const { host, username, targets } = offer;
  if (offer.theme !== "system") document.documentElement.dataset.theme = offer.theme;
  selected = offer.selected === NEW_LOGIN || targets.some((t) => t.id === offer.selected) ? offer.selected : NEW_LOGIN;
  const site = host.replace(/^www\./, "");

  const brand = el("span", "sheet-brand");
  const mark = el("span", "row");
  mark.setAttribute("aria-hidden", "true");
  mark.innerHTML = logoSvg(18);
  brand.append(mark, "PassAuth");
  const close = button("btn btn-icon", "", () => void answer("dismiss"));
  close.setAttribute("aria-label", "Close");
  close.innerHTML = closeSvg;
  const bar = el("div", "sheet-bar");
  bar.append(brand, close);

  const title = el("h1", "sheet-title");
  title.id = "title";
  const heading = el("div", "grow");
  heading.append(title, el("p", "sheet-sub", host));
  const context = el("div", "sheet-context");
  context.append(tile(site), heading);

  const note = el("p", "sheet-note");
  note.id = "note";
  // Shown while a login in a shared vault is selected (never preselected: the save rule).
  const warn = el("p", "alert alert-warn");
  warn.setAttribute("role", "status");
  warn.hidden = true;
  const primary = button("btn btn-primary btn-block", "", () => void answer("save"));
  const parts = (list: TextPart[]) => list.map((part) => (typeof part === "string" ? part : el("strong", "", part.strong)));

  // Title, button, the sentence that names what will be saved and the shared-vault warning all follow the selection.
  const update = () => {
    const target = targets.find((t) => t.id === selected);
    title.textContent = target ? "Update login?" : "Save login?";
    primary.textContent = target ? "Update" : "Save";
    note.replaceChildren(...parts(describeSave(target, username, site)));
    const shared = sharedWarning(target);
    warn.hidden = !shared;
    warn.replaceChildren(...parts(shared ?? []));
  };

  const body = el("div", "modal-body");
  body.append(context);
  if (targets.length && !state.closed) {
    const group = el("fieldset", "choice-group");
    const list = el("div", "choices");
    const row = (id: string, name: string, sub: string, icon: HTMLElement) => {
      const label = el("label", "choice");
      const text = el("span", "choice-text");
      text.append(el("span", "choice-title", name), el("span", "choice-sub", sub));
      const input = el("input");
      input.type = "radio";
      input.name = "target";
      input.value = id;
      input.checked = id === selected;
      label.append(icon, text, input);
      return label;
    };
    for (const t of targets) {
      const user = t.username || "No user name";
      // A login in a shared vault (only one saved under the typed user name, never preselected) says so.
      list.append(row(t.id, t.name, t.vault ? `In ${t.vault}: ${user}` : user, tile(t.name)));
    }
    list.append(row(NEW_LOGIN, "New login", username || site, tile(plusSvg, true)));
    group.append(el("legend", "field-label", "Save in"), list);
    group.addEventListener("change", (e) => {
      const input = e.target as HTMLInputElement;
      // Only the user changes the choice (clicks and arrow keys are trusted events).
      if (!e.isTrusted || busy) {
        const shown = list.querySelector<HTMLInputElement>(`input[value="${CSS.escape(selected)}"]`);
        if (shown) shown.checked = true;
        return;
      }
      selected = input.value;
      update();
    });
    body.append(group);
  }
  if (!state.closed) body.append(note, warn);
  // A password PassAuth generated on this page: nobody else knows it yet.
  if (offer.generated && !state.closed) body.append(el("p", "sheet-note", "PassAuth generated this password. Save it so you can sign in again."));
  const message = state.error ?? state.notice;
  if (message) {
    const alert = el("p", state.error ? "alert alert-error" : "alert alert-warn", message);
    alert.setAttribute("role", "alert");
    body.append(alert);
  }

  const actions = el("div", "sheet-actions");
  const quiet = el("div", "sheet-quiet");
  if (state.closed) {
    // Nothing left to save from here: the only way on is to close.
    actions.append(button("btn btn-primary btn-block", "Close", () => void answer("dismiss")));
  } else {
    // "Never" only for a site PassAuth has nothing for yet.
    if (!targets.length) quiet.append(button("btn btn-text", "Never for this site", () => void answer("never")));
    quiet.append(button("btn btn-text", "Not now", () => void answer("dismiss")));
    actions.append(primary, quiet);
  }
  body.append(actions);
  update();
  root.replaceChildren(bar, body);
  // With the focus (a keyboard submit): on the dialog itself, never on a button, so a key press that was already on
  // its way can't accept anything. Without it: announced, and the focus stays in the page.
  if (document.hasFocus()) root.focus({ preventScroll: true });
  else if (!announced) {
    announced = true;
    setTimeout(() => (live.textContent = `PassAuth: ${title.textContent} ${site}`), 100);
  }
  arm();
}

// Disappears after 30 s, but not while the pointer or the focus is in it (a generated password's prompt stays until answered).
function arm() {
  clearTimeout(timer);
  if (pointerInside || focusInside || last?.generated) return;
  timer = setTimeout(() => void answer("dismiss"), 30_000);
}
document.documentElement.addEventListener("pointerenter", () => {
  pointerInside = true;
  clearTimeout(timer);
});
document.documentElement.addEventListener("pointerleave", () => {
  pointerInside = false;
  if (!busy) arm();
});
addEventListener("focus", () => {
  focusInside = true;
  clearTimeout(timer);
  // The content script focused the frame (a keyboard submit): the dialog takes it, not a button.
  if (document.activeElement === document.body || document.activeElement === null) root.focus({ preventScroll: true });
});
addEventListener("blur", () => {
  focusInside = false;
  if (!busy) arm();
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && e.isTrusted) void answer("dismiss");
});

// Tell the content script how tall the sheet is (a number is all it learns).
let reported = 0;
new ResizeObserver(() => {
  const height = Math.ceil(root.getBoundingClientRect().height);
  if (!nonce || !height || height === reported) return;
  reported = height;
  // An expired prompt keeps its size until the page side removes it.
  void callSave("save:resize", { nonce, height }).catch(() => {});
}).observe(root);

// Only as a frame directly inside a page's top frame (where the content script put it); nothing is asked before the nonce arrives.
const framed = window.top !== window && window.parent === window.top;
if (framed) {
  void receiveNonce().then((n) => {
    nonce = n;
    if (touchPending) sendTouch();
    callSave("save:offer", { nonce }).then(render, () => {
      /* expired, or not this frame's to show: nothing to do here (the real prompt is left alone) */
    });
  });
}
