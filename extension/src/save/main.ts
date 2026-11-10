/**
 * Save prompt (inside the page, in an extension frame): "Save login?" /
 * "Update login?" with the "Save in" choice. The website can't read this
 * frame, so the logins listed here and the user's pick never reach the page;
 * the content script that placed the frame only knows its nonce and height.
 *
 * Clickjacking: buttons and choices only react to real (trusted) events, and
 * only once the frame has been fully visible — not covered, transparent or
 * filtered by the page around it — for half a second.
 */
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@web/styles/app.css";
import "./save.css";
import { describeSave, NEW_LOGIN } from "../background/save-plan";
import { closeSvg, logoSvg, plusSvg } from "../content/brand";
import { visibilityGate } from "../content/guard";
import { send, type SaveAnswer, type SaveOffer } from "../shared/messages";

const nonce = location.hash.slice(1);
const root = document.getElementById("prompt")!;
const gate = visibilityGate(document.documentElement);

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

function button(className: string, text: string, onClick: () => void) {
  const b = el("button", className, text);
  b.type = "button";
  b.addEventListener("click", (e) => {
    // Only real clicks (or key presses) on a prompt the user can see.
    if (!e.isTrusted || !gate.ok() || busy) return;
    onClick();
  });
  return b;
}

let busy = false;
let selected = NEW_LOGIN;
let timer: ReturnType<typeof setTimeout> | undefined;
/** After the user has used the prompt, it also stays while the keyboard focus is in it. */
let used = false;

async function answer(accept: "save" | "never" | "dismiss") {
  if (busy) return;
  busy = true;
  clearTimeout(timer);
  root.setAttribute("aria-busy", "true");
  let reply: SaveAnswer;
  try {
    reply = await send<SaveAnswer>({ type: "save:answer", nonce, accept, target: selected });
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
  const primary = button("btn btn-primary btn-block", "", () => void answer("save"));

  // Title, button and the sentence that names what will be saved all follow the selection.
  const update = () => {
    const target = targets.find((t) => t.id === selected);
    title.textContent = target ? "Update login?" : "Save login?";
    primary.textContent = target ? "Update" : "Save";
    note.replaceChildren(...describeSave(target, username, site).map((part) => (typeof part === "string" ? part : el("strong", "", part.strong))));
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
      // A login in a shared vault (only ever the one already saved under this user name) says so.
      list.append(row(t.id, t.name, t.vault ? `In ${t.vault}: ${user}` : user, tile(t.name)));
    }
    list.append(row(NEW_LOGIN, "New login", username || site, tile(plusSvg, true)));
    group.append(el("legend", "field-label", "Save in"), list);
    group.addEventListener("change", (e) => {
      const input = e.target as HTMLInputElement;
      // Only the user changes the choice (clicks and arrow keys are trusted events).
      if (!e.isTrusted || busy) return void (list.querySelector<HTMLInputElement>(`input[value="${CSS.escape(selected)}"]`)!.checked = true);
      selected = input.value;
      update();
    });
    body.append(group);
  }
  if (!state.closed) body.append(note);
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
  // Focus on the dialog itself, never on a button: a key press that was already on its way can't accept anything.
  root.focus({ preventScroll: true });
  arm();
}

// Disappears after 30 s, but not while the pointer is on it or the user is working in it.
function arm() {
  clearTimeout(timer);
  timer = setTimeout(() => void answer("dismiss"), 30_000);
}
document.documentElement.addEventListener("pointerenter", () => clearTimeout(timer));
document.documentElement.addEventListener("pointerleave", () => !busy && arm());
const noteUse = (e: Event) => {
  if (!e.isTrusted) return;
  used = true;
  clearTimeout(timer);
};
document.addEventListener("pointerdown", noteUse, true);
document.addEventListener("keydown", noteUse, true);
document.addEventListener("focusin", () => used && clearTimeout(timer));
addEventListener("blur", () => !busy && arm());

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && e.isTrusted) void answer("dismiss");
});

// Tell the content script how tall the sheet is (a number is all it learns).
let reported = 0;
new ResizeObserver(() => {
  const height = Math.ceil(root.getBoundingClientRect().height);
  if (!height || height === reported) return;
  reported = height;
  void send({ type: "save:resize", nonce, height }).catch(() => {});
}).observe(root);

// Only as a frame directly inside a page's top frame (where the content script put it).
const framed = window.top !== window && window.parent === window.top;
if (framed && nonce) {
  send<SaveOffer>({ type: "save:offer", nonce }).then(render, () => {
    /* expired or not for this tab: the background has told the content script to remove the frame */
  });
}
