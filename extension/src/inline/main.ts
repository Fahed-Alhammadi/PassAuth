/** Inline autofill menu (inside the page, in an extension frame). */
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@web/styles/app.css";
import "./inline.css";
import { send, type InlineItems, type ItemSummary } from "../shared/messages";
import { logoSvg } from "../content/brand";
import { visibilityGate } from "../content/guard";

const nonce = location.hash.slice(1);
const menu = document.getElementById("menu")!;
// Brand line, so it is clear whose list this is; the rows (or a message) go below it.
const head = el("div", { className: "head" });
head.innerHTML = logoSvg(16);
head.append("PassAuth");
const root = el("div", { className: "rows" });
menu.append(head, root);
/** What is shown under the brand line: the rows, or a message. */
let body: HTMLElement = root;
function show(next: HTMLElement) {
  body.replaceWith(next);
  body = next;
}
// Clicks count only once this frame has been fully visible (not covered or made
// transparent by the page around it) for half a second.
const gate = visibilityGate(document.documentElement);

function showError(e: unknown) {
  const text = e instanceof Error ? e.message : String(e);
  const close = el("button", { className: "btn", type: "button", textContent: "Close" });
  close.addEventListener("click", () => void send({ type: "inline:close", nonce }).catch(() => {}));
  const message = el("p", { title: text }, text);
  show(el("div", { className: "locked", role: "alert" }, message, close));
  close.focus();
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> = {}, ...children: (Node | string)[]) {
  const e = Object.assign(document.createElement(tag), props);
  e.append(...children);
  return e;
}

function siteIcon(item: ItemSummary, data: InlineItems) {
  const letter = (item.name.trim()[0] ?? "?").toUpperCase();
  const box = el("span", { className: "avatar", ariaHidden: "true" }, letter);
  if (data.showIcons && item.host) {
    const img = el("img", { src: `${data.server}/api/icons/${encodeURIComponent(item.host)}`, alt: "", referrerPolicy: "no-referrer" });
    img.addEventListener("load", () => (box.classList.add("has-img"), box.replaceChildren(img)));
  }
  return box;
}

function render(data: InlineItems) {
  if (data.theme !== "system") document.documentElement.dataset.theme = data.theme;
  if (data.locked) {
    const unlock = el("button", { className: "btn btn-accent", type: "button", textContent: "Unlock PassAuth" });
    unlock.addEventListener("click", (e) => {
      if (!e.isTrusted || !gate.ok()) return;
      void send({ type: "openPopup" }).then(() => send({ type: "inline:close", nonce }), showError);
    });
    show(el("div", { className: "locked" }, el("p", {}, "Unlock PassAuth to fill this login."), unlock));
    unlock.focus();
    return;
  }
  root.replaceChildren(
    ...data.items.map((item) => {
      const row = el(
        "button",
        { className: "row", type: "button", title: `Fill ${item.name}` },
        siteIcon(item, data),
        el("span", { className: "txt" }, el("span", { className: "name", textContent: item.name }), el("span", { className: "user", textContent: item.subtitle })),
      );
      row.addEventListener("click", (e) => {
        if (!e.isTrusted || !gate.ok()) return;
        void send({ type: "inline:fill", nonce, id: item.id }).catch(showError);
      });
      return row;
    }),
  );
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") void send({ type: "inline:close", nonce });
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    const rows = [...menu.querySelectorAll<HTMLButtonElement>(".row")];
    const i = rows.indexOf(document.activeElement as HTMLButtonElement);
    rows[(i + (e.key === "ArrowDown" ? 1 : rows.length - 1)) % rows.length]?.focus();
    e.preventDefault();
  }
});

send<InlineItems>({ type: "inline:items", nonce }).then(render, showError);
