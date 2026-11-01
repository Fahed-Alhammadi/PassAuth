/** Inline autofill menu (inside the page, in an extension frame). */
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "./inline.css";
import { send, type InlineItems, type ItemSummary } from "../shared/messages";

const nonce = location.hash.slice(1);
const root = document.getElementById("menu")!;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> = {}, ...children: (Node | string)[]) {
  const e = Object.assign(document.createElement(tag), props);
  e.append(...children);
  return e;
}

function siteIcon(item: ItemSummary, data: InlineItems) {
  const letter = (item.name[0] ?? "?").toUpperCase();
  const box = el("span", { className: "ic", ariaHidden: "true" }, letter);
  if (data.showIcons && item.host) {
    const img = el("img", { src: `${data.server}/api/icons/${encodeURIComponent(item.host)}`, alt: "", referrerPolicy: "no-referrer" });
    img.addEventListener("load", () => box.replaceChildren(img));
  }
  return box;
}

function render(data: InlineItems) {
  if (data.locked) {
    const unlock = el("button", { className: "btn", type: "button", textContent: "Unlock PassAuth" });
    unlock.addEventListener("click", () => void send({ type: "openPopup" }).then(() => send({ type: "inline:close", nonce })));
    root.replaceChildren(el("div", { className: "locked" }, el("p", {}, "PassAuth is locked. Unlock it to fill this login."), unlock));
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
      row.addEventListener("click", () => void send({ type: "inline:fill", nonce, id: item.id }).catch(() => {}));
      return row;
    }),
  );
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") void send({ type: "inline:close", nonce });
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    const rows = [...root.querySelectorAll<HTMLButtonElement>(".row")];
    const i = rows.indexOf(document.activeElement as HTMLButtonElement);
    rows[(i + (e.key === "ArrowDown" ? 1 : rows.length - 1)) % rows.length]?.focus();
    e.preventDefault();
  }
});

send<InlineItems>({ type: "inline:items", nonce }).then(render, () => root.replaceChildren(el("p", { className: "locked" }, "Reload the page to use PassAuth here.")));
