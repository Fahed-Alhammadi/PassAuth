/** The inline menu's picture for a login (kept apart from main.ts, which runs the menu, so it can be tested alone). */
import { globeSvg } from "../content/brand";
import type { InlineItems, ItemSummary } from "../shared/types";

/**
 * The site's icon from the server, the login's first letter until (or unless) the icon loads. With website icons off,
 * the same globe for every login (no letter, no request), like the popup's SiteIcon.
 */
export function siteIcon(item: Pick<ItemSummary, "name" | "host">, d: Pick<InlineItems, "showIcons" | "server">): HTMLElement {
  const box = document.createElement("span");
  box.className = "avatar";
  box.setAttribute("aria-hidden", "true");
  if (!d.showIcons) {
    box.classList.add("glyph");
    box.innerHTML = globeSvg;
    return box;
  }
  box.textContent = (item.name.trim()[0] ?? "?").toUpperCase();
  if (item.host) {
    const img = document.createElement("img");
    img.src = `${d.server}/api/icons/${encodeURIComponent(item.host)}`;
    img.alt = "";
    img.referrerPolicy = "no-referrer";
    img.addEventListener("load", () => {
      box.classList.add("has-img");
      box.replaceChildren(img);
    });
  }
  return box;
}
