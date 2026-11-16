/**
 * Where PassAuth's icon goes in a field: at the right edge, left of whatever the site draws there (a
 * show-password eye, a clear button, another password manager's icon), found with elementsFromPoint, and left of
 * a wide right padding (room the site keeps for such a control); just outside the field when that leaves no room
 * inside. The icon is a 24 px hit area. Measured when the icon appears and when the field changes size; scrolling
 * only moves it with the field.
 */
import { composedContains } from "./fields";
import type { Placement } from "./guard";

/** The icon's hit area (px). */
export const ICON_HIT = 24;
const GAP = 4;

/** `inset`: from the field's right edge to the icon's right edge, when inside; otherwise the icon sits just right of the field. */
export interface IconSpot {
  inside: boolean;
  inset: number;
}

/** Where the icon goes in `field`; `ours` tells PassAuth's own hosts apart (they are skipped). */
export function iconSpot(field: HTMLElement, ours: (el: Element) => boolean): IconSpot {
  const r = field.getBoundingClientRect();
  const s = getComputedStyle(field);
  const border = parseFloat(s.borderRightWidth) || 0;
  const padding = parseFloat(s.paddingRight) || 0;
  // The rightmost the icon's right edge may go: just inside the border, or left of a right padding wide enough for a control.
  let edge = r.right - border - (padding >= ICON_HIT ? padding : GAP);
  // Hit-test in the field's own tree (a shadow root, or the document), so controls beside it in that tree are seen.
  const root = field.getRootNode() as Node & Partial<DocumentOrShadowRoot>;
  const at: Partial<DocumentOrShadowRoot> = typeof root.elementsFromPoint === "function" ? root : document;
  if (typeof at.elementsFromPoint === "function" && r.width > 0 && r.height > 0) {
    const y = r.top + r.height / 2;
    const stop = r.right - Math.min(r.width / 2, 120);
    for (let x = r.right - 2; x > stop; x -= 8) {
      for (const el of at.elementsFromPoint(x, y)) {
        // Topmost first: once the field (or something holding it) is reached, the rest lies beneath it.
        if (el === field || composedContains(el, field)) break;
        if (ours(el)) continue;
        const c = el.getBoundingClientRect();
        // An overlay or a wrapper over the whole field isn't a control in it.
        if (c.width > r.width / 2 || c.height > r.height * 2) continue;
        edge = Math.min(edge, c.left - GAP);
      }
    }
  }
  // Not enough room left of those without covering the text: outside the field.
  if (edge - ICON_HIT < r.left + Math.min(r.width / 2, 120)) return { inside: false, inset: 0 };
  return { inside: true, inset: r.right - edge };
}

/** The icon's box for the field at `r` (viewport pixels); `viewportWidth`: room to the right for the outside spot. */
export function iconPlacement(r: DOMRect, spot: IconSpot, viewportWidth: number): Placement {
  const top = r.top + (r.height - ICON_HIT) / 2;
  let left = spot.inside ? r.right - spot.inset - ICON_HIT : r.right + GAP;
  // No room outside either: at the field's right edge after all.
  if (!spot.inside && left + ICON_HIT > viewportWidth) left = r.right - GAP - ICON_HIT;
  return { left, top, width: ICON_HIT, height: ICON_HIT };
}
