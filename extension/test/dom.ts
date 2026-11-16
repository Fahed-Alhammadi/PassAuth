/**
 * Helpers for the DOM tests (happy-dom; files that start with `// @vitest-environment happy-dom`). happy-dom does no
 * layout, so every element gets a box here: `data-rect="left,top,width,height"`, else 10,10,200,30 (a field you
 * can see). `display: none` and the `hidden` attribute still hide it (checkVisibility).
 */
import { afterEach, beforeEach } from "vitest";

const BOX = [10, 10, 200, 30] as const;

/** Give elements a layout box and the window an origin (`self.origin`, which happy-dom leaves out) for each test. */
export function fakeLayout() {
  let restore: (() => void) | null = null;
  beforeEach(() => {
    const original = Element.prototype.getBoundingClientRect;
    Element.prototype.getBoundingClientRect = function (this: Element) {
      const rect = (this as HTMLElement).dataset?.rect?.split(",").map(Number) ?? BOX;
      const [left = 0, top = 0, width = 0, height = 0] = rect;
      return { left, top, width, height, right: left + width, bottom: top + height, x: left, y: top, toJSON: () => ({}) } as DOMRect;
    };
    Object.defineProperty(globalThis, "origin", { value: location.origin, configurable: true, writable: true });
    restore = () => {
      Element.prototype.getBoundingClientRect = original;
    };
  });
  afterEach(() => {
    restore?.();
    document.body.innerHTML = "";
  });
}

/** Put `html` into the page and return the element with each id. */
export function page<T extends string>(html: string, ...ids: T[]): Record<T, HTMLInputElement> {
  document.body.innerHTML = html;
  return Object.fromEntries(ids.map((id) => [id, document.getElementById(id)])) as Record<T, HTMLInputElement>;
}
