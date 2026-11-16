// @vitest-environment happy-dom
// Where the inline icon goes (content/place.ts, D10): left of the site's own controls at the field's right edge
// (found with elementsFromPoint) and of a wide right padding; just outside the field when there is no room; 24 px.

import { afterEach, expect, test } from "vitest";
import { ICON_HIT, iconPlacement, iconSpot } from "../src/content/place";
import { fakeLayout, page } from "./dom";

fakeLayout();

/** elementsFromPoint for the boxes in the page (happy-dom has none): later in the document = painted on top = first in the answer. */
function hitTesting() {
  const doc = document as unknown as { elementsFromPoint?: (x: number, y: number) => Element[] };
  doc.elementsFromPoint = (x: number, y: number) =>
    [...document.body.querySelectorAll("*")]
      .filter((el) => {
        const r = el.getBoundingClientRect();
        return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom;
      })
      .reverse();
  return () => {
    delete doc.elementsFromPoint;
  };
}
let restore: (() => void) | null = null;
afterEach(() => restore?.());

const field = (html: string) => page(html, "f").f;
const ours = () => false;

test("no controls: inside, at the right edge", () => {
  restore = hitTesting();
  const f = field(`<input id="f" data-rect="10,10,300,30">`);
  const spot = iconSpot(f, ours);
  expect(spot.inside).toBe(true);
  const at = iconPlacement(f.getBoundingClientRect(), spot, 1000);
  expect(at).toStrictEqual({ left: 310 - 4 - ICON_HIT, top: 13, width: 24, height: 24 });
});

test("a show-password eye over the field's right edge: the icon goes left of it", () => {
  restore = hitTesting();
  document.body.innerHTML = `<div data-rect="0,0,400,60"><input id="f" data-rect="10,10,300,30"><button id="eye" data-rect="278,13,24,24"></button></div>`;
  const f = document.getElementById("f") as HTMLInputElement;
  const at = iconPlacement(f.getBoundingClientRect(), iconSpot(f, ours), 1000);
  expect(at.left + at.width).toBeLessThanOrEqual(278 - 4);
});

test("PassAuth's own icon there is not a control to avoid", () => {
  restore = hitTesting();
  document.body.innerHTML = `<input id="f" data-rect="10,10,300,30"><div id="icon" data-rect="282,13,24,24"></div>`;
  const f = document.getElementById("f") as HTMLInputElement;
  const icon = document.getElementById("icon")!;
  expect(iconSpot(f, (el) => el === icon)).toStrictEqual({ inside: true, inset: 4 });
});

test("a wide right padding is room the site keeps for a control: the icon stays left of it", () => {
  restore = hitTesting();
  const f = field(`<input id="f" data-rect="10,10,300,30" style="padding-right: 44px">`);
  const at = iconPlacement(f.getBoundingClientRect(), iconSpot(f, ours), 1000);
  expect(at.left + at.width).toBeLessThanOrEqual(310 - 44);
});

test("a narrow field with a control: just outside it, or at its edge when the window has no room", () => {
  restore = hitTesting();
  document.body.innerHTML = `<input id="f" data-rect="10,10,80,30"><span id="x" data-rect="66,15,20,20"></span>`;
  const f = document.getElementById("f") as HTMLInputElement;
  const spot = iconSpot(f, ours);
  expect(spot.inside).toBe(false);
  expect(iconPlacement(f.getBoundingClientRect(), spot, 1000).left).toBe(94);
  expect(iconPlacement(f.getBoundingClientRect(), spot, 100).left).toBe(90 - 4 - ICON_HIT);
});
