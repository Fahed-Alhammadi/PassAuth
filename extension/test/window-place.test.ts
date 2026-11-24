// Window placement (src/shared/window-place.ts): PassAuth's windows open centred over the browser window.

import { expect, test } from "vitest";
import {
  type Bounds,
  centerOver,
  clampTo,
  defaultFrame,
  outerSize,
  plausibleFrame,
  resizeCentered,
  resizeFrom,
  sameBounds,
  TOOLBAR_SPOT,
  underToolbar,
  usableBounds,
} from "../src/shared/window-place";

const centre = (b: Bounds) => [b.left + b.width / 2, b.top + b.height / 2];

test("centerOver: centred on the browser window", () => {
  const anchor = { left: 400, top: 150, width: 1280, height: 800 };
  const b = centerOver(anchor, { width: 380, height: 420 });
  expect(b).toStrictEqual({ left: 850, top: 340, width: 380, height: 420 });
  expect(centre(b)).toStrictEqual(centre(anchor));
});

test("centerOver: odd leftovers round to whole pixels", () => {
  const b = centerOver({ left: 0, top: 0, width: 1001, height: 701 }, { width: 380, height: 420 });
  expect(Number.isInteger(b.left) && Number.isInteger(b.top)).toBe(true);
  expect(Math.abs(b.left - 310.5) <= 0.5 && Math.abs(b.top - 140.5) <= 0.5).toBe(true);
});

test("centerOver: a display left of or above the primary one (negative coordinates)", () => {
  const anchor = { left: -1700, top: -300, width: 1200, height: 900 };
  const b = centerOver(anchor, { width: 380, height: 500 });
  expect(b).toStrictEqual({ left: -1290, top: -100, width: 380, height: 500 });
  expect(centre(b)).toStrictEqual(centre(anchor));
});

test("centerOver: a display to the right keeps the window on that display", () => {
  const anchor = { left: 1920 + 300, top: 60, width: 1000, height: 700 };
  const b = centerOver(anchor, { width: 380, height: 420 });
  expect(b.left >= anchor.left && b.left + b.width <= anchor.left + anchor.width).toBe(true);
  expect(b.top >= anchor.top && b.top + b.height <= anchor.top + anchor.height).toBe(true);
});

test("centerOver: larger than a small browser window: lines up with its top-left corner, never beyond it", () => {
  const anchor = { left: 20, top: 30, width: 300, height: 260 };
  expect(centerOver(anchor, { width: 380, height: 420 })).toStrictEqual({ left: 20, top: 30, width: 380, height: 420 });
  // Only the axis that doesn't fit is aligned; the other is still centred.
  expect(centerOver({ ...anchor, width: 1000 }, { width: 380, height: 420 })).toStrictEqual({ left: 330, top: 30, width: 380, height: 420 });
});

test("clampTo: pulls a window back inside the display's work area", () => {
  const area = { left: 0, top: 25, width: 1440, height: 875 };
  expect(clampTo({ left: 1300, top: 700, width: 380, height: 420 }, area)).toStrictEqual({ left: 1060, top: 480, width: 380, height: 420 });
  expect(clampTo({ left: -50, top: 0, width: 380, height: 420 }, area)).toStrictEqual({ left: 0, top: 25, width: 380, height: 420 });
  // Already inside: unchanged.
  const inside = { left: 500, top: 200, width: 380, height: 420 };
  expect(clampTo(inside, area)).toStrictEqual(inside);
});

test("clampTo: work areas of other displays (negative or offset origins)", () => {
  const left = { left: -1920, top: 0, width: 1920, height: 1080 };
  expect(clampTo({ left: -2000, top: 900, width: 380, height: 420 }, left)).toStrictEqual({ left: -1920, top: 660, width: 380, height: 420 });
  const right = { left: 1600, top: 0, width: 1920, height: 1200 };
  expect(clampTo({ left: 1500, top: -40, width: 380, height: 420 }, right)).toStrictEqual({ left: 1600, top: 0, width: 380, height: 420 });
});

test("clampTo: a window larger than the display is shrunk to it", () => {
  const area = { left: 0, top: 0, width: 800, height: 600 };
  expect(clampTo({ left: 100, top: 100, width: 380, height: 760 }, area)).toStrictEqual({ left: 100, top: 0, width: 380, height: 600 });
});

test("resizeCentered: a size correction keeps the centre", () => {
  const cur = { left: 850, top: 340, width: 380, height: 420 };
  const next = resizeCentered(cur, { width: 380, height: 452 });
  expect(next).toStrictEqual({ left: 850, top: 324, width: 380, height: 452 });
  expect(centre(next)).toStrictEqual(centre(cur));
});

test("resizeCentered: stays on the display when growing near its edge", () => {
  const area = { left: 0, top: 0, width: 1440, height: 900 };
  const next = resizeCentered({ left: 1060, top: 560, width: 380, height: 300 }, { width: 380, height: 400 }, area);
  expect(next).toStrictEqual({ left: 1060, top: 500, width: 380, height: 400 });
});

test("outerSize: page size plus the OS frame", () => {
  expect(outerSize({ width: 380, height: 412.4 }, { width: 0, height: 28 })).toStrictEqual({ width: 380, height: 440 });
  expect(outerSize({ width: 380, height: 400 }, defaultFrame("win"))).toStrictEqual({ width: 396, height: 439 });
  // Unknown systems get a sane guess.
  expect(defaultFrame("openbsd")).toStrictEqual(defaultFrame("linux"));
});

test("plausibleFrame: measured frames distorted by zoom or odd states are ignored", () => {
  expect(plausibleFrame({ width: 0, height: 28 })).toBe(true);
  expect(plausibleFrame({ width: 16, height: 39 })).toBe(true);
  expect(plausibleFrame({ width: -40, height: 28 })).toBe(false);
  expect(plausibleFrame({ width: 0, height: 400 })).toBe(false);
  expect(plausibleFrame({ width: NaN, height: 28 })).toBe(false);
  expect(plausibleFrame(undefined)).toBe(false);
});

test("usableBounds: minimised windows and missing numbers can't anchor a window", () => {
  expect(usableBounds({ left: 1, top: 2, width: 800, height: 600, state: "normal" })).toStrictEqual({ left: 1, top: 2, width: 800, height: 600 });
  expect(usableBounds({ left: -32000, top: -32000, width: 160, height: 28, state: "minimized" })).toBe(null);
  expect(usableBounds({ left: 1, top: 2, width: 800 })).toBe(null);
  expect(usableBounds({ left: 1, top: 2, width: 0, height: 600 })).toBe(null);
  expect(usableBounds(undefined)).toBe(null);
});

test("sameBounds: within a pixel", () => {
  const a = { left: 10, top: 10, width: 380, height: 420 };
  expect(sameBounds(a, { ...a, top: 11 })).toBe(true);
  expect(sameBounds(a, { ...a, height: 424 })).toBe(false);
});

test("underToolbar: top right of the browser window, under its toolbar", () => {
  const anchor = { left: 400, top: 150, width: 1280, height: 800 };
  const b = underToolbar(anchor, { width: 380, height: 420 });
  expect(b).toStrictEqual({ left: 400 + 1280 - 380 - TOOLBAR_SPOT.right, top: 150 + TOOLBAR_SPOT.top, width: 380, height: 420 });
  // Negative coordinates (a display left of the primary one) work the same way.
  expect(underToolbar({ left: -1700, top: -300, width: 1200, height: 900 }, { width: 380, height: 500 })).toStrictEqual({
    left: -1700 + 1200 - 380 - TOOLBAR_SPOT.right,
    top: -300 + TOOLBAR_SPOT.top,
    width: 380,
    height: 500,
  });
});

test("underToolbar: a browser window too small for it there: centred instead", () => {
  const anchor = { left: 20, top: 30, width: 390, height: 900 };
  expect(underToolbar(anchor, { width: 380, height: 420 })).toStrictEqual(centerOver(anchor, { width: 380, height: 420 }));
  const short = { left: 0, top: 0, width: 1200, height: 480 };
  expect(underToolbar(short, { width: 380, height: 420 })).toStrictEqual(centerOver(short, { width: 380, height: 420 }));
});

test("resizeFrom top-right: the top-right corner stays where it is", () => {
  const current = { left: 1288, top: 234, width: 380, height: 420 };
  const b = resizeFrom(current, { width: 380, height: 520 }, "top-right");
  expect(b).toStrictEqual({ left: 1288, top: 234, width: 380, height: 520 });
  const wider = resizeFrom(current, { width: 400, height: 300 }, "top-right");
  expect(wider.left + wider.width).toBe(current.left + current.width);
  expect(wider.top).toBe(current.top);
  // Still kept inside the display.
  expect(resizeFrom({ left: 100, top: 700, width: 380, height: 100 }, { width: 380, height: 400 }, "top-right", { left: 0, top: 0, width: 1440, height: 900 }).top).toBe(500);
  // "center" is resizeCentered.
  expect(resizeFrom(current, { width: 380, height: 520 }, "center")).toStrictEqual(resizeCentered(current, { width: 380, height: 520 }));
});
