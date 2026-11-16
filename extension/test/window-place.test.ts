// Window placement (src/shared/window-place.ts): PassAuth's windows open centred over the browser window.

import { expect, test } from "vitest";
import { type Bounds, centerOver, clampTo, defaultFrame, outerSize, plausibleFrame, resizeCentered, sameBounds, usableBounds } from "../src/shared/window-place";

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
