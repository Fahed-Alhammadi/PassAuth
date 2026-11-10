// Tests for window placement (src/shared/window-place.ts): PassAuth's windows open centred over the browser window.
// Run with plain Node (type stripping):  node extension/test/window-place.test.mjs

import assert from "node:assert/strict";
import { centerOver, clampTo, defaultFrame, outerSize, plausibleFrame, resizeCentered, sameBounds, usableBounds } from "../src/shared/window-place.ts";

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

const centre = (b) => [b.left + b.width / 2, b.top + b.height / 2];

test("centerOver: centred on the browser window", () => {
  const anchor = { left: 400, top: 150, width: 1280, height: 800 };
  const b = centerOver(anchor, { width: 380, height: 420 });
  assert.deepEqual(b, { left: 850, top: 340, width: 380, height: 420 });
  assert.deepEqual(centre(b), centre(anchor));
});

test("centerOver: odd leftovers round to whole pixels", () => {
  const b = centerOver({ left: 0, top: 0, width: 1001, height: 701 }, { width: 380, height: 420 });
  assert.ok(Number.isInteger(b.left) && Number.isInteger(b.top));
  assert.ok(Math.abs(b.left - 310.5) <= 0.5 && Math.abs(b.top - 140.5) <= 0.5);
});

test("centerOver: a display left of or above the primary one (negative coordinates)", () => {
  const anchor = { left: -1700, top: -300, width: 1200, height: 900 };
  const b = centerOver(anchor, { width: 380, height: 500 });
  assert.deepEqual(b, { left: -1290, top: -100, width: 380, height: 500 });
  assert.deepEqual(centre(b), centre(anchor));
});

test("centerOver: a display to the right keeps the window on that display", () => {
  const anchor = { left: 1920 + 300, top: 60, width: 1000, height: 700 };
  const b = centerOver(anchor, { width: 380, height: 420 });
  assert.ok(b.left >= anchor.left && b.left + b.width <= anchor.left + anchor.width);
  assert.ok(b.top >= anchor.top && b.top + b.height <= anchor.top + anchor.height);
});

test("centerOver: larger than a small browser window: lines up with its top-left corner, never beyond it", () => {
  const anchor = { left: 20, top: 30, width: 300, height: 260 };
  assert.deepEqual(centerOver(anchor, { width: 380, height: 420 }), { left: 20, top: 30, width: 380, height: 420 });
  // Only the axis that doesn't fit is aligned; the other is still centred.
  assert.deepEqual(centerOver({ ...anchor, width: 1000 }, { width: 380, height: 420 }), { left: 330, top: 30, width: 380, height: 420 });
});

test("clampTo: pulls a window back inside the display's work area", () => {
  const area = { left: 0, top: 25, width: 1440, height: 875 };
  assert.deepEqual(clampTo({ left: 1300, top: 700, width: 380, height: 420 }, area), { left: 1060, top: 480, width: 380, height: 420 });
  assert.deepEqual(clampTo({ left: -50, top: 0, width: 380, height: 420 }, area), { left: 0, top: 25, width: 380, height: 420 });
  // Already inside: unchanged.
  const inside = { left: 500, top: 200, width: 380, height: 420 };
  assert.deepEqual(clampTo(inside, area), inside);
});

test("clampTo: work areas of other displays (negative or offset origins)", () => {
  const left = { left: -1920, top: 0, width: 1920, height: 1080 };
  assert.deepEqual(clampTo({ left: -2000, top: 900, width: 380, height: 420 }, left), { left: -1920, top: 660, width: 380, height: 420 });
  const right = { left: 1600, top: 0, width: 1920, height: 1200 };
  assert.deepEqual(clampTo({ left: 1500, top: -40, width: 380, height: 420 }, right), { left: 1600, top: 0, width: 380, height: 420 });
});

test("clampTo: a window larger than the display is shrunk to it", () => {
  const area = { left: 0, top: 0, width: 800, height: 600 };
  assert.deepEqual(clampTo({ left: 100, top: 100, width: 380, height: 760 }, area), { left: 100, top: 0, width: 380, height: 600 });
});

test("resizeCentered: a size correction keeps the centre", () => {
  const cur = { left: 850, top: 340, width: 380, height: 420 };
  const next = resizeCentered(cur, { width: 380, height: 452 });
  assert.deepEqual(next, { left: 850, top: 324, width: 380, height: 452 });
  assert.deepEqual(centre(next), centre(cur));
});

test("resizeCentered: stays on the display when growing near its edge", () => {
  const area = { left: 0, top: 0, width: 1440, height: 900 };
  const next = resizeCentered({ left: 1060, top: 560, width: 380, height: 300 }, { width: 380, height: 400 }, area);
  assert.deepEqual(next, { left: 1060, top: 500, width: 380, height: 400 });
});

test("outerSize: page size plus the OS frame", () => {
  assert.deepEqual(outerSize({ width: 380, height: 412.4 }, { width: 0, height: 28 }), { width: 380, height: 440 });
  assert.deepEqual(outerSize({ width: 380, height: 400 }, defaultFrame("win")), { width: 396, height: 439 });
  // Unknown systems get a sane guess.
  assert.deepEqual(defaultFrame("openbsd"), defaultFrame("linux"));
});

test("plausibleFrame: measured frames distorted by zoom or odd states are ignored", () => {
  assert.equal(plausibleFrame({ width: 0, height: 28 }), true);
  assert.equal(plausibleFrame({ width: 16, height: 39 }), true);
  assert.equal(plausibleFrame({ width: -40, height: 28 }), false);
  assert.equal(plausibleFrame({ width: 0, height: 400 }), false);
  assert.equal(plausibleFrame({ width: NaN, height: 28 }), false);
  assert.equal(plausibleFrame(undefined), false);
});

test("usableBounds: minimised windows and missing numbers can't anchor a window", () => {
  assert.deepEqual(usableBounds({ left: 1, top: 2, width: 800, height: 600, state: "normal" }), { left: 1, top: 2, width: 800, height: 600 });
  assert.equal(usableBounds({ left: -32000, top: -32000, width: 160, height: 28, state: "minimized" }), null);
  assert.equal(usableBounds({ left: 1, top: 2, width: 800 }), null);
  assert.equal(usableBounds({ left: 1, top: 2, width: 0, height: 600 }), null);
  assert.equal(usableBounds(undefined), null);
});

test("sameBounds: within a pixel", () => {
  const a = { left: 10, top: 10, width: 380, height: 420 };
  assert.equal(sameBounds(a, { ...a, top: 11 }), true);
  assert.equal(sameBounds(a, { ...a, height: 424 }), false);
});

// ------------------------------------------------------------------ runner

let failed = 0;
for (const { name, fn } of tests) {
  try {
    await fn();
    console.log(`ok   - ${name}`);
  } catch (e) {
    failed++;
    console.log(`FAIL - ${name}\n${e?.stack ?? e}`);
  }
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exitCode = failed ? 1 : 0;
