// @vitest-environment happy-dom
// The click gate in PassAuth's framed pages (content/guard.ts clickGate): a click counts once the frame has been
// visible and the pointer has rested inside it for 500 ms, and the wait starts again when the frame moves under a
// resting pointer (found in a real browser: a page that moved the open inline menu with a translate on <body> got a
// row filled by the next click, before the content script's 250 ms tamper check closed the menu).

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { againHint, CONFIRM_MAX_MS, clickGate, confirmsTap, covered, HOST_CSS, placeHost, tampered } from "../src/content/guard";

/** IntersectionObserver v2 that reports the target fully visible at once; `seen(false)` hides it (covered by the page). */
let seen: (visible: boolean) => void = () => {};
class VisibleObserver {
  constructor(private callback: (entries: unknown[]) => void) {}
  observe(target: Element) {
    seen = (isVisible) => this.callback([{ target, isVisible }]);
    seen(true);
  }
  disconnect() {}
}

let gate: ReturnType<typeof clickGate>;
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["performance", "Date", "setTimeout"] });
  vi.stubGlobal("IntersectionObserver", VisibleObserver);
  // Fake time starts at 0, which the gate reads as "not yet".
  vi.advanceTimersByTime(1000);
  gate = clickGate(document.documentElement);
});
afterEach(() => {
  gate.stop();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

/** A trusted pointer event at a screen point and a point in this frame. */
function pointer(type: string, screen: [number, number], client: [number, number]) {
  const e = new PointerEvent(type, { bubbles: true, pointerType: "mouse", screenX: screen[0], screenY: screen[1], clientX: client[0], clientY: client[1] });
  Object.defineProperty(e, "isTrusted", { value: true });
  window.dispatchEvent(e);
}
const click = () => {
  const e = new MouseEvent("click", { detail: 1 });
  Object.defineProperty(e, "isTrusted", { value: true });
  return e;
};

test("a click counts once the pointer has rested inside the frame for 500 ms", () => {
  pointer("pointerover", [400, 300], [120, 80]);
  vi.advanceTimersByTime(300);
  expect(gate.ok(click())).toBe(false);
  vi.advanceTimersByTime(250);
  pointer("pointerdown", [400, 300], [120, 80]);
  expect(gate.ok(click())).toBe(true);
});

test("the frame moved under a resting pointer: the next click doesn't count", () => {
  pointer("pointermove", [400, 300], [120, 80]);
  vi.advanceTimersByTime(700);
  expect(gate.ok(click())).toBe(true);
  // The page moved the frame 40 px right and 20 px up: the same screen point is elsewhere in the frame.
  pointer("pointerdown", [400, 300], [80, 100]);
  pointer("pointerup", [400, 300], [80, 100]);
  expect(gate.ok(click())).toBe(false);
  vi.advanceTimersByTime(500);
  expect(gate.ok(click())).toBe(true);
});

test("moving the pointer inside the frame doesn't restart the wait", () => {
  pointer("pointermove", [400, 300], [120, 80]);
  vi.advanceTimersByTime(600);
  pointer("pointermove", [430, 310], [150, 90]);
  pointer("pointerdown", [430, 310], [150, 90]);
  expect(gate.ok(click())).toBe(true);
});

test("PassAuth's own move (moved) and a pointer that left start the wait again", () => {
  pointer("pointermove", [400, 300], [120, 80]);
  vi.advanceTimersByTime(600);
  gate.moved();
  expect(gate.ok(click())).toBe(false);
  vi.advanceTimersByTime(500);
  expect(gate.ok(click())).toBe(true);
  document.documentElement.dispatchEvent(new PointerEvent("pointerleave"));
  expect(gate.ok(click())).toBe(false);
});

test("untrusted pointer events are ignored", () => {
  window.dispatchEvent(new PointerEvent("pointermove", { screenX: 1, screenY: 1, clientX: 1, clientY: 1 }));
  vi.advanceTimersByTime(600);
  expect(gate.ok(click())).toBe(false);
});

// ------------------------------------------------------------------ touch and pen: a confirm tap

/**
 * A trusted tap as Chrome sends it on a touch screen: pointerover, pointerdown, pointerup, pointerout and
 * pointerleave, then the click (a PointerEvent with pointerType "touch"). `screen`/`client`: where it lands on the
 * screen and in the frame.
 */
function tap(screen: [number, number], client: [number, number], pointerType = "touch") {
  for (const type of ["pointerover", "pointerdown", "pointerup", "pointerout"]) {
    const e = new PointerEvent(type, { bubbles: true, pointerType, screenX: screen[0], screenY: screen[1], clientX: client[0], clientY: client[1] });
    Object.defineProperty(e, "isTrusted", { value: true });
    window.dispatchEvent(e);
  }
  document.documentElement.dispatchEvent(new PointerEvent("pointerleave", { pointerType }));
  const click = new PointerEvent("click", { pointerType, detail: 1, screenX: screen[0], screenY: screen[1], clientX: client[0], clientY: client[1] });
  Object.defineProperty(click, "isTrusted", { value: true });
  return gate.ok(click);
}

describe("touch and pen taps: a second tap at the same place confirms the first", () => {
  test("the first tap asks for a confirm tap; one 0.5–5 s later on the unmoved frame counts", () => {
    expect(tap([400, 300], [120, 80])).toBe(false);
    vi.advanceTimersByTime(800);
    // Not the same point of the frame (another row), but the frame is where it was: the offset is the same.
    expect(tap([420, 340], [140, 120])).toBe(true);
    // Used up: the next action asks again.
    expect(tap([420, 340], [140, 120])).toBe(false);
  });

  test("a double tap is no decision: the second must come at least half a second later", () => {
    expect(tap([400, 300], [120, 80])).toBe(false);
    vi.advanceTimersByTime(200);
    expect(tap([400, 300], [120, 80])).toBe(false);
    vi.advanceTimersByTime(600);
    expect(tap([400, 300], [120, 80])).toBe(true);
  });

  test("too late: a tap after 5 s starts over", () => {
    expect(tap([400, 300], [120, 80])).toBe(false);
    vi.advanceTimersByTime(CONFIRM_MAX_MS + 100);
    expect(tap([400, 300], [120, 80])).toBe(false);
    vi.advanceTimersByTime(700);
    expect(tap([400, 300], [120, 80])).toBe(true);
  });

  test("the page moved the frame between the taps: the second tap doesn't count", () => {
    expect(tap([400, 300], [120, 80])).toBe(false);
    vi.advanceTimersByTime(800);
    // The same point of the frame, 60 px further down the screen.
    expect(tap([400, 360], [120, 80])).toBe(false);
    // That tap asks again, at the frame's new place.
    vi.advanceTimersByTime(800);
    expect(tap([400, 360], [120, 80])).toBe(true);
  });

  test("PassAuth moved or resized the frame between the taps (moved, resize): start over", () => {
    expect(tap([400, 300], [120, 80])).toBe(false);
    vi.advanceTimersByTime(300);
    gate.moved();
    vi.advanceTimersByTime(500);
    expect(tap([400, 300], [120, 80])).toBe(false);
    vi.advanceTimersByTime(600);
    expect(tap([400, 300], [120, 80])).toBe(true);
    expect(tap([400, 300], [120, 80])).toBe(false);
    vi.advanceTimersByTime(300);
    window.dispatchEvent(new Event("resize"));
    vi.advanceTimersByTime(500);
    expect(tap([400, 300], [120, 80])).toBe(false);
  });

  test("the frame was covered between the taps: no confirm until it has been seen for half a second again", () => {
    expect(tap([400, 300], [120, 80])).toBe(false);
    vi.advanceTimersByTime(300);
    seen(false);
    vi.advanceTimersByTime(100);
    seen(true);
    vi.advanceTimersByTime(400);
    expect(tap([400, 300], [120, 80])).toBe(false);
    // That tap asked again; the frame has now been visible long enough.
    vi.advanceTimersByTime(600);
    expect(tap([400, 300], [120, 80])).toBe(true);
  });

  test("a pen works the same way; a mouse click still needs the pointer to rest (unchanged)", () => {
    expect(tap([400, 300], [120, 80], "pen")).toBe(false);
    vi.advanceTimersByTime(800);
    expect(tap([400, 300], [120, 80], "pen")).toBe(true);
    // A mouse "tap" sequence (in, out, click) never counts: the pointer left before the click.
    expect(tap([400, 300], [120, 80], "mouse")).toBe(false);
    vi.advanceTimersByTime(800);
    expect(tap([400, 300], [120, 80], "mouse")).toBe(false);
  });

  test("the hint names the input: Tap again, Click again, Press Enter again", () => {
    expect(againHint(new PointerEvent("click", { pointerType: "touch", detail: 1 }))).toBe("Tap again");
    expect(againHint(new PointerEvent("click", { pointerType: "pen", detail: 1 }))).toBe("Tap again");
    expect(againHint(new MouseEvent("click", { detail: 1 }))).toBe("Click again");
    expect(againHint(new KeyboardEvent("keydown", { key: "Enter" }))).toBe("Press Enter again");
    // Enter or Space on a focused button: a click without a pointer.
    expect(againHint(new MouseEvent("click", { detail: 0 }))).toBe("Press Enter again");
  });
});

test("confirmsTap: the rule on its own", () => {
  const first = { at: 10_000, dx: 280, dy: 220 };
  const visible = 9_000;
  expect(confirmsTap(first, { at: 10_600, dx: 280, dy: 220 }, visible)).toBe(true);
  expect(confirmsTap(first, { at: 10_600, dx: 282.5, dy: 218 }, visible), "rounding of fractional touch points").toBe(true);
  expect(confirmsTap(first, { at: 10_600, dx: 290, dy: 220 }, visible), "the frame moved").toBe(false);
  expect(confirmsTap(first, { at: 10_400, dx: 280, dy: 220 }, visible), "too soon").toBe(false);
  expect(confirmsTap(first, { at: 15_100, dx: 280, dy: 220 }, visible), "too late").toBe(false);
  expect(confirmsTap(first, { at: 10_600, dx: 280, dy: 220 }, 10_200), "seen again only after the first tap").toBe(false);
  expect(confirmsTap(first, { at: 10_600, dx: 280, dy: 220 }, 0), "not visible").toBe(false);
  expect(confirmsTap(null, { at: 10_600, dx: 280, dy: 220 }, visible), "no first tap").toBe(false);
});

// ------------------------------------------------------------------ L-4: the confirm tap is on the same control

/** A trusted touch tap on `el`, whose click listener asks the gate (as the framed pages' buttons and rows do). */
function tapOn(el: HTMLElement, screen: [number, number], client: [number, number]): boolean {
  let counted = false;
  const listener = (e: Event) => {
    counted = gate.ok(e);
  };
  el.addEventListener("click", listener);
  const click = new PointerEvent("click", { bubbles: true, pointerType: "touch", detail: 1, screenX: screen[0], screenY: screen[1], clientX: client[0], clientY: client[1] });
  Object.defineProperty(click, "isTrusted", { value: true });
  el.dispatchEvent(click);
  el.removeEventListener("click", listener);
  return counted;
}

test('L-4: a first tap on one control never confirms a tap on another ("New card", then a card row)', () => {
  document.body.innerHTML = `<button id="add">New card</button><div id="row" data-id="card-1"></div><div id="row-again" data-id="card-1"></div>`;
  const add = document.getElementById("add")!;
  const row = document.getElementById("row")!;
  expect(tapOn(add, [400, 300], [120, 80])).toBe(false);
  vi.advanceTimersByTime(800);
  // The row: a first tap of its own, not the confirm of "New card".
  expect(tapOn(row, [400, 340], [120, 120])).toBe(false);
  vi.advanceTimersByTime(800);
  expect(tapOn(row, [400, 340], [120, 120])).toBe(true);
  // A row is the same control when it was drawn again (codes refresh): by its item id.
  expect(tapOn(row, [400, 340], [120, 120])).toBe(false);
  vi.advanceTimersByTime(800);
  expect(tapOn(document.getElementById("row-again")!, [400, 340], [120, 120])).toBe(true);
  expect(confirmsTap({ at: 1000, dx: 0, dy: 0, control: "id:a" }, { at: 1600, dx: 0, dy: 0, control: "id:b" }, 500)).toBe(false);
});

// ------------------------------------------------------------------ M-1: keys count only once armed

const key = () => {
  const e = new KeyboardEvent("keydown", { key: "Enter" });
  Object.defineProperty(e, "isTrusted", { value: true });
  return e;
};

test("M-1: a key press counts only after PassAuth gave the frame the focus (or a click passed), until the frame loses it", () => {
  vi.spyOn(document, "hasFocus").mockReturnValue(true);
  vi.advanceTimersByTime(600);
  // Visible long enough, but the focus came some other way (a page with a handle on this window): nothing.
  expect(gate.keysArmed()).toBe(false);
  expect(gate.ok(key())).toBe(false);
  // The content script's focus request (with the nonce): keys count.
  gate.armKeys();
  expect(gate.ok(key())).toBe(true);
  // The frame lost the focus: disarmed.
  window.dispatchEvent(new Event("blur"));
  expect(gate.ok(key())).toBe(false);
  // A mouse click that passed the checks arms it again.
  pointer("pointermove", [400, 300], [120, 80]);
  vi.advanceTimersByTime(600);
  expect(gate.ok(click())).toBe(true);
  expect(gate.ok(key())).toBe(true);
  window.dispatchEvent(new Event("blur"));
  // A focus request while the frame doesn't have the focus arms nothing by itself…
  vi.spyOn(document, "hasFocus").mockReturnValue(false);
  gate.armKeys();
  expect(gate.ok(key())).toBe(false);
  // …but the focus it asked for, arriving just after it, does (the two travel separately).
  window.dispatchEvent(new Event("focus"));
  expect(gate.ok(key())).toBe(true);
  window.dispatchEvent(new Event("blur"));
  // A focus long after the request (not the one PassAuth asked for) arms nothing.
  gate.armKeys();
  vi.advanceTimersByTime(1500);
  window.dispatchEvent(new Event("focus"));
  expect(gate.ok(key())).toBe(false);
  // Nor does a focus that comes with no request at all.
  window.dispatchEvent(new Event("blur"));
  window.dispatchEvent(new Event("focus"));
  expect(gate.ok(key())).toBe(false);
});

// ------------------------------------------------------------------ H-1: outlines and masks

/** Computed styles as Chrome reports them for an untouched PassAuth host (and plain html/body), with `over` on top. */
function styles(over: Record<string, string> = {}) {
  const base: Record<string, string> = {
    opacity: "1",
    filter: "none",
    clipPath: "none",
    visibility: "visible",
    mixBlendMode: "normal",
    position: "fixed",
    pointerEvents: "auto",
    display: "block",
    contentVisibility: "visible",
    transform: "none",
    translate: "none",
    scale: "none",
    rotate: "none",
    zoom: "1",
    marginTop: "0px",
    marginRight: "0px",
    marginBottom: "0px",
    marginLeft: "0px",
    outlineStyle: "none",
    outlineWidth: "3px",
    "mask-image": "none",
    "-webkit-mask-image": "none",
    "-webkit-mask-box-image-source": "none",
    ...over,
  };
  return { ...base, getPropertyValue: (p: string) => base[p] ?? "" };
}

describe("H-1: tampered() sees outlines and masks a page puts on the host, <html> or <body>", () => {
  let host: HTMLElement;
  let byElement: Map<Element, ReturnType<typeof styles>>;
  beforeEach(() => {
    host = document.createElement("div");
    document.body.append(host);
    byElement = new Map();
    vi.stubGlobal("getComputedStyle", (el: Element) => byElement.get(el) ?? styles());
  });
  afterEach(() => host.remove());

  test("an untouched host is fine", () => {
    expect(tampered(host)).toBe(false);
  });
  test("an outline on the host (the page drew a wide one over the frame)", () => {
    byElement.set(host, styles({ outlineStyle: "solid", outlineWidth: "1000px" }));
    expect(tampered(host)).toBe(true);
  });
  test("a mask on the host, prefixed or not, or a mask border", () => {
    for (const p of ["mask-image", "-webkit-mask-image", "-webkit-mask-box-image-source"]) {
      byElement.set(host, styles({ [p]: "linear-gradient(transparent, transparent)" }));
      expect(tampered(host), p).toBe(true);
    }
  });
  test("a wide outline or a mask on <body> or <html>; a focus ring there is fine", () => {
    for (const el of [document.body, document.documentElement]) {
      byElement.clear();
      byElement.set(el, styles({ outlineStyle: "solid", outlineWidth: "1000px" }));
      expect(tampered(host)).toBe(true);
      byElement.set(el, styles({ "-webkit-mask-image": "url(x.png)" }));
      expect(tampered(host)).toBe(true);
      byElement.set(el, styles({ outlineStyle: "auto", outlineWidth: "1px" }));
      expect(tampered(host)).toBe(false);
    }
  });
  test("content-visibility on the host hides what is inside it", () => {
    byElement.set(host, styles({ contentVisibility: "hidden" }));
    expect(tampered(host)).toBe(true);
  });
});

test("H-1: the host's styles are all pinned (all: initial !important), outline and masks too; placement comes through custom properties", () => {
  expect(HOST_CSS).toMatch(/:host \{ all: initial !important;/);
  for (const d of ["outline: none !important", "mask: none !important", "-webkit-mask: none !important", "-webkit-mask-box-image: none !important", "left: var(--pa-left, auto) !important"]) {
    expect(HOST_CSS).toContain(d);
  }
  const el = document.createElement("div");
  placeHost(el, { left: 10, top: 20, width: 300, height: 220 });
  expect(["--pa-left", "--pa-top", "--pa-width", "--pa-height"].map((p) => [el.style.getPropertyValue(p), el.style.getPropertyPriority(p)])).toStrictEqual([
    ["10px", "important"],
    ["20px", "important"],
    ["300px", "important"],
    ["220px", "important"],
  ]);
});

// Safari and Firefox have no IntersectionObserver v2 (no `isVisible`): the frame counts as visible from when it was
// shown, and the content script checks every animation frame that nothing of the page lies over it (`covered`).
describe("browsers without the visibility check (Safari, Firefox)", () => {
  class PlainObserver {
    constructor(private callback: (entries: unknown[]) => void) {}
    observe(target: Element) {
      this.callback([{ target, isIntersecting: true, intersectionRatio: 1 }]);
    }
    disconnect() {}
  }
  let plain: ReturnType<typeof clickGate>;
  beforeEach(() => {
    vi.stubGlobal("IntersectionObserver", PlainObserver);
    plain = clickGate(document.documentElement);
  });
  afterEach(() => plain.stop());

  test("a click counts once the frame was shown and the pointer rested inside it for 500 ms", () => {
    pointer("pointerover", [500, 300], [20, 10]);
    expect(plain.ok(click())).toBe(false);
    vi.advanceTimersByTime(500);
    expect(plain.ok(click())).toBe(true);
  });

  test("the keyboard counts after PassAuth gave the frame the focus, once it was shown for 500 ms", () => {
    vi.spyOn(document, "hasFocus").mockReturnValue(true);
    plain.armKeys();
    const enter = new KeyboardEvent("keydown", { key: "Enter" });
    expect(plain.ok(enter)).toBe(false);
    vi.advanceTimersByTime(500);
    expect(plain.ok(enter)).toBe(true);
  });

  test("a frame only partly on the screen doesn't count as shown", () => {
    class PartObserver {
      constructor(private callback: (entries: unknown[]) => void) {}
      observe(target: Element) {
        this.callback([{ target, isIntersecting: true, intersectionRatio: 0.6 }]);
      }
      disconnect() {}
    }
    vi.stubGlobal("IntersectionObserver", PartObserver);
    const part = clickGate(document.documentElement);
    pointer("pointerover", [500, 300], [20, 10]);
    vi.advanceTimersByTime(1000);
    expect(part.ok(click())).toBe(false);
    part.stop();
  });

  test("tampered: the page laying something over the menu closes it; the in-field icon isn't checked this way", () => {
    vi.stubGlobal("getComputedStyle", () => styles());
    const host = document.createElement("div");
    document.body.append(host);
    vi.spyOn(host, "getBoundingClientRect").mockReturnValue({ left: 10, top: 10, width: 200, height: 100, right: 210, bottom: 110 } as DOMRect);
    const other = document.createElement("div");
    Object.defineProperty(document, "elementFromPoint", { value: () => other, configurable: true });
    expect(tampered(host)).toBe(true);
    expect(tampered(host, null, null, { cover: false })).toBe(false);
    Object.defineProperty(document, "elementFromPoint", { value: () => host, configurable: true });
    expect(tampered(host)).toBe(false);
    host.remove();
  });

  test("covered: the frame must be the top element at its centre and near its corners", () => {
    const host = document.createElement("div");
    const other = document.createElement("div");
    const rect = { left: 100, top: 50, width: 300, height: 200, right: 400, bottom: 250 } as DOMRect;
    expect(covered(host, rect, () => host)).toBe(false);
    expect(covered(host, rect, (x, y) => (x > 350 && y > 200 ? other : host))).toBe(true);
    expect(covered(host, rect, () => null)).toBe(true);
  });
});

test("Chrome (visibility check present): if its observer can't start, a click never counts (as before)", () => {
  class Broken {
    constructor() {
      throw new Error("no");
    }
  }
  vi.stubGlobal("IntersectionObserver", Broken);
  vi.stubGlobal(
    "IntersectionObserverEntry",
    class {
      isVisible = false;
    },
  );
  Object.defineProperty((globalThis as { IntersectionObserverEntry: { prototype: object } }).IntersectionObserverEntry.prototype, "isVisible", { value: false });
  const g = clickGate(document.documentElement);
  pointer("pointerover", [500, 300], [20, 10]);
  vi.advanceTimersByTime(1000);
  expect(g.ok(click())).toBe(false);
  g.stop();
});
