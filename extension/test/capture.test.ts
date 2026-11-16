// @vitest-environment happy-dom
// @vitest-environment-options {"url": "https://shop.example/login"}
// Offering to save, page side (content/capture.ts, C13): a submit is found by the page's structure — a click on a
// button in the same form or container as a typed password, in any language — not only by English button words;
// show-password toggles aren't submits; keyboard submits are marked so the prompt can take the focus (D12); only
// real (trusted) events with a user gesture count; L-2: only a password the user typed, and only a submit that
// follows the user's own input in that form within about a second.

import { beforeAll, beforeEach, expect, test, vi } from "vitest";
import { installCapture } from "../src/content/capture";
import { installedChrome } from "./chrome";
import { fakeLayout } from "./dom";

fakeLayout();
const fake = installedChrome();

beforeAll(() => {
  Object.defineProperty(navigator, "userActivation", { value: { isActive: true }, configurable: true });
  installCapture();
});
beforeEach(() => {
  fake.runtimeMessages.length = 0;
});

/** A trusted event, as the browser makes them (`detail` 0: a click from the keyboard). */
function trusted<E extends Event>(e: E): E {
  Object.defineProperty(e, "isTrusted", { value: true });
  return e;
}
const click = (el: Element, detail = 1) => el.dispatchEvent(trusted(new MouseEvent("click", { bubbles: true, composed: true, detail })));
const submitted = () => fake.runtimeMessages.filter((m) => (m as { type: string }).type === "page:submitted");

/** The user types `value` into `el` (a trusted input event leaves it there). */
function type(el: HTMLInputElement, value: string) {
  el.value = value;
  el.dispatchEvent(trusted(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText", data: value })));
}

/** Fields and buttons one under the other (a button drawn over the password field is a show-password eye); the user types both values. */
function form(html: string, user: string, password: string) {
  document.body.innerHTML = html;
  for (const [i, el] of [...document.querySelectorAll<HTMLElement>("input, button, [role=button]")].entries()) el.dataset.rect = `10,${10 + i * 40},200,30`;
  type(document.getElementById("u") as HTMLInputElement, user);
  type(document.getElementById("p") as HTMLInputElement, password);
}

test("a button in the same form as a typed password, whatever it says", () => {
  form(`<form><input id="u" name="email"><input id="p" type="password"><button id="b" type="submit">Anmelden</button></form>`, "alex", "pw-1");
  click(document.getElementById("b")!);
  expect(submitted()).toStrictEqual([{ type: "page:submitted", username: "alex", password: "pw-1", keyboard: false }]);
});

test("no form: a button in the same container as the typed password", () => {
  form(`<div class="card"><div><input id="u" name="user"></div><div><input id="p" type="password"></div><div><span role="button" id="b">→</span></div></div>`, "sam", "pw-2");
  click(document.getElementById("b")!, 0);
  expect(submitted()).toStrictEqual([{ type: "page:submitted", username: "sam", password: "pw-2", keyboard: true }]);
});

test("a show-password toggle or 'Forgot password?' isn't a submit", () => {
  form(
    `<form><input id="u" name="user"><input id="p" type="password"><button id="eye" type="button" aria-pressed="false">👁</button><button id="forgot" type="button">Forgot password?</button></form>`,
    "kim",
    "pw-3",
  );
  click(document.getElementById("eye")!);
  click(document.getElementById("forgot")!);
  expect(submitted()).toStrictEqual([]);
});

test("a button drawn over the password field (an eye without a label) isn't a submit", () => {
  form(`<form><input id="u" name="user"><input id="p" type="password"><button id="b" type="button"><svg></svg></button></form>`, "ann", "pw-6");
  document.getElementById("b")!.dataset.rect = "180,55,24,20";
  click(document.getElementById("b")!);
  expect(submitted()).toStrictEqual([]);
});

test("Enter in the password field is a keyboard submit; a script's event or click counts for nothing", () => {
  form(`<form><input id="u" name="user"><input id="p" type="password"></form>`, "lee", "pw-4");
  const p = document.getElementById("p")!;
  p.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, composed: true }));
  (document.querySelector("form") as HTMLFormElement).dispatchEvent(new Event("submit", { bubbles: true }));
  expect(submitted()).toStrictEqual([]);
  p.dispatchEvent(trusted(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, composed: true })));
  expect(submitted()).toStrictEqual([{ type: "page:submitted", username: "lee", password: "pw-4", keyboard: true }]);
});

test("without a recent user gesture nothing is offered", () => {
  form(`<form><input id="u" name="user"><input id="p" type="password"><button id="b">Go</button></form>`, "max", "pw-5");
  Object.defineProperty(navigator, "userActivation", { value: { isActive: false }, configurable: true });
  try {
    click(document.getElementById("b")!);
    expect(submitted()).toStrictEqual([]);
  } finally {
    Object.defineProperty(navigator, "userActivation", { value: { isActive: true }, configurable: true });
  }
});

// ------------------------------------------------------------------ L-2: only what the user typed, right after

test("L-2: a password the page set itself (or changed after the user typed) is never offered", () => {
  form(`<form><input id="u" name="user"><input id="p" type="password"><button id="b">Go</button></form>`, "ann", "typed-pw");
  const p = document.getElementById("p") as HTMLInputElement;
  // The page replaces what the user typed: not the user's password any more.
  p.value = "the-page-chose-this";
  click(document.getElementById("b")!);
  expect(submitted()).toStrictEqual([]);
  // A field the user never typed into at all.
  document.body.innerHTML = `<form><input id="u2" name="user"><input id="p2" type="password"><button id="b2">Go</button></form>`;
  (document.getElementById("u2") as HTMLInputElement).value = "victim";
  (document.getElementById("p2") as HTMLInputElement).value = "page-password";
  click(document.getElementById("b2")!);
  expect(submitted()).toStrictEqual([]);
  // Typed again by the user: offered.
  const first = p.form!;
  document.body.innerHTML = "";
  document.body.append(first);
  type(p, "typed-again");
  click(document.getElementById("b")!);
  expect(submitted()).toStrictEqual([{ type: "page:submitted", username: "ann", password: "typed-again", keyboard: false }]);
});

test("L-2: a trusted submit counts only right after the user's own input inside that form", () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  try {
    vi.setSystemTime(10_000_000);
    form(`<form id="f"><input id="u" name="user"><input id="p" type="password"></form><button id="elsewhere">Accept cookies</button>`, "kim", "pw-7");
    const f = document.getElementById("f") as HTMLFormElement;
    // form.requestSubmit() right after an unrelated click elsewhere: the browser marks that submit trusted.
    vi.setSystemTime(10_005_000);
    document.getElementById("elsewhere")!.dispatchEvent(trusted(new PointerEvent("pointerdown", { bubbles: true, composed: true })));
    f.dispatchEvent(trusted(new Event("submit", { bubbles: true })));
    expect(submitted()).toStrictEqual([]);
    // Long after the user's last input in the form: nothing either.
    document.getElementById("p")!.dispatchEvent(trusted(new PointerEvent("pointerdown", { bubbles: true, composed: true })));
    vi.setSystemTime(10_006_500);
    f.dispatchEvent(trusted(new Event("submit", { bubbles: true })));
    expect(submitted()).toStrictEqual([]);
    // Right after the user pressed a key in the form: offered.
    document.getElementById("p")!.dispatchEvent(trusted(new KeyboardEvent("keyup", { key: "a", bubbles: true, composed: true })));
    vi.setSystemTime(10_006_800);
    f.dispatchEvent(trusted(new Event("submit", { bubbles: true })));
    expect(submitted()).toMatchObject([{ username: "kim", password: "pw-7" }]);
  } finally {
    vi.useRealTimers();
  }
});
