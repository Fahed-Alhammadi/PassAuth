// @vitest-environment happy-dom
// L-1: the inline menu opens by itself only when the user's own last input put the focus into that field — a click
// or tap on the field or its label, or Tab — never when the page focuses a field from its script, even right after
// an unrelated click (content/inline.ts `inputAimedAt`).

import { expect, test } from "vitest";
import { inputAimedAt } from "../src/content/inline";

const NOW = 1_000_000;

function page() {
  document.body.innerHTML = `
    <form>
      <label id="lbl" for="card">Card number</label>
      <label id="wrap">Name <span id="inner">on card</span><input id="name" autocomplete="cc-name"></label>
      <input id="card" autocomplete="cc-number">
    </form>
    <button id="cookies">Accept cookies</button>`;
  const $ = (id: string) => document.getElementById(id) as HTMLInputElement;
  return { card: $("card"), name: $("name"), lbl: $("lbl"), inner: $("inner"), cookies: $("cookies") };
}

test("a click on the field itself, or on one of its labels, opens it", () => {
  const p = page();
  expect(inputAimedAt({ at: NOW - 100, target: p.card, tab: false }, p.card, NOW)).toBe(true);
  expect(inputAimedAt({ at: NOW - 100, target: p.lbl, tab: false }, p.card, NOW)).toBe(true);
  // A label wrapping the field, clicked on its text.
  expect(inputAimedAt({ at: NOW - 100, target: p.inner, tab: false }, p.name, NOW)).toBe(true);
});

test("Tab (or Shift+Tab) into the field opens it", () => {
  const p = page();
  expect(inputAimedAt({ at: NOW - 50, target: p.name, tab: true }, p.card, NOW)).toBe(true);
});

test("the page focusing a field right after an unrelated click (its cookie banner) or key press doesn't", () => {
  const p = page();
  expect(inputAimedAt({ at: NOW - 100, target: p.cookies, tab: false }, p.card, NOW)).toBe(false);
  // Enter in another field (the page then moves the focus to the next step's field itself).
  expect(inputAimedAt({ at: NOW - 100, target: p.name, tab: false }, p.card, NOW)).toBe(false);
  // Another field's label.
  expect(inputAimedAt({ at: NOW - 100, target: p.inner, tab: false }, p.card, NOW)).toBe(false);
  expect(inputAimedAt({ at: NOW - 100, target: null, tab: false }, p.card, NOW)).toBe(false);
});

test("only within a second of that input", () => {
  const p = page();
  expect(inputAimedAt({ at: NOW - 999, target: p.card, tab: false }, p.card, NOW)).toBe(true);
  expect(inputAimedAt({ at: NOW - 1000, target: p.card, tab: false }, p.card, NOW)).toBe(false);
  expect(inputAimedAt({ at: NOW - 1500, target: p.card, tab: true }, p.card, NOW)).toBe(false);
});
