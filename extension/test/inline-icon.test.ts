// @vitest-environment happy-dom
// Website icons off: the inline menu shows one globe glyph for every login (no letter, no icon request); on, the
// letter stays until the server's icon loads.

import { expect, test } from "vitest";
import { siteIcon } from "../src/inline/site-icon";

const item = { name: "github", host: "github.com" };

test("icons off: a globe glyph, no letter and no request", () => {
  const box = siteIcon(item, { showIcons: false, server: "https://vault.test" });
  expect(box.className).toBe("avatar glyph");
  expect(box.querySelector("svg")).not.toBeNull();
  expect(box.querySelector("img")).toBeNull();
  expect(box.textContent).toBe("");
  expect(box.getAttribute("aria-hidden")).toBe("true");
});

test("icons on: the first letter until the site's icon loads", () => {
  const box = siteIcon(item, { showIcons: true, server: "https://vault.test" });
  expect(box.className).toBe("avatar");
  expect(box.textContent).toBe("G");
  expect(box.querySelector("svg")).toBeNull();
});
