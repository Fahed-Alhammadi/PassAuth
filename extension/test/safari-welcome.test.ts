// @vitest-environment happy-dom
// Safari's first run opens the welcome page (popup.html?welcome=1): without shortcuts or a privacy API it must render
// (no keyboard or default-password-manager steps), not crash into the error screen.

import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { expect, test, vi } from "vitest";

vi.mock("../src/shared/protocol", () => ({ callPopup: async () => ({ status: "setup", server: "" }), setFailureHandler: () => {} }));

test("Safari: the welcome page renders without shortcut and default-manager steps", async () => {
  const c = globalThis.chrome as unknown as Record<string, unknown> & { runtime: { getURL: (p: string) => string } };
  delete c.commands;
  delete c.privacy;
  c.runtime.getURL = (p: string) => `safari-web-extension://ABC/${p}`;
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  const errors: unknown[] = [];
  const { Welcome } = await import("../src/popup/welcome");
  const root = document.createElement("div");
  document.body.append(root);
  await act(async () => {
    createRoot(root, { onUncaughtError: (e) => errors.push(e), onCaughtError: (e) => errors.push(e) }).render(createElement(Welcome));
  });
  expect(errors).toEqual([]);
  expect(root.textContent).toContain("Welcome to PassAuth");
  expect(root.textContent).not.toContain("Fill with the keyboard");
  expect(root.textContent).not.toContain("default password manager");
});

test("Safari: the popup fills the sheet's width on a touch screen, keeps 380 px elsewhere", async () => {
  const { fluidPopup } = await import("../src/shared/browser");
  expect(fluidPopup(true, true)).toBe(true);
  expect(fluidPopup(true, false)).toBe(false);
  expect(fluidPopup(false, true)).toBe(false);
});
