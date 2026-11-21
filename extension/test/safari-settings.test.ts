// Safari also shows macOS's own AutoFill sheet when a login field gets focus, so there PassAuth's menu opens from its
// icon in the field by default (two menus at once otherwise); other browsers open it on focus. A choice the user made
// is kept.

import { afterEach, expect, test, vi } from "vitest";

const rt = globalThis.chrome.runtime as unknown as { getURL: (p: string) => string };
const realGetURL = rt.getURL;
afterEach(() => {
  rt.getURL = realGetURL;
  vi.resetModules();
});

test("Safari: the inline menu opens from the field's PassAuth icon by default", async () => {
  rt.getURL = (p: string) => `safari-web-extension://ABC/${p}`;
  const { getSettings } = await import("../src/background/storage");
  expect((await getSettings()).inlineMenu).toBe("click");
});

test("Safari: a menu setting the user chose is kept", async () => {
  rt.getURL = (p: string) => `safari-web-extension://ABC/${p}`;
  await chrome.storage.local.set({ settings: { inlineMenu: "focus" } });
  const { getSettings } = await import("../src/background/storage");
  expect((await getSettings()).inlineMenu).toBe("focus");
  await chrome.storage.local.remove("settings");
});

test("Chrome and Firefox: the inline menu opens on focus by default", async () => {
  const { getSettings } = await import("../src/background/storage");
  expect((await getSettings()).inlineMenu).toBe("focus");
});
