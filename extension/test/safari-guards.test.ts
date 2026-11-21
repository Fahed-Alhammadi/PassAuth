// Safari (the "PassAuth for Safari" app) has no right-click menu, shortcuts or idle API, and on iPhone no windows API.
// The background must still start, and PassAuth's windows open as tabs there.

import { expect, test, vi } from "vitest";
import { installChrome } from "./chrome";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const fake = installChrome();
const c = globalThis.chrome as unknown as Record<string, unknown>;
delete c.contextMenus;
delete c.commands;
delete c.idle;
delete c.windows;

test("the background starts without contextMenus, commands, idle and windows", async () => {
  await expect(import("../src/background/main")).resolves.toBeDefined();
});

test("no contextMenus API: a menu rebuild does nothing and doesn't throw", async () => {
  const { applyMenu } = await import("../src/background/menus");
  await expect(applyMenu()).resolves.toBeUndefined();
  expect(fake.menus.size).toBe(0);
});

test("no windows API: PassAuth's windows open as a tab", async () => {
  const { canUseWindows, openCentered } = await import("../src/shared/windows");
  expect(canUseWindows()).toBe(false);
  const before = fake.createdTabs.length;
  await expect(openCentered("chrome-extension://x/popup.html?popout=1", { width: 380, height: 600 })).resolves.toBeUndefined();
  expect(fake.createdTabs.slice(before)).toEqual(["chrome-extension://x/popup.html?popout=1"]);
});

test("browserFeatures: Safari offers no shortcuts, right-click menu or default password manager setting", async () => {
  const { browserFeatures } = await import("../src/shared/browser");
  const real = globalThis.chrome.runtime.getURL;
  globalThis.chrome.runtime.getURL = (p: string) => `safari-web-extension://ABC/${p}`;
  try {
    expect(browserFeatures()).toEqual({ shortcuts: false, rightClickMenu: false, defaultPasswordManager: false });
  } finally {
    globalThis.chrome.runtime.getURL = real;
  }
});

test("needsSiteAccess: Safari hides a tab's address until PassAuth is allowed on that website", async () => {
  const { needsSiteAccess } = await import("../src/shared/browser");
  const real = globalThis.chrome.runtime.getURL;
  expect(needsSiteAccess({ id: 1 })).toBe(false); // Chrome: never
  globalThis.chrome.runtime.getURL = (p: string) => `safari-web-extension://ABC/${p}`;
  try {
    expect(needsSiteAccess({ id: 1 })).toBe(true);
    expect(needsSiteAccess({ id: 1, url: "https://example.com/" })).toBe(false);
    expect(needsSiteAccess(undefined)).toBe(false);
  } finally {
    globalThis.chrome.runtime.getURL = real;
  }
});
