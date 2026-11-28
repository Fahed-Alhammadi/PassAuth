// The Safari manifest (the extension in the desktop app on macOS) is made from the Chrome one (safari-manifest.mjs): no
// passkey scripts (the macOS AutoFill extension handles passkeys), the right-click menu and shortcuts with a fill key that
// leaves Safari's sidebar key alone, a non-persistent event-page background, and the desktop app's version.

import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { MIN_SAFARI, SAFARI_KEYS, safariManifest } from "../safari-manifest.mjs";
import { browserName, isFirefox, isSafari } from "../src/shared/browser";

const chrome = JSON.parse(readFileSync(new URL("../public/manifest.json", import.meta.url), "utf8"));
const safari = safariManifest(chrome, "0.16.0");

test("Safari: non-persistent event-page background, minimum version, the Safari app's version", () => {
  expect(safari.background).toEqual({ scripts: ["background.js"], type: "module", persistent: false });
  expect(MIN_SAFARI).toBe("17.0");
  expect(safari.browser_specific_settings).toEqual({ safari: { strict_min_version: "17.0" } });
  expect(safari.version).toBe("0.16.0");
});

test("Safari: no offscreen page, privacy or Chrome-only keys", () => {
  expect(safari.permissions).not.toContain("offscreen");
  expect(safari).not.toHaveProperty("optional_permissions");
  expect(safari).not.toHaveProperty("externally_connectable");
  expect(safari).not.toHaveProperty("minimum_chrome_version");
  for (const r of safari.web_accessible_resources) expect(r).not.toHaveProperty("use_dynamic_url");
});

test("Safari: the right-click menu and the shortcuts; fill is Shift+Command+P (Shift+Command+L is Safari's sidebar)", () => {
  expect(safari.permissions).toContain("contextMenus");
  expect(Object.keys(safari.commands)).toEqual(Object.keys(chrome.commands));
  expect(SAFARI_KEYS).toEqual({ autofill: "Command+Shift+P" });
  expect(safari.commands.autofill.suggested_key.mac).toBe("Command+Shift+P");
  expect(safari.commands._execute_action.suggested_key.mac).toBe("Command+Shift+Y");
  expect(safari.commands.generate_password.suggested_key.mac).toBe("Command+Shift+9");
  // Safari's own Shift+Command shortcuts (View → Show Sidebar, Edit → AutoFill Form, …) stay with Safari.
  const taken = ["L", "A", "B", "D", "F", "G", "H", "N", "R", "S", "Z", "\\"];
  for (const c of Object.values(safari.commands) as { suggested_key?: { mac: string } }[]) {
    const key = c.suggested_key?.mac;
    if (key) expect(taken.map((k) => `Command+Shift+${k}`)).not.toContain(key);
  }
});

test("Safari: native messaging for the sign-in hand-off from the app", () => {
  expect(safari.permissions).toContain("nativeMessaging");
  expect(chrome.permissions).not.toContain("nativeMessaging");
});

test("Safari: only the fill content script (no passkey bridge or page shim)", () => {
  const scripts = safari.content_scripts.flatMap((c: { js: string[] }) => c.js);
  expect(scripts).toEqual(["content.js"]);
  for (const c of safari.content_scripts) {
    expect(c).not.toHaveProperty("match_origin_as_fallback");
    expect(c).not.toHaveProperty("world");
  }
});

test("Safari: the Chrome manifest is untouched", () => {
  expect(chrome.background.service_worker).toBe("background.js");
  expect(chrome.permissions).toContain("contextMenus");
  expect(chrome.commands.autofill.suggested_key.mac).toBe("Command+Shift+L");
});

test("isSafari / browserName tell Safari apart by its extension URL scheme", () => {
  const real = globalThis.chrome.runtime.getURL;
  globalThis.chrome.runtime.getURL = (p: string) => `safari-web-extension://ABC/${p}`;
  try {
    expect(isSafari()).toBe(true);
    expect(isFirefox()).toBe(false);
    expect(browserName()).toBe("Safari");
  } finally {
    globalThis.chrome.runtime.getURL = real;
  }
  expect(isSafari()).toBe(false);
});

test("browserFeatures: Chrome offers shortcuts, the right-click menu and the default password manager setting", async () => {
  const { browserFeatures } = await import("../src/shared/browser");
  expect(browserFeatures()).toEqual({ shortcuts: true, rightClickMenu: true, defaultPasswordManager: true });
});
