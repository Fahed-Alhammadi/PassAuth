// The Safari (iOS) manifest is made from the Chrome one (safari-manifest.mjs): no passkey scripts (the iOS AutoFill
// extension handles passkeys), no shortcuts or right-click menu, a non-persistent event-page background, and the iOS
// app's version.

import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { MIN_SAFARI, safariManifest } from "../safari-manifest.mjs";
import { browserName, isFirefox, isSafari } from "../src/shared/browser";

const chrome = JSON.parse(readFileSync(new URL("../public/manifest.json", import.meta.url), "utf8"));
const safari = safariManifest(chrome, "0.16.0");

test("Safari: non-persistent event-page background, minimum version, the Safari app's version", () => {
  expect(safari.background).toEqual({ scripts: ["background.js"], type: "module", persistent: false });
  expect(MIN_SAFARI).toBe("17.0");
  expect(safari.browser_specific_settings).toEqual({ safari: { strict_min_version: "17.0" } });
  expect(safari.version).toBe("0.16.0");
});

test("Safari: no offscreen page, right-click menu, privacy, shortcuts or Chrome-only keys", () => {
  expect(safari.permissions).not.toContain("offscreen");
  expect(safari.permissions).not.toContain("contextMenus");
  expect(safari).not.toHaveProperty("optional_permissions");
  expect(safari).not.toHaveProperty("commands");
  expect(safari).not.toHaveProperty("externally_connectable");
  expect(safari).not.toHaveProperty("minimum_chrome_version");
  for (const r of safari.web_accessible_resources) expect(r).not.toHaveProperty("use_dynamic_url");
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
  expect(chrome.commands).toBeDefined();
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
