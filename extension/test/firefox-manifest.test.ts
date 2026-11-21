// The Firefox manifest is made from the Chrome one (firefox-manifest.mjs): same scripts, permissions and commands,
// Firefox's background and add-on settings, no Chrome-only keys.

import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { firefoxManifest, GECKO_ID, MIN_FIREFOX } from "../firefox-manifest.mjs";

const chrome = JSON.parse(readFileSync(new URL("../public/manifest.json", import.meta.url), "utf8"));
const firefox = firefoxManifest(chrome);

test("Firefox: event-page background, fixed add-on id, minimum version and data declaration", () => {
  expect(firefox.background).toEqual({ scripts: ["background.js"], type: "module" });
  expect(firefox.browser_specific_settings.gecko).toEqual({
    id: GECKO_ID,
    strict_min_version: MIN_FIREFOX,
    data_collection_permissions: { required: ["authenticationInfo", "personallyIdentifyingInfo"] },
  });
});

test("Firefox: no Chrome-only keys or permissions", () => {
  expect(firefox.permissions).not.toContain("offscreen");
  expect(firefox).not.toHaveProperty("minimum_chrome_version");
  expect(firefox).not.toHaveProperty("externally_connectable");
  for (const r of firefox.web_accessible_resources) expect(r).not.toHaveProperty("use_dynamic_url");
});

test("Firefox: the same version, scripts, permissions and commands as Chrome; the Chrome manifest is untouched", () => {
  expect(firefox.version).toBe(chrome.version);
  expect(firefox.content_scripts).toEqual(chrome.content_scripts);
  expect(firefox.permissions).toEqual(chrome.permissions.filter((p: string) => p !== "offscreen"));
  expect(firefox.host_permissions).toEqual(chrome.host_permissions);
  expect(firefox.commands).toEqual(chrome.commands);
  expect(chrome.background.service_worker).toBe("background.js");
  expect(chrome.permissions).toContain("offscreen");
});
