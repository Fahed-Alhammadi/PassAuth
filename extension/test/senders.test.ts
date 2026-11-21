// S7 / S8: sites are checked by the sender's real document origin, and a frame that claims a fill is checked
// against the login's websites before it gets anything (background/senders.ts).

import type { LoginUrl } from "@web/lib/types";
import { expect, test } from "vitest";
import { extensionPage, frameMayFill, sameSiteAsTab, senderOrigin, senderUrl } from "../src/background/senders";
import { EXTENSION_ID } from "./chrome";

const tab = { id: 7, url: "https://shop.example.com/cart" };

test("senderOrigin: the document's own web origin, matching its URL", () => {
  expect(senderOrigin({ origin: "https://login.example.com", url: "https://login.example.com/x?y" })).toBe("https://login.example.com");
  // Sandboxed frame on the site's own URL: opaque origin.
  expect(senderOrigin({ origin: "null", url: "https://login.example.com/user-content.html" })).toBe(null);
  // about:blank / srcdoc frames borrow their creator's origin; their URL says otherwise.
  expect(senderOrigin({ origin: "https://example.com", url: "about:blank" })).toBe(null);
  expect(senderOrigin({ origin: "https://evil.test", url: "https://example.com/" })).toBe(null);
  expect(senderOrigin({ url: "https://example.com/" })).toBe(null);
  expect(senderOrigin({ origin: "chrome-extension://x", url: "chrome-extension://x/a.html" })).toBe(null);
  expect(senderUrl({ origin: "https://example.com", url: "https://example.com/a?b" })?.href).toBe("https://example.com/a?b");
});

test("sameSiteAsTab: by the frame's real origin, not its URL alone", () => {
  expect(sameSiteAsTab({ tab, origin: "https://login.example.com", url: "https://login.example.com/" })).toBe(true);
  expect(sameSiteAsTab({ tab, origin: "null", url: "https://login.example.com/" })).toBe(false);
  expect(sameSiteAsTab({ tab, origin: "https://evil.test", url: "https://evil.test/" })).toBe(false);
  expect(sameSiteAsTab({ tab: { id: 7, url: "chrome://settings" }, origin: "https://example.com", url: "https://example.com/" })).toBe(false);
});

test("extensionPage: PassAuth's own pages, also through a per-session dynamic URL; never a web page", () => {
  const own = [`chrome-extension://${EXTENSION_ID}`, "chrome-extension://5b1c7a2e-dynamic"];
  expect(extensionPage({ id: EXTENSION_ID, url: `chrome-extension://${EXTENSION_ID}/popup.html#passkey=1` }, EXTENSION_ID, own)).toBe("/popup.html");
  expect(extensionPage({ id: EXTENSION_ID, url: "chrome-extension://5b1c7a2e-dynamic/inline-menu.html" }, EXTENSION_ID, own)).toBe("/inline-menu.html");
  // Content scripts carry the extension's id but a web URL.
  expect(extensionPage({ id: EXTENSION_ID, url: "https://example.com/popup.html" }, EXTENSION_ID, own)).toBe(null);
  expect(extensionPage({ id: "another-extension", url: `chrome-extension://${EXTENSION_ID}/popup.html` }, EXTENSION_ID, own)).toBe(null);
  expect(extensionPage({ id: EXTENSION_ID, url: "chrome-extension://someone-else/popup.html" }, EXTENSION_ID, own)).toBe(null);
  expect(extensionPage({ id: EXTENSION_ID }, EXTENSION_ID, own)).toBe(null);
});

test("extensionPage: Firefox's moz-extension pages; a moz-extension page of another add-on is not PassAuth", () => {
  const own = ["moz-extension://0d7c4a8e-1111-4c3b-9d1e-2f6a7b8c9d00"];
  expect(extensionPage({ id: EXTENSION_ID, url: `${own[0]}/save-prompt.html` }, EXTENSION_ID, own)).toBe("/save-prompt.html");
  expect(extensionPage({ id: EXTENSION_ID, url: "moz-extension://ffffffff-2222-4c3b-9d1e-2f6a7b8c9d00/popup.html" }, EXTENSION_ID, own)).toBe(null);
});

test("frameMayFill: the login's websites must match the claiming frame, by its real origin", () => {
  const urls: LoginUrl[] = [{ url: "https://login.example.com", match: "host" }];
  const frame = (origin: string, url = `${origin}/form`) => ({ origin, url });
  expect(frameMayFill(frame("https://login.example.com"), urls, "domain", "example.com", true)).toBe(true);
  // A same-site frame the login isn't saved for.
  expect(frameMayFill(frame("https://ads.example.com"), urls, "domain", "example.com", true)).toBe(false);
  // Cross-site frame.
  expect(frameMayFill(frame("https://evil.test"), urls, "domain", "example.com", true)).toBe(false);
  // Sandboxed frame on the right URL.
  expect(frameMayFill({ origin: "null", url: "https://login.example.com/form" }, urls, "domain", "example.com", true)).toBe(false);
  // https login, http frame.
  expect(frameMayFill(frame("http://login.example.com"), [{ url: "https://login.example.com", match: "domain" }], "domain", "example.com", true)).toBe(false);
  // No websites saved: only frames on the tab's own site.
  expect(frameMayFill(frame("https://login.example.com"), [], "domain", "example.com", true)).toBe(true);
  expect(frameMayFill(frame("https://evil.test"), [], "domain", "example.com", true)).toBe(false);
});

test("frameMayFill: regular expressions count only for the user's own items (S13)", () => {
  const urls: LoginUrl[] = [{ url: "^https://login\\.example\\.com/", match: "regex" }];
  const f = { origin: "https://login.example.com", url: "https://login.example.com/form" };
  expect(frameMayFill(f, urls, "domain", "example.com", true)).toBe(true);
  expect(frameMayFill(f, urls, "domain", "example.com", false)).toBe(false);
});
