// S12: caps on strings a page hands to PassAuth (shared/limits.ts).

import { expect, test } from "vitest";
import { capName, capPasskeyNames, credentialsFit, MAX_PASSKEY_NAME, MAX_PASSWORD, MAX_USERNAME } from "../src/shared/limits";

test("credentialsFit: a password, user name ≤ 1 KiB, password ≤ 4 KiB; longer values are not offered at all", () => {
  expect([MAX_USERNAME, MAX_PASSWORD, MAX_PASSKEY_NAME]).toStrictEqual([1024, 4096, 256]);
  expect(credentialsFit("alex", "pw")).toBe(true);
  expect(credentialsFit("", "pw")).toBe(true);
  expect(credentialsFit("a".repeat(1024), "p".repeat(4096))).toBe(true);
  expect(credentialsFit("a".repeat(1025), "pw")).toBe(false);
  expect(credentialsFit("alex", "p".repeat(4097))).toBe(false);
  expect(credentialsFit("alex", "")).toBe(false);
  expect(credentialsFit(7, "pw")).toBe(false);
  expect(credentialsFit("alex", { length: 1 })).toBe(false);
});

test("capName: whole characters, nothing cut when short enough", () => {
  expect(capName("Example")).toBe("Example");
  expect(capName("x".repeat(300))).toHaveLength(256);
  // Astral characters are not split in half.
  const emoji = "😀".repeat(300);
  expect([...capName(emoji)]).toHaveLength(256);
  expect(capName(emoji).endsWith("😀")).toBe(true);
});

test("capPasskeyNames: rp.name, user.name and user.displayName cut to 256; the rest untouched", () => {
  const long = "n".repeat(10_000);
  const req = { rp: { id: "example.com", name: long }, user: { id: "AAAA", name: long, displayName: long }, challenge: "c", pubKeyCredParams: [] };
  const out = capPasskeyNames(req);
  expect([out.rp.name.length, out.user.name.length, out.user.displayName.length]).toStrictEqual([256, 256, 256]);
  expect([out.rp.id, out.user.id, out.challenge]).toStrictEqual(["example.com", "AAAA", "c"]);
  // The page's object is not changed.
  expect(req.rp.name).toHaveLength(10_000);
  // Malformed shapes pass through for the validator to refuse.
  expect(capPasskeyNames({ rp: "x", user: null })).toStrictEqual({ rp: "x", user: null });
  expect(capPasskeyNames(null)).toBe(null);
  expect(capPasskeyNames({ rp: { name: 5 } })).toStrictEqual({ rp: { name: 5 } });
});
