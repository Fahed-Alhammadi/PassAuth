// The sign-in search in the passkey window (popup/Passkey.tsx `signInMatches`).

import { expect, test, vi } from "vitest";

vi.mock("../src/popup/fit-window", () => ({ fitWindow: async () => {} }));
const { signInMatches } = await import("../src/popup/Passkey");

const list = [
  { credentialId: "1", userName: "alex@example.com", itemName: "Example" },
  { credentialId: "2", userName: "Sam", itemName: "Example (work)" },
  { credentialId: "3", userName: "", itemName: "Old account" },
];

test("an empty search shows every passkey, in order", () => {
  expect(signInMatches(list, "")).toBe(list);
  expect(signInMatches(list, "   ")).toBe(list);
});

test("matches the user name or the login's name, ignoring case and outer spaces", () => {
  expect(signInMatches(list, "SAM").map((c) => c.credentialId)).toStrictEqual(["2"]);
  expect(signInMatches(list, " work ").map((c) => c.credentialId)).toStrictEqual(["2"]);
  expect(signInMatches(list, "example").map((c) => c.credentialId)).toStrictEqual(["1", "2"]);
  expect(signInMatches(list, "old").map((c) => c.credentialId)).toStrictEqual(["3"]);
  expect(signInMatches(list, "nobody")).toStrictEqual([]);
});
