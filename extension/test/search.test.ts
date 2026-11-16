// The popup's one search (popup/search.ts): words ANDed over name, user name, websites, tags and folder; the
// current site's logins first, then name or website prefixes, then list order.

import { expect, test } from "vitest";
import { queryWords, searchItems } from "../src/popup/search";
import type { ItemSummary } from "../src/shared/types";

const item = (id: string, name: string, extra: Partial<ItemSummary> = {}): ItemSummary => ({
  id,
  name,
  subtitle: "",
  host: "",
  url: "",
  folder: "",
  kind: "login",
  favorite: false,
  hasPassword: true,
  hasTotp: false,
  passkeys: 0,
  vaultName: "Personal",
  ...extra,
});

const ITEMS = [
  item("a", "Bank of Example", { username: "alex", subtitle: "alex", websites: ["https://bank.example"], tags: ["money"], folder: "Finance" }),
  item("b", "GitHub", { username: "alex-dev", subtitle: "alex-dev", host: "github.com", websites: ["https://github.com/login"] }),
  item("c", "Work mail", { username: "alex@work.test", subtitle: "alex@work.test", websites: ["https://mail.work.test"], folder: "Work" }),
  item("d", "Wifi", { kind: "note", subtitle: "Secure note", tags: ["home"] }),
];
const found = (q: string, current?: Set<string>) => searchItems(ITEMS, q, current).map((i) => i.id);

test("an empty query keeps every item in its order", () => {
  expect(found("   ")).toStrictEqual(["a", "b", "c", "d"]);
  expect(queryWords("  Foo   bar ")).toStrictEqual(["foo", "bar"]);
});

test("it looks in the name, the user name, every website, the tags and the folder", () => {
  expect(found("github")).toStrictEqual(["b"]);
  expect(found("alex-dev")).toStrictEqual(["b"]);
  expect(found("mail.work")).toStrictEqual(["c"]);
  expect(found("money")).toStrictEqual(["a"]);
  expect(found("finance")).toStrictEqual(["a"]);
  expect(found("HOME")).toStrictEqual(["d"]);
});

test("every word must match (in any of the fields)", () => {
  expect(found("alex work")).toStrictEqual(["c"]);
  expect(found("alex finance")).toStrictEqual(["a"]);
  expect(found("alex nothing")).toStrictEqual([]);
});

test("the current site's logins first, then name and website prefixes, then the list order", () => {
  // "alex" is in three items; none starts with it.
  expect(found("alex")).toStrictEqual(["a", "b", "c"]);
  expect(found("alex", new Set(["c"]))).toStrictEqual(["c", "a", "b"]);
  // "m" is in all four; only "Work mail" has a word starting with it.
  expect(found("m")).toStrictEqual(["c", "a", "b", "d"]);
  // A website's host (without "www.") counts like a name: both start with "git", so list order decides.
  expect(searchItems([ITEMS[0]!, item("x", "Code", { websites: ["https://www.gitlab.example"] }), ITEMS[1]!], "git").map((i) => i.id)).toStrictEqual(["x", "b"]);
});
