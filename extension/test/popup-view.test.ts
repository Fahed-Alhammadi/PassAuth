// Where the popup starts (popup/view-state.ts): a page the background asked for is used once; otherwise where the
// popup was, for the same account and within 2 minutes; a stored route of an unknown shape is ignored. And the list
// rows' second line never shows a note's text (background/vault.ts subtitleOf).

import { emptyItem } from "@web/lib/types";
import { beforeEach, expect, test, vi } from "vitest";
import { type FakeChrome, installChrome } from "./chrome";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const { takeStart, routeFor, LIST, NO_FILTER, saveView, saveDraft, flushView, dropPendingView, editorKey, vaultChanged } = await import("../src/popup/view-state");
const { matchIndex } = await import("../src/background/match-index");
const { subtitleOf } = await import("../src/background/vault");

let fake: FakeChrome;
beforeEach(() => {
  fake = installChrome();
});

test("a page the background asked for: opened once, with the address and user name it brought", async () => {
  await fake.session.set({ popupRoute: { page: "new", kind: "login", url: "https://example.com", username: "alex" } });
  expect((await takeStart("a1")).route).toStrictEqual({ tab: "vault", page: "new", kind: "login", prefill: { url: "https://example.com", username: "alex" } });
  expect(fake.session.data.has("popupRoute")).toBe(false);
  expect((await takeStart("a1")).route).toStrictEqual(LIST);
  expect(routeFor({ page: "generator" })).toStrictEqual({ tab: "generator" });
  expect(routeFor({ page: "new", kind: "ssh_key" })).toBe(null);
  expect(routeFor("nonsense")).toBe(null);
});

test("where the popup was: the same account within 2 minutes, else the list", async () => {
  const view = { account: "a1", at: Date.now(), route: { tab: "vault", page: "item", id: "i1" }, filter: { ...NO_FILTER, query: "bank" }, scroll: 420 };
  await fake.session.set({ popupView: view });
  expect(await takeStart("a1")).toStrictEqual({ route: view.route, filter: view.filter, scroll: 420 });
  expect((await takeStart("a2")).route).toStrictEqual(LIST);
  await fake.session.set({ popupView: { ...view, at: Date.now() - 3 * 60_000 } });
  expect(await takeStart("a1")).toStrictEqual({ route: LIST, filter: NO_FILTER, scroll: 0 });
  await fake.session.set({ popupView: { ...view, route: { tab: "vault", page: "item" } } });
  expect((await takeStart("a1")).route).toStrictEqual(LIST);
});

test("list rows: a secure note says so (never its text), an identity shows name and email, a card its last digits", () => {
  const note = { ...emptyItem("note"), name: "Wifi", notes: "password: hunter2" };
  expect(subtitleOf(note)).toBe("Secure note");
  const person = emptyItem("identity");
  person.identity = { ...person.identity!, first_name: "Alex", last_name: "Morgan", email: "alex@example.com" };
  expect(subtitleOf(person)).toBe("Alex Morgan · alex@example.com");
  const card = emptyItem("card");
  card.card = { ...card.card!, brand: "Visa", number: "4111 1111 1111 1234" };
  expect(subtitleOf(card)).toBe("Visa •••• 1234");
  expect(subtitleOf(emptyItem("ssh_key"))).toBe("SSH key");
});

test("an open editor's draft is kept with the view and comes back with that editor only; leaving it forgets it", async () => {
  const route = { tab: "vault", page: "edit", id: "i1" } as const;
  const item = { ...emptyItem("login"), name: "Bank (unsaved)" };
  saveView({ account: "a1", route, filter: NO_FILTER, scroll: 0 });
  saveDraft({ key: editorKey(route)!, item });
  flushView();
  await new Promise((r) => setTimeout(r, 5));
  const start = await takeStart("a1");
  expect(start.route).toStrictEqual(route);
  expect(start.draft?.item.name).toBe("Bank (unsaved)");
  // Another account, or a stale view: no draft.
  expect((await takeStart("a2")).draft).toBeUndefined();
  // A draft from another editor isn't offered to this one.
  await fake.session.set({ popupView: { ...(fake.session.data.get("popupView") as object), draft: { key: "edit:other", item } } });
  expect((await takeStart("a1")).draft).toBeUndefined();
  // Saved, discarded or left: the next write has no draft.
  saveDraft({ key: editorKey(route)!, item });
  saveDraft(null);
  flushView();
  await new Promise((r) => setTimeout(r, 5));
  expect((fake.session.data.get("popupView") as { draft?: unknown }).draft).toBeUndefined();
  // A new item's draft keeps its id (a save tried again after reopening can't add it twice).
  const fresh = { tab: "vault", page: "new", kind: "login" } as const;
  const newId = crypto.randomUUID();
  saveView({ account: "a1", route: fresh, filter: NO_FILTER, scroll: 0 });
  saveDraft({ key: editorKey(fresh)!, item, newId });
  flushView();
  await new Promise((r) => setTimeout(r, 5));
  expect((await takeStart("a1")).draft?.newId).toBe(newId);
  dropPendingView();
});

test("a page the background asked for starts without a draft", async () => {
  const route = { tab: "vault", page: "new", kind: "login" } as const;
  await fake.session.set({
    popupView: { account: "a1", at: Date.now(), route, filter: NO_FILTER, scroll: 0, draft: { key: "new:login", item: emptyItem("login") } },
    popupRoute: { page: "new", kind: "login", url: "https://example.com" },
  });
  expect((await takeStart("a1")).draft).toBeUndefined();
});

test("the open popup reloads its list when the worker rewrites the account's match index (a sync brought changes) or drops it (lock)", async () => {
  // Found in a real browser: with the popup open in a tab, a login added on another device reached the badge by live
  // sync but not the popup's list until it was reopened.
  const seen: boolean[] = [];
  chrome.storage.onChanged.addListener((changes: Record<string, unknown>, area: string) => void seen.push(vaultChanged(changes, area, "a1")));
  await matchIndex.set("a1", { revision: 7, logins: [] });
  await matchIndex.set("b2", { revision: 3, logins: [] });
  await fake.session.set({ popupView: { account: "a1" } });
  await fake.local.set({ "index:a1": "a local key of the same name" });
  await matchIndex.clear(["a1"]);
  expect(seen).toStrictEqual([true, false, false, false, true]);
  expect(vaultChanged({ "index:a1": {} }, "session", "")).toBe(false);
});
