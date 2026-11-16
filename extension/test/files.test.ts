// Files attached to items (servers with `attachments`), the worker's part (background/attachments.ts, through the
// router as the popup asks): which listed files the server no longer has, what downloading one needs (only for a
// file the item lists; a new token after a 401), and the file list of an item saved from the popup — always the list
// as last synced, never the draft's, so a file attached elsewhere is never dropped (the web vault's rule).

import type { Item } from "@web/lib/types";
import { beforeEach, expect, test, vi } from "vitest";
import { EXTENSION_ID, type FakeChrome, installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer, sessionKeys } from "./fake-server";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const vault = await import("../src/background/vault");
const { dispatch } = await import("../src/background/router");
const { forgetServerFeatures } = await import("../src/background/api");

const popup = { id: EXTENSION_ID, url: `chrome-extension://${EXTENSION_ID}/popup.html` };
const ask = (msg: Record<string, unknown>) => dispatch(msg, popup as chrome.runtime.MessageSender);

const A = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";
const B = "6fa459ea-ee8a-3ca4-894e-db77e160355e";
const file = (id: string, name: string) => ({ id, name, size: 1200, key: `key-${name}` });

const withFiles = (files: unknown[]): Item => ({
  name: "Tax return",
  notes: "",
  favorite: false,
  folder: null,
  tags: [],
  login: null,
  card: null,
  identity: null,
  ssh_key: null,
  fields: [],
  password_history: [],
  created_at: 0,
  updated_at: 0,
  attachments: files as Item["attachments"],
});

let fake: FakeChrome;
let server: FakeServer;

beforeEach(async () => {
  vi.unstubAllGlobals();
  await vault.lockAll().catch(() => {});
  fake = installChrome();
  server = fakeServer();
  server.features = [...server.features, "attachments"];
  server.items = [{ id: "i1", vault_id: "v-own", item_key: "own-1:1", data: JSON.stringify(withFiles([file(A, "a.pdf")])), revision: 1, deleted_at: null }];
  vi.stubGlobal("fetch", server.fetch);
  forgetServerFeatures();
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
});

test("the item's files the server no longer has; null when it can't say", async () => {
  server.handlers["GET /items/i1/attachments"] = () => ({ body: { attachments: [{ id: A, size: 1256, state: "ready", updated_at: 1 }] } });
  expect(await ask({ type: "files:missing", id: "i1" })).toStrictEqual({ ok: true, data: [] });
  server.handlers["GET /items/i1/attachments"] = () => ({ body: { attachments: [{ id: A, size: 1256, state: "pending", updated_at: 1 }] } });
  expect(await ask({ type: "files:missing", id: "i1" })).toStrictEqual({ ok: true, data: [A] });
  // An older server (no such route) or none reachable: nothing is marked.
  delete server.handlers["GET /items/i1/attachments"];
  expect(await ask({ type: "files:missing", id: "i1" })).toStrictEqual({ ok: true, data: null });
});

test("what a download needs: the file's address and the current token, only for a file the item lists", async () => {
  const r = await ask({ type: "files:access", itemId: "i1", attachmentId: A.toUpperCase() });
  expect(r).toStrictEqual({ ok: true, data: { url: `https://vault.test/api/attachments/${A}`, token: "access-1", client: "extension/9.8.7" } });
  expect(await ask({ type: "files:access", itemId: "i1", attachmentId: B })).toMatchObject({ ok: false, code: "not_found" });
  // After a 401 the popup asks again with `renew`: a new token, by the refresh token.
  server.handlers["POST /auth/refresh"] = () => ({ body: { access_token: "access-2", refresh_token: "refresh-2" } });
  expect(await ask({ type: "files:access", itemId: "i1", attachmentId: A, renew: true })).toMatchObject({ ok: true, data: { token: "access-2" } });
  // A refused refresh token signs the account out here, as any request would.
  server.handlers["POST /auth/refresh"] = () => ({ status: 401, body: { error: "unauthorized", message: "no" } });
  expect(await ask({ type: "files:access", itemId: "i1", attachmentId: A, renew: true })).toMatchObject({ ok: false, code: "signed_out" });
});

test("a save from the popup keeps the file list as last synced: files attached elsewhere stay, a draft's list never counts", async () => {
  // Another device attached a second file after the editor opened (the draft still has only the first) …
  server.editElsewhere("i1", { attachments: [file(A, "a.pdf"), file(B, "b.pdf")] });
  await vault.sync();
  const draft = { ...withFiles([file(A, "a.pdf")]), name: "Tax return 2025" };
  expect(await ask({ type: "updateItem", id: "i1", item: draft })).toMatchObject({ ok: true });
  const put = server.requests.findLast((r) => r.method === "PUT" && r.path === "/items/i1");
  const saved = JSON.parse(put?.body.data) as Item;
  expect(saved.name).toBe("Tax return 2025");
  expect(saved.attachments?.map((a) => a.id)).toStrictEqual([A, B]);
  // … and a draft that names other files (or none) changes nothing about the list either.
  expect(await ask({ type: "updateItem", id: "i1", item: { ...withFiles([file("00000000-0000-4000-8000-000000000000", "x")]), favorite: true } })).toMatchObject({ ok: true });
  const again = JSON.parse(server.requests.findLast((r) => r.method === "PUT")?.body.data) as Item;
  expect([again.favorite, again.attachments?.map((a) => a.id)]).toStrictEqual([true, [A, B]]);
});

test("a new item from the popup lists no files", async () => {
  const r = await ask({ type: "createItem", item: withFiles([file(A, "a.pdf")]) });
  expect(r).toMatchObject({ ok: true });
  const post = server.requests.findLast((r) => r.method === "POST" && r.path === "/items");
  expect("attachments" in (JSON.parse(post?.body.data) as object)).toBe(false);
});
