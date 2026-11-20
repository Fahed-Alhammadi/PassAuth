// Offline changes in the worker (background/vault.ts section "offline changes" with offline-rules.ts and the fake
// server): saves while the server can't be reached wait sealed in storage.local `offlineChanges:<account>`, are shown
// over the offline copy with their markers, survive a lock, are sent after a sync that checks out (create, edit,
// trash), and a change that meets another device's change waits for the user's decision (every choice). Leaving
// (Log out, Change server) deletes them; a vault manifest write carries the vault's next manifest like any save.

import type { Item } from "@web/lib/types";
import { beforeEach, expect, test, vi } from "vitest";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer, sessionKeys } from "./fake-server";
import { expectReject } from "./helpers";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const vault = await import("../src/background/vault");
const { forgetServerFeatures } = await import("../src/background/api");
const { MAX_OFFLINE_CHANGES, TOO_MANY_TEXT } = await import("../src/background/offline-rules");

let server: FakeServer;
let fake: FakeChrome;

const login = (name: string, password = "pw"): Item => ({
  name,
  notes: "",
  favorite: false,
  folder: null,
  tags: [],
  login: { username: "alex", password, urls: [{ url: "https://example.com", match: "default" }], totp: null, passkeys: [] },
  card: null,
  identity: null,
  ssh_key: null,
  fields: [],
  password_history: [],
  created_at: 0,
  updated_at: 0,
});

const down = () => vi.stubGlobal("fetch", async () => Promise.reject(new TypeError("Failed to fetch")));
const up = () => vi.stubGlobal("fetch", server.fetch);
const writes = () => server.requests.filter((r) => r.method !== "GET");
const stored = async () => (await fake.local.get("offlineChanges:a1"))["offlineChanges:a1"] as { sealed: string; count: number } | undefined;
/** Back online: a sync that checks out, then the sender (joined). */
async function backOnline() {
  up();
  await vault.sync();
  await vault.sendOfflineChanges();
}

async function signedIn() {
  fake = installChrome();
  server = fakeServer();
  up();
  forgetServerFeatures();
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  await vault.lockAll();
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  await vault.createItem(login("Bank", "old"));
  return vault.allEntries()[0]!;
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

test("offline create, edit and trash wait sealed, show with markers, and are sent when the server answers again", async () => {
  const bank = await signedIn();
  const mail = vault.getEntry(await vault.createItem(login("Mail")))!;
  const before = writes().length;
  down();
  const id = await vault.createItem(login("Shop"));
  await vault.updateItem(bank, { ...bank.item, login: { ...bank.item.login!, password: "new" } });
  await vault.trashItem(mail);
  expect(writes().length, "nothing reached the server").toBe(before);
  // Shown over the offline copy: created item, the edit, the trashed item gone; markers on each.
  expect(vault.getEntry(id)?.item.name).toBe("Shop");
  expect(vault.getEntry(bank.id)?.item.login?.password).toBe("new");
  expect(vault.getEntry(bank.id)?.item.password_history[0]?.password, "the old password is kept in the history").toBe("old");
  expect(vault.getEntry(mail.id)).toBeUndefined();
  expect(vault.summarize(vault.getEntry(id)!).offline).toEqual({ state: "waiting", kind: "create", text: "Waiting to sync" });
  expect(vault.offlineMark(mail.id)?.kind).toBe("trash");
  expect(vault.offlineSummary()).toEqual({ text: "3 changes waiting to sync", decide: 0 });
  // Sealed with the account key; the count readable while locked; the state line says so too.
  const kept = await stored();
  expect(kept?.count).toBe(3);
  expect(kept?.sealed).not.toContain("Shop".repeat(2));
  expect((await vault.state()).offlineChanges).toBe(3);
  // The retry alarm is set while changes wait.
  expect(await chrome.alarms.get("offlineChanges")).toBeTruthy();
  // A lock keeps them; after unlocking they are shown again.
  await vault.lockAll();
  expect((await vault.state()).offlineChanges).toBe(3);
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(vault.getEntry(id)?.item.name).toBe("Shop");
  // Back online: sent oldest first, the list emptied, the server has everything.
  await backOnline();
  expect(vault.offlineSummary()).toBeNull();
  expect(await stored()).toBeUndefined();
  expect(server.items.find((i) => i.id === id)).toBeTruthy();
  expect(JSON.parse(server.items.find((i) => i.id === bank.id)!.data).login.password).toBe("new");
  expect(server.items.find((i) => i.id === mail.id)?.deleted_at).toBeTruthy();
  expect(vault.getEntry(id)?.item.name).toBe("Shop");
  expect(vault.summarize(vault.getEntry(id)!).offline).toBeUndefined();
  expect(await chrome.alarms.get("offlineChanges")).toBeFalsy();
});

test("known offline (the last request got no answer): saves go to the list without a request; the next answer sends them", async () => {
  await signedIn();
  vault.noteReach("a1", false);
  const before = server.requests.length;
  await vault.createItem(login("Quiet"));
  expect(server.requests.length).toBe(before);
  vault.noteReach("a1", true); // starts a sync, which sends
  await vault.sync();
  await vault.sendOfflineChanges();
  expect(vault.offlineSummary()).toBeNull();
  expect(server.items).toHaveLength(2);
});

test("one change per item: create + edit is one create; create + trash leaves nothing; a change waiting for the trash can't be edited", async () => {
  await signedIn();
  down();
  const id = await vault.createItem(login("Draft"));
  await vault.updateItem(vault.getEntry(id)!, { ...vault.getEntry(id)!.item, notes: "more" });
  expect(vault.offlineSummary()?.text).toBe("1 change waiting to sync");
  await vault.trashItem(vault.getEntry(id)!);
  // The failed request may have reached the server: a trash of it waits (done without a request when it didn't).
  expect(vault.offlineSummary()?.text).toBe("1 change waiting to sync");
  // Known offline, nothing was sent: create + trash leaves nothing.
  vault.noteReach("a1", false);
  const quiet = await vault.createItem(login("Never sent"));
  await vault.trashItem(vault.getEntry(quiet)!);
  expect(vault.offlineSummary()?.text).toBe("1 change waiting to sync");
  vault.noteReach("a1", true);
  const bank = vault.allEntries()[0]!;
  await vault.trashItem(bank);
  await expectReject(vault.updateItem(bank, bank.item), (e) => /trash/.test(e.message));
  await backOnline();
  expect(server.items.filter((i) => !i.deleted_at)).toHaveLength(0);
  expect(server.requests.filter((r) => r.method === "POST" && r.path === "/items")).toHaveLength(1);
});

test("Discard this change: removed; nothing reaches the server", async () => {
  const bank = await signedIn();
  down();
  await vault.updateItem(bank, { ...bank.item, notes: "never" });
  await vault.discardOfflineChange(bank.id);
  expect(vault.getEntry(bank.id)?.item.notes).toBe("");
  await backOnline();
  expect(server.requests.filter((r) => r.method === "PUT")).toHaveLength(0);
});

test("an edit that meets another device's edit waits for a decision: Keep mine", async () => {
  const bank = await signedIn();
  down();
  await vault.updateItem(bank, { ...bank.item, notes: "mine" });
  server.editElsewhere(bank.id, { notes: "theirs" });
  await backOnline();
  expect(vault.offlineSummary()).toEqual({ text: "1 change needs your decision", decide: 1 });
  expect(vault.offlineMark(bank.id)?.text).toBe("Changed on another device");
  expect(server.requests.filter((r) => r.method === "PUT")).toHaveLength(0);
  const sheet = await vault.offlineConflict(bank.id);
  expect(sheet.kind).toBe("edit");
  expect(sheet.choices.map((c) => c.id)).toEqual(["mine", "other", "both"]);
  expect(sheet.fields.find((f) => f.label === "Notes")).toMatchObject({ mine: "mine", theirs: "theirs", differs: true });
  expect(sheet.fields.find((f) => f.label === "Password")).toMatchObject({ secret: true, differs: false });
  await vault.resolveOfflineConflict(bank.id, "mine");
  await backOnline();
  expect(JSON.parse(server.items.find((i) => i.id === bank.id)!.data).notes).toBe("mine");
  expect(vault.offlineSummary()).toBeNull();
});

test("Keep the other: the change goes; Keep both: mine is a new item '(offline copy)' in the same vault", async () => {
  const bank = await signedIn();
  down();
  await vault.updateItem(bank, { ...bank.item, notes: "mine" });
  server.editElsewhere(bank.id, { notes: "theirs" });
  await backOnline();
  await vault.resolveOfflineConflict(bank.id, "other");
  expect(vault.offlineSummary()).toBeNull();
  expect(vault.getEntry(bank.id)?.item.notes).toBe("theirs");
  down();
  await vault.updateItem(vault.getEntry(bank.id)!, { ...vault.getEntry(bank.id)!.item, notes: "mine again" });
  server.editElsewhere(bank.id, { notes: "theirs again" });
  await backOnline();
  await vault.resolveOfflineConflict(bank.id, "both");
  await backOnline();
  const names = server.items.map((i) => JSON.parse(i.data).name).sort();
  expect(names).toEqual(["Bank", "Bank (offline copy)"]);
  const copy = server.items.find((i) => JSON.parse(i.data).name === "Bank (offline copy)")!;
  expect([copy.vault_id, JSON.parse(copy.data).notes]).toEqual(["v-own", "mine again"]);
  expect(JSON.parse(server.items.find((i) => i.id === bank.id)!.data).notes).toBe("theirs again");
});

test("an edit of an item deleted on another device: Save mine as a new item / Discard mine", async () => {
  const bank = await signedIn();
  down();
  await vault.updateItem(bank, { ...bank.item, notes: "mine" });
  server.deleteElsewhere(bank.id);
  await backOnline();
  const sheet = await vault.offlineConflict(bank.id);
  expect(sheet.kind).toBe("deleted");
  expect(sheet.choices.map((c) => c.title)).toEqual(["Save mine as a new item", "Discard mine"]);
  // Shown until decided, though the copy no longer has it.
  expect(vault.getEntry(bank.id)?.item.notes).toBe("mine");
  await vault.resolveOfflineConflict(bank.id, "new");
  await backOnline();
  expect(server.items.map((i) => JSON.parse(i.data))).toMatchObject([{ name: "Bank", notes: "mine" }]);
  expect(server.items[0]!.id).not.toBe(bank.id);
  // Discard mine.
  const again = vault.allEntries()[0]!;
  down();
  await vault.updateItem(again, { ...again.item, notes: "x" });
  server.deleteElsewhere(again.id);
  await backOnline();
  await vault.resolveOfflineConflict(again.id, "discard");
  expect(vault.offlineSummary()).toBeNull();
  expect(vault.getEntry(again.id)).toBeUndefined();
});

test("a trash that meets another device's edit: Move to trash anyway / Keep the other", async () => {
  const bank = await signedIn();
  down();
  await vault.trashItem(bank);
  server.editElsewhere(bank.id, { notes: "theirs" });
  await backOnline();
  const sheet = await vault.offlineConflict(bank.id);
  expect(sheet.kind).toBe("trash");
  expect([sheet.hasMine, sheet.hasTheirs]).toEqual([false, true]);
  expect(sheet.choices.map((c) => c.title)).toEqual(["Move to trash anyway", "Keep the other"]);
  await vault.resolveOfflineConflict(bank.id, "other");
  expect(vault.getEntry(bank.id)?.item.notes).toBe("theirs");
  down();
  await vault.trashItem(vault.getEntry(bank.id)!);
  server.editElsewhere(bank.id, { notes: "theirs again" });
  await backOnline();
  await vault.resolveOfflineConflict(bank.id, "trash");
  await backOnline();
  expect(server.items.find((i) => i.id === bank.id)?.deleted_at).toBeTruthy();
});

test("held: a vault that is gone holds the change with its reason; a server error (not offline) is shown as now", async () => {
  await signedIn();
  down();
  const id = await vault.createItem(login("Orphan"));
  up();
  server.handlers["POST /items"] = () => ({ status: 403, body: { error: "quota_exceeded", message: "full" } });
  await backOnline();
  expect(vault.offlineMark(id)).toMatchObject({ state: "held", text: expect.stringMatching(/^Not sent: You've reached this server's storage limit/) });
  // While online, a save that the server refuses is an error, not a waiting change.
  await expectReject(vault.createItem(login("Refused")), (e) => e.code === "quota_exceeded");
  // Fixed on the server: sent at the next sync.
  delete server.handlers["POST /items"];
  await backOnline();
  expect(vault.offlineSummary()).toBeNull();
});

test("502/503/504 wait like no answer; 500 doesn't", async () => {
  await signedIn();
  server.handlers["POST /items"] = () => ({ status: 503, body: "<html>" });
  await vault.createItem(login("Later"));
  expect(vault.offlineSummary()?.text).toBe("1 change waiting to sync");
  server.handlers["POST /items"] = () => ({ status: 500, body: { error: "internal", message: "no" } });
  await expectReject(vault.createItem(login("Now")), () => true);
});

test("at most 500 changes", async () => {
  await signedIn();
  down();
  for (let n = 0; n < MAX_OFFLINE_CHANGES; n++) await vault.createItem(login(`n${n}`));
  await expectReject(vault.createItem(login("one too many")), (e) => e.message === TOO_MANY_TEXT);
}, 30_000); // 500 saves, each sealing the whole list

test("Log out and Change server delete the list; removing the account deletes it too", async () => {
  await signedIn();
  down();
  await vault.createItem(login("Lost"));
  expect(await stored()).toBeTruthy();
  await vault.logout();
  expect(await stored()).toBeUndefined();
  // Change server (the sign-in screen's "Change server").
  await fake.local.set({ "offlineChanges:a1": { sealed: "x", count: 1 } });
  up();
  await vault.setServer("https://vault.test");
  expect(await stored()).toBeUndefined();
});

test("with a vault manifest, an offline change is sent with the vault's next manifest", async () => {
  const bank = await signedIn();
  server.features.push("vault_manifest", "delta_sync");
  forgetServerFeatures();
  server.startManifestElsewhere("v-own");
  await vault.sync();
  down();
  await vault.updateItem(bank, { ...bank.item, notes: "with manifest" });
  await backOnline();
  const put = server.requests.filter((r) => r.method === "PUT").at(-1)!;
  expect(put.body.manifests).toHaveLength(1);
  expect(server.manifestErrors).toEqual([]);
  expect(vault.manifestSummary()).toBeNull();
  expect(vault.offlineSummary()).toBeNull();
});

/** The list as stored (the fake core seals it as `offline:<user>:<json>`). */
const storedList = async () => {
  const sealed = (await stored())!.sealed;
  return JSON.parse(sealed.slice(sealed.indexOf(":", "offline:".length) + 1)) as { changes: { sent: { key: string; data: string } | null; item_id: string }[] };
};
const notesOn = (id: string) => JSON.parse(server.items.find((i) => i.id === id)!.data).notes;

test("a create sent again after an edit merged in: the new content, not the body of the earlier attempt", async () => {
  await signedIn();
  down();
  const id = await vault.createItem(login("Draft"));
  expect((await storedList()).changes[0]!.sent, "the failed attempt's body is kept").toBeTruthy();
  await vault.updateItem(vault.getEntry(id)!, { ...vault.getEntry(id)!.item, notes: "edited" });
  await backOnline();
  expect(notesOn(id)).toBe("edited");
  expect(vault.offlineSummary()).toBeNull();
});

test("a create whose earlier attempt arrives late (after the sync): the stored row is edited, no copy under a new id", async () => {
  await signedIn();
  down();
  const id = await vault.createItem(login("Draft"));
  await vault.updateItem(vault.getEntry(id)!, { ...vault.getEntry(id)!.item, notes: "edited" });
  const old = (await storedList()).changes[0]!.sent!;
  up();
  await vault.sync();
  // The first attempt reaches the server only now, just before the new one.
  server.handlers["POST /items"] = () => {
    delete server.handlers["POST /items"];
    server.items.push({ id, vault_id: "v-own", item_key: old.key, data: old.data, revision: ++server.revision, deleted_at: null, seq: server.bump("v-own") });
    return undefined;
  };
  await vault.sendOfflineChanges();
  expect(server.items.filter((i) => !i.deleted_at)).toHaveLength(2);
  expect(server.items.find((i) => i.id === id) && notesOn(id)).toBe("edited");
  expect(vault.offlineSummary()).toBeNull();
});

test("a landed attempt (answer lost) followed by an offline edit: sent as an edit at the row's revision (create and edit)", async () => {
  const bank = await signedIn();
  server.dropReply.add("POST /items");
  const id = await vault.createItem(login("Landed"));
  expect(vault.offlineSummary()?.text).toBe("1 change waiting to sync");
  down();
  await vault.updateItem(vault.getEntry(id)!, { ...vault.getEntry(id)!.item, notes: "after" });
  await backOnline();
  expect(notesOn(id)).toBe("after");
  expect(server.requests.filter((r) => r.method === "POST" && r.path === "/items" && r.body.id === id)).toHaveLength(1);
  // The same for an edit whose PUT landed.
  server.dropReply.add("PUT /items/:id");
  await vault.updateItem(vault.getEntry(bank.id)!, { ...vault.getEntry(bank.id)!.item, notes: "first" });
  expect(vault.offlineMark(bank.id)?.state).toBe("waiting");
  down();
  await vault.updateItem(vault.getEntry(bank.id)!, { ...vault.getEntry(bank.id)!.item, notes: "second" });
  await backOnline();
  expect(notesOn(bank.id)).toBe("second");
  expect(vault.offlineSummary()).toBeNull();
});

/** Back online, with `during` run while the first request of `route` is out (after the server applied it). */
async function backOnlineWith(route: (r: { method: string; path: string }) => boolean, during: () => Promise<void>) {
  let once = true;
  vi.stubGlobal("fetch", async (input: string, init: RequestInit = {}) => {
    const reply = await server.fetch(input, init);
    const path = new URL(input).pathname.replace(/^\/api/, "");
    if (once && route({ method: init.method ?? "GET", path })) {
      once = false;
      await during();
    }
    return reply;
  });
  await vault.sync();
  await vault.sendOfflineChanges();
  up();
  await vault.sync();
  await vault.sendOfflineChanges();
}

test("an edit saved while its change is being sent is kept and sent after it", async () => {
  const bank = await signedIn();
  down();
  await vault.updateItem(bank, { ...bank.item, notes: "one" });
  await backOnlineWith(
    (r) => r.method === "PUT",
    () => vault.updateItem(vault.getEntry(bank.id)!, { ...vault.getEntry(bank.id)!.item, notes: "two" }),
  );
  expect(notesOn(bank.id)).toBe("two");
  expect(vault.offlineSummary()).toBeNull();
  expect(vault.getEntry(bank.id)?.item.notes).toBe("two");
});

test("a trash saved while a create is being sent: the created item goes to the trash", async () => {
  await signedIn();
  down();
  const id = await vault.createItem(login("Short-lived"));
  await backOnlineWith(
    (r) => r.method === "POST" && r.path === "/items",
    () => vault.trashItem(vault.getEntry(id)!),
  );
  expect(server.items.find((i) => i.id === id)?.deleted_at).toBeTruthy();
  expect(vault.offlineSummary()).toBeNull();
});

test("Discard while the change is being sent: the server's result stays, the local change is gone", async () => {
  const bank = await signedIn();
  down();
  await vault.updateItem(bank, { ...bank.item, notes: "sent anyway" });
  await backOnlineWith(
    (r) => r.method === "PUT",
    () => vault.discardOfflineChange(bank.id),
  );
  expect(notesOn(bank.id)).toBe("sent anyway");
  expect(await stored()).toBeUndefined();
  expect(vault.offlineSummary()).toBeNull();
  expect(vault.getEntry(bank.id)?.item.notes).toBe("sent anyway");
  expect(server.requests.filter((r) => r.method === "PUT")).toHaveLength(1);
});

test("a list that doesn't decrypt for this account is dropped with a notice; one that can't be read otherwise is kept and refuses writes", async () => {
  await signedIn();
  await vault.lockAll();
  await fake.local.set({ "offlineChanges:a1": { sealed: "offline:someone-else:{}", count: 2 } });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(vault.offlineNotice()).toEqual({ text: "Changes waiting on this device couldn't be read and were removed.", key: expect.any(String) });
  expect(await stored()).toBeUndefined();
  down();
  await vault.createItem(login("Fine"));
  expect(vault.offlineSummary()?.text).toBe("1 change waiting to sync");
  // Opens, but isn't a list this version reads: kept, nothing written over it.
  await vault.lockAll();
  const prefix = (await stored())!.sealed.slice(0, (await stored())!.sealed.indexOf(":", "offline:".length) + 1);
  const unread = { sealed: `${prefix}{"version":99}`, count: 3 };
  await fake.local.set({ "offlineChanges:a1": unread });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(vault.offlineNotice()).toEqual({ text: "Changes waiting on this device can't be read.", key: null });
  await expectReject(vault.createItem(login("Refused")), (e) => e.message === "Changes waiting on this device can't be read.");
  expect(await stored()).toEqual(unread);
});
