/** Send v2 on the owner's side and the visitor's keys, with the real core (WASM) and a fake server. */
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as core from "../wasm/passauth_core";
import { allVectors, loadCore, signedVectors, vectorAccounts } from "./test-core";

type Opts = { method?: string; body?: unknown };
const h = vi.hoisted(() => ({
  account: null as unknown,
  features: ["sends", "send_v2"] as string[],
  calls: [] as { path: string; method: string; body: Record<string, unknown> }[],
  stored: new Map<string, Record<string, unknown>>(),
}));

vi.mock("./api", async (importOriginal) => {
  const orig = await importOriginal<typeof import("./api")>();
  const answer = (row: Record<string, unknown>) => ({ ...row, has_password: typeof row.access_verifier === "string", delete_at: row.delete_at ?? 9e9 });
  return {
    ...orig,
    knownPublicConfig: () => ({ features: h.features }),
    loadPublicConfig: async () => ({ features: h.features }),
    api: async (path: string, opts: Opts = {}) => {
      const method = opts.method ?? (opts.body === undefined ? "GET" : "POST");
      const body = (opts.body ?? {}) as Record<string, unknown>;
      h.calls.push({ path, method, body });
      if (path === "/sends" && method === "POST") {
        // Like the server: an old one drops owner_content_key.
        const row = { ...body, id: `send-${h.stored.size + 1}`, ...(h.features.includes("send_v2") ? {} : { owner_content_key: undefined }) };
        h.stored.set(row.id as string, row);
        return answer(row);
      }
      const one = /^\/sends\/([^/]+)$/.exec(path);
      if (one && method === "GET") return answer(h.stored.get(decodeURIComponent(one[1]))!);
      if (one && method === "PUT") {
        const id = decodeURIComponent(one[1]);
        const row = { ...h.stored.get(id)!, ...body };
        if (body.access_verifier === null) delete row.access_salt;
        h.stored.set(id, row);
        return answer(row);
      }
      throw new Error(`no route ${method} ${path}`);
    },
  };
});
vi.mock("./vault", () => ({ getAccount: () => h.account }));
vi.stubGlobal("location", new URL("https://vault.example.test/"));

import { SEND_PASSWORD_NEEDS_V2, SEND_PASSWORD_TO_EDIT, SEND_UNREADABLE, createSend, getSend, nameOf, sendFormat, textOf, updateSend } from "./send-client";
import { sendKeysHere } from "./send-kdf";
import { readSend, type OwnedSend } from "./sends";

const PW = "correct horse";
const base = { maxViews: null, expiresAt: null, deleteAt: 9e9, hideEmail: false };
/** The link's key, as the visitor has it. */
const linkKey = (link: string) => link.slice(link.indexOf("#") + 1);
const version = (field: unknown) => core.sendFieldVersion(field as string);
const lastBody = () => h.calls[h.calls.length - 1].body;

beforeAll(async () => {
  await loadCore();
  h.account = vectorAccounts(await signedVectors()).get("alice")!.account;
});
beforeEach(() => {
  h.features = ["sends", "send_v2"];
  h.calls = [];
  h.stored.clear();
});

describe("Send v2 (password-derived content key)", () => {
  it("matches the shared vectors", async () => {
    const v = (await allVectors()).sendV2 as { key: string; password: string; salt: string; text: string; verifier: string; contentKey: string; data: string };
    expect(sendKeysHere(v.password, v.salt, v.key)).toEqual({ verifier: v.verifier, contentKey: v.contentKey });
    expect(core.sendOpen(v.key, v.contentKey, "data", v.data)).toBe(v.text);
    expect(() => core.sendOpen(v.key, null, "data", v.data)).toThrow("password_required");
  });

  it("a new Send with a password is v2: the link alone doesn't open it, the owner does without the password", async () => {
    const { send, link } = await createSend({ ...base, name: "Wi-Fi", text: "hunter2", password: PW });
    const body = lastBody();
    expect(version(body.name)).toBe(2);
    expect(version(body.data)).toBe(2);
    expect(body.owner_content_key).toEqual(expect.any(String));
    // The visitor: the link's key and the password give the verifier the server checks and the content key.
    const key = linkKey(link);
    const keys = sendKeysHere(PW, body.access_salt as string, key);
    expect(keys.verifier).toBe(body.access_verifier);
    expect(() => core.sendOpen(key, null, "data", body.data as string)).toThrow("password_required");
    expect(core.sendOpen(key, keys.contentKey, "data", body.data as string)).toBe("hunter2");
    expect(() => core.sendOpen(key, sendKeysHere("wrong", body.access_salt as string, key).contentKey, "data", body.data as string)).toThrow();
    // The owner.
    expect(nameOf(send)).toBe("Wi-Fi");
    expect(textOf(await getSend(send.id))).toBe("hunter2");
  }, 60_000);

  it("stays v1 without a password; a password is never written v1: a server without send_v2 gets no password Send (core M4a)", async () => {
    await createSend({ ...base, name: "Note", text: "plain", password: null });
    expect(version(lastBody().name)).toBe(1);
    expect(lastBody().owner_content_key).toBeUndefined();
    h.features = ["sends"];
    h.calls = [];
    await expect(createSend({ ...base, name: "Old", text: "server", password: PW })).rejects.toThrow(SEND_PASSWORD_NEEDS_V2);
    expect(SEND_PASSWORD_NEEDS_V2).toBe("Update your PassAuth server to protect a Send with a password.");
    // Nothing was sent, and a Send without a password still works there.
    expect(h.calls).toEqual([]);
    await createSend({ ...base, name: "Plain", text: "ok", password: null });
    expect(version(lastBody().data)).toBe(1);
  }, 60_000);

  it("a server that stops listing send_v2 can't downgrade a Send: no password is set or changed there, a v2 Send stays v2 (review 7 / core M4b)", async () => {
    const { send, link } = await createSend({ ...base, name: "Wi-Fi", text: "one", password: PW });
    const plain = (await createSend({ ...base, name: "Note", text: "plain", password: null })).send;
    h.features = ["sends"];
    h.calls = [];
    // Changing the password of a v2 Send, or giving a v1 Send one: refused here, nothing sent.
    await expect(updateSend(send, { password: "another one" })).rejects.toThrow(SEND_PASSWORD_NEEDS_V2);
    await expect(updateSend(send, { password: "another one", text: "x" })).rejects.toThrow(SEND_PASSWORD_NEEDS_V2);
    await expect(updateSend(plain, { password: PW })).rejects.toThrow(SEND_PASSWORD_NEEDS_V2);
    expect(h.calls).toEqual([]);
    // Editing the text of the v2 Send keeps it v2 (its own content key), whatever the server lists.
    const s = await updateSend(send, { text: "two", name: "Wi-Fi 2" });
    expect(version(lastBody().data)).toBe(2);
    expect(version(lastBody().name)).toBe(2);
    expect(lastBody()).not.toHaveProperty("owner_content_key");
    expect(lastBody()).not.toHaveProperty("access_verifier");
    expect(() => core.sendOpen(linkKey(link), null, "data", lastBody().data as string)).toThrow();
    expect(textOf(await getSend(s.id))).toBe("two");
    // Taking the password away is the owner's choice and still goes back to v1.
    await updateSend(s, { password: null });
    expect(lastBody()).toMatchObject({ access_verifier: null, owner_content_key: null });
    expect(version(lastBody().data)).toBe(1);
  }, 60_000);

  it("the format is read from the fields, not from a list: a Send whose content key and text disagree is unreadable and never rewritten (contract 7c)", async () => {
    const { send } = await createSend({ ...base, name: "Wi-Fi", text: "x", password: PW });
    const full = await getSend(send.id);
    expect(sendFormat(full)).toBe(2);
    const plain = await getSend((await createSend({ ...base, name: "Note", text: "plain", password: null })).send.id);
    expect(sendFormat(plain)).toBe(1);
    // The server drops the content key of a v2 Send, or hands a v1 Send someone's key, or sends garbage.
    const dropped: OwnedSend = { ...full, ownerContentKey: null };
    const planted: OwnedSend = { ...plain, ownerContentKey: full.ownerContentKey };
    const garbage: OwnedSend = { ...plain, name: "zzzz" };
    h.calls = [];
    for (const bad of [dropped, planted, garbage]) {
      expect(sendFormat(bad)).toBeNull();
      expect(nameOf(bad)).toBeNull();
      expect(() => textOf(bad)).toThrow();
      await expect(updateSend(bad, { text: "repaired" })).rejects.toThrow(SEND_UNREADABLE);
      await expect(updateSend(bad, { password: null })).rejects.toThrow(SEND_UNREADABLE);
      await expect(updateSend(bad, { password: PW })).rejects.toThrow(SEND_UNREADABLE);
    }
    expect(h.calls).toEqual([]);
    // Its settings can still be changed (to switch it off), which sends no text.
    await updateSend(dropped, { disabled: true });
    expect(lastBody()).toEqual({ disabled: true });
  }, 60_000);

  it("edits keep the format; a new password re-keys both fields; removing it goes back to v1", async () => {
    const { send, link } = await createSend({ ...base, name: "Wi-Fi", text: "one", password: PW });
    const key = linkKey(link);
    const first = lastBody();
    // Text only: v2 with the same content key, nothing else re-keyed.
    let s: OwnedSend = await updateSend(send, { text: "two" });
    expect(lastBody()).toEqual({ data: expect.any(String) });
    expect(version(lastBody().data)).toBe(2);
    expect(textOf(await getSend(s.id))).toBe("two");
    // Settings only.
    s = await updateSend(s, { disabled: true });
    expect(lastBody()).toEqual({ disabled: true });
    // A new password: new salt and content key, name and text sent again with it.
    s = await updateSend(s, { password: "new password" });
    const changed = lastBody();
    expect(Object.keys(changed).sort()).toEqual(["access_salt", "access_verifier", "data", "name", "owner_content_key"]);
    expect(changed.access_salt).not.toBe(first.access_salt);
    const ck = sendKeysHere("new password", changed.access_salt as string, key).contentKey;
    expect(core.sendOpen(key, ck, "data", changed.data as string)).toBe("two");
    expect(core.sendOpen(key, ck, "name", changed.name as string)).toBe("Wi-Fi");
    expect(nameOf(s)).toBe("Wi-Fi");
    // Removing it: v1 again, the content key cleared, the link alone opens it.
    s = await updateSend(s, { password: null });
    const removed = lastBody();
    expect(removed).toMatchObject({ access_verifier: null, owner_content_key: null });
    expect(version(removed.data)).toBe(1);
    expect(core.sendOpen(key, null, "data", removed.data as string)).toBe("two");
    expect(readSend({ ...h.stored.get(s.id), has_password: false, delete_at: 9e9 })!.ownerContentKey).toBeNull();
  }, 60_000);

  it("setting a password on a v1 Send makes it v2", async () => {
    const { send, link } = await createSend({ ...base, name: "Note", text: "plain", password: null });
    await updateSend(send, { password: PW });
    const b = lastBody();
    expect(version(b.name)).toBe(2);
    expect(core.sendOpen(linkKey(link), sendKeysHere(PW, b.access_salt as string, linkKey(link)).contentKey, "data", b.data as string)).toBe("plain");
  }, 60_000);

  it("rereview 8 (S8): a v1 state of a Send the server says has a password takes a new name or text only together with the password", async () => {
    const { send, link } = await createSend({ ...base, name: "Note", text: "plain", password: null });
    // Later the Send got a password (v2); the server serves its earlier v1 fields again and still lists the password.
    const replayed = { ...send, hasPassword: true };
    expect(sendFormat(replayed)).toBe(1);
    h.calls = [];
    await expect(updateSend(replayed, { text: "secret" })).rejects.toThrow(SEND_PASSWORD_TO_EDIT);
    await expect(updateSend(replayed, { name: "Renamed" })).rejects.toThrow(SEND_PASSWORD_TO_EDIT);
    expect(SEND_PASSWORD_TO_EDIT).toBe("Enter this Send's password to change its text.");
    expect(h.calls.filter((c) => c.method === "PUT")).toEqual([]);
    // Settings alone still go through.
    await updateSend(replayed, { disabled: true });
    expect(lastBody().name).toBeUndefined();
    expect(lastBody().data).toBeUndefined();
    // With the password the text is written v2: the link alone doesn't open it.
    await updateSend(replayed, { text: "secret", password: PW });
    const b = lastBody();
    expect(version(b.data)).toBe(2);
    expect(() => core.sendOpen(linkKey(link), null, "data", b.data as string)).toThrow();
    // Taking the password away writes v1, as before; so does an ordinary v1 Send without a password.
    await updateSend(replayed, { text: "open", password: null });
    expect(version(lastBody().data)).toBe(1);
    await updateSend(send, { text: "still plain" });
    expect(version(lastBody().data)).toBe(1);
    // A server without send_v2 (an old one keeps v1 password Sends): edited as before.
    h.features = ["sends"];
    await updateSend(replayed, { text: "old server" });
    expect(version(lastBody().data)).toBe(1);
  }, 60_000);

  it("a v2 Send whose content key can't be opened shows as unreadable", async () => {
    const { send } = await createSend({ ...base, name: "Wi-Fi", text: "x", password: PW });
    expect(nameOf({ ...send, ownerContentKey: null })).toBeNull();
    expect(nameOf({ ...send, ownerContentKey: "garbage" })).toBeNull();
  }, 60_000);
});
