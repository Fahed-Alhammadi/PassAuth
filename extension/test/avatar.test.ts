// Profile pictures (server feature `avatar`): the background fetches and opens a picture only when `/sync`
// `user.avatar_seq` changed, keeps it per account in storage.local (so a locked popup can show it), seals uploads
// itself, and forgets the picture on sign-out and when the account is removed. The popup's resize keeps the JPEG
// within 256 KiB.

import { beforeEach, expect, test, vi } from "vitest";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer, sessionKeys } from "./fake-server";
import { expectReject } from "./helpers";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const vault = await import("../src/background/vault");
const { forgetServerFeatures } = await import("../src/background/api");
const { local } = await import("../src/background/storage");
const { avatars, avatarSeqOf, imageType, MAX_AVATAR_BYTES, toBase64 } = await import("../src/background/avatar");
const { encodeWithin, squareCrop, bytesToBase64 } = await import("../src/popup/avatar-image");

/** A tiny "JPEG": the signature is all the background checks. */
const JPEG = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 4]);
const sealed = (b: Uint8Array) => `sealed:${toBase64(b)}`;

let fake: FakeChrome;
let server: FakeServer;
let picture: { avatar: string | null; avatar_seq: number };

async function signedIn() {
  fake = installChrome();
  server = fakeServer();
  server.features = [...server.features, "avatar"];
  picture = { avatar: null, avatar_seq: 0 };
  Object.assign(server.user, { avatar_seq: 0 });
  server.handlers["GET /account/avatar"] = () => ({ body: picture });
  server.handlers["PUT /account/avatar"] = (req) => {
    picture = { avatar: req.body.avatar, avatar_seq: picture.avatar_seq + 1 };
    Object.assign(server.user, { avatar_seq: picture.avatar_seq });
    return { body: { ok: true, avatar_seq: picture.avatar_seq } };
  };
  server.handlers["DELETE /account/avatar"] = () => {
    picture = { avatar: null, avatar_seq: picture.avatar_seq + 1 };
    Object.assign(server.user, { avatar_seq: picture.avatar_seq });
    return { body: { ok: true, avatar_seq: picture.avatar_seq } };
  };
  vi.stubGlobal("fetch", server.fetch);
  forgetServerFeatures();
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  await vault.lockAll();
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
}

/** Another device set a picture: the server's number moves on. */
function setElsewhere(bytes: Uint8Array | null, raw?: string) {
  picture = { avatar: raw ?? (bytes ? sealed(bytes) : null), avatar_seq: picture.avatar_seq + 1 };
  Object.assign(server.user, { avatar_seq: picture.avatar_seq });
  server.revision++;
}

const avatarGets = () => server.requests.filter((r) => r.method === "GET" && r.path === "/account/avatar").length;

beforeEach(() => {
  vi.unstubAllGlobals();
});

test("a sync fetches the picture only when avatar_seq changed, and the popup state carries it", async () => {
  await signedIn();
  await vault.sync();
  expect(avatarGets()).toBe(0); // seq 0 = never set: nothing to fetch
  setElsewhere(JPEG);
  await vault.sync();
  await vi.waitFor(async () => expect((await avatars.get("a1"))?.seq).toBe(1));
  expect((await avatars.get("a1"))?.dataUrl).toBe(`data:image/jpeg;base64,${toBase64(JPEG)}`);
  expect(avatarGets()).toBe(1);
  server.revision++;
  await vault.sync();
  await vault.sync();
  expect(avatarGets()).toBe(1); // same number: no download
  const state = await vault.state();
  expect(state.avatar).toMatch(/^data:image\/jpeg;base64,/);
  expect(state.avatarEditable).toBe(true);
  expect(state.accounts[0]?.avatar).toBe(state.avatar);
});

test("a picture that can't be opened shows initials, and isn't downloaded again for the same number", async () => {
  await signedIn();
  setElsewhere(null, "garbage");
  await vault.sync();
  await vi.waitFor(async () => expect((await avatars.get("a1"))?.seq).toBe(1));
  expect((await avatars.get("a1"))?.dataUrl).toBeNull();
  expect((await vault.state()).avatar).toBeUndefined();
  server.revision++;
  await vault.sync();
  expect(avatarGets()).toBe(1);
});

test("a removed picture clears the kept one", async () => {
  await signedIn();
  setElsewhere(JPEG);
  await vault.sync();
  await vi.waitFor(async () => expect((await avatars.get("a1"))?.dataUrl).toBeTruthy());
  setElsewhere(null);
  await vault.sync();
  await vi.waitFor(async () => expect((await avatars.get("a1"))?.dataUrl).toBeNull());
});

test("setting seals the JPEG before upload; removing deletes it; neither while locked", async () => {
  await signedIn();
  await vault.setAvatar(JPEG);
  const put = server.requests.find((r) => r.method === "PUT" && r.path === "/account/avatar");
  expect(put?.body).toEqual({ avatar: sealed(JPEG) });
  expect(await avatars.get("a1")).toEqual({ seq: 1, dataUrl: `data:image/jpeg;base64,${toBase64(JPEG)}` });
  // The sync after our own change sees the number we already have.
  server.revision++;
  await vault.sync();
  expect(avatarGets()).toBe(0);

  await vault.removeAvatar();
  expect(await avatars.get("a1")).toEqual({ seq: 2, dataUrl: null });

  await expectReject(vault.setAvatar(new Uint8Array([1, 2, 3])), (e) => /couldn't be used/.test(e.message));
  await expectReject(vault.setAvatar(Uint8Array.from({ length: MAX_AVATAR_BYTES + 1 }, (_, i) => JPEG[i] ?? 0)), (e) => /too large/.test(e.message));
  await vault.lockAll();
  await expectReject(vault.setAvatar(JPEG), (e) => e.code === "locked");
});

test("signing out forgets the picture; so does removing the account", async () => {
  await signedIn();
  await vault.setAvatar(JPEG);
  expect(await avatars.get("a1")).not.toBeNull();
  await vault.logout();
  expect(await avatars.get("a1")).toBeNull();

  await avatars.set("a1", { seq: 3, dataUrl: "data:image/jpeg;base64,AA==" });
  await fake.local.set({ accounts: { a1: accountRecord(), a2: accountRecord("https://other.test") } });
  await local.removeAccount("a1");
  expect(await avatars.get("a1")).toBeNull();
});

test("an older server (no avatar_seq) never asks for a picture or offers one", async () => {
  await signedIn();
  server.features = server.features.filter((f) => f !== "avatar");
  forgetServerFeatures();
  delete (server.user as { avatar_seq?: number }).avatar_seq;
  server.revision++;
  await vault.sync();
  expect(avatarGets()).toBe(0);
  expect((await vault.state()).avatarEditable).toBeUndefined();
  expect(avatarSeqOf({})).toBeNull();
  expect(avatarSeqOf({ avatar_seq: -1 })).toBeNull();
  expect(avatarSeqOf({ avatar_seq: 4 })).toBe(4);
});

test("only image bytes become a data URL", () => {
  expect(imageType(JPEG)).toBe("image/jpeg");
  expect(imageType(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0]))).toBe("image/png");
  expect(imageType(new TextEncoder().encode("<svg onload=alert(1)>"))).toBeNull();
});

test("resize: a centred square crop, encoded at falling quality until it fits in 256 KiB", async () => {
  expect(squareCrop(400, 300)).toEqual({ sx: 50, sy: 0, size: 300 });
  expect(squareCrop(300, 500)).toEqual({ sx: 0, sy: 100, size: 300 });
  const tried: number[] = [];
  // Pretend the size shrinks with the quality: 0.85 → 340 KiB, 0.75 → 300 KiB, 0.65 → 260 KiB, 0.55 → 220 KiB.
  const out = await encodeWithin(async (q) => {
    tried.push(q);
    return new Blob([new Uint8Array(Math.round(q * 400 * 1024))]);
  });
  expect(tried).toEqual([0.85, 0.75, 0.65, 0.55]);
  expect(out.length).toBeLessThanOrEqual(MAX_AVATAR_BYTES);
  await expectReject(
    encodeWithin(async () => new Blob([new Uint8Array(MAX_AVATAR_BYTES + 1)])),
    (e) => /too large/.test(e.message),
  );
  // A whole 256 KiB picture goes over the message channel as base64 (no call with too many arguments).
  const big = new Uint8Array(MAX_AVATAR_BYTES).fill(7);
  expect(bytesToBase64(big)).toBe(toBase64(big));
});
