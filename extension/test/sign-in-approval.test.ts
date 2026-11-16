// Approve a sign-in from another device (servers with `login_with_device`), both sides in the worker:
// - approving (background/sign-in-requests.ts): listed only while unlocked, kept in session storage for the badge and
//   the popup, shown with the words worked out from the request's own key (never the server's), approved with the
//   account key sealed to that key and the challenge opened as proof, denied, dropped when answered elsewhere;
// - the new device (background/device-sign-in.ts): its requests carried to the account's server with this browser's
//   own device fields and the access code in a header, and an approved sign-in installed like a password one.

import type { Bundle } from "@web/lib/types";
import { beforeEach, expect, test, vi } from "vitest";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer, sessionKeys } from "./fake-server";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const core = await import("../src/wasm/passauth_core");
const vault = await import("../src/background/vault");
const { refreshSignInRequests, signInRequests, answerSignIn, signInAnswered, forgetSignInRequests, signInWaiting } = await import("../src/background/sign-in-requests");
const { startDeviceSignIn, createDeviceRequest, pollDeviceRequest, verifyDeviceTwoStep } = await import("../src/background/device-sign-in");
const { forgetServerFeatures } = await import("../src/background/api");
const { pageStateChanged, refreshBadge } = await import("../src/background/badge");
const { readLiveMessage } = await import("../src/background/sync-rules");

let fake: FakeChrome;
let server: FakeServer;

/** A request's public key (32 bytes, base64url) and what the server lists for it. */
const KEY = "q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA";
const request = (id: string, extra: Record<string, unknown> = {}) => ({
  id,
  public_key: KEY,
  fingerprint_phrase: "words the server chose",
  challenge: `challenge-${id}`,
  device_name: "Chrome on macOS",
  device_kind: "web",
  client: "web/0.9.0",
  ip: "203.0.113.7",
  created_at: 1_700_000_000,
  expires_at: Math.floor(Date.now() / 1000) + 600,
  ...extra,
});

beforeEach(async () => {
  vi.unstubAllGlobals();
  await vault.lockAll().catch(() => {});
  fake = installChrome();
  server = fakeServer();
  server.features = [...server.features, "delta_sync", "login_with_device"];
  vi.stubGlobal("fetch", server.fetch);
  forgetServerFeatures();
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  // What a lock does in the worker (main.ts): the lists, and the requests answered lately, go.
  await forgetSignInRequests();
});

/** Unlocked, with these requests waiting on the server. */
async function unlocked(requests: Record<string, unknown>[]) {
  server.handlers["GET /account/auth-requests"] = () => ({ body: { requests } });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
}

const listed = () => server.requests.filter((r) => r.path === "/account/auth-requests").length;

/** The waiting requests as the popup gets them. */
const views = async () => (await signInRequests()).requests;
/** An approval as the popup's sheet sends it: the request as frozen when it opened, and the words picked. */
const approval = (id: string, extra: Partial<{ publicKey: string; challenge: string; phrase: string }> = {}) => ({
  publicKey: KEY,
  challenge: `challenge-${id}`,
  phrase: core.loginPhrase(KEY),
  ...extra,
});

test("listed while unlocked, kept for the badge and the popup, with the words worked out here (never the server's)", async () => {
  await unlocked([request("r1")]);
  await refreshSignInRequests(true);
  expect(await signInWaiting()).toBe(true);
  const [view] = await views();
  expect(view).toMatchObject({ id: "r1", deviceName: "Chrome on macOS", client: "web/0.9.0", ip: "203.0.113.7", publicKey: KEY, challenge: "challenge-r1" });
  expect(view?.phrase).toBe(core.loginPhrase(KEY));
  expect(view?.phrase?.split(" ")).toHaveLength(5);
  // Three sets of words to pick from: the request's own among two decoys (the core's).
  expect(view?.choices).toHaveLength(3);
  expect(view?.choices).toContain(view?.phrase);
  expect(JSON.stringify(await signInRequests())).not.toContain("words the server chose");
  // Kept in session storage, so the badge can show its dot; that key change refreshes the badge.
  expect(pageStateChanged({ "signInRequests:a1": {} }, "session")).toBe(true);
  // Without a reason, asked again at most every 30 s.
  const asked = listed();
  await refreshSignInRequests();
  expect(listed()).toBe(asked);
  await refreshSignInRequests(true);
  expect(listed()).toBe(asked + 1);
});

test("locked, or a server without the feature: nothing is asked and nothing is kept", async () => {
  server.handlers["GET /account/auth-requests"] = () => ({ body: { requests: [request("r1")] } });
  await refreshSignInRequests(true);
  expect(listed()).toBe(0);
  expect(await signInWaiting()).toBe(false);
  server.features = server.features.filter((f) => f !== "login_with_device");
  forgetServerFeatures();
  await unlocked([request("r1")]);
  await refreshSignInRequests(true);
  expect(listed()).toBe(0);
});

test("approve: the account key sealed to the request's key (with the Secret Key kept here) and the challenge opened as proof", async () => {
  await fake.local.set({ secretKeys: { "https://vault.test|alex@example.com": "PA1-SECRET" } });
  await unlocked([request("r1"), request("r2")]);
  await refreshSignInRequests(true);
  server.handlers["POST /account/auth-requests/r1"] = () => ({ body: { id: "r1", status: "approved" } });
  // The code to enter on the new device comes back with the approval (the popup shows it until Done).
  expect(await answerSignIn("r1", true, approval("r1"))).toStrictEqual({ outcome: "done", code: "123456" });
  const post = server.requests.find((r) => r.method === "POST" && r.path === "/account/auth-requests/r1");
  expect(post?.body).toStrictEqual({ approve: true, sealed_key: `sealed(${KEY},r1,PA1-SECRET)`, proof: "proof(challenge-r1,r1)" });
  expect((await views()).map((r) => r.id)).toStrictEqual(["r2"]);
  // Answered here: listed among the answered ids, so a sheet whose request went can say why.
  expect((await signInRequests()).answered).toContain("r1");
});

test("deny; answered elsewhere first (409) or expired: the request leaves the list either way", async () => {
  await unlocked([request("r1"), request("r2"), request("r3")]);
  await refreshSignInRequests(true);
  server.handlers["POST /account/auth-requests/r1"] = () => ({ body: { id: "r1", status: "denied" } });
  server.handlers["POST /account/auth-requests/r2"] = () => ({ status: 409, body: { error: "conflict", message: "already answered" } });
  server.handlers["POST /account/auth-requests/r3"] = () => ({ status: 400, body: { error: "expired", message: "expired" } });
  expect(await answerSignIn("r1", false)).toStrictEqual({ outcome: "done" });
  expect(server.requests.find((r) => r.path === "/account/auth-requests/r1")?.body).toStrictEqual({ approve: false });
  expect(await answerSignIn("r2", true, approval("r2"))).toStrictEqual({ outcome: "answered" });
  expect(await answerSignIn("r3", true, approval("r3"))).toStrictEqual({ outcome: "expired" });
  expect(await signInWaiting()).toBe(false);
  // Gone already: said so, nothing sent.
  await expect(answerSignIn("r1", true, approval("r1"))).rejects.toMatchObject({ code: "expired" });
});

test("F1: an approval names the request as its sheet froze it; a listing with another key for its id since is refused, nothing sent", async () => {
  await unlocked([request("r1")]);
  await refreshSignInRequests(true);
  const frozen = approval("r1");
  // The server lists the same id again with its own key (and a challenge sealed to the account).
  const OTHER = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
  server.handlers["GET /account/auth-requests"] = () => ({ body: { requests: [request("r1", { public_key: OTHER, challenge: "challenge-r1-theirs" })] } });
  await refreshSignInRequests(true);
  await expect(answerSignIn("r1", true, frozen)).rejects.toMatchObject({ code: "request_changed" });
  // No approval without the frozen request either.
  await expect(answerSignIn("r1", true)).rejects.toMatchObject({ code: "request_changed" });
  expect(server.requests.some((r) => r.method === "POST")).toBe(false);
});

test("the challenge is sealed again at every listing (other text, same plaintext): same key, other challenge text — the approval goes through with the frozen challenge", async () => {
  await unlocked([request("r1")]);
  await refreshSignInRequests(true);
  const frozen = approval("r1");
  // A re-list (live-sync connect, auth_request, the popup opening, the minute poll) brings a newly sealed challenge.
  server.handlers["GET /account/auth-requests"] = () => ({ body: { requests: [request("r1", { challenge: "challenge-r1-sealed-again" })] } });
  await refreshSignInRequests(true);
  expect((await views())[0]?.challenge).toBe("challenge-r1-sealed-again");
  server.handlers["POST /account/auth-requests/r1"] = () => ({ body: { id: "r1", status: "approved" } });
  expect(await answerSignIn("r1", true, frozen)).toStrictEqual({ outcome: "done", code: "123456" });
  // The proof is the frozen challenge opened (its plaintext is the same as the re-sealed one's).
  const post = server.requests.find((r) => r.method === "POST" && r.path === "/account/auth-requests/r1");
  expect(post?.body).toMatchObject({ approve: true, proof: "proof(challenge-r1,r1)" });
});

test("F1: words that aren't the request's: it is denied, and the answer says so", async () => {
  await unlocked([request("r1")]);
  await refreshSignInRequests(true);
  server.handlers["POST /account/auth-requests/r1"] = () => ({ body: { id: "r1", status: "denied" } });
  expect(await answerSignIn("r1", true, approval("r1", { phrase: "some other five words here" }))).toStrictEqual({ outcome: "mismatch" });
  expect(server.requests.find((r) => r.method === "POST" && r.path === "/account/auth-requests/r1")?.body).toStrictEqual({ approve: false });
  expect(await views()).toStrictEqual([]);
});

test("a listing already on its way when a request was answered elsewhere doesn't bring it back", async () => {
  await unlocked([request("r1"), request("r2")]);
  await refreshSignInRequests(true);
  // The next listing is held on the network while the socket says r1 was answered on another device.
  let release!: () => void;
  const held = new Promise<void>((r) => (release = r));
  vi.stubGlobal("fetch", async (input: string, init?: RequestInit) => {
    if (String(input).endsWith("/account/auth-requests")) await held;
    return server.fetch(input, init);
  });
  const listing = refreshSignInRequests(true);
  await new Promise((r) => setTimeout(r, 10));
  await signInAnswered("r1");
  release();
  await listing;
  expect((await views()).map((r) => r.id)).toStrictEqual(["r2"]);
});

test("a request whose key can't be read is never approved, only denied", async () => {
  await unlocked([request("r1", { public_key: "not base64url!" })]);
  await refreshSignInRequests(true);
  expect((await views())[0]).toMatchObject({ phrase: null, choices: [] });
  await expect(answerSignIn("r1", true, approval("r1", { publicKey: "not base64url!" }))).rejects.toMatchObject({ code: "expired" });
  expect(server.requests.some((r) => r.method === "POST")).toBe(false);
});

test("the socket's auth_request_answered drops it at once; a lock forgets the list", async () => {
  await unlocked([request("r1"), request("r2")]);
  await refreshSignInRequests(true);
  await signInAnswered("r1");
  expect((await views()).map((r) => r.id)).toStrictEqual(["r2"]);
  // Answered on another device: the popup's sheet for it says so when it closes.
  expect((await signInRequests()).answered).toContain("r1");
  await forgetSignInRequests();
  expect(await signInWaiting()).toBe(false);
  // The socket's messages, as live-sync.ts reads them.
  expect(readLiveMessage('{"type":"auth_request","id":"r9"}')).toStrictEqual({ type: "auth_request", id: "r9" });
  expect(readLiveMessage('{"type":"auth_request_answered","id":"r9"}')).toStrictEqual({ type: "auth_request_answered", id: "r9" });
  expect(readLiveMessage('{"type":"auth_request"}')).toBe(null);
});

test("while one waits, the toolbar badge is a dot in the warning colour and the title says why; nothing opens", async () => {
  fake.tabs.set(1, { id: 1, url: "https://example.com/", windowId: 1, active: true });
  await unlocked([request("r1")]);
  await refreshSignInRequests(true);
  refreshBadge();
  await new Promise((r) => setTimeout(r, 400));
  expect(fake.action.badges.get(1)).toStrictEqual({ color: "#965A00", text: " " });
  expect(fake.action.title).toBe("PassAuth: a sign-in on another device is waiting for your approval");
  expect(fake.action.popupOpened).toBe(0);
  // Answered: back to the count (none for this page) and the plain title.
  await signInAnswered("r1");
  refreshBadge();
  await new Promise((r) => setTimeout(r, 400));
  expect(fake.action.badges.get(1)).toStrictEqual({ color: "#0866ED", text: "" });
  expect(fake.action.title).toBe("PassAuth");
});

// ------------------------------------------------------------------ the new device

/** Signed out of a1 on the server's sign-in screen. */
async function signedOut() {
  await fake.local.set({ accounts: { a1: { ...accountRecord(), tokens: null } }, active: "a1", rememberTokens: { "https://vault.test|alex@example.com": "rt-1" } });
}

test("a request goes to the account's server with this browser's own device fields and remember token", async () => {
  await signedOut();
  const start = await startDeviceSignIn("alex@example.com");
  expect(start).toMatchObject({ account: "a1", device: { kind: "extension" }, rememberToken: "rt-1" });
  server.handlers["POST /auth/requests"] = () => ({ body: { id: "r1", fingerprint_phrase: "x", expires_at: 1 } });
  await createDeviceRequest("a1", { email: "alex@example.com", public_key: KEY, access_code: "c".repeat(43), device_id: "forged", device_name: "forged", device_kind: "forged" });
  const sent = server.requests.find((r) => r.path === "/auth/requests");
  expect(sent?.headers.authorization).toBeUndefined();
  expect(sent?.body).toStrictEqual({
    email: "alex@example.com",
    public_key: KEY,
    access_code: "c".repeat(43),
    device_id: start.device.id,
    device_name: start.device.name,
    device_kind: "extension",
    remember_token: "rt-1",
  });
});

test("polling: the access code in a header (never in the URL); gone, wait and answers sorted for the run", async () => {
  await signedOut();
  server.handlers["GET /auth/requests/r1"] = () => ({ body: { status: "pending" } });
  expect(await pollDeviceRequest("a1", "r1", "secret-code")).toStrictEqual({ kind: "answer", body: { status: "pending" } });
  const poll = server.requests.find((r) => r.path === "/auth/requests/r1");
  expect(poll?.headers["x-passauth-access-code"]).toBe("secret-code");
  expect(JSON.stringify(poll?.query)).not.toContain("secret-code");
  server.handlers["GET /auth/requests/r1"] = () => ({ status: 404, body: { error: "not_found", message: "not found" } });
  expect(await pollDeviceRequest("a1", "r1", "secret-code")).toStrictEqual({ kind: "gone" });
  server.handlers["GET /auth/requests/r1"] = () => ({ status: 429, body: { error: "rate_limited", message: "slow down" }, headers: { "retry-after": "7" } });
  expect(await pollDeviceRequest("a1", "r1", "secret-code")).toStrictEqual({ kind: "retry", afterMs: 7000 });
});

test("an approved sign-in is installed like a password one: tokens, keys, the Secret Key it brought, the vault synced", async () => {
  await signedOut();
  // The fake core's bundle (it opens with `password`), typed as the API's.
  const bundle = { account_id: "acc-1", password: "pw", secret_key_enabled: true } as unknown as Bundle;
  server.bundle = bundle;
  await vault.finishDeviceSignIn(
    "a1",
    { email: "alex@example.com", accessToken: "a2", refreshToken: "r2", bundle, accountId: "acc-1", keys: "AQID", secretKey: "PA1-NEW", rememberToken: "rt-2" },
    "Alex@Example.com",
  );
  const state = await vault.state();
  expect([state.status, state.email]).toStrictEqual(["unlocked", "alex@example.com"]);
  expect((fake.local.data.get("accounts") as Record<string, { tokens: unknown }>).a1?.tokens).toStrictEqual({ access: "a2", refresh: "r2" });
  expect(fake.local.data.get("secretKeys")).toStrictEqual({ "https://vault.test|alex@example.com": "PA1-NEW" });
  expect(fake.local.data.get("rememberTokens")).toStrictEqual({ "https://vault.test|alex@example.com": "rt-2" });
  expect(server.requests.some((r) => r.path === "/sync")).toBe(true);
  // Approving elsewhere is no master password typed here: passkey user verification still asks for it.
  expect(await vault.recentlyVerified()).toBe(false);
});

test("F7: a Secret Key that came along is kept only for the email typed here, never over a different one kept for it", async () => {
  const bundle = { account_id: "acc-1", password: "pw", secret_key_enabled: true } as unknown as Bundle;
  server.bundle = bundle;
  const signIn = { email: "alex@example.com", accessToken: "a2", refreshToken: "r2", bundle, accountId: "acc-1", keys: "AQID", secretKey: "PA1-FROM-SERVER" };
  // The session is for another email than the one typed: nothing kept.
  await signedOut();
  await vault.finishDeviceSignIn("a1", signIn, "someone.else@example.com");
  expect(fake.local.data.get("secretKeys") ?? {}).toStrictEqual({});
  await vault.lockAll();
  // A different Secret Key is kept for this email already: it stays.
  await signedOut();
  await fake.local.set({ secretKeys: { "https://vault.test|alex@example.com": "PA1-KEPT" } });
  await vault.finishDeviceSignIn("a1", signIn, "alex@example.com");
  expect(fake.local.data.get("secretKeys")).toStrictEqual({ "https://vault.test|alex@example.com": "PA1-KEPT" });
});

test("an approval for another account, or after PassAuth switched accounts, is refused", async () => {
  await signedOut();
  const bundle = { account_id: "acc-1", password: "pw", secret_key_enabled: false } as unknown as Bundle;
  await expect(vault.finishDeviceSignIn("a1", { email: "alex@example.com", accessToken: "a", refreshToken: "r", bundle, accountId: "acc-OTHER", keys: "AQID" })).rejects.toThrow(
    /doesn't belong to this account/,
  );
  await expect(vault.finishDeviceSignIn("a2", { email: "alex@example.com", accessToken: "a", refreshToken: "r", bundle, accountId: "acc-1", keys: "AQID" })).rejects.toMatchObject({ code: "expired" });
  await expect(verifyDeviceTwoStep("a2", "t", "totp", "123456", false)).rejects.toMatchObject({ code: "expired" });
  expect((await vault.state()).status).toBe("logged-out");
});
