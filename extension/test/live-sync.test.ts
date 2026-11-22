// Live sync in the service worker (background/live-sync.ts, wired by main.ts): a socket while the active account is
// unlocked on a server with delta sync, a keepalive frame every 20 s, messages handed to vault.ts, the `hello` origin
// kept, a session check on `logout`, reconnects after a revision check, the 5-minute fallback alarm, and nothing left
// after a lock, a sign-out or an account switch. Older servers: no socket at all.

import { beforeEach, expect, test, vi } from "vitest";
import { installedChrome, resetChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer, sessionKeys } from "./fake-server";
import { FakeWebSocket } from "./fake-socket";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

await import("../src/background/main");
const fake = installedChrome();
const live = await import("../src/background/live-sync");
const vault = await import("../src/background/vault");
const { forgetServerFeatures } = await import("../src/background/api");

const DELTA = ["key_epoch", "idempotent_create", "error_codes", "delta_sync"];
let server: FakeServer;

const login = (name: string) =>
  JSON.stringify({
    name,
    notes: "",
    favorite: false,
    folder: null,
    tags: [],
    login: { username: "alex", password: "pw", urls: [{ url: "https://example.com", match: "domain" }], totp: null, passkeys: [] },
    card: null,
    identity: null,
    ssh_key: null,
    fields: [],
    password_history: [],
    created_at: 0,
    updated_at: 0,
  });

/** Signed in and unlocked (the vault opened, which starts live sync); resolves once the socket is made. */
async function unlocked(features = DELTA) {
  server.features = features;
  server.addElsewhere("i1", "v-own", login("One"));
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  await live.ensureLive();
}

const socket = () => {
  const open = FakeWebSocket.live();
  expect(open, "exactly one socket").toHaveLength(1);
  return open[0]!;
};
const paths = () => server.requests.map((r) => `${r.method} ${r.path}`);

beforeEach(async () => {
  vi.useRealTimers();
  await vault.lockAll();
  resetChrome(fake);
  FakeWebSocket.all = [];
  server = fakeServer();
  vi.stubGlobal("fetch", server.fetch);
  forgetServerFeatures();
});

test("unlocked on a server with delta sync: a revision check, then a socket with the access token, and the fallback alarm", async () => {
  await unlocked();
  const ws = socket();
  expect(ws.url).toBe("wss://vault.test/api/ws?access_token=access-1");
  // The check came first (it also refreshes an expired token).
  expect(paths().lastIndexOf("GET /sync/revision")).toBeGreaterThan(-1);
  expect(fake.alarms.has(live.LIVE_ALARM)).toBe(true);
  // A second call (the popup opening, the vault changing) keeps the same socket.
  await live.ensureLive();
  expect(FakeWebSocket.all).toHaveLength(1);
});

test("a small text frame every 20 seconds keeps the worker running; the hello origin is kept", async () => {
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
  await unlocked();
  const ws = socket();
  ws.open();
  vi.advanceTimersByTime(live.KEEPALIVE_MS * 3);
  expect(ws.sent).toStrictEqual(['{"type":"ping"}', '{"type":"ping"}', '{"type":"ping"}']);
  expect(ws.sent.every((f) => f.length < 4096)).toBe(true);
  ws.receive({ type: "hello", origin: "session-origin" });
  expect(live.liveOrigin()).toBe("session-origin");
});

test("sync messages: a number the copy has is skipped (even from another origin); a newer one syncs only what changed", async () => {
  await unlocked();
  const ws = socket();
  ws.open();
  ws.receive({ type: "hello", origin: "me" });
  const syncs = () => server.requests.filter((r) => r.path === "/sync").length;
  const before = syncs();
  ws.receive({ type: "sync", revision: server.revision, vaults: { "v-own": 1 }, origin: "other" });
  await new Promise((r) => setTimeout(r, 30));
  expect(syncs()).toBe(before);
  server.editElsewhere("i1", { notes: "from the phone" });
  // This session's own origin is no reason to skip: tabs and windows share it.
  ws.receive({ type: "sync", revision: server.revision, vaults: { "v-own": 2 }, origin: "me" });
  await vi.waitFor(() => expect(vault.getEntry("i1")?.item.notes).toBe("from the phone"));
  expect(server.requests.filter((r) => r.path === "/sync").at(-1)?.query.since).toBeTruthy();
});

test("a logout message checks the session: an ended one signs the account out here and the socket closes", async () => {
  await unlocked();
  const ws = socket();
  ws.open();
  server.handlers["GET /sync/revision"] = () => ({ status: 401, body: { error: "unauthorized", message: "authentication required" } });
  ws.receive({ type: "logout" });
  await vi.waitFor(() => expect(ws.closedWith).toBe(1000));
  const accounts = fake.local.data.get("accounts") as Record<string, { tokens: unknown }>;
  expect(accounts.a1?.tokens).toBe(null);
  expect(fake.session.data.has("unlocked:a1")).toBe(false);
});

test("a dropped socket reconnects after the backoff, with a revision check first", async () => {
  await unlocked();
  const first = socket();
  first.open();
  const checks = () => server.requests.filter((r) => r.path === "/sync/revision").length;
  const before = checks();
  first.drop();
  await vi.waitFor(() => expect(FakeWebSocket.all).toHaveLength(2), { timeout: 3000 });
  expect(checks()).toBe(before + 1);
  expect(socket()).toBe(FakeWebSocket.all[1]);
});

test("the server requires two-step login now (its message, then 1008 two_step_required): no reconnect loop, the popup's two-step notice", async () => {
  for (const how of ["message", "close"] as const) {
    await vault.lockAll();
    resetChrome(fake);
    FakeWebSocket.all = [];
    await unlocked();
    const ws = socket();
    ws.open();
    if (how === "message") ws.receive({ type: "two_step_required" });
    // The server closes with 1008 right after its message (or only closes).
    ws.drop(1008, "two_step_required");
    await new Promise((r) => setTimeout(r, 1500));
    expect(FakeWebSocket.all, `${how}: no new socket after the backoff`).toHaveLength(1);
    expect(fake.alarms.has(live.LIVE_ALARM), `${how}: no fallback alarm`).toBe(false);
    // As after a 403 two_step_required: the popup shows what to do.
    await vi.waitFor(() => expect(fake.session.data.get("twoStep:a1")).toBe(true));
    expect((await vault.state()).twoStepRequired).toBe(true);
  }
});

test("lock, account switch and sign-out close the socket and stop reconnecting; the alarm goes", async () => {
  await unlocked();
  let ws = socket();
  ws.open();
  await vault.lockAll();
  expect(ws.closedWith).toBe(1000);
  expect(FakeWebSocket.live()).toHaveLength(0);
  await vi.waitFor(() => expect(fake.alarms.has(live.LIVE_ALARM)).toBe(false));

  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  await live.ensureLive();
  ws = socket();
  await fake.local.set({ accounts: { a1: accountRecord(), a2: accountRecord("https://vault.test", "sam@example.com") }, active: "a1" });
  await vault.switchAccount("a2");
  expect(ws.closedWith).toBe(1000);

  await vault.switchAccount("a1");
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  await live.ensureLive();
  ws = socket();
  await vault.logout();
  expect(ws.closedWith).toBe(1000);
  await new Promise((r) => setTimeout(r, 1500));
  expect(FakeWebSocket.live(), "nothing reconnects").toHaveLength(0);
});

test("the fallback alarm: unlocked without a socket, it checks for changes and connects; locked, it stops", async () => {
  await unlocked();
  socket().drop();
  server.editElsewhere("i1", { notes: "missed" });
  await live.onLiveAlarm();
  expect(vault.getEntry("i1")?.item.notes, "what was missed came with the check").toBe("missed");
  expect(FakeWebSocket.live()).toHaveLength(1);

  await vault.lockAll();
  await fake.alarms.set(live.LIVE_ALARM, { name: live.LIVE_ALARM, scheduledTime: 0 });
  await live.onLiveAlarm();
  expect(FakeWebSocket.live()).toHaveLength(0);
  await vi.waitFor(() => expect(fake.alarms.has(live.LIVE_ALARM)).toBe(false));
});
