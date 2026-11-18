// API client (background/api.ts): X-PassAuth-Client everywhere, error codes before message text, Retry-After,
// a lost session reported with a code, and feature detection from /api/config.

import { beforeEach, expect, test, vi } from "vitest";
import {
  ApiError,
  api,
  apiError,
  errorCode,
  forgetServerFeatures,
  logoutRemote,
  refuseOutdated,
  retryAfterSeconds,
  SERVER_OUTDATED,
  SERVER_UPDATE_TEXT,
  serverConfig,
  serverFeatures,
  serverOutdated,
  UNREACHABLE_TEXT,
} from "../src/background/api";
import { knownFeatures } from "../src/background/storage";
import { codeOf, SIGNED_OUT } from "../src/shared/errors";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer } from "./fake-server";
import { expectReject } from "./helpers";

let fake: FakeChrome;
let server: FakeServer;

beforeEach(async () => {
  vi.unstubAllGlobals();
  fake = installChrome();
  server = fakeServer();
  vi.stubGlobal("fetch", server.fetch);
  forgetServerFeatures();
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
});

test("errorCode: the v2 code first; for older servers the known reasons in the message text", () => {
  expect(errorCode({ error: "vault_key_changed", message: "whatever" })).toBe("vault_key_changed");
  expect(errorCode({ error: "email_not_verified", message: "email_not_verified" })).toBe("email_not_verified");
  // Older servers: a generic code, the reason in the message.
  expect(errorCode({ error: "forbidden", message: "email_not_verified" })).toBe("email_not_verified");
  expect(errorCode({ error: "forbidden", message: "reauth_required" })).toBe("reauth_required");
  expect(errorCode({ error: "conflict", message: "item id already exists" })).toBe("item_exists");
  expect(errorCode({ error: "conflict", message: "item changed on another device; sync and retry" })).toBe("revision_conflict");
  // Anything else keeps the server's code.
  expect(errorCode({ error: "conflict", message: "something else" })).toBe("conflict");
  expect(errorCode({ error: "unauthorized", message: "authentication required" })).toBe("unauthorized");
  expect(errorCode(null)).toBe("error");
  expect(errorCode({ message: 7 })).toBe("error");
});

test("apiError: known codes in PassAuth's own words; any other code gets the generic sentence, the request id and the server's message only as a detail", () => {
  const e = apiError(403, { error: "forbidden", message: "email_not_verified" });
  expect([e.status, e.code, e.message]).toStrictEqual([403, "email_not_verified", "Confirm your email address first, then sign in."]);
  expect(apiError(400, { error: "bad_request", message: "ids must be UUIDs", request_id: "req-81f2" }).message).toBe(
    "Your PassAuth server couldn't do this. Request ID: req-81f2. Server message: ids must be UUIDs",
  );
  expect(apiError(500, null).message).toBe("Your PassAuth server couldn't do this.");
  // A code PassAuth doesn't know keeps its code (callers check codes), but not its sentence.
  const odd = apiError(403, { error: "brand_new_reason", message: "Call +1 555 0100 to unlock your vault" });
  expect([odd.code, odd.message]).toStrictEqual(["brand_new_reason", "Your PassAuth server couldn't do this. Server message: Call +1 555 0100 to unlock your vault"]);
});

test("§5: 507 insufficient_storage in PassAuth's words (also from a server that sends no code)", () => {
  const words = "Your server is running out of storage space, so this wasn't saved. Ask the server's admin.";
  const e = apiError(507, { error: "insufficient_storage", message: "the server is almost out of disk space" });
  expect([e.code, e.message]).toStrictEqual(["insufficient_storage", words]);
  expect(apiError(507, null).message).toBe(words);
});

test("§6: the server's message as a detail: control and format characters gone (bidi overrides too), at most 200 characters", () => {
  const msg = apiError(400, { error: "bad_request", message: `line one\nline two \u202Egnp.exe\u202C \u200Bzero-width\u0007 ${"x".repeat(400)}`, request_id: "abc<script>" }).message;
  expect(msg.startsWith("Your PassAuth server couldn't do this. Server message: line one line two gnp.exe zero-width x")).toBe(true);
  expect([...msg].filter((c) => /[\p{Cc}\p{Cf}]/u.test(c))).toStrictEqual([]);
  // A request id that isn't one is left out.
  expect(msg).not.toContain("abc<script>");
  const detail = msg.slice(msg.indexOf("Server message: ") + "Server message: ".length);
  expect([...detail]).toHaveLength(200);
  expect(detail.endsWith("…")).toBe(true);
});

test("429: the wait comes from Retry-After (seconds or a date)", () => {
  expect(retryAfterSeconds("120")).toBe(120);
  expect(retryAfterSeconds(null)).toBe(undefined);
  expect(retryAfterSeconds("soon")).toBe(undefined);
  const now = Date.parse("2026-11-15T10:00:00Z");
  expect(retryAfterSeconds("Sun, 15 Nov 2026 10:01:30 GMT", now)).toBe(90);
  expect(apiError(429, { error: "rate_limited", message: "too many requests, try again later" }, 30).message).toBe("Too many attempts. Try again in 30 seconds.");
  expect(apiError(429, { error: "rate_limited", message: "x" }, 600).message).toBe("Too many attempts. Try again in 10 minutes.");
  expect(apiError(429, { error: "rate_limited", message: "x" }, 1).message).toBe("Too many attempts. Try again in a moment.");
  expect(apiError(429, {}, 30).retryAfter).toBe(30);
});

test("api(): Retry-After of a real response reaches the error", async () => {
  server.handlers["GET /account"] = () => ({ status: 429, body: { error: "rate_limited", message: "too many requests, try again later" }, headers: { "retry-after": "45" } });
  await expectReject(api("/account"), (e) => e instanceof ApiError && e.status === 429 && e.retryAfter === 45 && e.message === "Too many attempts. Try again in 45 seconds.");
});

test("X-PassAuth-Client on API calls, the refresh, a remote sign-out and the config check", async () => {
  server.handlers["GET /account"] = (req) =>
    req.headers.authorization === "Bearer access-2" ? { body: { ok: true } } : { status: 401, body: { error: "unauthorized", message: "authentication required" } };
  server.handlers["POST /auth/refresh"] = () => ({ body: { access_token: "access-2", refresh_token: "refresh-2" } });
  expect(await api("/account")).toStrictEqual({ ok: true });
  await logoutRemote(server.base, { access: "access-2" });
  await serverConfig(server.base);
  expect(server.requests.map((r) => r.path)).toStrictEqual(["/config", "/account", "/auth/refresh", "/account", "/auth/logout", "/config"]);
  for (const r of server.requests) expect(r.headers["x-passauth-client"], r.path).toBe("extension/9.8.7");
});

test("a refused refresh token: tokens dropped, the error says signed_out", async () => {
  const lost = vi.fn();
  const { setSessionLostHandler } = await import("../src/background/api");
  setSessionLostHandler(lost);
  server.handlers["GET /account"] = () => ({ status: 401, body: { error: "unauthorized", message: "authentication required" } });
  const e = await api("/account").catch((err) => err);
  expect(codeOf(e)).toBe(SIGNED_OUT);
  expect(lost).toHaveBeenCalledWith("a1");
  expect((fake.local.data.get("accounts") as Record<string, { tokens: unknown }>).a1?.tokens).toBe(null);
});

test("serverFeatures: from /api/config, cached per server; an older server has none; unreachable isn't remembered", async () => {
  expect([...(await serverFeatures(server.base))]).toContain("key_epoch");
  await serverFeatures(server.base);
  expect(server.requests.filter((r) => r.path === "/config")).toHaveLength(1);

  const old = fakeServer("https://old.test");
  old.outdated = "old";
  vi.stubGlobal("fetch", old.fetch);
  expect([...(await serverFeatures(old.base))]).toStrictEqual([]);

  vi.stubGlobal("fetch", () => Promise.reject(new TypeError("Failed to fetch")));
  expect([...(await serverFeatures("https://down.test"))]).toStrictEqual([]);
  const later = fakeServer("https://down.test");
  vi.stubGlobal("fetch", later.fetch);
  expect([...(await serverFeatures("https://down.test"))]).toContain("key_epoch");
});

test("servers this app refuses: a config that doesn't list signed_sharing (API 2 without it, or from before API 2); a config that can't be read is no way around it", async () => {
  expect(SERVER_UPDATE_TEXT).toBe("Update your PassAuth server to keep using this app.");
  expect(serverOutdated(null), "the server can't be reached: decided at the next answer").toBe(false);
  expect(serverOutdated({ features: new Set(["signed_sharing", "delta_sync"]) })).toBe(false);
  expect(serverOutdated({ features: new Set(["delta_sync", "key_epoch"]) })).toBe(true);
  expect(serverOutdated({ features: new Set() })).toBe(true);

  // Every request is refused before it is sent, except the sign-out (the session there still ends).
  for (const kind of ["unsigned", "old"] as const) {
    server = fakeServer();
    server.outdated = kind;
    vi.stubGlobal("fetch", server.fetch);
    forgetServerFeatures();
    await expectReject(api("/sync"), (e) => codeOf(e) === SERVER_OUTDATED && e.message === SERVER_UPDATE_TEXT && e.pageSafe === true);
    await expectReject(api("/auth/prelogin", { body: { email: "alex@example.com" }, auth: false }), (e) => codeOf(e) === SERVER_OUTDATED);
    await expectReject(api("/items", { body: {} }), (e) => codeOf(e) === SERVER_OUTDATED);
    await expectReject(refuseOutdated(server.base), (e) => codeOf(e) === SERVER_OUTDATED);
    await api("/auth/logout", { method: "POST" });
    expect(
      server.requests.map((r) => r.path),
      kind,
    ).toStrictEqual(["/config", "/auth/logout"]);
  }
  // Unreachable, and this browser never read a feature list from that server: "can't reach", nothing is asked.
  vi.stubGlobal("fetch", () => Promise.reject(new TypeError("Failed to fetch")));
  forgetServerFeatures();
  await expectReject(api("/sync"), (e) => codeOf(e) === "unreachable");
  await expectReject(refuseOutdated("https://vault.test"), (e) => codeOf(e) === "unreachable");
  // Review (Part S): a server that fails `/api/config` (an error, or something that isn't a config) but would answer
  // everything else is not used either: no sign-in is started, no `/sync` is asked.
  for (const broken of [() => ({ status: 500, body: {} }), () => ({ status: 200, body: null }), () => ({ status: 404, body: { error: "not_found" } })]) {
    fake = installChrome();
    await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
    expect(await knownFeatures.get("https://vault.test")).toBe(null);
    server = fakeServer();
    server.handlers["GET /config"] = broken;
    vi.stubGlobal("fetch", server.fetch);
    forgetServerFeatures();
    await expectReject(api("/sync"), (e) => codeOf(e) === "unreachable" && e.message === UNREACHABLE_TEXT);
    await expectReject(api("/auth/prelogin", { body: { email: "alex@example.com" }, auth: false }), (e) => codeOf(e) === "unreachable");
    await expectReject(refuseOutdated(server.base), (e) => codeOf(e) === "unreachable");
    expect(server.requests.map((r) => r.path)).toStrictEqual(["/config", "/config", "/config"]);
  }
  // An up-to-date server is used as before, and its feature list is kept…
  server = fakeServer();
  vi.stubGlobal("fetch", server.fetch);
  forgetServerFeatures();
  await refuseOutdated(server.base);
  expect(await api("/sync/revision")).toMatchObject({ revision: 1 });
  expect(await knownFeatures.get(server.base)).toContain("signed_sharing");
  // …so the same server with its config unreachable later keeps working (offline use: the next answer decides).
  server.handlers["GET /config"] = () => ({ status: 500, body: {} });
  forgetServerFeatures();
  await refuseOutdated(server.base);
  expect(await api("/sync/revision")).toMatchObject({ revision: 1 });
  // A list kept from when the server didn't sign is no pass.
  await knownFeatures.set(server.base, ["delta_sync"]);
  forgetServerFeatures();
  await expectReject(api("/sync/revision"), (e) => codeOf(e) === "unreachable");
  expect(await knownFeatures.get("https://other.test")).toBe(null);
});
