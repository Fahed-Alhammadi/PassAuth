// The server admin's account policies in the extension (background/policies.ts, api.ts): the longest vault timeout
// (choices clamped, a saved one above it lowered and said so), `policy_violations` as popup notices linking to the
// web vault, 403 two_step_required remembered for the popup, and quota_exceeded in plain words.

import { beforeEach, expect, test, vi } from "vitest";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer } from "./fake-server";

const { allowedTimeout, enforceTimeoutPolicy, policyState, timeoutLimit, accountNotices, noteTwoStepRequired, noteTwoStepDone, forgetPolicyState } = await import("../src/background/policies");
const { apiError, forgetServerFeatures, iconsShown, QUOTA_TEXT, refreshServerInfo, serverInfo, siteIconsShown } = await import("../src/background/api");
const { getSettings } = await import("../src/background/storage");

let fake: FakeChrome;
let server: FakeServer;

/** A server with the `policies` feature and these policies. */
function withPolicies(s: FakeServer, policies: Record<string, unknown>) {
  s.features = [...s.features, "policies"];
  s.handlers["GET /config"] = () => ({ body: { name: "PassAuth", api: 2, features: s.features, policies } });
}

beforeEach(async () => {
  vi.unstubAllGlobals();
  fake = installChrome();
  server = fakeServer();
  vi.stubGlobal("fetch", server.fetch);
  forgetServerFeatures();
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
});

test("a saved vault timeout above the server's limit is lowered to it, and remembered for Settings", async () => {
  withPolicies(server, { max_vault_timeout_minutes: 60 });
  await fake.local.set({ settings: { vaultTimeout: "never" } });
  expect(await timeoutLimit()).toBe(60);
  expect(await enforceTimeoutPolicy()).toBe(true);
  expect((await getSettings()).vaultTimeout).toBe(60);
  expect(await policyState("a1")).toStrictEqual({ timeoutLimit: 60, timeoutLowered: "never" });
  // Within the limit now: nothing more to do.
  expect(await enforceTimeoutPolicy()).toBe(false);
});

test("timeout choices: within the limit they stand; above it (and moments without a time limit) they become the limit", async () => {
  withPolicies(server, { max_vault_timeout_minutes: 30 });
  expect(await allowedTimeout(15)).toBe(15);
  expect(await allowedTimeout("immediately")).toBe("immediately");
  for (const v of [240, "never", "restart", "system-lock"] as const) expect(await allowedTimeout(v), String(v)).toBe(30);
  await fake.local.set({ settings: { vaultTimeout: 5 } });
  expect(await enforceTimeoutPolicy()).toBe(false);
});

test("no policy (or an older server): no limit, nothing changes", async () => {
  await fake.local.set({ settings: { vaultTimeout: "never" } });
  expect(await timeoutLimit()).toBe(0);
  expect(await enforceTimeoutPolicy()).toBe(false);
  expect((await getSettings()).vaultTimeout).toBe("never");
  expect(await policyState("a1")).toStrictEqual({});
});

test("several accounts: the setting is shared, so the shortest limit of their servers applies", async () => {
  const other = fakeServer("https://other.test");
  withPolicies(server, { max_vault_timeout_minutes: 240 });
  withPolicies(other, { max_vault_timeout_minutes: 45 });
  vi.stubGlobal("fetch", (input: string, init?: RequestInit) => (String(input).startsWith("https://other.test") ? other.fetch(input, init) : server.fetch(input, init)));
  await fake.local.set({ accounts: { a1: accountRecord(), a2: accountRecord("https://other.test") }, active: "a1" });
  expect(await timeoutLimit()).toBe(45);
  expect(await allowedTimeout(60)).toBe(45);
});

test("policy violations become popup notices linking to the web vault, asked again only after a while", async () => {
  withPolicies(server, { require_two_step: true });
  server.handlers["GET /account"] = () => ({ body: { policy_violations: ["kdf", "two_step", "unknown"] } });
  const n = await accountNotices();
  expect(n.key).toBe("a1|two_step,kdf");
  expect(n.notices.map((x) => [x.text, x.url])).toStrictEqual([
    ["Your server requires two-step login.", "https://vault.test/settings/two-step"],
    ["Your server asks you to update your account's encryption settings. Change your master password to do it; you can keep the same one.", "https://vault.test/settings/security"],
  ]);
  const asked = server.requests.filter((r) => r.path === "/account").length;
  await accountNotices();
  expect(server.requests.filter((r) => r.path === "/account").length, "kept for a few minutes").toBe(asked);
  // Gone with the account's policy state (sign-out).
  await forgetPolicyState(["a1"]);
  await accountNotices();
  expect(server.requests.filter((r) => r.path === "/account").length).toBe(asked + 1);
});

test("a server without the policies feature: no notices and no /account request", async () => {
  expect(await accountNotices()).toStrictEqual({ key: "", notices: [] });
  expect(server.requests.some((r) => r.path === "/account")).toBe(false);
});

test("two_step_required is remembered for the popup until a sync gets through", async () => {
  await noteTwoStepRequired("a1");
  expect((await policyState("a1")).twoStepRequired).toBe(true);
  await noteTwoStepDone("a1");
  expect((await policyState("a1")).twoStepRequired).toBeUndefined();
});

test("quota_exceeded and two_step_required in plain words", () => {
  const quota = apiError(403, { error: "quota_exceeded", message: "storage limit reached" });
  expect([quota.code, quota.message]).toStrictEqual(["quota_exceeded", QUOTA_TEXT]);
  expect(QUOTA_TEXT).toBe("You've reached this server's storage limit. Delete items or ask the server's admin.");
  expect(apiError(403, { error: "two_step_required", message: "this server requires two-step login" }).message).toBe(
    "Your server requires two-step login. Set it up in the web vault, then try again.",
  );
});

test("a policy the admin changed applies at the next unlock: refreshServerInfo asks again; unreachable keeps what was known", async () => {
  let max = 240;
  withPolicies(server, {});
  server.handlers["GET /config"] = () => ({ body: { name: "PassAuth", api: 2, features: server.features, policies: { max_vault_timeout_minutes: max } } });
  expect(await timeoutLimit()).toBe(240);
  max = 30;
  // Cached for an hour otherwise …
  expect(await timeoutLimit()).toBe(240);
  // … asked again at an unlock (vault.ts calls this), and what is asked meanwhile waits for that answer.
  const refreshing = refreshServerInfo("https://vault.test");
  expect(await timeoutLimit()).toBe(30);
  await refreshing;
  // The server can't be reached at the next unlock: the last answer stays.
  vi.stubGlobal("fetch", async () => {
    throw new TypeError("Failed to fetch");
  });
  expect((await refreshServerInfo("https://vault.test"))?.policies).toStrictEqual({ max_vault_timeout_minutes: 30 });
  expect(await timeoutLimit()).toBe(30);
});

test("website icons: the setting and the server together (API 2 servers list `icons` while the service is on; older ones always had it)", async () => {
  // The rule, as the web vault's siteIconsShown.
  expect(siteIconsShown(false, null)).toBe(false);
  expect(siteIconsShown(true, null), "the server's answer unknown: the setting decides").toBe(true);
  expect(siteIconsShown(true, { api: null, features: new Set() }), "a server from before API 2").toBe(true);
  expect(siteIconsShown(true, { api: 2, features: new Set(["icons"]) })).toBe(true);
  expect(siteIconsShown(true, { api: 2, features: new Set() }), "the admin turned the icon service off").toBe(false);
  expect(siteIconsShown(false, { api: 2, features: new Set(["icons"]) })).toBe(false);
  // From the server's cached features.
  server.features = [...server.features, "icons"];
  expect(await iconsShown("https://vault.test", true)).toBe(true);
  expect(await iconsShown("https://vault.test", false)).toBe(false);
  server.features = server.features.filter((f) => f !== "icons");
  forgetServerFeatures();
  expect((await serverInfo("https://vault.test"))?.api).toBe(2);
  expect(await iconsShown("https://vault.test", true)).toBe(false);
  // An older server (no `api`): icons as before.
  server.features = [];
  forgetServerFeatures();
  expect(await iconsShown("https://vault.test", true)).toBe(true);
});
