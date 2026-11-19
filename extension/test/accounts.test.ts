// C9 + S10: what the browser remembers per account (Secret Key, "remember this device" token) is keyed by
// server|email, migrated from the old email-only keys, and forgotten on sign-out, account removal and
// "Forget this browser"; two-step sign-in keeps a remember token only when asked to.

import { beforeEach, expect, test, vi } from "vitest";
import { codeOf, SECRET_KEY_REQUIRED } from "../src/shared/errors";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer, sessionKeys } from "./fake-server";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const vault = await import("../src/background/vault");
const { accountKey, local } = await import("../src/background/storage");
const { migrate, migrateSecretKeys } = await import("../src/background/migrations");

let fake: FakeChrome;
const A = "https://vault.test";
const B = "https://other.test";
const EMAIL = "alex@example.com";

/** Two servers on one fetch; each answers sign-in for EMAIL with a Secret Key. */
function servers(opts: { twoFactor?: boolean } = {}) {
  const make = (base: string, sk: string) => {
    const s = fakeServer(base);
    s.bundle = { account_id: "acc-1", password: "pw", secret_key_enabled: true, secret_key: sk };
    s.handlers["POST /auth/prelogin"] = () => ({ body: { account_id: "acc-1", kdf: {}, secret_key_required: true } });
    s.handlers["POST /auth/login/start"] = () => ({ body: { login_id: "l1", message: "m" } });
    s.handlers["POST /auth/login/finish"] = (req) =>
      opts.twoFactor && !req.body.remember_token
        ? { body: { two_factor_required: true, two_factor_token: "tf", providers: ["totp"] } }
        : { body: { access_token: "a", refresh_token: "r", email: EMAIL, bundle: s.bundle } };
    s.handlers["POST /auth/2fa/verify"] = (req) => ({
      body: { access_token: "a", refresh_token: "r", email: EMAIL, bundle: s.bundle, ...(req.body.remember ? { remember_token: `rt-${base}` } : {}) },
    });
    return s;
  };
  const a = make(A, "SK-A");
  const b = make(B, "SK-B");
  vi.stubGlobal("fetch", (input: string, init?: RequestInit) => (String(input).startsWith(B) ? b.fetch(input, init) : a.fetch(input, init)));
  return { a, b };
}

const stored = (field: "secretKeys" | "rememberTokens") => (fake.local.data.get(field) ?? {}) as Record<string, string>;

beforeEach(async () => {
  vi.unstubAllGlobals();
  fake = installChrome();
  await vault.lockAll().catch(() => {});
});

test("accountKey: server address as stored, email trimmed and lower-cased", () => {
  expect(accountKey("https://vault.test", " Alex@Example.COM ")).toBe("https://vault.test|alex@example.com");
  expect(accountKey("https://host/passauth", "a@b.c")).toBe("https://host/passauth|a@b.c");
});

test("migrateSecretKeys: email-only entries move to server|email when exactly one account has that email", () => {
  const accounts = {
    a1: { server: A, email: "Alex@Example.com" },
    a2: { server: B, email: "sam@example.com" },
    a3: { server: B, email: "kim@example.com" },
    a4: { server: A, email: "kim@example.com" },
    a5: { server: "", email: "pat@example.com" },
  };
  const out = migrateSecretKeys(
    { "alex@example.com": "SK-ALEX", "sam@example.com": "SK-SAM", "kim@example.com": "SK-KIM", "pat@example.com": "SK-PAT", "nobody@example.com": "SK-X", [`${B}|sam@example.com`]: "SK-SAM-NEW" },
    accounts,
  );
  expect(out).toStrictEqual({
    [`${A}|alex@example.com`]: "SK-ALEX",
    // An entry already in the new form wins over the old one.
    [`${B}|sam@example.com`]: "SK-SAM-NEW",
    // kim is on two servers: whose key it was can't be known, so it's dropped (asked for again); pat has no server; nobody has no account.
  });
});

test("the migration moves old entries once, behind schemaVersion", async () => {
  await fake.local.set({ accounts: { a1: accountRecord(A, EMAIL) }, active: "a1", secretKeys: { [EMAIL]: "SK-OLD" } });
  await migrate();
  expect((await local.get()).secretKeys).toStrictEqual({ [`${A}|${EMAIL}`]: "SK-OLD" });
  expect(stored("secretKeys")).toStrictEqual({ [`${A}|${EMAIL}`]: "SK-OLD" });
  expect(fake.local.data.get("schemaVersion")).toBe(4);
});

test("the same email on two servers keeps two Secret Keys", async () => {
  servers();
  await fake.local.set({ accounts: { a1: { ...accountRecord(A, EMAIL), tokens: null }, a2: { ...accountRecord(B, EMAIL), tokens: null } }, active: "a1" });
  await vault.login(EMAIL, "pw", "SK-A");
  await local.setActive("a2");
  await vault.login(EMAIL, "pw", "SK-B");
  expect(stored("secretKeys")).toStrictEqual({ [`${A}|${EMAIL}`]: "SK-A", [`${B}|${EMAIL}`]: "SK-B" });
  // Each account finds its own: signing in again needs no Secret Key typed.
  await vault.login(EMAIL, "pw");
  await local.setActive("a1");
  await vault.login(EMAIL, "pw");
  expect((await vault.state()).secretKeyStored).toBe(true);
});

test("without a stored Secret Key, sign-in says so with a code (not a message text)", async () => {
  servers();
  await fake.local.set({ accounts: { a1: { ...accountRecord(A, EMAIL), tokens: null } }, active: "a1" });
  const e = await vault.login(EMAIL, "pw").catch((err) => err);
  expect(codeOf(e)).toBe(SECRET_KEY_REQUIRED);
  expect(stored("secretKeys")).toStrictEqual({});
});

test("two-step sign-in: a remember token is kept only when asked; the Secret Key once the sign-in worked", async () => {
  servers({ twoFactor: true });
  await fake.local.set({ accounts: { a1: { ...accountRecord(A, EMAIL), tokens: null } }, active: "a1" });
  const r = await vault.login(EMAIL, "pw", "SK-A");
  expect("twoFactor" in r).toBe(true);
  // Not remembered before the second step is done.
  expect(stored("secretKeys")).toStrictEqual({});
  await vault.verifyTwoFactor("tf", "totp", "123456", false);
  expect(stored("rememberTokens")).toStrictEqual({});
  expect(stored("secretKeys")).toStrictEqual({ [`${A}|${EMAIL}`]: "SK-A" });

  await vault.login(EMAIL, "pw");
  await vault.verifyTwoFactor("tf", "totp", "123456", true);
  expect(stored("rememberTokens")).toStrictEqual({ [`${A}|${EMAIL}`]: `rt-${A}` });
  expect((await vault.state()).rememberedDevice).toBe(true);
});

test("S10: signing out forgets this account's Secret Key and remember token, and only this account's", async () => {
  servers();
  await fake.local.set({
    accounts: { a1: accountRecord(A, EMAIL), a2: accountRecord(B, EMAIL) },
    active: "a1",
    secretKeys: { [`${A}|${EMAIL}`]: "SK-A", [`${B}|${EMAIL}`]: "SK-B" },
    rememberTokens: { [`${A}|${EMAIL}`]: "rt-A", [`${B}|${EMAIL}`]: "rt-B" },
  });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  await vault.logout();
  expect(stored("secretKeys")).toStrictEqual({ [`${B}|${EMAIL}`]: "SK-B" });
  expect(stored("rememberTokens")).toStrictEqual({ [`${B}|${EMAIL}`]: "rt-B" });
  // With another account present, the signed-out one is removed from the list.
  expect(Object.keys(fake.local.data.get("accounts") as object)).toStrictEqual(["a2"]);
});

test("S10: removing an account forgets what the browser kept for it", async () => {
  await fake.local.set({
    accounts: { a1: accountRecord(A, EMAIL), a2: accountRecord(B, "sam@example.com") },
    active: "a1",
    secretKeys: { [`${A}|${EMAIL}`]: "SK-A", [`${B}|sam@example.com`]: "SK-SAM" },
    rememberTokens: { [`${A}|${EMAIL}`]: "rt-A" },
  });
  await local.removeAccount("a1");
  expect(stored("secretKeys")).toStrictEqual({ [`${B}|sam@example.com`]: "SK-SAM" });
  expect(stored("rememberTokens")).toStrictEqual({});
});

test("Forget this browser: the active account's Secret Key and remember token go; the sign-in stays", async () => {
  await fake.local.set({
    accounts: { a1: accountRecord(A, EMAIL) },
    active: "a1",
    secretKeys: { [`${A}|${EMAIL}`]: "SK-A", [`${B}|${EMAIL}`]: "SK-B" },
    rememberTokens: { [`${A}|${EMAIL}`]: "rt-A" },
  });
  expect((await vault.state()).secretKeyStored).toBe(true);
  await vault.forgetBrowser();
  expect(stored("secretKeys")).toStrictEqual({ [`${B}|${EMAIL}`]: "SK-B" });
  expect(stored("rememberTokens")).toStrictEqual({});
  const state = await vault.state();
  expect([state.secretKeyStored, state.rememberedDevice, state.status]).toStrictEqual([false, false, "locked"]);
});

test("unlocking with a typed Secret Key stores it under server|email", async () => {
  const s: FakeServer = servers().a;
  s.bundle = { account_id: "acc-1", password: "pw", secret_key_enabled: true, secret_key: "SK-A" };
  await fake.local.set({ accounts: { a1: accountRecord(A, "Alex@Example.com") }, active: "a1" });
  await vault.unlock("pw", " SK-A ");
  expect(stored("secretKeys")).toStrictEqual({ [`${A}|alex@example.com`]: "SK-A" });
});

test("unlocking asks the server for its features and policies again (a lowered vault timeout applies from this unlock)", async () => {
  const s: FakeServer = servers().a;
  s.bundle = { account_id: "acc-1", password: "pw", secret_key_enabled: false };
  await fake.local.set({ accounts: { a1: accountRecord(A, EMAIL) }, active: "a1" });
  const configs = () => s.requests.filter((r) => r.path === "/config").length;
  await vault.state();
  const before = configs();
  await vault.unlock("pw");
  await vault.state();
  expect(configs()).toBe(before + 1);
});
