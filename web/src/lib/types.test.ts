import { describe, expect, it } from "vitest";
import {
  UNEXPECTED_RESPONSE,
  expectStrings,
  isSyncResponse,
  readFoundUser,
  readLoginFinish,
  readMembers,
  readPrelogin,
  readRecoveryCodes,
  readStrings,
} from "./types";

/** A value the WASM glue would size by its `length`: it must never reach a string parameter of the core. */
const HUGE = { length: 900000000 };
const BUNDLE = { account_id: "acct-1", kdf: { m: 1 }, secret_key_enabled: false };
const SYNC = {
  revision: 3,
  user: { id: "u1", email: "alex@example.com", name: "Alex", email_verified: true },
  bundle: BUNDLE,
  vaults: [],
  items: [],
};

describe("checking the server's answers", () => {
  it("accepts a /sync answer only with a usable user and bundle", () => {
    expect(isSyncResponse(SYNC)).toBe(true);
    for (const user of [{ ...SYNC.user, email: HUGE }, { ...SYNC.user, email: null }, { ...SYNC.user, name: 1 }, { ...SYNC.user, email_verified: 1 }, { ...SYNC.user, id: "" }])
      expect(isSyncResponse({ ...SYNC, user })).toBe(false);
    expect(isSyncResponse({ ...SYNC, bundle: { ...BUNDLE, account_id: HUGE } })).toBe(false);
    expect(isSyncResponse({ ...SYNC, bundle: [BUNDLE] })).toBe(false);
    expect(isSyncResponse({ ...SYNC, vaults: {} })).toBe(false);
    expect(isSyncResponse({ ...SYNC, revision: "3" })).toBe(false);
    expect(isSyncResponse(null)).toBe(false);
  });

  it("reads string fields, or says the answer is unexpected", () => {
    expect(readStrings({ login_id: "l1", message: "m", extra: 1 }, "login_id", "message")).toEqual({ login_id: "l1", message: "m" });
    expect(readStrings({ login_id: "l1", message: HUGE }, "login_id", "message")).toBeNull();
    expect(readStrings({ message: "" }, "message")).toBeNull();
    expect(readStrings("message", "message")).toBeNull();
    expect(() => expectStrings({ message: 42 }, "message")).toThrow(UNEXPECTED_RESPONSE);
    expect(expectStrings({ message: "ok" }, "message")).toEqual({ message: "ok" });
  });

  it("reads prelogin answers", () => {
    expect(readPrelogin({ account_id: "a", kdf: { m: 1 }, secret_key_required: true })).toEqual({ account_id: "a", kdf: { m: 1 }, secret_key_required: true });
    expect(readPrelogin({ account_id: HUGE, kdf: {}, secret_key_required: false })).toBeNull();
    expect(readPrelogin({ account_id: "a", kdf: "argon2", secret_key_required: false })).toBeNull();
    expect(readPrelogin({ account_id: "a", kdf: {}, secret_key_required: "no" })).toBeNull();
  });

  it("reads the three kinds of sign-in answers and refuses anything else", () => {
    const session = { access_token: "a", refresh_token: "r", remember_token: null, user_id: "u1", email: "alex@example.com", bundle: BUNDLE, expires_in: 900 };
    expect(readLoginFinish(session)).toEqual(session);
    expect(readLoginFinish({ ...session, sealed_key: "s" })).toMatchObject({ sealed_key: "s" });
    expect(readLoginFinish({ two_factor_required: true, two_factor_token: "t", providers: ["totp", 5, "email"] })).toMatchObject({
      two_factor_token: "t",
      providers: ["totp", "email"],
    });
    expect(readLoginFinish({ two_factor_required: true, providers: [] })).toBeNull();
    expect(readLoginFinish({ reauth_token: "rt" })).toEqual({ reauth_token: "rt" });
    for (const broken of [
      { ...session, user_id: HUGE },
      { ...session, email: 1 },
      { ...session, access_token: "" },
      { ...session, bundle: "b" },
      { ...session, bundle: { kdf: {} } },
      { ...session, remember_token: 7 },
      { reauth_token: HUGE },
      null,
      "ok",
    ])
      expect(readLoginFinish(broken)).toBeNull();
  });

  it("reads a vault's members only when every row is whole", () => {
    const m = { user_id: "u2", email: "sam@example.com", name: "Sam", role: "write", public_key: "pk", status: "invited", invited_by: "u1", invited_at: 5 };
    expect(readMembers({ members: [m] })).toEqual([m]);
    expect(readMembers({ members: [{ ...m, status: "odd", invited_at: null }] })).toEqual([{ user_id: "u2", email: "sam@example.com", name: "Sam", role: "write", public_key: "pk", invited_by: "u1" }]);
    expect(readMembers({ members: [m, { ...m, public_key: HUGE }] })).toBeNull();
    expect(readMembers({ members: [{ ...m, email: null }] })).toBeNull();
    expect(readMembers({ members: "none" })).toBeNull();
    expect(readMembers({ members: [] })).toEqual([]);
  });

  it("reads recovery codes only as text", () => {
    expect(readRecoveryCodes({ recovery_codes: ["a1", "b2"] })).toEqual(["a1", "b2"]);
    expect(readRecoveryCodes({ recovery_codes: ["a1", { b: 2 }, 3] })).toEqual(["a1"]);
    expect(readRecoveryCodes({ recovery_codes: null })).toBeNull();
    expect(readRecoveryCodes({ recovery_codes: [] })).toBeNull();
    expect(readRecoveryCodes(null)).toBeNull();
  });

  it("reads the person found to share with", () => {
    expect(readFoundUser({ user_id: "u2", name: "Sam", public_key: "pk" })).toEqual({ user_id: "u2", name: "Sam", public_key: "pk" });
    expect(readFoundUser({ user_id: "u2", public_key: "pk" })).toEqual({ user_id: "u2", name: "", public_key: "pk" });
    expect(readFoundUser({ user_id: "u2", name: "Sam", public_key: HUGE })).toBeNull();
  });
});
