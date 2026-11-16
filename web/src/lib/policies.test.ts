import { afterEach, describe, expect, it } from "vitest";
import { ApiError, api, onTwoStepRequired, type PublicConfig } from "./api";
import type { VaultTimeout } from "./platform";
import {
  DEFAULT_POLICIES,
  afterTwoStepSetup,
  clampTimeout,
  exportAllowed,
  isTwoStepClose,
  isTwoStepNotice,
  isTwoStepRequired,
  minPasswordLength,
  minutesLabel,
  newKeyKdf,
  newKeysMeetKdf,
  policyNotices,
  readPolicies,
  readViolations,
  timeoutOptions,
  timeoutWithin,
  violationsKey,
  webLockMinutes,
  type Policies,
} from "./policies";
import { configureServer } from "./server";

const config = (policies?: Record<string, unknown>): PublicConfig => ({
  name: "PassAuth",
  version: "0.10.0",
  signups_allowed: true,
  email_enabled: false,
  api: 2,
  features: policies ? ["policies"] : [],
  ...(policies ? { policies } : {}),
});

const SERVER_POLICIES = {
  require_two_step: true,
  require_secret_key: true,
  min_kdf_memory_mib: 256,
  min_kdf_iterations: 4,
  master_password_min_length: 14,
  max_vault_timeout_minutes: 60,
  disable_export: true,
};

const with_ = (patch: Partial<Policies>): Policies => ({ ...DEFAULT_POLICIES, ...patch });

describe("readPolicies", () => {
  it("has defaults that change nothing for servers without policies", () => {
    expect(readPolicies(null)).toEqual(DEFAULT_POLICIES);
    expect(readPolicies(undefined)).toEqual(DEFAULT_POLICIES);
    expect(readPolicies(config())).toEqual(DEFAULT_POLICIES);
    expect(DEFAULT_POLICIES).toEqual({
      requireTwoStep: false,
      requireSecretKey: false,
      minKdfMemoryMib: 64,
      minKdfIterations: 3,
      masterPasswordMinLength: 10,
      maxVaultTimeoutMinutes: 0,
      disableExport: false,
    });
  });

  it("reads the server's policies", () => {
    expect(readPolicies(config(SERVER_POLICIES))).toEqual({
      requireTwoStep: true,
      requireSecretKey: true,
      minKdfMemoryMib: 256,
      minKdfIterations: 4,
      masterPasswordMinLength: 14,
      maxVaultTimeoutMinutes: 60,
      disableExport: true,
    });
  });

  it("uses the default for a value that's missing or malformed", () => {
    const p = readPolicies(
      config({
        require_two_step: "yes",
        require_secret_key: 1,
        min_kdf_memory_mib: "512",
        min_kdf_iterations: 3.5,
        master_password_min_length: null,
        disable_export: "true",
      }),
    );
    expect(p).toEqual(DEFAULT_POLICIES);
    expect(readPolicies({ ...config(), policies: "on" as unknown as Record<string, unknown> })).toEqual(DEFAULT_POLICIES);
  });

  it("keeps numbers within what the server can set", () => {
    const p = readPolicies(config({ min_kdf_memory_mib: 4096, min_kdf_iterations: 1, master_password_min_length: 4, max_vault_timeout_minutes: -5 }));
    expect(p.minKdfMemoryMib).toBe(1024);
    expect(p.minKdfIterations).toBe(3);
    expect(p.masterPasswordMinLength).toBe(10);
    expect(p.maxVaultTimeoutMinutes).toBe(0);
    expect(readPolicies(config({ max_vault_timeout_minutes: 100_000 })).maxVaultTimeoutMinutes).toBe(43_200);
  });
});

describe("master password length", () => {
  it("is the server's minimum, never below the apps' own", () => {
    expect(minPasswordLength(DEFAULT_POLICIES)).toBe(10);
    expect(minPasswordLength(with_({ masterPasswordMinLength: 16 }))).toBe(16);
    expect(minPasswordLength(with_({ masterPasswordMinLength: 6 }))).toBe(10);
  });
});

describe("export", () => {
  it("is offered unless the admin turned it off", () => {
    expect(exportAllowed(DEFAULT_POLICIES)).toBe(true);
    expect(exportAllowed(readPolicies(config()))).toBe(true);
    expect(exportAllowed(readPolicies(config({ disable_export: false })))).toBe(true);
    expect(exportAllowed(readPolicies(config({ disable_export: true })))).toBe(false);
  });
});

describe("key derivation", () => {
  it("gives new keys the core's settings, raised to the server's minimums", () => {
    expect(newKeyKdf(DEFAULT_POLICIES)).toEqual({ memoryMib: 128, iterations: 3 });
    expect(newKeyKdf(with_({ minKdfMemoryMib: 64, minKdfIterations: 3 }))).toEqual({ memoryMib: 128, iterations: 3 });
    expect(newKeyKdf(with_({ minKdfMemoryMib: 256 }))).toEqual({ memoryMib: 256, iterations: 3 });
    expect(newKeyKdf(with_({ minKdfIterations: 6 }))).toEqual({ memoryMib: 128, iterations: 6 });
    expect(newKeyKdf(readPolicies(config({ min_kdf_memory_mib: 1024, min_kdf_iterations: 20 })))).toEqual({ memoryMib: 1024, iterations: 20 });
  });

  it("can meet every minimum the server allows", () => {
    expect(newKeysMeetKdf(DEFAULT_POLICIES)).toBe(true);
    expect(newKeysMeetKdf(with_({ minKdfMemoryMib: 129, minKdfIterations: 4 }))).toBe(true);
    expect(newKeysMeetKdf(readPolicies(config({ min_kdf_memory_mib: 1024, min_kdf_iterations: 20 })))).toBe(true);
    // Out of the server's own range (a policy reader clamps these; a hand-made value isn't).
    expect(newKeysMeetKdf(with_({ minKdfMemoryMib: 2048 }))).toBe(false);
    expect(newKeysMeetKdf(with_({ minKdfIterations: 21 }))).toBe(false);
  });
});

describe("vault timeout", () => {
  const OPTIONS: [VaultTimeout, string][] = [
    ["immediately", "Immediately"],
    [1, "1 minute"],
    [5, "5 minutes"],
    [15, "15 minutes"],
    [30, "30 minutes"],
    [60, "1 hour"],
    [240, "4 hours"],
    ["system-lock", "On system lock"],
    ["restart", "On app restart"],
    ["never", "Never"],
  ];
  const values = (options: [VaultTimeout, string][]) => options.map(([v]) => v);

  it("allows every choice without a limit", () => {
    for (const [v] of OPTIONS) {
      expect(timeoutWithin(v, 0)).toBe(true);
      expect(clampTimeout(v, 0)).toBe(v);
    }
    expect(timeoutOptions(OPTIONS, 0)).toBe(OPTIONS);
  });

  it("uses the limit for a longer choice, and for moments without a time limit", () => {
    expect(clampTimeout("immediately", 10)).toBe("immediately");
    expect(clampTimeout(5, 10)).toBe(5);
    expect(clampTimeout(10, 10)).toBe(10);
    expect(clampTimeout(15, 10)).toBe(10);
    expect(clampTimeout("system-lock", 10)).toBe(10);
    expect(clampTimeout("restart", 10)).toBe(10);
    expect(clampTimeout("never", 10)).toBe(10);
    expect(timeoutWithin("never", 43_200)).toBe(false);
  });

  it("offers the choices within the limit, plus the limit itself", () => {
    expect(values(timeoutOptions(OPTIONS, 60))).toEqual(["immediately", 1, 5, 15, 30, 60]);
    expect(timeoutOptions(OPTIONS, 10)).toEqual([
      ["immediately", "Immediately"],
      [1, "1 minute"],
      [5, "5 minutes"],
      [10, "10 minutes"],
    ]);
    expect(values(timeoutOptions(OPTIONS, 20))).toEqual(["immediately", 1, 5, 15, 20]);
    expect(values(timeoutOptions(OPTIONS, 43_200))).toEqual(["immediately", 1, 5, 15, 30, 60, 240, 43_200]);
    expect(timeoutOptions(OPTIONS, 43_200).at(-1)).toEqual([43_200, "30 days"]);
  });

  it("names a limit in words", () => {
    expect(minutesLabel(1)).toBe("1 minute");
    expect(minutesLabel(45)).toBe("45 minutes");
    expect(minutesLabel(60)).toBe("1 hour");
    expect(minutesLabel(90)).toBe("90 minutes");
    expect(minutesLabel(120)).toBe("2 hours");
    expect(minutesLabel(1440)).toBe("1 day");
    expect(minutesLabel(2880)).toBe("2 days");
  });

  it("shortens the web vault's idle lock, never lengthens it", () => {
    expect(webLockMinutes(0)).toBe(15);
    expect(webLockMinutes(5)).toBe(5);
    expect(webLockMinutes(15)).toBe(15);
    expect(webLockMinutes(240)).toBe(15);
  });
});

describe("policy violations", () => {
  it("reads the known violations in a fixed order", () => {
    expect(readViolations(["kdf", "secret_key", "two_step"])).toEqual(["two_step", "secret_key", "kdf"]);
    expect(readViolations(["kdf", "kdf", "something_new"])).toEqual(["kdf"]);
    expect(readViolations(undefined)).toEqual([]);
    expect(readViolations("kdf")).toEqual([]);
    expect(violationsKey(["secret_key", "kdf"])).toBe("secret_key,kdf");
  });

  it("says what to do, and where", () => {
    const [sk, kdf] = policyNotices(["secret_key", "kdf"], DEFAULT_POLICIES);
    expect(sk.text).toBe("Your server asks you to turn on a Secret Key.");
    expect(sk.action).toEqual({ label: "Turn on a Secret Key", to: "/settings/security" });
    expect(kdf.action).toEqual({ label: "Change master password", to: "/settings/security" });
    expect(kdf.text).toContain("you can keep the same one");
    expect(policyNotices(["two_step"], DEFAULT_POLICIES)[0].action?.to).toBe("/settings/two-step");
  });

  it("links stronger key settings to a master password change too", () => {
    const [kdf] = policyNotices(["kdf"], with_({ minKdfMemoryMib: 256, minKdfIterations: 6 }));
    expect(kdf.action).toEqual({ label: "Change master password", to: "/settings/security" });
    // Only a value outside what the server itself allows leaves no action.
    expect(policyNotices(["kdf"], with_({ minKdfMemoryMib: 4096 }))[0].action).toBeUndefined();
  });
});

describe("two-step gate", () => {
  it("recognises the server's answer", () => {
    expect(isTwoStepRequired(403, "two_step_required")).toBe(true);
    expect(isTwoStepRequired(403, "forbidden")).toBe(false);
    expect(isTwoStepRequired(401, "two_step_required")).toBe(false);
    expect(isTwoStepRequired(403, undefined)).toBe(false);
  });

  it("recognises it on live sync, so the app stops instead of reconnecting", () => {
    expect(isTwoStepNotice({ type: "two_step_required" })).toBe(true);
    expect(isTwoStepNotice({ type: "sync" })).toBe(false);
    expect(isTwoStepNotice(null)).toBe(false);
    expect(isTwoStepClose(1008, "two_step_required")).toBe(true);
    expect(isTwoStepClose(1008, "policy")).toBe(false);
    expect(isTwoStepClose(1000, "two_step_required")).toBe(false);
  });

  it("opens the vault after setup when the keys are in memory, else loads the session again", () => {
    expect(afterTwoStepSetup(true)).toBe("sync");
    expect(afterTwoStepSetup(false)).toBe("boot");
  });

  describe("the API client", () => {
    let unsubscribe = () => {};
    afterEach(() => {
      unsubscribe();
      configureServer({ base: "", fetch: globalThis.fetch.bind(globalThis) });
    });

    function answer(status: number, body: unknown) {
      configureServer({
        base: "https://vault.example.com",
        fetch: async () => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }),
      });
    }

    function count() {
      let n = 0;
      unsubscribe = onTwoStepRequired(() => n++) as () => void;
      return () => n;
    }

    it("tells the app before the error is thrown", async () => {
      const calls = count();
      answer(403, { error: "two_step_required", message: "this server requires two-step login" });
      const error = await api("/sync", { auth: false }).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(ApiError);
      expect((error as ApiError).code).toBe("two_step_required");
      expect(calls()).toBe(1);
    });

    it("stays quiet for other refusals, and when the caller handles it", async () => {
      const calls = count();
      answer(403, { error: "forbidden", message: "forbidden" });
      await api("/sync", { auth: false }).catch(() => {});
      answer(403, { error: "two_step_required", message: "turn on another method first" });
      await api("/account/2fa/totp", { method: "DELETE", auth: false, twoStepGate: false }).catch(() => {});
      expect(calls()).toBe(0);
    });
  });
});
