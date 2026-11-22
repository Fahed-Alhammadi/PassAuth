import { describe, expect, it } from "vitest";
import type { PublicConfig } from "./api";
import { siteIconsShown } from "./site-icons";

const base: PublicConfig = { name: "PassAuth", version: "0.9.0", signups_allowed: true, email_enabled: false };

describe("siteIconsShown", () => {
  it("never shows icons the user turned off", () => {
    expect(siteIconsShown(false, { ...base, api: 2, features: ["icons"] })).toBe(false);
  });
  it("follows the server's icons feature", () => {
    expect(siteIconsShown(true, { ...base, api: 2, features: ["icons", "delta_sync"] })).toBe(true);
    expect(siteIconsShown(true, { ...base, api: 2, features: ["delta_sync"] })).toBe(false);
  });
  it("keeps icons before the first answer", () => {
    expect(siteIconsShown(true, null)).toBe(true);
  });
});
