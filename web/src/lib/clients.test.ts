import { describe, expect, it } from "vitest";
import { clientInfo, deviceKindInfo } from "./clients";

describe("clientInfo", () => {
  it("names known apps with their version", () => {
    expect(clientInfo("desktop/0.7.0")?.label).toBe("Desktop app 0.7.0");
    expect(clientInfo("web/0.9.0")?.label).toBe("Web");
    expect(clientInfo(null)).toBeNull();
    expect(clientInfo("   ")).toBeNull();
  });

  it("shows a claimed name as one clean line", () => {
    const shown = clientInfo("evil‮exe.pdf​/1.0\n")?.label ?? "";
    expect(shown).not.toMatch(/[‪-‮⁦-⁩​\n]/);
    expect(shown.startsWith("Evilexe.pdf")).toBe(true);
    expect(clientInfo(42 as unknown as string)).toBeNull();
  });
});

describe("deviceKindInfo", () => {
  it("keeps known kinds and cleans claimed ones", () => {
    expect(deviceKindInfo("mobile").label).toBe("Mobile app");
    expect(deviceKindInfo("toString").label).toBe("ToString");
    expect(deviceKindInfo("lap‮top").label).toBe("Laptop");
    expect(deviceKindInfo("").label).toBe("Device");
  });
});
