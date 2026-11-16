import { describe, expect, it } from "vitest";
import { base64Length, encryptedSizeBound, formatBytes } from "./sizes";

describe("formatBytes", () => {
  it("speaks in the units the server counts in", () => {
    expect(formatBytes(0)).toBe("0 bytes");
    expect(formatBytes(1)).toBe("1 byte");
    expect(formatBytes(800)).toBe("800 bytes");
    expect(formatBytes(64 * 1024)).toBe("64 KB");
    expect(formatBytes(1536 * 1024)).toBe("1.5 MB");
    expect(formatBytes(2048 * 1024)).toBe("2 MB");
    expect(formatBytes(150 * 1024 * 1024)).toBe("150 MB");
    expect(formatBytes(3 * 1024 ** 3)).toBe("3 GB");
    expect(formatBytes(Number.NaN)).toBe("0 bytes");
    expect(formatBytes(-5)).toBe("0 bytes");
  });
});

describe("encryptedSizeBound", () => {
  /** What the core produces: unpadded base64 of version byte + nonce + the item's JSON (UTF-8) + tag. */
  const actual = (json: string) => base64Length(1 + 24 + new TextEncoder().encode(json).length + 16);

  it("is never below the real length, also for text that isn't ASCII", () => {
    for (const item of [
      { name: "a" },
      { name: "Bank", notes: "x".repeat(70_000) },
      { name: "日本語のメモ", notes: "🔐".repeat(5000) + "é".repeat(3000) },
      { name: "control\n\t\u0001chars", fields: [{ name: "quote \" and \\", value: "" }] },
    ]) {
      const json = JSON.stringify({ ...item, format: 2 });
      expect(encryptedSizeBound(item)).toBeGreaterThanOrEqual(actual(json));
    }
  });

  it("stays close for ordinary items", () => {
    const item = { name: "Example", notes: "n".repeat(10_000) };
    expect(encryptedSizeBound(item) - actual(JSON.stringify(item))).toBeLessThan(1500);
  });
});
