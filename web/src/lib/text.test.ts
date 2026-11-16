import { describe, expect, it } from "vitest";
import { oneLine, stripInvisible } from "./text";

describe("text from elsewhere", () => {
  it("drops control and format characters, bidi overrides and isolates included", () => {
    expect(stripInvisible("invoice\u202Efdp.exe")).toBe("invoicefdp.exe");
    expect(stripInvisible("a\u202Ab\u202Bc\u202Cd\u202De")).toBe("abcde");
    expect(stripInvisible("a\u2066b\u2067c\u2068d\u2069e")).toBe("abcde");
    expect(stripInvisible("\uFEFFa\u200Eb\u200Fc\u200Bd\u200De")).toBe("abcde");
    expect(stripInvisible("a\u0000b\u001Fc\u007Fd\u0085e\u2028f\u2029g")).toBe("abcdefg");
    expect(stripInvisible("a\u3164b")).toBe("ab");
    expect(stripInvisible("Gr\u00FC\u00DFe, \u6771\u4EAC \u{1F642}")).toBe("Gr\u00FC\u00DFe, \u6771\u4EAC \u{1F642}");
  });

  it("makes one line of at most so many characters", () => {
    expect(oneLine("  Chrome\u000Aon\u0009macOS  ", 64)).toBe("Chrome on macOS");
    expect(oneLine("Your\u202E MacBook", 64)).toBe("Your MacBook");
    expect(oneLine("x".repeat(70), 64)).toBe(`${"x".repeat(63)}\u2026`);
    expect(Array.from(oneLine("\u{1F642}".repeat(70), 10))).toHaveLength(10);
    expect(oneLine("exactly ten", 11)).toBe("exactly ten");
    expect(oneLine(null, 64)).toBe("");
    expect(oneLine({ length: 900000000 }, 64)).toBe("");
    expect(oneLine(42, 64)).toBe("");
  });
});
