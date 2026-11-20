import { describe, expect, it } from "vitest";
import { normalizeRelayUrl, relayUrlProblem } from "./push-relay";

describe("push relay address", () => {
  it("accepts https addresses and http to this machine", () => {
    for (const ok of ["https://push.example.com", " https://push.example.com/ ", "https://push.example.com/relay", "http://127.0.0.1:8787", "http://localhost:8787", "http://[::1]:8787"]) {
      expect(relayUrlProblem(ok), ok).toBeNull();
    }
  });
  it("refuses everything else, the way the server does", () => {
    for (const bad of ["", "push.example.com", "http://push.example.com", "ftp://push.example.com", "https://u:p@push.example.com", "https://push.example.com/?a=b", "https://push.example.com/#x", "http://10.0.0.1"]) {
      expect(relayUrlProblem(bad), bad).not.toBeNull();
    }
  });
  it("saves it without spaces or a trailing slash", () => {
    expect(normalizeRelayUrl("  https://push.example.com/ ")).toBe("https://push.example.com");
  });
});
