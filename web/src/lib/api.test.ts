import { describe, expect, it } from "vitest";
import {
  ATTACHMENT_QUOTA_EXCEEDED,
  ApiError,
  OUT_OF_STORAGE,
  QUOTA_EXCEEDED,
  UnreachableError,
  errorMessage,
  friendlyError,
  isOutOfStorage,
  isQuotaExceeded,
  nativeFailure,
} from "./api";
import { server } from "./server";

const err = (status: number, code: string, message: string, requestId?: string, retryAfter?: number) => new ApiError(status, code, message, retryAfter, requestId);

describe("error wording", () => {
  it("says what the app knows in its own words, never the server's", () => {
    expect(friendlyError(err(507, "insufficient_storage", "Click here: evil.example"))).toBe(OUT_OF_STORAGE);
    expect(friendlyError(err(403, "quota_exceeded", "anything"))).toBe(QUOTA_EXCEEDED);
    expect(friendlyError(err(400, "invalid_code", "call +1 555 0100 to unlock your vault"))).toBe("That code didn't work. Enter the code that's showing now and try again.");
    expect(friendlyError(err(403, "reauth_required", "reauth_required"))).toBe("Your confirmation expired. Enter your master password again.");
    expect(friendlyError(err(409, "vault_key_changed", "x"))).toBe("Someone replaced this vault's key just now. Try again.");
    expect(friendlyError(err(413, "too_large", "attachments can be at most 1 MB"))).toBe("This is larger than your server allows.");
    // Known messages under a generic code (older servers sent coded reasons this way).
    expect(friendlyError(err(400, "bad_request", "invalid code"))).toBe("That code didn't work. Enter the code that's showing now and try again.");
    expect(friendlyError(err(403, "forbidden", "storage limit reached"))).toBe(QUOTA_EXCEEDED);
    expect(friendlyError(err(400, "expired", "start setup first"))).toBe("The setup expired. Cancel and start setup again.");
    // errorMessage (used where the text is put into a sentence) words them the same.
    expect(errorMessage(err(507, "insufficient_storage", "x"))).toBe(OUT_OF_STORAGE);
  });

  it("shows an unknown server message only as a labelled, cleaned and shortened detail, with the reference", () => {
    const text = friendlyError(err(400, "bad_request", "Your vault is locked.\u202E Call 555-0100\u000Anow", "req-123"));
    expect(text).toBe("Your PassAuth server refused this request. Reference: req-123. Server message: Your vault is locked. Call 555-0100 now");
    const long = friendlyError(err(409, "conflict", "x".repeat(500)));
    expect(long.startsWith("Your PassAuth server refused this request. Server message: ")).toBe(true);
    expect(Array.from(long.slice(long.indexOf(": ") + 2))).toHaveLength(200);
    expect(friendlyError(err(503, "maintenance", "down for maintenance"))).toBe("Something went wrong on your PassAuth server. Server message: down for maintenance");
    // A reference that isn't a server's request id is left out.
    expect(friendlyError(err(400, "odd", "", "visit evil.example to fix this"))).toBe("Your PassAuth server refused this request.");
    expect(friendlyError(err(500, "internal", "internal error", "<b>x</b>"))).toBe(
      "Something went wrong on your PassAuth server. Try again; if it keeps happening, tell the server's admin.",
    );
    expect(friendlyError(err(500, "internal", "internal error", "abc123"))).toContain("give them this reference: abc123.");
  });

  it("keeps its own wording for answers it made itself and for waiting", () => {
    expect(friendlyError(err(502, "bad_response", "The server sent an unexpected response (502)."))).toBe("The server sent an unexpected response (502).");
    expect(friendlyError(err(429, "rate_limited", "slow down", undefined, 600))).toBe("Too many attempts. Wait 10 minutes, then try again.");
    expect(friendlyError(err(429, "rate_limited", "slow down"))).toBe("Too many attempts. Wait a minute, then try again.");
    expect(friendlyError(new Error("secret_key_required"))).toContain("doesn't have your Secret Key saved");
    expect(friendlyError(new Error("Wrong master password or Secret Key."))).toBe("That master password is wrong. Check it and try again.");
    expect(friendlyError(new Error("something local"))).toBe("Something local.");
  });

  it("tells the attachment storage limit from the others", () => {
    expect(friendlyError(err(403, "quota_exceeded", "attachment storage limit reached"))).toBe(ATTACHMENT_QUOTA_EXCEEDED);
    expect(friendlyError(err(403, "quota_exceeded", "storage limit reached"))).toBe(QUOTA_EXCEEDED);
    expect(friendlyError(err(403, "reauth_required", "reauth_required"))).toBe("Your confirmation expired. Enter your master password again.");
  });

  it("shows the desktop app's own words when its native client failed, else the general sentence", () => {
    const tooLarge = "The answer from vault.example.com is larger than 128 MB, so PassAuth didn't read it.";
    expect(nativeFailure(tooLarge)).toBe(tooLarge);
    expect(nativeFailure(new TypeError("Failed to fetch"))).toBeNull();
    expect(nativeFailure("   ")).toBeNull();
    expect(errorMessage(new UnreachableError(0, tooLarge))).toBe(tooLarge);
    const base = server.base;
    server.base = "https://vault.example.com";
    try {
      expect(errorMessage(new UnreachableError())).toBe("Can't reach your PassAuth server at vault.example.com. Check your connection, then try again.");
    } finally {
      server.base = base;
    }
  });

  it("knows when the server's storage is full", () => {
    expect(isOutOfStorage(err(507, "insufficient_storage", ""))).toBe(true);
    expect(isOutOfStorage(err(507, "error", ""))).toBe(true);
    expect(isOutOfStorage(err(403, "quota_exceeded", ""))).toBe(false);
    expect(isQuotaExceeded(err(403, "quota_exceeded", ""))).toBe(true);
    expect(isOutOfStorage(new Error("insufficient_storage"))).toBe(false);
  });
});
