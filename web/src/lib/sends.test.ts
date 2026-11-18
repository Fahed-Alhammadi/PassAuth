import { describe, expect, it } from "vitest";
import {
  DEFAULT_SEND_MAX_BYTES,
  changesBody,
  defaultDeletion,
  durationChoices,
  encryptedFieldLength,
  isSendPage,
  maskedSendLink,
  maxTextBytes,
  parseSendLocation,
  readOpenedSend,
  readPublicSend,
  readSend,
  readSends,
  sendLimits,
  sendLink,
  sendState,
  utf8Length,
  viewsText,
  visitorError,
  type OwnedSend,
} from "./sends";

const ID = "AbCdEfGhIjKlMnOpQrSt_-";
const KEY = "k".repeat(40) + "_-A";

describe("links", () => {
  it("builds the link with the key after #", () => {
    expect(sendLink("https://vault.example.com", ID, KEY)).toBe(`https://vault.example.com/send/${ID}#${KEY}`);
    expect(sendLink("https://vault.example.com/", ID, KEY)).toBe(`https://vault.example.com/send/${ID}#${KEY}`);
  });

  it("reads the id from the path and the key from the fragment", () => {
    expect(parseSendLocation(`/send/${ID}`, `#${KEY}`)).toEqual({ id: ID, key: KEY });
    expect(parseSendLocation(`/send/${ID}/`, `#${KEY}&utm=x`)).toEqual({ id: ID, key: KEY });
  });

  it("round-trips a link", () => {
    const url = new URL(sendLink("https://vault.example.com", ID, KEY));
    expect(parseSendLocation(url.pathname, url.hash)).toEqual({ id: ID, key: KEY });
  });

  it("refuses a missing or malformed id or key", () => {
    expect(parseSendLocation(`/send/${ID}`, "")).toEqual({ id: ID, key: null });
    expect(parseSendLocation(`/send/${ID}`, `#${KEY.slice(1)}`)).toEqual({ id: ID, key: null });
    expect(parseSendLocation(`/send/${ID}`, `#${KEY}=`)).toEqual({ id: ID, key: null });
    expect(parseSendLocation(`/send/${ID}`, `#${KEY.replace("_", "/")}`)).toEqual({ id: ID, key: null });
    expect(parseSendLocation("/send/short", `#${KEY}`)).toEqual({ id: null, key: KEY });
    expect(parseSendLocation("/send/%E0%A4%A", `#${KEY}`)).toEqual({ id: null, key: KEY });
    expect(parseSendLocation(`/vault/${ID}`, `#${KEY}`)).toEqual({ id: null, key: KEY });
  });

  it("hides the key when the link is shown, never anything before it", () => {
    const link = sendLink("https://vault.example.com", ID, KEY);
    const masked = maskedSendLink(link);
    expect(masked.startsWith(`https://vault.example.com/send/${ID}#`)).toBe(true);
    expect(masked).not.toContain(KEY);
    expect(masked).not.toContain(KEY.slice(0, 4));
    expect(maskedSendLink("https://vault.example.com/send/x")).toBe("https://vault.example.com/send/x");
  });

  it("knows the public page's paths", () => {
    expect(isSendPage(`/send/${ID}`)).toBe(true);
    expect(isSendPage("/send/")).toBe(false);
    expect(isSendPage("/sends")).toBe(false);
    expect(isSendPage(`/send/${ID}/more`)).toBe(false);
  });
});

describe("sizes", () => {
  it("measures the encrypted text as the server does", () => {
    // 1 version byte, 24-byte nonce, the text, 16-byte tag, in unpadded base64url.
    expect(encryptedFieldLength(0)).toBe(Math.ceil((41 * 4) / 3));
    expect(encryptedFieldLength(5)).toBe(Math.ceil((46 * 4) / 3));
    expect(utf8Length("héllo")).toBe(6);
  });

  it("knows the most text that fits", () => {
    const max = maxTextBytes(DEFAULT_SEND_MAX_BYTES);
    expect(encryptedFieldLength(max, true)).toBeLessThanOrEqual(DEFAULT_SEND_MAX_BYTES);
    expect(encryptedFieldLength(max + 1, true)).toBeGreaterThan(DEFAULT_SEND_MAX_BYTES);
    expect(maxTextBytes(10)).toBe(0);
  });

  it("reads the limits from /api/config, else the server's defaults", () => {
    expect(sendLimits({ send_max_days: 7, send_max_bytes: 2048 })).toEqual({ maxDays: 7, maxBytes: 2048 });
    expect(sendLimits(undefined)).toEqual({ maxDays: 30, maxBytes: DEFAULT_SEND_MAX_BYTES });
    expect(sendLimits({ send_max_days: 0, send_max_bytes: "x" })).toEqual({ maxDays: 30, maxBytes: DEFAULT_SEND_MAX_BYTES });
  });
});

describe("durations", () => {
  it("offers what the server allows, and its limit", () => {
    expect(durationChoices(30).map(([, l]) => l)).toEqual(["1 hour", "1 day", "2 days", "3 days", "7 days", "14 days", "30 days"]);
    expect(durationChoices(10).map(([, l]) => l)).toEqual(["1 hour", "1 day", "2 days", "3 days", "7 days", "10 days"]);
    expect(durationChoices(1).map(([, l]) => l)).toEqual(["1 hour", "1 day"]);
    expect(durationChoices(365).at(-1)).toEqual([365 * 86400, "365 days"]);
  });

  it("deletes after 7 days by default, or sooner when the server says so", () => {
    expect(defaultDeletion(30)).toBe(7 * 86400);
    expect(defaultDeletion(3)).toBe(3 * 86400);
  });
});

describe("the owner's Sends", () => {
  const raw = {
    id: ID,
    path: `/send/${ID}`,
    kind: "text",
    name: "enc-name",
    owner_key: "wrapped",
    size: 100,
    has_password: true,
    access_salt: "sendpw-v1$m=131072,t=3,p=1$abc",
    max_views: 5,
    views: 2,
    expires_at: 2000,
    delete_at: 3000,
    disabled: false,
    hide_email: true,
    available: true,
    created_at: 100,
    updated_at: 200,
  };

  it("reads them", () => {
    const s = readSend(raw)!;
    expect(s).toMatchObject({ id: ID, name: "enc-name", ownerKey: "wrapped", hasPassword: true, maxViews: 5, views: 2, expiresAt: 2000, deleteAt: 3000, hideEmail: true, data: null });
    expect(readSend({ ...raw, data: "enc-text" })!.data).toBe("enc-text");
    // Send v2: the content key wrapped for the owner; null (or missing, an older server) for v1 Sends.
    expect(readSend(raw)!.ownerContentKey).toBeNull();
    expect(readSend({ ...raw, owner_content_key: null })!.ownerContentKey).toBeNull();
    expect(readSend({ ...raw, owner_content_key: "wrapped-ck" })!.ownerContentKey).toBe("wrapped-ck");
    expect(readSends({ sends: [raw, { id: "x" }, null] })).toHaveLength(1);
    expect(readSends({})).toEqual([]);
  });

  it("says whether they can be opened", () => {
    const s = readSend(raw)! as OwnedSend;
    expect(sendState(s, 1000)).toBe("available");
    expect(sendState({ ...s, disabled: true }, 1000)).toBe("disabled");
    expect(sendState(s, 2000)).toBe("expired");
    expect(sendState({ ...s, views: 5 }, 1000)).toBe("used-up");
    expect(sendState(s, 3000)).toBe("deleted");
    expect(sendState({ ...s, available: false }, 1000)).toBe("unavailable");
  });

  it("counts views", () => {
    expect(viewsText({ views: 0, maxViews: null })).toBe("Not opened yet");
    expect(viewsText({ views: 1, maxViews: null })).toBe("Opened 1 time");
    expect(viewsText({ views: 2, maxViews: 5 })).toBe("Opened 2 of 5 times");
    expect(viewsText({ views: 0, maxViews: 1 })).toBe("Opened 0 of 1 time");
  });

  it("sends only what changed", () => {
    expect(changesBody({})).toEqual({});
    expect(changesBody({ name: "n", disabled: true })).toEqual({ name: "n", disabled: true });
    expect(changesBody({ password: { salt: "s", verifier: "v" } })).toEqual({ access_salt: "s", access_verifier: "v" });
    expect(changesBody({ password: null, maxViews: null, expiresAt: null })).toEqual({ access_verifier: null, max_views: null, expires_at: null });
    expect(changesBody({ deleteAt: 5, hideEmail: false, data: "d" })).toEqual({ delete_at: 5, hide_email: false, data: "d" });
    expect(changesBody({ ownerContentKey: "ck" })).toEqual({ owner_content_key: "ck" });
    expect(changesBody({ password: null, ownerContentKey: null })).toEqual({ access_verifier: null, owner_content_key: null });
  });
});

describe("the visitor's page", () => {
  it("reads what the page shows before opening", () => {
    expect(readPublicSend({ id: ID, name: "enc", needs_password: false, access_salt: null, expires_at: null, delete_at: 9, sender: "alex@example.com" })).toEqual({
      id: ID,
      name: "enc",
      needsPassword: false,
      accessSalt: null,
      expiresAt: null,
      deleteAt: 9,
      sender: "alex@example.com",
    });
    // The name is withheld while a password is needed.
    expect(readPublicSend({ id: ID, name: null, needs_password: true, access_salt: "salt", sender: null })).toMatchObject({ name: null, needsPassword: true, accessSalt: "salt" });
    expect(readPublicSend({ id: ID, needs_password: true })).toBeNull();
    expect(readPublicSend({})).toBeNull();
  });

  it("reads the opened Send", () => {
    expect(readOpenedSend({ kind: "text", name: "n", data: "d" })).toEqual({ name: "n", data: "d" });
    expect(readOpenedSend({ name: "n" })).toBeNull();
  });

  it("explains failures", () => {
    expect(visitorError(404, "not_found")).toContain("doesn't exist, has expired or was used up");
    expect(visitorError(401, "wrong_password")).toContain("password isn't right");
    expect(visitorError(429, null)).toContain("Too many attempts");
    expect(visitorError(0, null)).toContain("couldn't open");
  });
});
