import { afterEach, describe, expect, it } from "vitest";
import { avatars } from "./avatar";
import { lock } from "./vault";

afterEach(() => avatars.clear());

describe("profile picture in the vault's memory", () => {
  it("is forgotten (and its URL revoked) when the vault locks", () => {
    avatars.set(4, new Uint8Array([0xff, 0xd8, 0xff]));
    const url = avatars.get().url!;
    expect(url).toMatch(/^blob:/);
    lock(false);
    expect(avatars.get()).toEqual({ seq: -1, url: null });
  });
});
