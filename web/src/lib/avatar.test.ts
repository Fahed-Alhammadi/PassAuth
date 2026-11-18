import { describe, expect, it, vi } from "vitest";
import { AVATAR_TOO_BIG, MAX_AVATAR_BYTES, createAvatarStore, encodeWithinLimit, initialsOf, squareCrop, type AvatarDeps } from "./avatar";

function fakeDeps(answer: { avatar: string | null; avatar_seq: number } | (() => Promise<never>)) {
  let n = 0;
  const revoked: string[] = [];
  const deps: AvatarDeps = {
    get: vi.fn(typeof answer === "function" ? answer : async () => answer),
    createUrl: vi.fn(() => `blob:pic-${++n}`),
    revokeUrl: vi.fn((url: string) => void revoked.push(url)),
  };
  return { deps, revoked };
}

const open = (sealed: string) => new TextEncoder().encode(`jpeg:${sealed}`);

describe("avatar store", () => {
  it("fetches only when the seq from /sync changes", async () => {
    const { deps } = fakeDeps({ avatar: "sealed", avatar_seq: 3 });
    const store = createAvatarStore(deps);
    await store.note(3, open);
    expect(deps.get).toHaveBeenCalledTimes(1);
    expect(store.get()).toEqual({ seq: 3, url: "blob:pic-1" });
    await store.note(3, open);
    await store.note(3, open);
    expect(deps.get).toHaveBeenCalledTimes(1);
    deps.get = vi.fn(async () => ({ avatar: "newer", avatar_seq: 4 }));
    await store.note(4, open);
    expect(deps.get).toHaveBeenCalledTimes(1);
    expect(store.get()).toEqual({ seq: 4, url: "blob:pic-2" });
  });

  it("does nothing for servers without pictures and never fetches for seq 0", async () => {
    const { deps } = fakeDeps({ avatar: null, avatar_seq: 0 });
    const store = createAvatarStore(deps);
    await store.note(undefined, open);
    await store.note("3", open);
    expect(store.get().seq).toBe(-1);
    await store.note(0, open);
    expect(deps.get).not.toHaveBeenCalled();
    expect(store.get()).toEqual({ seq: 0, url: null });
  });

  it("starts one fetch for repeated syncs while it runs", async () => {
    let release!: () => void;
    const { deps } = fakeDeps({ avatar: "x", avatar_seq: 2 });
    deps.get = vi.fn(() => new Promise<{ avatar: string; avatar_seq: number }>((r) => (release = () => r({ avatar: "x", avatar_seq: 2 }))));
    const store = createAvatarStore(deps);
    const first = store.note(2, open);
    await store.note(2, open);
    release();
    await first;
    expect(deps.get).toHaveBeenCalledTimes(1);
    expect(store.get().url).toBe("blob:pic-1");
  });

  it("shows initials when the picture can't be opened, and keeps going", async () => {
    const { deps } = fakeDeps({ avatar: "damaged", avatar_seq: 5 });
    const store = createAvatarStore(deps);
    await store.note(5, () => {
      throw new Error("decrypt_failed");
    });
    expect(store.get()).toEqual({ seq: 5, url: null });
  });

  it("removing the picture (null) revokes the old URL", async () => {
    const { deps, revoked } = fakeDeps({ avatar: "a", avatar_seq: 1 });
    const store = createAvatarStore(deps);
    await store.note(1, open);
    deps.get = vi.fn(async () => ({ avatar: null, avatar_seq: 2 }));
    await store.note(2, open);
    expect(store.get()).toEqual({ seq: 2, url: null });
    expect(revoked).toEqual(["blob:pic-1"]);
  });

  it("a failed fetch keeps what's shown and is tried again on the next sync", async () => {
    const { deps } = fakeDeps(() => Promise.reject(new Error("offline")));
    const store = createAvatarStore(deps);
    await store.note(7, open);
    expect(store.get().seq).toBe(-1);
    deps.get = vi.fn(async () => ({ avatar: "s", avatar_seq: 7 }));
    await store.note(7, open);
    expect(store.get()).toEqual({ seq: 7, url: "blob:pic-1" });
  });

  it("clear (lock, sign-out) revokes the URL and drops an answer still on its way", async () => {
    const { deps, revoked } = fakeDeps({ avatar: "a", avatar_seq: 1 });
    const store = createAvatarStore(deps);
    await store.note(1, open);
    const seen = vi.fn();
    store.subscribe(seen);
    store.clear();
    expect(store.get()).toEqual({ seq: -1, url: null });
    expect(revoked).toEqual(["blob:pic-1"]);
    expect(seen).toHaveBeenCalledTimes(1);

    let release!: () => void;
    deps.get = vi.fn(() => new Promise<{ avatar: string; avatar_seq: number }>((r) => (release = () => r({ avatar: "b", avatar_seq: 2 }))));
    const late = store.note(2, open);
    store.clear();
    release();
    await late;
    expect(store.get()).toEqual({ seq: -1, url: null });
  });

  it("a picture set on this device is shown without fetching it back", async () => {
    const { deps } = fakeDeps({ avatar: "a", avatar_seq: 9 });
    const store = createAvatarStore(deps);
    store.set(9, new Uint8Array([1, 2, 3]));
    await store.note(9, open);
    expect(deps.get).not.toHaveBeenCalled();
    expect(store.get().url).toBe("blob:pic-1");
  });
});

describe("picture encoding", () => {
  it("crops the centred square", () => {
    expect(squareCrop(400, 300)).toEqual({ sx: 50, sy: 0, side: 300 });
    expect(squareCrop(300, 401)).toEqual({ sx: 0, sy: 50, side: 300 });
    expect(squareCrop(256, 256)).toEqual({ sx: 0, sy: 0, side: 256 });
  });

  it("lowers the quality until the JPEG is at most 256 KiB", async () => {
    const tried: number[] = [];
    // Pretend size shrinks with quality: 408 KiB at 0.85 … fits from 0.45.
    const bytes = await encodeWithinLimit(async (q) => {
      tried.push(q);
      return new Blob([new Uint8Array(Math.round(q * 480 * 1024))]);
    });
    expect(bytes.length).toBeLessThanOrEqual(MAX_AVATAR_BYTES);
    expect(tried[0]).toBe(0.85);
    expect(tried.at(-1)).toBe(0.45);
  });

  it("keeps the first quality when it already fits", async () => {
    const encode = vi.fn(async () => new Blob([new Uint8Array(30_000)]));
    expect((await encodeWithinLimit(encode)).length).toBe(30_000);
    expect(encode).toHaveBeenCalledTimes(1);
  });

  it("refuses a picture that never fits", async () => {
    await expect(encodeWithinLimit(async () => new Blob([new Uint8Array(MAX_AVATAR_BYTES + 1)]))).rejects.toThrow(AVATAR_TOO_BIG);
  });
});

describe("initials", () => {
  it("are the first and last name's first letters, else the email's", () => {
    expect(initialsOf("Alex Morgan", "a@example.com")).toBe("AM");
    expect(initialsOf("  alex  van der morgan ", "a@example.com")).toBe("AM");
    expect(initialsOf("Alex", "a@example.com")).toBe("A");
    expect(initialsOf("", "sam@example.com")).toBe("S");
    expect(initialsOf("", "")).toBe("?");
  });
});
