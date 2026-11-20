import { beforeAll, describe, expect, it, vi } from "vitest";
import * as core from "../wasm/passauth_core";
import {
  combineGroup,
  CombineIncomplete,
  findDuplicates,
  GROUP_CHANGED,
  groupKey,
  HISTORY_CAP,
  joinNames,
  mergeGroup,
  mergeNotes,
  MergeError,
  siteDomains,
  totpKey,
  type DuplicateEntry,
  type DuplicateOptions,
} from "./duplicates";
import { loadCore } from "./test-core";
import { emptyItem, type Item, type Passkey } from "./types";

beforeAll(loadCore);

const OWN = "vault-own";
const SHARED = "vault-shared";

let opts: DuplicateOptions;
beforeAll(() => {
  opts = { baseDomain: core.baseDomain, writableVault: (id) => id === OWN || id === SHARED };
});

let seq = 0;
function passkey(id: string): Passkey {
  return { credential_id: id, rp_id: "apple.com", rp_name: "Apple", user_handle: "h", user_name: "me", user_display_name: "Me", algorithm: -7, private_key: "k", counter: 0, discoverable: true, created_at: 1 };
}

function login(
  o: { name?: string; user?: string; password?: string; urls?: string[]; totp?: string | null; passkeys?: Passkey[]; notes?: string; vault?: string; created?: number; attachments?: number; deleted?: boolean } & Omit<Partial<Item>, "attachments"> = {},
): DuplicateEntry {
  const item = emptyItem("login");
  const id = `item-${++seq}`;
  item.name = o.name ?? id;
  item.notes = o.notes ?? "";
  item.created_at = o.created ?? seq;
  item.login = {
    username: o.user ?? "me@example.com",
    password: o.password ?? "correct horse",
    urls: (o.urls ?? ["https://apple.com"]).map((url) => ({ url, match: "default" as const })),
    totp: o.totp ?? null,
    passkeys: o.passkeys ?? [],
  };
  if (o.attachments) item.attachments = Array.from({ length: o.attachments }, (_, n) => ({ id: `a${n}`, name: `f${n}`, size: 1, key: "k" }));
  for (const k of ["fields", "tags", "password_history", "favorite", "folder"] as const) if (o[k] !== undefined) (item as unknown as Record<string, unknown>)[k] = o[k];
  return { id, vaultId: o.vault ?? OWN, revision: 1, deletedAt: o.deleted ? 100 : null, item };
}

const ids = (groups: { entries: DuplicateEntry[] }[]) => groups.map((g) => g.entries.map((e) => e.id));

describe("findDuplicates", () => {
  it("groups apple.com and signin.apple.com with the same user and password; the merge has the passkey and the 2FA", () => {
    const a = login({ name: "Apple", urls: ["https://apple.com"], passkeys: [passkey("pk1")], created: 10 });
    const b = login({ name: "Apple ID", urls: ["https://signin.apple.com/login"], totp: "JBSWY3DPEHPK3PXP", created: 20 });
    const groups = findDuplicates([a, b], opts);
    expect(ids(groups)).toEqual([[a.id, b.id]]);
    const g = groups[0];
    expect(g.site).toBe("apple.com");
    expect(g.keeper.id).toBe(a.id);
    expect(g.differentTotp).toBe(false);
    const merged = mergeGroup(g);
    expect(merged.login?.passkeys.map((p) => p.credential_id)).toEqual(["pk1"]);
    expect(merged.login?.totp).toBe("JBSWY3DPEHPK3PXP");
    expect(merged.login?.urls.map((u) => u.url)).toEqual(["https://apple.com", "https://signin.apple.com/login"]);
    expect(merged.name).toBe("Apple");
  });

  it("compares user names trimmed and case-insensitive", () => {
    const a = login({ user: "Me@Example.com " });
    const b = login({ user: "me@example.com" });
    expect(ids(findDuplicates([a, b], opts))).toEqual([[a.id, b.id]]);
  });

  it("leaves out a different user name", () => {
    expect(findDuplicates([login({ user: "alice" }), login({ user: "bob" })], opts)).toEqual([]);
  });

  it("leaves out a different password (exact)", () => {
    expect(findDuplicates([login({ password: "secret" }), login({ password: "Secret" })], opts)).toEqual([]);
  });

  it("leaves out apple.com and icloud.com (no shared site)", () => {
    expect(findDuplicates([login({ urls: ["https://apple.com"] }), login({ urls: ["https://icloud.com"] })], opts)).toEqual([]);
  });

  it("leaves out x.github.io and y.github.io (public suffix)", () => {
    expect(findDuplicates([login({ urls: ["https://alice.github.io"] }), login({ urls: ["https://bob.github.io"] })], opts)).toEqual([]);
  });

  it("leaves out logins in different vaults (shared vs personal)", () => {
    expect(findDuplicates([login({ vault: OWN }), login({ vault: SHARED })], opts)).toEqual([]);
  });

  it("leaves out vaults that can't be written to or didn't pass their checks", () => {
    const only = { ...opts, writableVault: (id: string) => id === SHARED };
    expect(findDuplicates([login(), login()], only)).toEqual([]);
  });

  it("leaves out logins with an offline change waiting and items shown as rolled back", () => {
    const a = login();
    const b = login();
    expect(findDuplicates([a, b], { ...opts, pending: new Set([b.id]) })).toEqual([]);
    expect(findDuplicates([a, { ...b, rollback: true }], opts)).toEqual([]);
  });

  it("finds a three-way group, keeper the oldest", () => {
    const a = login({ urls: ["https://www.example.co.uk"], created: 30 });
    const b = login({ urls: ["https://example.co.uk"], created: 10 });
    const c = login({ urls: ["example.co.uk/account"], created: 20 });
    const groups = findDuplicates([a, b, c], opts);
    expect(ids(groups)).toEqual([[b.id, c.id, a.id]]);
    expect(groups[0].keeper.id).toBe(b.id);
    expect(groups[0].site).toBe("example.co.uk");
  });

  it("requires every pair to share a site", () => {
    // a–b share apple.com, b–c share icloud.com, a–c share nothing: one pair is grouped, the third stays out.
    const a = login({ urls: ["https://apple.com"], created: 1 });
    const b = login({ urls: ["https://apple.com", "https://icloud.com"], created: 2 });
    const c = login({ urls: ["https://icloud.com"], created: 3 });
    expect(ids(findDuplicates([a, b, c], opts))).toEqual([[a.id, b.id]]);
  });

  it("makes the login with attachments the keeper", () => {
    const a = login({ created: 1 });
    const b = login({ created: 2, attachments: 1 });
    const groups = findDuplicates([a, b], opts);
    expect(groups[0].keeper.id).toBe(b.id);
    expect(groups[0].entries.map((e) => e.id)).toEqual([b.id, a.id]);
    expect(mergeGroup(groups[0]).attachments).toHaveLength(1);
  });

  it("leaves out a group where more than one login has attachments", () => {
    expect(findDuplicates([login({ attachments: 1 }), login({ attachments: 2 })], opts)).toEqual([]);
  });

  it("flags different 2FA codes", () => {
    const a = login({ totp: "JBSWY3DPEHPK3PXP" });
    const b = login({ totp: "otpauth://totp/Apple:me?secret=GEZDGNBVGY3TQOJQ&issuer=Apple" });
    const g = findDuplicates([a, b], opts)[0];
    expect(g.differentTotp).toBe(true);
    expect(g.totps.map((t) => t.label)).toEqual([a.item.name, "Apple: me"]);
  });

  it("treats the same secret as a bare key and as an otpauth address as one", () => {
    const a = login({ totp: "jbsw y3dp ehpk 3pxp" });
    const b = login({ totp: "otpauth://totp/X:me?secret=JBSWY3DPEHPK3PXP" });
    const g = findDuplicates([a, b], opts)[0];
    expect(g.differentTotp).toBe(false);
    expect(g.totps).toHaveLength(1);
    expect(totpKey("otpauth://totp/X?secret=AAAA&digits=8")).not.toBe(totpKey("AAAA"));
  });

  it("leaves out the trash, empty passwords, other item kinds and logins without a website", () => {
    const note = { ...login(), item: emptyItem("note") };
    expect(findDuplicates([login(), login({ deleted: true })], opts)).toEqual([]);
    expect(findDuplicates([login({ password: "" }), login({ password: "" })], opts)).toEqual([]);
    expect(findDuplicates([login(), note], opts)).toEqual([]);
    expect(findDuplicates([login({ urls: ["androidapp://com.apple"] }), login({ urls: ["androidapp://com.apple"] })], opts)).toEqual([]);
  });

  it("reads only http(s) websites; regular expressions and app addresses don't count", () => {
    const item = login({ urls: ["https://a.example.com", "http://b.example.org", "ftp://example.net", "androidapp://x.y", "example.dev"] }).item;
    item.login?.urls.push({ url: "^https://apple\\.com/", match: "regex" });
    expect([...siteDomains(item, core.baseDomain)].sort()).toEqual(["example.com", "example.dev", "example.org"]);
  });
});

describe("mergeGroup", () => {
  it("needs the 2FA choice when the codes differ and keeps the one chosen", () => {
    const a = login({ totp: "JBSWY3DPEHPK3PXP" });
    const b = login({ totp: "GEZDGNBVGY3TQOJQ" });
    const g = findDuplicates([a, b], opts)[0];
    expect(() => mergeGroup(g)).toThrow(MergeError);
    expect(() => mergeGroup(g, { totp: "something else" })).toThrow(MergeError);
    expect(mergeGroup(g, { totp: "GEZDGNBVGY3TQOJQ" }).login?.totp).toBe("GEZDGNBVGY3TQOJQ");
  });

  it("keeps the keeper's id-bound data and takes a chosen name from the group", () => {
    const a = login({ name: "Apple", folder: "Work", created: 5 });
    const b = login({ name: "Apple ID", created: 9 });
    const g = findDuplicates([a, b], opts)[0];
    const merged = mergeGroup(g, { name: "Apple ID" });
    expect(merged.name).toBe("Apple ID");
    expect(merged.folder).toBe("Work");
    expect(merged.created_at).toBe(5);
    expect(mergeGroup(g, { name: "Not in the group" }).name).toBe("Apple");
  });

  it("unions websites (exact duplicates once, each with its match), passkeys by credential id, fields, tags and favourite", () => {
    const a = login({ urls: ["https://apple.com", "androidapp://com.apple"], passkeys: [passkey("p1")], tags: ["x"], fields: [{ name: "PIN", value: "1", type: "hidden" }] });
    const b = login({ urls: ["https://apple.com", "https://id.apple.com"], passkeys: [passkey("p1"), passkey("p2")], tags: ["x", "y"], favorite: true, fields: [{ name: "PIN", value: "1", type: "hidden" }, { name: "PIN", value: "2", type: "hidden" }] });
    b.item.login?.urls.push({ url: "https://apple.com", match: "host" });
    const merged = mergeGroup(findDuplicates([a, b], opts)[0]);
    expect(merged.login?.urls).toEqual([
      { url: "https://apple.com", match: "default" },
      { url: "androidapp://com.apple", match: "default" },
      { url: "https://id.apple.com", match: "default" },
      { url: "https://apple.com", match: "host" },
    ]);
    expect(merged.login?.passkeys.map((p) => p.credential_id)).toEqual(["p1", "p2"]);
    expect(merged.fields.map((f) => f.value)).toEqual(["1", "2"]);
    expect(merged.tags).toEqual(["x", "y"]);
    expect(merged.favorite).toBe(true);
  });

  it("combines notes: equal or one empty → that one, else keeper's, a blank line, the others'", () => {
    expect(mergeNotes(["same", "same"])).toBe("same");
    expect(mergeNotes(["", "only"])).toBe("only");
    expect(mergeNotes(["keeper", "", "other"])).toBe("keeper\n\nother");
    const a = login({ notes: "first", created: 1 });
    const b = login({ notes: "second", created: 2 });
    expect(mergeGroup(findDuplicates([a, b], opts)[0]).notes).toBe("first\n\nsecond");
  });

  it("unions password history by date, newest first, capped", () => {
    const hist = (from: number, n: number) => Array.from({ length: n }, (_, i) => ({ password: `p${from + i}`, changed_at: from + i }));
    const a = login({ password_history: hist(0, 15) });
    const b = login({ password_history: [...hist(10, 15)] });
    const merged = mergeGroup(findDuplicates([a, b], opts)[0]);
    expect(merged.password_history).toHaveLength(HISTORY_CAP);
    expect(merged.password_history[0].changed_at).toBe(24);
    expect(merged.password_history.at(-1)?.changed_at).toBe(5);
  });
});

describe("combineGroup", () => {
  function setup(n = 2) {
    const entries = Array.from({ length: n }, (_, i) => login({ created: i + 1 }));
    const store = new Map(entries.map((e) => [e.id, e]));
    const g = findDuplicates(entries, opts)[0];
    const calls: string[] = [];
    const deps = {
      current: (id: string) => store.get(id),
      update: vi.fn(async (e: DuplicateEntry, item: Item) => {
        calls.push(`update ${e.id}`);
        store.set(e.id, { ...e, item, revision: e.revision + 1 });
      }),
      trash: vi.fn(async (id: string) => {
        calls.push(`trash ${id}`);
        const e = store.get(id);
        if (e) store.set(id, { ...e, deletedAt: 200, revision: e.revision + 1 });
      }),
    };
    return { entries, store, g, calls, deps };
  }

  it("saves the keeper, then trashes the others", async () => {
    const { entries, g, calls, deps } = setup(3);
    await combineGroup(g, mergeGroup(g), deps);
    expect(calls).toEqual([`update ${entries[0].id}`, `trash ${entries[1].id}`, `trash ${entries[2].id}`]);
  });

  it("writes nothing when a login changed since the group was made", async () => {
    const { entries, store, g, deps } = setup();
    store.set(entries[1].id, { ...entries[1], revision: 5 });
    await expect(combineGroup(g, mergeGroup(g), deps)).rejects.toThrow(GROUP_CHANGED);
    expect(deps.update).not.toHaveBeenCalled();
  });

  it("stops on a failed keeper save (revision conflict) without trashing", async () => {
    const { g, deps } = setup();
    deps.update.mockRejectedValueOnce(new Error("changed elsewhere"));
    await expect(combineGroup(g, mergeGroup(g), deps)).rejects.toThrow("changed elsewhere");
    expect(deps.trash).not.toHaveBeenCalled();
  });

  it("says which logins are still to be trashed when a later step fails", async () => {
    const { entries, g, deps } = setup(3);
    deps.trash.mockImplementationOnce(async () => {}).mockRejectedValueOnce(new Error("offline"));
    const err = await combineGroup(g, mergeGroup(g), deps).catch((e) => e);
    expect(err).toBeInstanceOf(CombineIncomplete);
    expect((err as CombineIncomplete).remaining.map((e) => e.id)).toEqual([entries[2].id]);
  });

  it("stops before trashing a login that changed after the keeper was saved", async () => {
    const { entries, store, g, deps } = setup();
    deps.update.mockImplementationOnce(async () => {
      store.set(entries[1].id, { ...entries[1], revision: 9 });
    });
    const err = await combineGroup(g, mergeGroup(g), deps).catch((e) => e);
    expect(err).toBeInstanceOf(CombineIncomplete);
    expect(deps.trash).not.toHaveBeenCalled();
  });
});

describe("helpers", () => {
  it("joins names in plain words", () => {
    expect(joinNames(["A"])).toBe("A");
    expect(joinNames(["Apple ID", "Apple"])).toBe("Apple ID and Apple");
    expect(joinNames(["A", "B", "C"])).toBe("A, B and C");
  });

  it("keys a group by its sorted ids", () => {
    expect(groupKey({ entries: [{ id: "b" }, { id: "a" }] })).toBe("a,b");
  });

  it("doesn't add a note twice when combining again", () => {
    expect(mergeNotes(["first\n\nsecond", "second"])).toBe("first\n\nsecond");
  });

  it("reports each step", async () => {
    const a = login({ created: 1 });
    const b = login({ created: 2 });
    const g = findDuplicates([a, b], opts)[0];
    const steps: unknown[] = [];
    const store = new Map([a, b].map((e) => [e.id, e]));
    await combineGroup(g, mergeGroup(g), {
      current: (id) => store.get(id),
      update: async () => {},
      trash: async () => {},
      progress: (s) => steps.push(s),
    });
    expect(steps).toEqual([{ kind: "save" }, { kind: "trash", left: 1 }]);
  });
});
