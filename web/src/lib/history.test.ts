import { describe, expect, it } from "vitest";
import { authorName, passkeysMissingFrom, readVersion, readVersions, restoredItem, versionLabel } from "./history";
import { emptyItem, type Item, type Passkey } from "./types";

const ME = "user-me";
const alex = { id: "user-alex", email: "alex@example.com", name: "Alex Morgan" };

describe("readVersions", () => {
  it("lists versions newest first", () => {
    const list = readVersions({
      versions: [
        { seq: 4, saved_at: 400, saved_by: alex },
        { seq: 9, saved_at: 900, saved_by: { id: ME, email: "me@example.com", name: "" } },
        { seq: 6, saved_at: 600, saved_by: null },
      ],
    });
    expect(list.map((v) => v.seq)).toEqual([9, 6, 4]);
    expect(list[0].savedBy).toEqual({ id: ME, email: "me@example.com", name: null });
    expect(list[1].savedBy).toBeNull();
  });

  it("leaves out malformed entries and repeated numbers", () => {
    const list = readVersions({
      versions: [
        { seq: 3, saved_at: 300, saved_by: null },
        { seq: 3, saved_at: 301, saved_by: alex },
        { seq: -1, saved_at: 1 },
        { seq: 2.5, saved_at: 1 },
        { seq: 5 },
        { saved_at: 5 },
        "x",
        null,
      ],
    });
    expect(list).toEqual([{ seq: 3, savedAt: 300, savedBy: null }]);
  });

  it("is empty when the answer isn't a list", () => {
    expect(readVersions(null)).toEqual([]);
    expect(readVersions({ versions: "none" })).toEqual([]);
    expect(readVersions({})).toEqual([]);
  });
});

describe("readVersion", () => {
  it("reads one stored version", () => {
    expect(readVersion({ seq: 7, vault_id: "v", item_key: "k", data: "d", saved_at: 70, saved_by: alex })).toEqual({
      seq: 7,
      vaultId: "v",
      itemKey: "k",
      data: "d",
      savedAt: 70,
      savedBy: alex,
    });
  });

  it("refuses an answer without its ciphertext", () => {
    expect(readVersion({ seq: 7, vault_id: "v", item_key: "", data: "d", saved_at: 70 })).toBeNull();
    expect(readVersion({ seq: 7, vault_id: "v", item_key: "k", saved_at: 70 })).toBeNull();
    expect(readVersion({ vault_id: "v", item_key: "k", data: "d", saved_at: 70 })).toBeNull();
    expect(readVersion(null)).toBeNull();
  });
});

describe("labels", () => {
  const when = (s: number) => `t${s}`;

  it("says who saved each version", () => {
    expect(authorName(null, ME)).toBeNull();
    expect(authorName({ id: ME, email: "me@example.com", name: "Sam" }, ME)).toBe("you");
    expect(authorName(alex, ME)).toBe("Alex Morgan");
    expect(authorName({ id: "x", email: "bo@example.com", name: null }, ME)).toBe("bo@example.com");
    expect(authorName({ id: "x", email: null, name: null }, ME)).toBe("a deleted account");
  });

  it("dates each version", () => {
    expect(versionLabel({ seq: 1, savedAt: 5, savedBy: alex }, ME, when)).toBe("Saved t5 by Alex Morgan");
    expect(versionLabel({ seq: 1, savedAt: 5, savedBy: null }, ME, when)).toBe("Saved t5");
  });
});

function login(password: string, history: [string, number][], passkeys: string[] = [], created = 100): Item {
  const item = emptyItem("login");
  item.created_at = created;
  item.login!.password = password;
  item.password_history = history.map(([p, t]) => ({ password: p, changed_at: t }));
  item.login!.passkeys = passkeys.map((id) => ({ credential_id: id }) as Passkey);
  return item;
}

describe("restoredItem", () => {
  it("brings back the version's content with the item's creation time", () => {
    const version = { ...login("A", []), name: "Old name", created_at: 0 };
    const current = { ...login("C", []), name: "New name" };
    const out = restoredItem(version, current);
    expect(out.name).toBe("Old name");
    expect(out.login?.password).toBe("A");
    expect(out.created_at).toBe(100);
    expect(version.password_history).toEqual([]);
  });

  it("keeps every earlier password from both histories, newest first", () => {
    const version = login("A", [["Z", 10]]);
    const current = login("C", [
      ["B", 30],
      ["A", 20],
      ["Z", 10],
    ]);
    expect(restoredItem(version, current).password_history).toEqual([
      { password: "B", changed_at: 30 },
      { password: "A", changed_at: 20 },
      { password: "Z", changed_at: 10 },
    ]);
  });

  it("keeps at most 20 earlier passwords", () => {
    const many = Array.from({ length: 30 }, (_, i) => [`p${i}`, i] as [string, number]);
    expect(restoredItem(login("A", many.slice(0, 15)), login("C", many.slice(15))).password_history).toHaveLength(20);
  });

  it("lists the attached files of both, the item's own first", () => {
    const file = (id: string, name: string) => ({ id, name, size: 1, key: `k-${id}` });
    const a = file("0b6b7c1e-0f55-4f2e-9d55-3c3a3c3a3c3a", "now.pdf");
    const b = file("1c7c8d2f-1066-4a3f-8e66-4d4b4d4b4d4b", "both.pdf");
    const c = file("2d8d9e30-2177-4b40-9f77-5e5c5e5c5e5c", "deleted since.pdf");
    const version = { ...login("A", []), attachments: [b, c] };
    const current = { ...login("C", []), attachments: [a, b] };
    expect(restoredItem(version, current).attachments).toEqual([a, b, c]);
    // Neither has files: the restored item has no list either.
    expect("attachments" in restoredItem(login("A", []), login("C", []))).toBe(false);
    expect(restoredItem(login("A", []), current).attachments).toEqual([a, b]);
  });
});

describe("passkeysMissingFrom", () => {
  it("lists the passkeys restoring would remove", () => {
    const version = login("A", [], ["k1"]);
    const current = login("C", [], ["k1", "k2", "k3"]);
    expect(passkeysMissingFrom(version, current).map((p) => p.credential_id)).toEqual(["k2", "k3"]);
    expect(passkeysMissingFrom(current, version)).toEqual([]);
    expect(passkeysMissingFrom(emptyItem("note"), emptyItem("note"))).toEqual([]);
  });
});
