import { beforeAll, describe, expect, it, vi } from "vitest";
import * as core from "../wasm/passauth_core";
import {
  applyDefaultMatch,
  findMatchGroups,
  MATCH_CHANGED,
  matchLabel,
  onlyBaseDomain,
  urlGroup,
  withDefaultMatch,
  type MatchEntry,
  type MatchOptions,
} from "./matching";
import { loadCore } from "./test-core";
import { emptyItem, type Item, type LoginUrl, type UrlMatch } from "./types";

beforeAll(loadCore);

const OWN = "vault-own";
const SHARED = "vault-shared";
const READ = "vault-read";

let opts: MatchOptions;
beforeAll(() => {
  opts = { baseDomain: core.baseDomain, writableVault: (id) => id === OWN || id === SHARED };
});

let seq = 0;
function login(urls: [string, UrlMatch][], o: { name?: string; vault?: string; deleted?: boolean; rollback?: boolean; kind?: "login" | "note" } = {}): MatchEntry {
  const item = emptyItem(o.kind ?? "login");
  const id = `item-${++seq}`;
  item.name = o.name ?? id;
  if (item.login) {
    item.login.username = "me@example.com";
    item.login.password = "pw";
    item.login.urls = urls.map(([url, match]) => ({ url, match }));
  }
  return { id, vaultId: o.vault ?? OWN, revision: 1, deletedAt: o.deleted ? 100 : null, item, rollback: o.rollback };
}

describe("urlGroup", () => {
  it("is the base domain of http(s) and bare addresses, the address itself for app addresses", () => {
    expect(urlGroup("https://radarr.example.com/login", core.baseDomain)).toBe("example.com");
    expect(urlGroup("cloudy.example.com", core.baseDomain)).toBe("example.com");
    expect(urlGroup("androidapp://com.example.app", core.baseDomain)).toBe("androidapp://com.example.app");
    expect(urlGroup("   ", core.baseDomain)).toBeNull();
  });
});

describe("findMatchGroups", () => {
  it("lists websites with their own match, grouped by base domain", () => {
    const a = login([["https://cloudy.example.com", "domain"]], { name: "Cloudy" });
    const b = login([["https://radarr.example.com", "domain"]], { name: "Radarr" });
    const c = login([["https://github.com", "host"]], { name: "GitHub" });
    const d = login([["https://apple.com", "default"]], { name: "Apple" });
    const r = findMatchGroups([a, b, c, d], opts);
    expect(r.groups.map((g) => g.domain)).toEqual(["example.com", "github.com"]);
    expect(r.groups[0].logins.map((l) => l.entry.id)).toEqual([a.id, b.id]);
    expect(r.groups[0].websites).toBe(2);
    expect(r.groups[1].logins[0].urls).toEqual([{ url: "https://github.com", match: "host" }]);
    expect(r.left).toBe(0);
  });

  it("qualifies domain, host, starts_with and exact; leaves regex and never as they are and counts them", () => {
    const a = login([
      ["https://a.example.com", "domain"],
      ["https://b.example.com", "host"],
      ["https://c.example.com/x", "starts_with"],
      ["https://d.example.com/y", "exact"],
      ["^https://e\\.example\\.com", "regex"],
      ["https://f.example.com", "never"],
      ["https://g.example.com", "default"],
    ]);
    const r = findMatchGroups([a], opts);
    expect(r.groups).toHaveLength(1);
    expect(r.groups[0].logins[0].urls.map((u) => u.match)).toEqual(["domain", "host", "starts_with", "exact"]);
    expect(r.left).toBe(2);
  });

  it("puts a login with websites on several base domains in each group, with only that group's websites", () => {
    const a = login([
      ["https://example.com", "domain"],
      ["https://example.org", "host"],
    ]);
    const r = findMatchGroups([a], opts);
    expect(r.groups.map((g) => [g.domain, g.logins[0].urls.map((u) => u.url)])).toEqual([
      ["example.com", ["https://example.com"]],
      ["example.org", ["https://example.org"]],
    ]);
  });

  it("leaves out read-only vaults, trashed items, rolled-back items, waiting offline changes and non-logins", () => {
    const ro = login([["https://ro.com", "domain"]], { vault: READ });
    const trashed = login([["https://t.com", "domain"]], { deleted: true });
    const back = login([["https://b.com", "domain"]], { rollback: true });
    const waiting = login([["https://w.com", "domain"]]);
    const note = login([], { kind: "note" });
    const shared = login([["https://s.com", "domain"]], { vault: SHARED });
    const r = findMatchGroups([ro, trashed, back, waiting, note, shared], { ...opts, pending: new Set([waiting.id]) });
    expect(r.groups.map((g) => g.domain)).toEqual(["s.com"]);
  });

  it("counts regex and never only in logins the user can change", () => {
    const ro = login([["https://ro.com", "never"]], { vault: READ });
    const own = login([["https://own.com", "never"]]);
    expect(findMatchGroups([ro, own], opts).left).toBe(1);
  });

  it("has nothing to do when every website follows the default", () => {
    const r = findMatchGroups([login([["https://a.com", "default"]]), login([])], opts);
    expect(r).toEqual({ groups: [], left: 0 });
  });
});

describe("withDefaultMatch", () => {
  it("changes only the match of qualifying websites in the chosen domains; everything else stays, unknown fields too", () => {
    const e = login([
      ["https://a.example.com", "domain"],
      ["https://example.org", "host"],
      ["^x", "regex"],
      ["https://n.example.com", "never"],
    ]);
    const extra = { future: { nested: [1, 2] } };
    const item = { ...e.item, ...extra } as Item & typeof extra;
    (item.login!.urls[0] as LoginUrl & { note?: string }).note = "kept";
    const next = withDefaultMatch(item, new Set(["example.com"]), core.baseDomain);
    expect(next).not.toBeNull();
    expect(next!.login!.urls).toEqual([
      { url: "https://a.example.com", match: "default", note: "kept" },
      { url: "https://example.org", match: "host" },
      { url: "^x", match: "regex" },
      { url: "https://n.example.com", match: "never" },
    ]);
    const strip = (i: Item) => ({ ...i, login: { ...i.login!, urls: [] } });
    expect(strip(next!)).toEqual(strip(item));
    expect((next as typeof item).future).toBe(item.future);
    // The input is not changed.
    expect(item.login!.urls[0].match).toBe("domain");
  });

  it("is null when nothing changes", () => {
    const e = login([["https://a.com", "default"]]);
    expect(withDefaultMatch(e.item, new Set(["a.com"]), core.baseDomain)).toBeNull();
    expect(withDefaultMatch(login([["https://b.com", "host"]]).item, new Set(["a.com"]), core.baseDomain)).toBeNull();
  });
});

describe("applyDefaultMatch", () => {
  it("saves each changed login once with the vault's update", async () => {
    const a = login([
      ["https://a.example.com", "domain"],
      ["https://example.org", "host"],
    ]);
    const b = login([["https://b.example.com", "host"]]);
    const c = login([["https://c.com", "host"]]);
    const { groups } = findMatchGroups([a, b, c], opts);
    const update = vi.fn(async () => {});
    const all = [a, b, c];
    const result = await applyDefaultMatch(groups, new Set(["example.com", "example.org"]), {
      update,
      current: (id) => all.find((x) => x.id === id),
      baseDomain: core.baseDomain,
    });
    expect(result).toEqual({ logins: 2, websites: 3 });
    expect(update).toHaveBeenCalledTimes(2);
    const first = update.mock.calls[0] as unknown as [MatchEntry, Item];
    expect(first[0].id).toBe(a.id);
    expect(first[1].login!.urls.map((u) => u.match)).toEqual(["default", "default"]);
  });

  it("writes nothing when a login changed since the list was made", async () => {
    const a = login([["https://a.com", "host"]]);
    const { groups } = findMatchGroups([a], opts);
    const update = vi.fn(async () => {});
    await expect(
      applyDefaultMatch(groups, new Set(["a.com"]), { update, current: () => ({ ...a, revision: 2 }), baseDomain: core.baseDomain }),
    ).rejects.toThrow(MATCH_CHANGED);
    expect(update).not.toHaveBeenCalled();
  });
});

describe("matchLabel", () => {
  it("names each match as the editor does", () => {
    expect(matchLabel("domain")).toBe("Base domain");
    expect(matchLabel("starts_with")).toBe("Starts with");
  });
});

describe("onlyBaseDomain", () => {
  const group = (...matches: UrlMatch[]) => ({
    domain: "example.com",
    websites: matches.length,
    logins: [{ entry: {} as MatchEntry, urls: matches.map((match, i) => ({ url: `https://h${i}.example.com`, match })) }],
  });
  it("is true only when every website is Base domain (Default can then only narrow it)", () => {
    expect(onlyBaseDomain(group("domain", "domain"))).toBe(true);
    expect(onlyBaseDomain(group("domain", "host"))).toBe(false);
    expect(onlyBaseDomain(group("exact"))).toBe(false);
    expect(onlyBaseDomain(group("starts_with"))).toBe(false);
  });
});
