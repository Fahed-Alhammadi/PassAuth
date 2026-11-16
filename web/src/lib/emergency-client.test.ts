/**
 * The emergency client's roster flows against a fake server and a fake account (the core's sealing is stood in for:
 * these tests are about what the app sends and refuses, not the cryptography, which the core's own tests cover).
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { readGrant, readRoster, rosterJson, sha256b64, type Roster, type RosterEntry } from "./emergency";

type Json = Record<string, unknown>;

const h = vi.hoisted(() => {
  class ApiError extends Error {
    constructor(
      public status: number,
      public code: string,
      message: string,
    ) {
      super(message);
    }
  }
  class UnreachableError extends Error {}
  let made = 0;
  const key = (grantId: string, n: number) => ({
    sealFor: () => `sealed:${grantId}:${n}`,
    wrapVaultKey: (_vk: unknown, vaultId: string) => `wrap:${grantId}:${n}:${vaultId}`,
    free() {},
  });
  const account = {
    newEmergencyKey(grantId: string) {
      const n = ++made;
      return { wrapped: `gk:${grantId}:${n}`, takeKey: () => key(grantId, n), free() {} };
    },
    openEmergencyKey(grantId: string, wrapped: string) {
      const m = /^gk:(.+):(\d+)$/.exec(wrapped);
      if (!m || m[1] !== grantId) throw new Error("decrypt_failed");
      return key(grantId, Number(m[2]));
    },
    sealEmergencyRoster: (json: string) => `R:${btoa(json)}`,
    openEmergencyRoster(sealed: string) {
      if (!sealed.startsWith("R:")) throw new Error("decrypt_failed");
      return atob(sealed.slice(2));
    },
  };
  const server = {
    grants: [] as Json[],
    roster: null as string | null,
    rosterSeq: 0,
    fills: [] as string[],
    confirms: 0,
    confirmHook: null as null | ((id: string) => void),
  };
  const grantAt = (id: string) => {
    const g = server.grants.find((x) => x.id === id);
    if (!g) throw new ApiError(404, "not_found", "not found");
    return g;
  };
  async function api(path: string, opts: { method?: string; body?: Json } = {}) {
    const method = opts.method ?? (opts.body === undefined ? "GET" : "POST");
    if (method === "GET" && path === "/emergency-access")
      return { as_grantor: structuredClone(server.grants), as_grantee: [], roster: server.roster, roster_seq: server.rosterSeq };
    if (method === "PUT" && path === "/emergency-access/roster") {
      if (opts.body?.seq !== server.rosterSeq + 1) throw new ApiError(409, "roster_changed", "changed");
      server.roster = String(opts.body.roster);
      server.rosterSeq += 1;
      return { roster_seq: server.rosterSeq };
    }
    let m = /^\/emergency-access\/([^/]+)\/confirm$/.exec(path);
    if (m) {
      server.confirms++;
      const id = decodeURIComponent(m[1]);
      server.confirmHook?.(id);
      Object.assign(grantAt(id), { status: "confirmed", grantor_key: opts.body?.grantor_key, missing_vaults: [] });
      return grantAt(id);
    }
    m = /^\/emergency-access\/([^/]+)\/vault-keys$/.exec(path);
    if (m) {
      const id = decodeURIComponent(m[1]);
      server.fills.push(id);
      Object.assign(grantAt(id), { missing_vaults: [] });
      return grantAt(id);
    }
    if (/^\/vaults\/v1\/members$/.test(path)) return { members: [{ user_id: "me", email: "me@example.com", name: "Me", role: "owner", public_key: "pk-me" }] };
    throw new ApiError(404, "not_found", `no fake for ${method} ${path}`);
  }
  const features = { features: ["emergency_access", "emergency_vault_keys"] };
  return {
    ApiError,
    UnreachableError,
    account,
    server,
    api,
    features,
    state: { userId: "me", status: "unlocked", vaults: [{ id: "v1", role: "owner", kind: "account", key: {}, epoch: 0 }] },
    reauth: vi.fn(async (password: string) => {
      if (password !== "right") throw new Error("That master password is wrong.");
      return "reauth-token";
    }),
  };
});

vi.mock("../wasm/passauth_core", () => ({}));
vi.mock("./api", () => ({
  ApiError: h.ApiError,
  UnreachableError: h.UnreachableError,
  api: h.api,
  friendlyError: (e: unknown) => (e instanceof Error ? e.message : String(e)),
  hasErrorCode: (e: unknown, code: string) => e instanceof h.ApiError && e.code === code,
  hasFeature: (config: { features?: string[] } | null, f: string) => !!config?.features?.includes(f),
  knownPublicConfig: () => h.features,
  loadPublicConfig: async () => h.features,
}));
vi.mock("./vault", () => ({
  getAccount: () => h.account,
  getState: () => h.state,
  onVaultKeysChange: () => {},
  reauth: h.reauth,
  rotateVaultKeys: async () => {},
  setEmergencyNotice: () => {},
  sync: async () => {},
}));

const { confirmAgain, confirmContact, fillEmergencyKeys, loadServerRoster, removeContact, rosterState, startNewRoster, useServerRoster } = await import(
  "./emergency-client"
);

const grantJson = (id: string, extra: Json = {}): Json => ({
  id,
  status: "approved",
  wait_days: 7,
  created_at: 1,
  updated_at: 1,
  requested_at: null,
  approved_at: null,
  auto_approve_at: null,
  grantor: { id: "me", email: "me@example.com", name: "Me", public_key: "pk-me" },
  grantee: { id: `u-${id}`, email: `${id}@example.com`, name: `Name ${id}`, public_key: `pk-${id}` },
  key_version: 2,
  grantor_key: `gk:${id}:100`,
  reconfirm: false,
  v1_exposed: false,
  missing_vaults: ["v1"],
  ...extra,
});
const sealRoster = (r: Omit<Roster, "removed"> & { removed?: Roster["removed"] }) =>
  h.account.sealEmergencyRoster(rosterJson({ removed: [], ...r }));
const serverRoster = (): Roster => readRoster(h.account.openEmergencyRoster(h.server.roster!))!;
const entry = async (id: string, name?: string, grantorKey = `gk:${id}:100`): Promise<RosterEntry> => ({
  id,
  contactKey: `pk-${id}`,
  grantorKeyHash: await sha256b64(grantorKey),
  ...(name ? { email: `${id}@example.com`, name } : {}),
});

beforeEach(() => {
  const store = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
  });
  Object.assign(h.server, { grants: [], roster: null, rosterSeq: 0, fills: [], confirms: 0, confirmHook: null });
});

describe("the roster, between the app and the server", () => {
  it("drops an access the contact ended for good: a server bringing it back later gets no keys and no Confirm again", async () => {
    h.server.grants = [grantJson("g1")];
    h.server.roster = sealRoster({ version: 1, accesses: [await entry("g1", "Name g1")] });
    h.server.rosterSeq = 1;
    await fillEmergencyKeys();
    expect(h.server.fills).toEqual(["g1"]);
    // The contact stepped down: the server no longer lists the access, and the next fill takes it out of the roster.
    h.server.grants = [];
    h.server.fills = [];
    await fillEmergencyKeys();
    const hash = await sha256b64("gk:g1:100");
    expect(serverRoster()).toEqual({ version: 2, accesses: [], removed: [{ id: "g1", grantorKeyHash: hash }] });
    // A server that lists it again, with its old key and vaults to wrap, gets nothing, and it can't be confirmed again.
    h.server.grants = [grantJson("g1")];
    await fillEmergencyKeys();
    expect(h.server.fills).toEqual([]);
    const state = await rosterState();
    expect([state.removed.has("g1"), state.confirmAgain.has("g1")]).toEqual([true, false]);
    await expect(confirmAgain(readGrant(grantJson("g1"))!)).rejects.toThrow("was removed from your emergency contacts");
  });

  it("keeps a contact the grantor removed out, even when the server lists them again", async () => {
    h.server.grants = [grantJson("g1"), grantJson("g2")];
    h.server.roster = sealRoster({ version: 1, accesses: [await entry("g1", "Name g1"), await entry("g2", "Name g2")] });
    h.server.rosterSeq = 1;
    await removeContact(readGrant(grantJson("g1"))!);
    expect(serverRoster().removed).toEqual([{ id: "g1", grantorKeyHash: await sha256b64("gk:g1:100") }]);
    expect(serverRoster().accesses.map((e) => e.id)).toEqual(["g2"]);
    // Re-listed (the server keeps the access after all): no fill, no Confirm again, no new confirmation.
    h.server.grants = [grantJson("g1"), grantJson("g2", { missing_vaults: [] })];
    await fillEmergencyKeys();
    expect(h.server.fills).toEqual([]);
    expect((await rosterState()).removed.has("g1")).toBe(true);
    await expect(confirmAgain(readGrant(grantJson("g1"))!)).rejects.toThrow("add them as a new contact");
    h.server.grants = [grantJson("g1", { status: "accepted", grantor_key: null }), grantJson("g2", { missing_vaults: [] })];
    await expect(confirmContact(readGrant(grantJson("g1", { status: "accepted", grantor_key: null }))!)).rejects.toThrow("add them as a new contact");
    expect(h.server.confirms).toBe(0);
  });

  it("puts an access back with Confirm again, using the key it holds, and refuses a key this account didn't make", async () => {
    h.server.grants = [grantJson("g1")];
    h.server.roster = sealRoster({ version: 2, accesses: [] });
    h.server.rosterSeq = 2;
    const g = readGrant(grantJson("g1"))!;
    expect((await rosterState()).confirmAgain.has("g1")).toBe(true);
    await confirmAgain(g);
    expect(serverRoster()).toEqual({ version: 3, accesses: [await entry("g1", "Name g1")], removed: [] });
    await fillEmergencyKeys();
    expect(h.server.fills).toEqual(["g1"]);
    // A contact key that changed since the user checked it, or a key not made by this account: refused.
    h.server.grants = [grantJson("g1", { missing_vaults: [] }), grantJson("g2", { grantee: { id: "u-g2", email: "g2@example.com", name: "Name g2", public_key: "pk-new" } })];
    await expect(confirmAgain(readGrant(grantJson("g2"))!)).rejects.toThrow("key changed");
    h.server.grants = [grantJson("g1", { missing_vaults: [] }), grantJson("g2", { grantor_key: "gk:someone-else:1" })];
    await expect(confirmAgain(readGrant(grantJson("g2"))!)).rejects.toThrow("wasn't made by your account");
    expect(serverRoster().accesses.map((e) => e.id)).toEqual(["g1"]);
  });

  it("points the roster at the key an access already holds when the confirm answer got lost", async () => {
    const accepted = grantJson("g1", { status: "accepted", grantor_key: null });
    h.server.grants = [accepted];
    // Another try (or another app) confirmed first: the server holds key 99 and refuses this one.
    h.server.confirmHook = (id) => {
      Object.assign(h.server.grants.find((g) => g.id === id)!, { status: "confirmed", grantor_key: "gk:g1:99", missing_vaults: [] });
      throw new h.ApiError(409, "conflict", "this emergency contact is confirmed already");
    };
    await confirmContact(readGrant(accepted)!);
    expect(serverRoster().accesses).toEqual([await entry("g1", "Name g1", "gk:g1:99")]);
    // Trying again from a page that still shows "accepted": no new key, no new confirmation.
    h.server.confirmHook = null;
    const confirms = h.server.confirms;
    await confirmContact(readGrant(accepted)!);
    expect(h.server.confirms).toBe(confirms);
    expect(serverRoster().accesses).toEqual([await entry("g1", "Name g1", "gk:g1:99")]);
  });

  it("reviews an older server list against this device's own, with names from inside it, and writes it forward", async () => {
    h.server.grants = [grantJson("g1"), grantJson("g2")];
    h.server.roster = sealRoster({ version: 5, accesses: [await entry("g1", "Sam")] });
    h.server.rosterSeq = 5;
    expect((await rosterState()).problem).toBeNull();
    // Restored to version 3: g1, g2 (removed since; the server's listing now calls them "Mom") and g4, which it no longer lists.
    h.server.grants = [grantJson("g1"), grantJson("g2", { grantee: { id: "u-g2", email: "mom@example.com", name: "Mom", public_key: "pk-g2" } })];
    h.server.roster = sealRoster({ version: 3, accesses: [await entry("g1", "Sam"), await entry("g2", "Eve"), await entry("g4", "Ann")] });
    h.server.rosterSeq = 3;
    expect((await rosterState()).problem).toBe("older");
    const list = await loadServerRoster();
    expect(list.entries.map((r) => [r.entry.id, r.entry.name, r.entry.email, r.wouldReturn])).toEqual([
      ["g1", "Sam", "g1@example.com", false],
      ["g2", "Eve", "g2@example.com", true],
    ]);
    // The master password first; then it is written one version above what this device saw, without g4.
    await expect(useServerRoster(list, "wrong")).rejects.toThrow("master password");
    expect(h.server.rosterSeq).toBe(3);
    await useServerRoster(list, "right");
    expect(serverRoster().version).toBe(6);
    expect(serverRoster().accesses).toEqual([await entry("g1", "Sam"), await entry("g2", "Eve")]);
    expect(serverRoster().removed.map((x) => x.id)).toEqual(["g4"]);
    expect((await rosterState()).problem).toBeNull();
    // A replay of a version in between is refused from then on.
    h.server.roster = sealRoster({ version: 5, accesses: [await entry("g1", "Sam")] });
    expect((await rosterState()).problem).toBe("older");
  });

  it("never writes a contact the user wasn't shown, when the server hides it during the review and lists it after", async () => {
    h.server.grants = [grantJson("g1")];
    h.server.roster = sealRoster({ version: 5, accesses: [await entry("g1", "Sam")] });
    h.server.rosterSeq = 5;
    await rosterState();
    // The restored list has C, but the server hides C's access while the dialog loads…
    h.server.roster = sealRoster({ version: 3, accesses: [await entry("g1", "Sam"), await entry("gc", "Carol")] });
    h.server.rosterSeq = 3;
    const list = await loadServerRoster();
    expect(list.entries.map((r) => r.entry.id)).toEqual(["g1"]);
    // …and lists it again when the list is written.
    h.server.grants = [grantJson("g1"), grantJson("gc")];
    await useServerRoster(list, "right");
    expect(serverRoster().accesses.map((e) => e.id)).toEqual(["g1"]);
    expect(serverRoster().removed.map((x) => x.id)).toEqual(["gc"]);
    await fillEmergencyKeys();
    expect(h.server.fills).not.toContain("gc");
    expect((await rosterState()).removed.has("gc")).toBe(true);
  });

  it("starts a new list when the server's doesn't open, keeping who was removed; the others need confirming again", async () => {
    h.server.grants = [grantJson("g1"), grantJson("g0")];
    h.server.roster = sealRoster({ version: 4, accesses: [await entry("g1", "Name g1")], removed: [{ id: "g0", grantorKeyHash: "h-g0" }] });
    h.server.rosterSeq = 4;
    expect((await rosterState()).problem).toBeNull();
    h.server.roster = "garbage written by someone else";
    h.server.rosterSeq = 5;
    expect((await rosterState()).problem).toBe("unreadable");
    await fillEmergencyKeys();
    expect(h.server.fills).toEqual([]);
    await expect(startNewRoster("wrong")).rejects.toThrow("master password");
    await startNewRoster("right");
    expect(serverRoster()).toEqual({ version: 5, accesses: [], removed: [{ id: "g0", grantorKeyHash: "h-g0" }] });
    const state = await rosterState();
    expect(state.problem).toBeNull();
    expect([state.confirmAgain.has("g1"), state.removed.has("g0"), state.confirmAgain.has("g0")]).toEqual([true, true, false]);
  });
});
