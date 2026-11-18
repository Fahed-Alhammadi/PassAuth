import { describe, expect, it } from "vitest";
import {
  EMPTY_ROSTER,
  MAX_REMOVED,
  MAX_EMAIL,
  MAX_NAME,
  MAX_SEALED_ROSTER,
  RosterFullError,
  accessesToFill,
  entryLabel,
  freshRoster,
  isRemoved,
  needsConfirmAgain,
  pruneRoster,
  reviewRoster,
  rosterEntry,
  confirmMeaning,
  fillableAccesses,
  nextRoster,
  readRoster,
  removedText,
  restoredRosterForward,
  rosterIsOlder,
  rosterJson,
  sealedLength,
  sha256b64,
  v1Warning,
  vaultsToReKey,
  daysText,
  grantorActions,
  grantorStatus,
  granteeActions,
  granteeStatus,
  hasKeys,
  isPersonal,
  needsAnswer,
  personName,
  readGrant,
  readGrantorVault,
  readGrants,
  reconfirmText,
  removalText,
  validWait,
  vaultsToRotate,
  vaultsToWrap,
  type Grant,
  type GrantStatus,
  type Roster,
  type RosterEntry,
} from "./emergency";

const raw = (status: string, extra: Record<string, unknown> = {}) => ({
  id: `grant-${status}`,
  status,
  wait_days: 7,
  created_at: 100,
  updated_at: 200,
  requested_at: null,
  approved_at: null,
  auto_approve_at: null,
  grantor: { id: "user-sam", email: "sam@example.com", name: "Sam Lee", public_key: "pk-sam" },
  grantee: { id: "user-alex", email: "alex@example.com", name: "", public_key: "pk-alex" },
  ...extra,
});
const grant = (status: GrantStatus, extra: Record<string, unknown> = {}): Grant => readGrant(raw(status, extra))!;
const when = (s: number) => `t${s}`;

describe("reading", () => {
  it("reads both lists", () => {
    const lists = readGrants({ as_grantor: [raw("invited"), { id: "x" }], as_grantee: [raw("approved", { approved_at: 300 })] });
    expect(lists.asGrantor).toHaveLength(1);
    expect(lists.asGrantor[0]).toMatchObject({ id: "grant-invited", status: "invited", waitDays: 7, grantee: { email: "alex@example.com", publicKey: "pk-alex" } });
    expect(lists.asGrantee[0]).toMatchObject({ status: "approved", approvedAt: 300 });
    expect(readGrants(null)).toEqual({ asGrantor: [], asGrantee: [], roster: null, rosterSeq: null });
  });

  it("leaves out unknown statuses and entries without people", () => {
    expect(readGrant(raw("paused"))).toBeNull();
    expect(readGrant({ ...raw("invited"), grantor: null })).toBeNull();
    expect(readGrant({ ...raw("invited"), wait_days: "7" })).toBeNull();
  });

  it("names people by name, else email", () => {
    const g = grant("invited");
    expect(personName(g.grantor)).toBe("Sam Lee");
    expect(personName(g.grantee)).toBe("alex@example.com");
    expect(personName({ id: "x", email: "", name: " ", publicKey: "" })).toBe("Someone");
  });
});

describe("waiting period", () => {
  it("accepts whole days from 1 to 90", () => {
    expect(validWait(1)).toBe(true);
    expect(validWait(90)).toBe(true);
    expect(validWait(0)).toBe(false);
    expect(validWait(91)).toBe(false);
    expect(validWait(2.5)).toBe(false);
    expect(daysText(1)).toBe("1 day");
    expect(daysText(30)).toBe("30 days");
  });
});

describe("status in words", () => {
  it("tells the grantor what each step means", () => {
    expect(grantorStatus(grant("invited"), when).text).toBe("Waiting for alex@example.com to accept.");
    expect(grantorStatus(grant("accepted"), when)).toMatchObject({ label: "Confirm", tone: "warn" });
    expect(grantorStatus(grant("accepted"), when).text).toContain("Check their fingerprint");
    expect(grantorStatus(grant("confirmed"), when).text).toContain("You'd have 7 days to say no");
    expect(grantorStatus(grant("requested", { requested_at: 1000, auto_approve_at: 5000 }), when).text).toBe(
      "alex@example.com asked for access on t1000. Unless you reject it, they can view your personal vaults from t5000.",
    );
    expect(grantorStatus(grant("requested"), when).text).toContain("after 7 days");
    expect(grantorStatus(grant("approved", { approved_at: 9 }), when)).toMatchObject({
      label: "Has access",
      text: "alex@example.com can view your personal vaults since t9.",
    });
    // Confirmed before emergency keys: confirm again.
    expect(grantorStatus(grant("accepted", { reconfirm: true }), when)).toEqual({
      label: "Confirm again",
      text: "PassAuth now gives emergency contacts a key to your personal vaults only. Confirm alex@example.com again to give them access.",
      tone: "warn",
    });
    expect(grantorActions(grant("accepted", { reconfirm: true }))).toContain("confirm");
    expect(grantorStatus(grant("rejected"), when).text).toContain("They can ask again");
  });

  it("tells the contact what each step means", () => {
    expect(granteeStatus(grant("invited"), when).text).toContain("Sam Lee named you as their emergency contact");
    expect(granteeStatus(grant("accepted"), when).text).toBe("Waiting for Sam Lee to confirm you.");
    expect(granteeStatus(grant("confirmed"), when).text).toContain("Sam Lee is told at once and has 7 days to say no");
    expect(granteeStatus(grant("requested", { auto_approve_at: 5000 }), when).text).toContain("you can view their vaults from t5000");
    expect(granteeStatus(grant("approved"), when)).toMatchObject({ label: "Access granted", tone: "ok" });
    expect(granteeStatus(grant("rejected"), when).text).toContain("You can ask again");
  });
});

describe("actions", () => {
  it("offers the grantor what each step allows", () => {
    expect(grantorActions(grant("invited"))).toEqual(["wait", "remove"]);
    expect(grantorActions(grant("accepted"))).toEqual(["confirm", "wait", "remove"]);
    expect(grantorActions(grant("confirmed"))).toEqual(["wait", "remove"]);
    expect(grantorActions(grant("requested"))).toEqual(["approve", "reject", "wait", "remove"]);
    expect(grantorActions(grant("approved"))).toEqual(["end", "wait", "remove"]);
    expect(grantorActions(grant("rejected"))).toEqual(["wait", "remove"]);
  });

  it("offers the contact what each step allows", () => {
    expect(granteeActions(grant("invited"))).toEqual(["accept", "decline"]);
    expect(granteeActions(grant("accepted"))).toEqual(["remove"]);
    expect(granteeActions(grant("confirmed"))).toEqual(["request", "remove"]);
    expect(granteeActions(grant("requested"))).toEqual(["remove"]);
    expect(granteeActions(grant("approved"))).toEqual(["view", "remove"]);
    expect(granteeActions(grant("rejected"))).toEqual(["request", "remove"]);
  });

  it("counts what waits for an answer", () => {
    expect(needsAnswer({ asGrantor: [grant("accepted"), grant("requested"), grant("approved")], asGrantee: [grant("invited"), grant("confirmed")] })).toBe(3);
    expect(needsAnswer({ asGrantor: [], asGrantee: [] })).toBe(0);
  });
});

describe("what is said about the keys", () => {
  it("says what confirming gives, before it is done", () => {
    const text = confirmMeaning("Alex");
    expect(text).toBe(
      "Confirming gives Alex a key to your personal vaults. Once they get access (or at once, if your server is ever compromised), they can read everything in those vaults. Shared vaults and Sends stay out of reach. If you remove them, PassAuth changes the keys of those vaults, so they can't read anything you add afterwards, unless your server is later compromised.",
    );
    expect(reconfirmText("Alex")).toContain("Confirm Alex again");
  });

  it("says when removing a contact changes keys and deletes earlier versions", () => {
    expect(removalText(grant("invited"))).toBe("alex@example.com can't ask for access any more.");
    expect(removalText(grant("accepted"))).toBe("alex@example.com can't ask for access any more.");
    const confirmed = removalText(grant("confirmed"));
    expect(confirmed).toContain("PassAuth changes the keys of your personal vaults");
    expect(confirmed).toContain("deletes the earlier versions");
    expect(confirmed).not.toContain("keep what they saw");
    for (const status of ["requested", "approved", "rejected"] as const) {
      expect(removalText(grant(status))).toContain("changes the keys");
      expect(removalText(grant(status))).toContain("keep what they saw");
    }
  });
});

describe("which vaults get the contact's key", () => {
  const own = { id: "v1", role: "owner" as const, kind: "account" as const };
  const me = "user-sam";
  const alone = [{ user_id: me }];

  it("takes only vaults this app sees as personal: owned with the own key, nobody else in them", () => {
    expect(isPersonal(own, alone, me)).toBe(true);
    expect(isPersonal(own, [...alone, { user_id: "user-alex" }], me)).toBe(false);
    expect(isPersonal(own, [{ user_id: "user-alex" }], me)).toBe(false);
    expect(isPersonal(own, [], me)).toBe(false);
    expect(isPersonal(own, null, me)).toBe(false);
    expect(isPersonal(undefined, alone, me)).toBe(false);
    expect(isPersonal({ ...own, role: "admin" }, alone, me)).toBe(false);
    expect(isPersonal({ ...own, kind: "sealed" }, alone, me)).toBe(false);
    expect(isPersonal(own, alone, "")).toBe(false);
  });

  it("never wraps a vault the server lists but this app sees as shared", () => {
    const personal = new Set(["v1", "v2"]);
    expect(vaultsToWrap(["v1", "v3", "v2", "v1"], (id) => personal.has(id))).toEqual({ wrap: ["v1", "v2"], refused: ["v3"] });
    expect(vaultsToWrap([], () => true)).toEqual({ wrap: [], refused: [] });
  });

  it("adds wraps only for accesses that hold keys, have this account's key and miss vaults", () => {
    const fill = (status: GrantStatus, extra: Record<string, unknown>) => grant(status, { grantor_key: "gk", missing_vaults: ["v1"], key_version: 2, ...extra });
    const todo = [
      fill("confirmed", {}),
      fill("requested", {}),
      fill("approved", {}),
      fill("rejected", {}),
      fill("accepted", {}),
      fill("invited", {}),
      fill("approved", { grantor_key: null }),
      fill("approved", { missing_vaults: [] }),
      fill("approved", { key_version: 3 }),
    ];
    expect(accessesToFill(todo).map((g) => g.status)).toEqual(["confirmed", "requested", "approved", "rejected"]);
    expect(hasKeys(grant("accepted"))).toBe(false);
  });

  it("reads what the grantor's listing adds", () => {
    const g = grant("confirmed", { key_version: 2, grantor_key: "gk", reconfirm: false, missing_vaults: ["v2", 5, "v2", ""] });
    expect(g).toMatchObject({ keyVersion: 2, grantorKey: "gk", reconfirm: false, missingVaults: ["v2"] });
    expect(grant("confirmed")).toMatchObject({ keyVersion: null, grantorKey: null, reconfirm: false, missingVaults: [] });
    expect(grant("accepted", { reconfirm: "yes" }).reconfirm).toBe(false);
  });

  it("reads which vaults need new keys after a removal", () => {
    expect(vaultsToRotate({ ok: true, rotation_pending: ["v1", "v2"] })).toEqual(["v1", "v2"]);
    expect(vaultsToRotate({ ok: true })).toEqual([]);
    expect(vaultsToRotate({ rotation_pending: "v1" })).toEqual([]);
    expect(vaultsToRotate(null)).toEqual([]);
  });
});

describe("the grantor's vault", () => {
  it("maps rows to what the core decrypts", () => {
    const data = readGrantorVault({
      grant: raw("approved"),
      key_version: 2,
      sealed_key: "sealed",
      vaults: [{ id: "v1", meta: "m", wrapped_key: "w", key_epoch: 2 }, { id: "v2" }],
      items: [
        { id: "i1", vault_id: "v1", item_key: "ik", data: "d", revision: 3, deleted_at: null, created_at: 1, updated_at: 2 },
        { id: "i2", vault_id: "v1", item_key: "ik2", data: "d2", revision: 4, deleted_at: 50, created_at: 1, updated_at: 3 },
        { id: "i3", vault_id: "v1", data: "no key" },
      ],
    })!;
    expect(data.sealedKey).toBe("sealed");
    expect(data.keyVersion).toBe(2);
    expect(data.vaults).toEqual([{ id: "v1", meta: "m", wrappedKey: "w", keyEpoch: 2, manifest: null, manifestSeq: 0, manifestPrev: null }]);
    // A row this app can't read is counted: a vault with a manifest then shows its warning.
    expect(data.malformed).toBe(1);
    const withManifest = readGrantorVault({ sealed_key: "s", vaults: [{ id: "v1", meta: "m", wrapped_key: "w", key_epoch: 1, manifest: "abc", manifest_seq: 4, manifest_prev: "pp" }, { id: "v2", meta: "m", wrapped_key: "w", manifest_seq: "x" }], items: [] })!;
    expect(withManifest.vaults.map((v) => [v.manifest, v.manifestSeq, v.manifestPrev])).toEqual([["abc", 4, "pp"], [null, -1, null]]);
    // A row whose trash time is neither null nor a whole number is no row (the trash state is `deleted_at` not null).
    const odd = readGrantorVault({ sealed_key: "s", vaults: [], items: [0, 5, 1.5, -1, "7", true, null, undefined].map((at, n) => ({ id: `i${n}`, vault_id: "v1", item_key: "k", data: "d", deleted_at: at })) })!;
    expect(odd.items.map((i) => i.deletedAt)).toEqual([0, 5, null, null]);
    expect(odd.malformed).toBe(4);
    expect(data.items).toEqual([
      { row: { id: "i1", vault_id: "v1", key: "ik", data: "d" }, deletedAt: null, updatedAt: 2 },
      { row: { id: "i2", vault_id: "v1", key: "ik2", data: "d2" }, deletedAt: 50, updatedAt: 3 },
    ]);
  });

  it("refuses an answer without the sealed key", () => {
    expect(readGrantorVault({ vaults: [], items: [] })).toBeNull();
    expect(readGrantorVault(null)).toBeNull();
  });

  it("tells answers from servers before emergency keys", () => {
    expect(readGrantorVault({ sealed_key: "s", vaults: [], items: [] })!.keyVersion).toBeNull();
  });
});

describe("contacts confirmed before emergency keys", () => {
  it("reads the flag and says what removing can't undo", () => {
    const g = grant("approved", { v1_exposed: true });
    expect(g.v1Exposed).toBe(true);
    expect(grant("approved").v1Exposed).toBe(false);
    const warning = v1Warning("Alex");
    expect(warning).toBe(
      "Alex was confirmed with an earlier version of PassAuth, which gave them your account key. Removing them can't take that back. If you no longer trust them, change the passwords that matter or move to a new account.",
    );
    // No promise about what they can't read afterwards, in the confirm step or when removing.
    expect(confirmMeaning("Alex", true)).toContain(warning);
    expect(confirmMeaning("Alex", true)).not.toContain("can't read anything you add afterwards");
    const removal = removalText(grant("approved", { v1_exposed: true }));
    expect(removal).toContain("changes the keys of your personal vaults");
    expect(removal).toContain(v1Warning("alex@example.com"));
    expect(removal).not.toContain("can't read anything you add afterwards");
    expect(removalText(grant("accepted", { v1_exposed: true, reconfirm: true }))).toContain("gave them your account key");
  });
});

describe("the roster", () => {
  const entry = (id: string, contactKey = `pk-${id}`, grantorKeyHash = `h-${id}`) => ({ id, contactKey, grantorKeyHash });
  const roster = (version: number, accesses: RosterEntry[], removed: { id: string; grantorKeyHash: string }[] = []): Roster => ({ version, accesses, removed });

  it("reads and writes its JSON, and refuses anything malformed", () => {
    const r = roster(3, [entry("g1"), entry("g2")], [{ id: "g0", grantorKeyHash: "h-g0" }]);
    expect(readRoster(rosterJson(r))).toEqual(r);
    expect(JSON.parse(rosterJson(r))).toEqual({
      version: 3,
      accesses: [
        { id: "g1", contact_key: "pk-g1", grantor_key_hash: "h-g1" },
        { id: "g2", contact_key: "pk-g2", grantor_key_hash: "h-g2" },
      ],
      removed: [{ id: "g0", grantor_key_hash: "h-g0" }],
    });
    // Rosters from before `removed` have none.
    expect(readRoster('{"version":1,"accesses":[]}')).toEqual(roster(1, []));
    for (const bad of [
      "",
      "nonsense",
      "null",
      "[]",
      '{"version":-1,"accesses":[]}',
      '{"version":1.5,"accesses":[]}',
      '{"version":1}',
      '{"version":1,"accesses":[{"id":"g1"}]}',
      '{"version":1,"accesses":[],"removed":{}}',
      '{"version":1,"accesses":[],"removed":[{"id":"g1"}]}',
    ]) {
      expect(readRoster(bad), bad).toBeNull();
    }
  });

  it("goes up a version with every change, past what this device has seen", () => {
    const added = nextRoster(EMPTY_ROSTER, 0, { add: entry("g1") })!;
    expect(added).toEqual(roster(1, [entry("g1")]));
    const replaced = nextRoster(added, 0, { add: entry("g1", "pk-new", "h-new") })!;
    expect(replaced).toEqual(roster(2, [entry("g1", "pk-new", "h-new")]));
    // Removing keeps the access as removed, with its key's hash.
    expect(nextRoster(replaced, 0, { remove: "g1" })).toEqual(roster(3, [], [{ id: "g1", grantorKeyHash: "h-new" }]));
    // A device that opened version 9 writes 10, whatever it read.
    expect(nextRoster(added, 9, { add: entry("g2") })!.version).toBe(10);
    // Nothing to change, nothing to write; an access the roster doesn't have is removed only with its key's hash.
    expect(nextRoster(added, 0, { remove: "g9" })).toBeNull();
    expect(nextRoster(added, 0, { remove: "g9", hash: "h-g9" })).toEqual(roster(2, [entry("g1")], [{ id: "g9", grantorKeyHash: "h-g9" }]));
    expect(nextRoster(added, 0, null, new Set(["g1"]))).toBeNull();
  });

  it("keeps the name and email the grantor confirmed, and reads entries from before without them", () => {
    const g = grant("approved", { id: "g1", grantee: { id: "u2", email: "alex@example.com", name: " Alex ", public_key: "pk-listed" } });
    const e = rosterEntry(g, "pk-checked", "h-1");
    expect(e).toEqual({ id: "g1", contactKey: "pk-checked", grantorKeyHash: "h-1", email: "alex@example.com", name: "Alex" });
    expect(readRoster(rosterJson(roster(1, [e])))!.accesses[0]).toEqual(e);
    expect(readRoster('{"version":1,"accesses":[{"id":"g1","contact_key":"k","grantor_key_hash":"h","email":5}]}')).toBeNull();
    expect(entryLabel(e)).toBe("Alex (alex@example.com)");
    expect(entryLabel(entry("g2"))).toBe("Unknown contact");
  });

  it("is refused when older than one this device opened (a server sending back removed contacts)", () => {
    expect(rosterIsOlder(roster(4, []), 5)).toBe(true);
    expect(rosterIsOlder(roster(5, []), 5)).toBe(false);
    expect(rosterIsOlder(roster(6, []), 5)).toBe(false);
    // No roster at all after one was seen counts as older.
    expect(rosterIsOlder(EMPTY_ROSTER, 1)).toBe(true);
    expect(rosterIsOlder(EMPTY_ROSTER, 0)).toBe(false);
  });

  it("names grantor keys by their SHA-256 in base64url", async () => {
    expect(await sha256b64("abc")).toBe("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
    expect(await sha256b64("")).toBe("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
  });

  it("keeps at most 300 removed accesses, the newest, and stays under the server's size limit", () => {
    const many = Array.from({ length: 310 }, (_, i) => ({ id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`, grantorKeyHash: "x".repeat(43) }));
    let r: Roster = roster(1, []);
    for (const x of many) r = nextRoster(r, 0, { remove: x.id, hash: x.grantorKeyHash })!;
    expect(r.removed.length).toBeLessThanOrEqual(MAX_REMOVED);
    expect(r.removed.at(-1)!.id).toBe(many.at(-1)!.id);
    expect(r.removed.some((x) => x.id === many[0].id)).toBe(false);
    expect(sealedLength(r)).toBeLessThanOrEqual(MAX_SEALED_ROSTER);
    // A roster too large for the server is refused: removed entries are never dropped to make room.
    const big = Array.from({ length: 50 }, (_, i) => ({ ...entry(`c${i}`), name: "N".repeat(100), email: `${"e".repeat(240)}@x.example` }));
    expect(() => nextRoster({ ...r, accesses: big }, 0, { remove: "00000000-0000-4000-8000-999999999999", hash: "y".repeat(43) })).toThrow(
      RosterFullError,
    );
    // Fewer removed accesses leave room for the same contacts.
    const roomy = nextRoster({ ...roster(1, []), accesses: big }, 0, { remove: "00000000-0000-4000-8000-999999999999", hash: "y".repeat(43) })!;
    expect(roomy.accesses).toHaveLength(50);
    expect(sealedLength(roomy)).toBeLessThanOrEqual(MAX_SEALED_ROSTER);
  });

  it("keeps names and emails on one line, without invisible characters, and bounded", () => {
    const padded = grant("approved", {
      id: "g1",
      grantee: { id: "u2", email: `${"\u200b".repeat(10000)}alex@example.com`, name: `${"A".repeat(500)}\u202e`, public_key: "pk" },
    });
    const e = rosterEntry(padded, "pk", "h-1");
    expect(e.email).toBe("alex@example.com");
    expect(Array.from(e.name ?? "").length).toBeLessThanOrEqual(MAX_NAME);
    expect(Array.from(rosterEntry(grant("approved", { id: "g2", grantee: { id: "u3", email: "e".repeat(400), name: "B", public_key: "pk" } }), "pk", "h").email ?? "").length).toBeLessThanOrEqual(MAX_EMAIL);
  });

  it("keeps this device's own removed accesses over the server's when trimming", () => {
    const ids = (n: number, p: string) => Array.from({ length: n }, (_, i) => ({ id: `${p}-${i}`, grantorKeyHash: "h".repeat(43) }));
    const server = roster(3, [], ids(MAX_REMOVED, "server"));
    const trusted = roster(5, [], [{ id: "mine", grantorKeyHash: "m".repeat(43) }]);
    const forward = restoredRosterForward([], server, trusted, 5, new Set());
    expect(forward.removed.some((x) => x.id === "mine")).toBe(true);
    expect(forward.removed.length).toBe(MAX_REMOVED);
  });

  it("is read from the listing", () => {
    expect(readGrants({ as_grantor: [], as_grantee: [], roster: "c2VhbGVk", roster_seq: 4 })).toMatchObject({ roster: "c2VhbGVk", rosterSeq: 4 });
    expect(readGrants({ as_grantor: [], as_grantee: [], roster: null, roster_seq: 0 })).toMatchObject({ roster: null, rosterSeq: 0 });
    expect(readGrants({ as_grantor: [], as_grantee: [] })).toMatchObject({ roster: null, rosterSeq: null });
    expect(readGrants({ roster: 5, roster_seq: -1 })).toMatchObject({ roster: null, rosterSeq: null });
  });
});

describe("which accesses get more vault keys", () => {
  const listed = (id: string, extra: Record<string, unknown> = {}) =>
    grant("approved", { id, grantor_key: `gk-${id}`, missing_vaults: ["v1"], key_version: 2, grantee: { id: "user-alex", email: "alex@example.com", name: "", public_key: "pk-alex" }, ...extra });
  const hashes = new Map([
    ["gk-g1", "h-g1"],
    ["gk-g2", "h-g2"],
    ["gk-g3", "h-g3"],
    ["gk-g5", "h-g5"],
  ]);
  const roster: Roster = {
    version: 2,
    accesses: [
      { id: "g1", contactKey: "pk-alex", grantorKeyHash: "h-g1" },
      { id: "g2", contactKey: "pk-alex", grantorKeyHash: "h-other" },
      { id: "g3", contactKey: "pk-someone-else", grantorKeyHash: "h-g3" },
      { id: "g5", contactKey: "pk-alex", grantorKeyHash: "h-g5" },
    ],
    // g5's key was removed under another access: refused too.
    removed: [{ id: "g6", grantorKeyHash: "h-g5" }],
  };

  it("only those in the roster with the same contact key and grantor key, and never a removed one", () => {
    const grants = [listed("g1"), listed("g2"), listed("g3"), listed("g4"), listed("g5")];
    // g2: another grantor key than the one confirmed; g3: another contact key; g4: not in the roster; g5: removed key.
    expect(fillableAccesses(grants, roster, hashes).map((g) => g.id)).toEqual(["g1"]);
    expect(fillableAccesses(grants, EMPTY_ROSTER, hashes)).toEqual([]);
    // Still only accesses that hold keys and miss vaults.
    expect(fillableAccesses([listed("g1", { missing_vaults: [] })], roster, hashes)).toEqual([]);
    expect(fillableAccesses([listed("g1", { status: "accepted" })], roster, hashes)).toEqual([]);
  });
});

describe("which vault keys a removal replaces", () => {
  it("only the vaults the server names that this app sees as personal", () => {
    const personal = new Set(["v1", "v3"]);
    const answer = { ok: true, rotation_pending: ["v1", "v2", "v3", "v4"] };
    expect(vaultsToReKey(answer, (id) => personal.has(id))).toEqual(["v1", "v3"]);
    expect(vaultsToReKey({ ok: true }, () => true)).toEqual([]);
    expect(vaultsToReKey(answer, () => false)).toEqual([]);
  });
});

describe("using the server's list after a restore", () => {
  const e = (id: string, contactKey = `pk-${id}`, name?: string): RosterEntry => ({
    id,
    contactKey,
    grantorKeyHash: `h-${id}`,
    ...(name ? { name, email: `${id}@example.com` } : {}),
  });

  it("writes exactly what was shown, one version above the newest this device saw, so nothing older comes back", () => {
    const seen = 7;
    const server: Roster = { version: 4, accesses: [e("g1"), e("g9")], removed: [] };
    expect(rosterIsOlder(server, seen)).toBe(true);
    // g9 wasn't listed at the review, so it wasn't shown: it is kept as removed, never written as an access.
    const shown = reviewRoster(server, null, new Set(["g1"]));
    const forward = restoredRosterForward(shown, server, null, seen, new Set(["g1", "g9"]));
    expect(forward).toEqual({ version: 8, accesses: [e("g1")], removed: [{ id: "g9", grantorKeyHash: "h-g9" }] });
    // Remembered once stored: the restored version and every one in between are refused from then on.
    for (const version of [4, 5, 6, 7]) expect(rosterIsOlder({ ...server, version }, forward.version), String(version)).toBe(true);
    expect(rosterIsOlder(forward, forward.version)).toBe(false);
    // A shown entry the server no longer lists when writing is left out too; no roster on the server at all: empty.
    expect(restoredRosterForward(shown, server, null, seen, new Set()).accesses).toEqual([]);
    expect(restoredRosterForward([], EMPTY_ROSTER, null, seen, new Set())).toEqual({ version: 8, accesses: [], removed: [] });
  });

  it("marks who this device's last trusted list doesn't have or removed, with names from inside the list", () => {
    const trusted: Roster = { version: 7, accesses: [e("g1", "pk-g1", "Sam")], removed: [{ id: "g5", grantorKeyHash: "h-g5" }] };
    // The server's (restored) list: g1 as before, g2 removed since, g3 with another key, g4 it no longer lists, g5 removed here.
    const server: Roster = {
      version: 4,
      accesses: [e("g1", "pk-g1", "Sam"), e("g2", "pk-g2", "Eve"), e("g3", "pk-other", "Max"), e("g4", "pk-g4", "Ann"), e("g5", "pk-g5", "Bo")],
      removed: [],
    };
    const review = reviewRoster(server, trusted, new Set(["g1", "g2", "g3", "g5"]));
    expect(review.map((r) => [r.entry.id, r.wouldReturn, r.removed])).toEqual([
      ["g1", false, false],
      ["g2", true, false],
      ["g3", true, false],
      ["g5", true, true],
    ]);
    // Names come from the list itself, never from the server's listing.
    expect(review.map((r) => entryLabel(r.entry))).toEqual(["Sam (g1@example.com)", "Eve (g2@example.com)", "Max (g3@example.com)", "Bo (g5@example.com)"]);
    // What is written keeps g5 removed (this device's own removal wins) and g4 too (not shown).
    const forward = restoredRosterForward(review, server, trusted, 7, new Set(["g1", "g2", "g3", "g5"]));
    expect(forward.accesses.map((x) => x.id)).toEqual(["g1", "g2", "g3"]);
    expect(forward.removed.map((x) => x.id).sort()).toEqual(["g4", "g5"]);
    // A device that keeps no list of its own marks everyone.
    expect(reviewRoster(server, null, new Set(["g1"])).map((r) => r.wouldReturn)).toEqual([true]);
  });

  it("starts a new, empty list above what this device saw, keeping what it removed", () => {
    const trusted: Roster = { version: 7, accesses: [e("g1")], removed: [{ id: "g0", grantorKeyHash: "h-g0" }] };
    expect(freshRoster(7)).toEqual({ version: 8, accesses: [], removed: [] });
    const fresh = freshRoster(7, trusted);
    expect(fresh).toEqual({ version: 8, accesses: [], removed: [{ id: "g0", grantorKeyHash: "h-g0" }] });
    expect(needsConfirmAgain(grant("approved", { id: "g1" }), fresh)).toBe(true);
    expect(needsConfirmAgain(grant("approved", { id: "g0" }), fresh)).toBe(false);
    expect(needsConfirmAgain(grant("accepted", { id: "g1" }), fresh)).toBe(false);
    // Not while the list can't be trusted (nothing to compare with).
    expect(needsConfirmAgain(grant("approved", { id: "g1" }), null)).toBe(false);
  });
});

describe("accesses that ended or were removed", () => {
  const listedGrant = (id: string, extra: Record<string, unknown> = {}) =>
    grant("approved", { id, grantor_key: `gk-${id}`, missing_vaults: ["v1"], key_version: 2, grantee: { id: "u2", email: "alex@example.com", name: "Alex", public_key: "pk-alex" }, ...extra });
  const hashes = new Map([["gk-g1", "h-g1"]]);
  const roster: Roster = { version: 3, accesses: [{ id: "g1", contactKey: "pk-alex", grantorKeyHash: "h-g1" }], removed: [] };

  it("leave the roster for good when the server no longer lists them: a replay gets nothing, and no Confirm again", () => {
    // The contact stepped down: the server lists nothing for g1, so the next write drops it and keeps it as removed.
    expect(pruneRoster(roster, new Set())).toEqual([]);
    const pruned = nextRoster(roster, 3, null, new Set())!;
    expect(pruned).toEqual({ version: 4, accesses: [], removed: [{ id: "g1", grantorKeyHash: "h-g1" }] });
    // Later a server lists g1 again, with its old key: no wraps, and it can't come back through Confirm again.
    expect(fillableAccesses([listedGrant("g1")], pruned, hashes)).toEqual([]);
    expect(needsConfirmAgain(listedGrant("g1"), pruned, "h-g1")).toBe(false);
    expect(isRemoved(pruned, "g1")).toBe(true);
    expect(removedText("Alex")).toBe("Alex was removed from your emergency contacts. To give them access again, add them as a new contact.");
    // Pruning again never drops what was removed.
    expect(nextRoster(pruned, 4, null, new Set())).toBeNull();
    expect(nextRoster(pruned, 4, { add: { id: "g2", contactKey: "k", grantorKeyHash: "h-g2" } }, new Set(["g2"]))!.removed).toEqual(pruned.removed);
  });

  it("missing without being removed (a lost write) come back through Confirm again", () => {
    const lost: Roster = { version: 4, accesses: [], removed: [] };
    const g = listedGrant("g1");
    expect(needsConfirmAgain(g, lost, "h-g1")).toBe(true);
    const back = nextRoster(lost, 4, { add: rosterEntry(g, "pk-alex", "h-g1") }, new Set(["g1"]))!;
    expect(back.version).toBe(5);
    expect(needsConfirmAgain(g, back, "h-g1")).toBe(false);
    expect(fillableAccesses([g], back, hashes).map((x) => x.id)).toEqual(["g1"]);
  });
});
