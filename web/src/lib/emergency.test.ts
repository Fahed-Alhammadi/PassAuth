import { describe, expect, it } from "vitest";
import {
  daysText,
  grantorActions,
  grantorStatus,
  granteeActions,
  granteeStatus,
  needsAnswer,
  personName,
  readGrant,
  readGrantorVault,
  readGrants,
  validWait,
  type Grant,
  type GrantStatus,
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
    expect(readGrants(null)).toEqual({ asGrantor: [], asGrantee: [] });
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
      "alex@example.com asked for access on t1000. Unless you reject it, they can view your vaults from t5000.",
    );
    expect(grantorStatus(grant("requested"), when).text).toContain("after 7 days");
    expect(grantorStatus(grant("approved", { approved_at: 9 }), when)).toMatchObject({ label: "Has access", text: "alex@example.com can view your vaults since t9." });
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

describe("the grantor's vault", () => {
  it("maps rows to what the core decrypts", () => {
    const data = readGrantorVault({
      grant: raw("approved"),
      sealed_key: "sealed",
      vaults: [{ id: "v1", meta: "m", wrapped_key: "w", key_epoch: 2 }, { id: "v2" }],
      items: [
        { id: "i1", vault_id: "v1", item_key: "ik", data: "d", revision: 3, deleted_at: null, created_at: 1, updated_at: 2 },
        { id: "i2", vault_id: "v1", item_key: "ik2", data: "d2", revision: 4, deleted_at: 50, created_at: 1, updated_at: 3 },
        { id: "i3", vault_id: "v1", data: "no key" },
      ],
    })!;
    expect(data.sealedKey).toBe("sealed");
    expect(data.vaults).toEqual([{ id: "v1", meta: "m", wrappedKey: "w" }]);
    expect(data.items).toEqual([
      { row: { id: "i1", vault_id: "v1", key: "ik", data: "d" }, deletedAt: null, updatedAt: 2 },
      { row: { id: "i2", vault_id: "v1", key: "ik2", data: "d2" }, deletedAt: 50, updatedAt: 3 },
    ]);
  });

  it("refuses an answer without the sealed key", () => {
    expect(readGrantorVault({ vaults: [], items: [] })).toBeNull();
    expect(readGrantorVault(null)).toBeNull();
  });
});
