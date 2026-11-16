import { describe, expect, it } from "vitest";
import { mergeSync } from "./delta";
import { invitationNotice, invitationsKey, openInvitations, readInvitations, sharerName, type Invitation } from "./invitations";
import type { SyncResponse } from "./types";

const ALEX = { id: "user-alex", email: "alex@example.com", name: "Alex Morgan", public_key: "pk-alex" };

function raw(vaultId: string, more: Record<string, unknown> = {}) {
  return { vault_id: vaultId, role: "read", wrapped_key: `sealed-${vaultId}`, meta: `meta-${vaultId}`, invited_by: ALEX, invited_at: 1_700_000_000, ...more };
}

describe("readInvitations", () => {
  it("reads the server's list", () => {
    expect(readInvitations([raw("v1")])).toEqual([
      { vault_id: "v1", role: "read", wrapped_key: "sealed-v1", meta: "meta-v1", invited_by: ALEX, invited_at: 1_700_000_000 },
    ]);
  });

  it("is empty for servers without invitations", () => {
    expect(readInvitations(undefined)).toEqual([]);
    expect(readInvitations(null)).toEqual([]);
    expect(readInvitations({})).toEqual([]);
  });

  it("leaves out entries it can't use and counts a vault once", () => {
    const list = readInvitations([
      raw("v1"),
      raw("v1", { role: "write" }),
      raw("", {}),
      raw("v2", { wrapped_key: "" }),
      raw("v3", { meta: 7 }),
      raw("v4", { role: null }),
      "nonsense",
      null,
      raw("v5"),
    ]);
    expect(list.map((i) => [i.vault_id, i.role])).toEqual([
      ["v1", "read"],
      ["v5", "read"],
    ]);
  });

  it("keeps an invitation whose sharer is gone, or whose role is new", () => {
    const [gone, future] = readInvitations([raw("v1", { invited_by: null, invited_at: null }), raw("v2", { role: "auditor", invited_by: { id: "u", email: null } })]);
    expect(gone).toMatchObject({ invited_by: null, invited_at: null });
    expect(future).toMatchObject({ role: "auditor", invited_by: { id: "u", email: "", name: "", public_key: "" } });
  });
});

describe("openInvitations", () => {
  it("reads each vault's name and says when it can't", () => {
    const list = readInvitations([raw("v1"), raw("v2"), raw("v3", { invited_by: null })]);
    const shown = openInvitations(list, (inv) => {
      if (inv.vault_id === "v2") throw new Error("decrypt_failed");
      return inv.vault_id === "v1" ? "Family" : null;
    });
    expect(shown).toEqual([
      { vaultId: "v1", role: "read", name: "Family", invitedBy: { id: ALEX.id, email: ALEX.email, name: ALEX.name, publicKey: ALEX.public_key }, invitedAt: 1_700_000_000 },
      { vaultId: "v2", role: "read", name: null, invitedBy: { id: ALEX.id, email: ALEX.email, name: ALEX.name, publicKey: ALEX.public_key }, invitedAt: 1_700_000_000 },
      { vaultId: "v3", role: "read", name: null, invitedBy: null, invitedAt: 1_700_000_000 },
    ]);
  });
});

describe("wording", () => {
  const inv = (more: Partial<Invitation> = {}): Invitation => ({
    vaultId: "v1",
    role: "read",
    name: "Family",
    invitedBy: { id: ALEX.id, email: ALEX.email, name: ALEX.name, publicKey: ALEX.public_key },
    invitedAt: 1,
    ...more,
  });

  it("names the sharer", () => {
    expect(sharerName(inv())).toBe("Alex Morgan (alex@example.com)");
    expect(sharerName(inv({ invitedBy: { id: "u", email: "bo@example.com", name: " ", publicKey: "" } }))).toBe("bo@example.com");
    expect(sharerName(inv({ invitedBy: null }))).toBe("Someone whose account was deleted");
  });

  it("says who invited you, or how many invitations wait", () => {
    expect(invitationNotice([])).toBeNull();
    expect(invitationNotice([inv()])).toBe('Alex Morgan invited you to the shared vault "Family".');
    expect(invitationNotice([inv({ name: null, invitedBy: null })])).toBe("Someone invited you to a shared vault.");
    expect(invitationNotice([inv(), inv({ vaultId: "v2" })])).toBe("You have 2 invitations to shared vaults.");
  });

  it("identifies a set of invitations whatever their order", () => {
    expect(invitationsKey([inv({ vaultId: "b" }), inv({ vaultId: "a" })])).toBe(invitationsKey([inv({ vaultId: "a" }), inv({ vaultId: "b" })]));
    expect(invitationsKey([inv({ vaultId: "a" })])).not.toBe(invitationsKey([inv({ vaultId: "a" }), inv({ vaultId: "b" })]));
  });
});

describe("invitations in the sync state", () => {
  const USER = { id: "user-1", email: "sam@example.com", name: "Sam", email_verified: true };
  const BUNDLE = { account_id: "acct-1", kdf: {}, secret_key_enabled: false };
  const vault = { id: "A", meta: "m", role: "owner" as const, wrapped_key: "wk", key_kind: "account" as const, key_epoch: 0, seq: 1 };

  it("keeps the list of every answer, full or delta", () => {
    const full: SyncResponse = { revision: 1, cursor: "c1", user: USER, bundle: BUNDLE, vaults: [vault], items: [], invitations: [raw("v1"), raw("v2")] as SyncResponse["invitations"] };
    const first = mergeSync(null, full)!.snapshot;
    expect(first.invitations.map((i) => i.vault_id)).toEqual(["v1", "v2"]);

    // v1 accepted: it leaves the list, and the vault arrives whole (reset).
    const delta: SyncResponse = {
      revision: 2,
      cursor: "c2",
      user: USER,
      bundle: BUNDLE,
      vaults: [vault, { ...vault, id: "v1", role: "read", key_kind: "sealed" }],
      items: [],
      deleted: [],
      reset: ["v1"],
      delta: true,
      invitations: [raw("v2")] as SyncResponse["invitations"],
    };
    const next = mergeSync(first, delta)!.snapshot;
    expect(next.invitations.map((i) => i.vault_id)).toEqual(["v2"]);

    // An answer without the field (an older server) has none.
    const old: SyncResponse = { revision: 3, user: USER, bundle: BUNDLE, vaults: [vault], items: [] };
    expect(mergeSync(next, old)!.snapshot.invitations).toEqual([]);
  });
});
