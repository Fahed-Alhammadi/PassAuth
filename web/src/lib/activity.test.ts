import { describe, expect, it } from "vitest";
import { collapseMoves, describeEvent, EVENT_TYPES, readEventPage, type ActivityEvent, type DescribeContext } from "./activity";

const ME = "user-me";
const VAULTS: Record<string, string> = { "v-personal": "Personal", "v-family": "Family" };
const ITEMS: Record<string, string> = { "i-github": "GitHub" };

const account: DescribeContext = { me: ME, vaultName: (id) => VAULTS[id] ?? null, itemName: (id) => ITEMS[id] ?? null };
const admin: DescribeContext = { me: null, admin: true, vaultName: (id) => VAULTS[id] ?? null, itemName: (id) => ITEMS[id] ?? null };

const me = { id: ME, email: "me@example.com", name: "Sam Lee" };
const alex = { id: "user-alex", email: "alex@example.com", name: "Alex Morgan" };

function ev(type: string, more: Partial<ActivityEvent> = {}): ActivityEvent {
  return { id: `e-${type}`, at: 1_700_000_000, type, actor: me, client: null, ip: null, vault_id: null, item_id: null, target_user: null, data: {}, ...more };
}

/** Every type the server writes (crates/server/src/events.rs and its callers). */
const SERVER_TYPES = [
  "account.created",
  "account.deleted",
  "account.password_changed",
  "account.recovery_codes_created",
  "account.security_key_added",
  "account.security_key_removed",
  "account.two_step_disabled",
  "account.two_step_enabled",
  "admin.recovery_codes_created",
  "admin.sessions_revoked",
  "admin.settings_changed",
  "admin.signed_in",
  "admin.two_step_disabled",
  "admin.two_step_enabled",
  "admin.two_step_reset",
  "admin.user_deleted",
  "admin.user_disabled",
  "admin.user_enabled",
  "attachment.added",
  "attachment.deleted",
  "auth.request_approved",
  "auth.request_created",
  "auth.request_denied",
  "auth.signed_in",
  "auth.signin_failed",
  "auth.two_step_locked",
  "emergency.accepted",
  "emergency.approved",
  "emergency.confirmed",
  "emergency.invited",
  "emergency.reconfirm",
  "emergency.rejected",
  "emergency.removed",
  "emergency.requested",
  "emergency.updated",
  "emergency.vaults_added",
  "emergency.viewed",
  "item.created",
  "item.deleted",
  "item.imported",
  "item.moved",
  "item.restored",
  "item.trashed",
  "item.updated",
  "member.accepted",
  "member.declined",
  "member.invited",
  "member.key_updated",
  "member.left",
  "member.removed",
  "member.role_changed",
  "send.accessed",
  "send.created",
  "send.deleted",
  "send.updated",
  "session.device_forgotten",
  "session.revoked",
  "session.revoked_others",
  "session.signed_out",
  "trash.emptied",
  "vault.created",
  "vault.deleted",
  "vault.key_rotated",
  "vault.manifest_reset",
  "vault.manifest_started",
  "vault.renamed",
];

describe("readEventPage", () => {
  it("reads events and the cursor, leaving malformed events out", () => {
    const page = readEventPage({
      events: [
        { id: "a", at: 5, type: "item.updated", actor: alex, client: "desktop/0.7.0", ip: "192.0.2.1", vault_id: "v", item_id: "i", target_user: null, data: null },
        { id: "b", at: "yesterday", type: "item.updated" },
        { at: 5, type: "item.updated" },
        null,
        { id: "c", at: 4, type: "member.invited", actor: { email: "no id" }, target_user: { id: "t", email: null }, data: { role: "read" } },
      ],
      next: "cursor-1",
    });
    expect(page.next).toBe("cursor-1");
    expect(page.events.map((e) => e.id)).toEqual(["a", "c"]);
    expect(page.events[0]).toMatchObject({ client: "desktop/0.7.0", ip: "192.0.2.1", data: {} });
    expect(page.events[1].actor).toBeNull();
    expect(page.events[1].target_user).toEqual({ id: "t", email: null });
  });

  it("treats a missing or empty cursor as the last page", () => {
    expect(readEventPage({ events: [], next: null }).next).toBeNull();
    expect(readEventPage({ events: [], next: "" }).next).toBeNull();
    expect(readEventPage("nonsense")).toEqual({ events: [], next: null });
  });
});

describe("attachments and emergency access", () => {
  const meTarget = { id: ME, email: "me@example.com" };
  const alexTarget = { id: alex.id, email: alex.email };

  it("names the item a file was attached to", () => {
    const t = describeEvent(ev("attachment.added", { vault_id: "v-personal", item_id: "i-github", data: { attachment: "a", size: 3 * 1024 * 1024 + 900 } }), account);
    expect(t.text).toBe('You attached a file to "GitHub" in "Personal"');
    expect(t.detail).toBe("3 MB encrypted.");
    expect(describeEvent(ev("attachment.deleted", { actor: alex, vault_id: "v-family", item_id: "i-x", data: { size: 500 } }), account).text).toBe(
      'Alex Morgan deleted a file of an item in "Family"',
    );
  });

  it("tells each side of an emergency access its own sentence", () => {
    // The grantor's log.
    expect(describeEvent(ev("emergency.invited", { target_user: alexTarget, data: { wait_days: 7 } }), account)).toEqual({
      text: "You named alex@example.com as your emergency contact",
      detail: "Waiting period: 7 days.",
    });
    expect(describeEvent(ev("emergency.accepted", { actor: alex, target_user: meTarget }), account).text).toBe("Alex Morgan accepted being your emergency contact");
    const asked = describeEvent(ev("emergency.requested", { actor: alex, target_user: meTarget, data: { wait_days: 2 } }), account);
    expect(asked).toMatchObject({ text: "Alex Morgan asked for emergency access to your vaults", tone: "warn" });
    expect(asked.detail).toBe("Granted after 2 days unless it is rejected.");
    expect(describeEvent(ev("emergency.viewed", { actor: alex, target_user: meTarget, data: { items: 12 } }), account)).toMatchObject({
      text: "Alex Morgan viewed your vaults through emergency access",
      detail: "12 items.",
      tone: "warn",
    });
    expect(describeEvent(ev("emergency.rejected", { target_user: alexTarget, data: { status: "approved" } }), account).text).toBe("You ended alex@example.com's emergency access");
    expect(describeEvent(ev("emergency.removed", { actor: alex, target_user: meTarget, data: { by: "grantee" } }), account).text).toBe(
      "Alex Morgan stopped being your emergency contact",
    );
    // The contact's log.
    expect(describeEvent(ev("emergency.invited", { actor: alex, target_user: meTarget }), account).text).toBe("Alex Morgan named you as their emergency contact");
    expect(describeEvent(ev("emergency.approved", { actor: alex, target_user: meTarget, data: { automatic: false } }), account).text).toBe(
      "Alex Morgan approved your emergency access",
    );
    expect(describeEvent(ev("emergency.approved", { actor: null, target_user: meTarget, data: { automatic: true } }), account)).toMatchObject({
      text: "Emergency access was granted after the waiting period",
      tone: "warn",
    });
    expect(describeEvent(ev("emergency.updated", { actor: alex, target_user: meTarget, data: { wait_days: 3 } }), account).text).toBe(
      "Alex Morgan changed the waiting period for you to 3 days",
    );
  });

  it("tells the keys of an emergency access", () => {
    expect(describeEvent(ev("emergency.confirmed", { target_user: alexTarget, data: { vaults: 2 } }), account)).toEqual({
      text: "You confirmed alex@example.com as your emergency contact",
      detail: "With a key to 2 personal vaults.",
    });
    expect(describeEvent(ev("emergency.confirmed", { actor: alex, target_user: meTarget, data: { vaults: 2 } }), account).detail).toBeUndefined();
    expect(describeEvent(ev("emergency.vaults_added", { data: { vaults: 1 } }), account).text).toBe(
      "You gave an emergency contact the key to 1 more personal vault",
    );
    expect(describeEvent(ev("emergency.reconfirm", { actor: null, target_user: meTarget }), account)).toEqual({
      text: "Emergency access now uses a key to personal vaults only",
      detail: "A contact confirmed before has to be confirmed again.",
    });
    const removed = describeEvent(ev("emergency.removed", { target_user: alexTarget, data: { by: "grantor", rotate_vaults: 2 } }), account);
    expect(removed).toEqual({
      text: "You removed alex@example.com as your emergency contact",
      detail: "The keys of 2 personal vaults are to be changed.",
    });
  });
});

describe("describeEvent", () => {
  it("has its own words for every type the server writes", () => {
    for (const type of SERVER_TYPES) {
      const t = describeEvent(ev(type), account);
      expect(t.text, type).not.toMatch(/activity( by|$)/);
      expect(t.detail ?? "", type).not.toContain("Recorded as");
      expect(t.text, type).not.toMatch(/undefined|null|NaN/);
    }
  });

  it("lists every server type in the admin filter", () => {
    const listed = EVENT_TYPES.flatMap((c) => c.types.map(([t]) => t));
    expect([...listed].sort()).toEqual([...SERVER_TYPES].sort());
    for (const c of EVENT_TYPES) for (const [t] of c.types) expect(t.startsWith(`${c.category}.`), t).toBe(true);
  });

  it("names the reader's own actions, vaults and items", () => {
    expect(describeEvent(ev("item.updated", { vault_id: "v-personal", item_id: "i-github" }), account).text).toBe('You edited "GitHub" in "Personal"');
    expect(describeEvent(ev("item.created", { vault_id: "v-family", item_id: "i-github", actor: alex }), account).text).toBe('Alex Morgan added "GitHub" to "Family"');
    expect(describeEvent(ev("vault.renamed", { vault_id: "v-family" }), account).text).toBe('You renamed the vault "Family"');
  });

  it("says what can't be decrypted", () => {
    expect(describeEvent(ev("item.deleted", { vault_id: "v-gone", item_id: "i-gone" }), account).text).toBe("You deleted an item for good in a vault you can't open");
    expect(describeEvent(ev("vault.deleted", { vault_id: "v-gone" }), account).text).toBe("You deleted a vault");
    expect(describeEvent(ev("member.removed", { actor: alex, vault_id: "v-gone", target_user: { id: ME, email: me.email }, data: { status: "active", rotated: true } }), account)).toEqual({
      text: "Alex Morgan removed you from a vault you can't open",
      detail: "The vault key was replaced at the same time.",
    });
  });

  it("calls the vault being viewed 'this vault'", () => {
    const ctx = { ...account, vault: "v-family" };
    expect(describeEvent(ev("item.trashed", { actor: alex, vault_id: "v-family", item_id: "i-github" }), ctx).text).toBe('Alex Morgan moved "GitHub" to the trash');
    expect(describeEvent(ev("member.invited", { vault_id: "v-family", target_user: { id: "u-b", email: "bo@example.com" }, data: { role: "write" } }), ctx)).toEqual({
      text: "You invited bo@example.com to this vault",
      detail: "Access: can edit.",
    });
    expect(describeEvent(ev("item.moved", { vault_id: "v-family", item_id: "i-github", data: { to: "v-personal" } }), ctx).text).toBe('You moved "GitHub" from this vault to "Personal"');
  });

  it("describes invitations and their answers", () => {
    const invited = ev("member.invited", { actor: alex, vault_id: "v-family", target_user: { id: ME, email: me.email }, data: { role: "read" } });
    expect(describeEvent(invited, account)).toEqual({ text: 'Alex Morgan invited you to the vault "Family"', detail: "Access: can view." });
    expect(describeEvent(ev("member.accepted", { vault_id: "v-family" }), account).text).toBe('You accepted the invitation to the vault "Family"');
    expect(describeEvent(ev("member.declined", { actor: alex, vault_id: "v-family" }), { ...account, vault: "v-family" }).text).toBe("Alex Morgan declined the invitation to this vault");
    const cancelled = ev("member.removed", { vault_id: "v-family", target_user: { id: "u-b", email: "bo@example.com" }, data: { status: "invited", rotated: false } });
    expect(describeEvent(cancelled, account)).toEqual({ text: 'You cancelled bo@example.com\'s invitation to the vault "Family"', detail: undefined });
    const changed = ev("member.role_changed", { vault_id: "v-family", target_user: { id: "u-b", email: "bo@example.com" }, data: { role: "write", from: "read", status: "invited" } });
    expect(describeEvent(changed, account)).toEqual({ text: 'You changed bo@example.com\'s invitation to the vault "Family"', detail: "From can view to can edit." });
  });

  it("flags failed sign-ins and protective sign-outs", () => {
    const failed = ev("auth.signin_failed", { actor: null, target_user: { id: ME, email: me.email }, data: { reason: "password", count: 3 } });
    expect(describeEvent(failed, account)).toEqual({ text: "Failed sign-in to your account", detail: "Wrong master password, 3 times.", tone: "warn" });
    expect(describeEvent(failed, admin).text).toBe("Failed sign-in to me@example.com");
    const reauth = ev("auth.signin_failed", { actor: null, target_user: { id: ME, email: me.email }, data: { reason: "reauth", count: 1 } });
    expect(describeEvent(reauth, account).detail).toBe("Wrong master password when confirming a change.");
    const locked = ev("auth.two_step_locked", { actor: null, target_user: { id: ME, email: me.email }, data: { seconds: 3600 } });
    expect(describeEvent(locked, account)).toMatchObject({ detail: "For 1 hour.", tone: "warn" });
    const stolen = ev("session.revoked", { actor: null, target_user: { id: ME, email: me.email }, data: { session: "s", reason: "refresh_token_reused" } });
    expect(describeEvent(stolen, account)).toMatchObject({ text: "A session of your account was signed out to protect it", tone: "warn" });
    expect(describeEvent(stolen, admin).detail).not.toContain("master password");
  });

  it("describes sign-ins with their second step", () => {
    expect(describeEvent(ev("auth.signed_in", { data: { two_step: "totp", new_device: true } }), account)).toEqual({
      text: "You signed in",
      detail: "New device. Second step: authenticator code.",
    });
    expect(describeEvent(ev("auth.signed_in", { data: { two_step: null, new_device: false } }), account).detail).toBeUndefined();
    expect(describeEvent(ev("auth.signed_in", { data: { two_step: "remembered_device", new_device: true, method: "device", request: "r1" } }), account).detail).toBe(
      "New device. Approved on a signed-in device. No second step: remembered device.",
    );
  });

  it("describes sign-ins approved from another device", () => {
    const asked = ev("auth.request_created", { actor: null, target_user: { id: ME, email: me.email }, data: { request: "r1", device_kind: "web" } });
    expect(describeEvent(asked, account)).toEqual({
      text: "A device asked to sign in to your account",
      detail: "It can sign in only if a device that's signed in approves it.",
    });
    expect(describeEvent(asked, admin).text).toBe("A device asked to sign in to me@example.com");
    expect(describeEvent(ev("auth.request_approved", { data: { request: "r1", device_kind: "mobile" } }), account)).toEqual({
      text: "You approved a sign-in from another device",
    });
    expect(describeEvent(ev("auth.request_denied", { actor: alex, data: { request: "r1" } }), admin)).toEqual({
      text: "alex@example.com denied a sign-in from another device",
    });
  });

  it("names settings, never values, and the admin page's actions", () => {
    const e = ev("admin.settings_changed", { actor: null, data: { changed: ["event_ip", "item_versions_kept", "brand_new_setting"] } });
    expect(describeEvent(e, admin)).toEqual({
      text: "The admin changed server settings",
      detail: "Changed: IP addresses in the activity log, earlier versions kept, brand new setting.",
    });
    expect(describeEvent(ev("admin.settings_changed", { actor: null, data: { changed: ["login_with_device"] } }), admin).detail).toBe(
      "Changed: approving sign-ins from another device.",
    );
    const reset = ev("admin.two_step_reset", { actor: null, target_user: { id: ME, email: me.email } });
    expect(describeEvent(reset, account)).toMatchObject({ text: "The server's admin turned off two-step login for your account", tone: "warn" });
    expect(describeEvent({ ...reset, target_user: { id: "u-x", email: null } }, admin).text).toBe("The admin turned off two-step login for an account that was deleted");
  });

  it("names people by email on the admin page and decrypts nothing there", () => {
    const e = ev("item.updated", { actor: alex, vault_id: "v-family", item_id: "i-github" });
    expect(describeEvent(e, admin).text).toBe("alex@example.com edited an item in a vault");
    expect(describeEvent({ ...e, actor: { id: "gone", email: null, name: null } }, admin).text).toBe("A deleted account edited an item in a vault");
  });

  it("counts imports and the server's trash sweeps", () => {
    expect(describeEvent(ev("item.imported", { vault_id: "v-personal", data: { count: 1200 } }), account).text).toBe('You imported 1,200 items into "Personal"');
    expect(describeEvent(ev("trash.emptied", { actor: null, vault_id: "v-personal", data: { count: 1, days: 30 } }), account)).toEqual({
      text: '1 item in the trash of "Personal" was deleted for good',
      detail: "It had been in the trash for more than 30 days.",
    });
  });

  it("describes Sends without their contents, and forgotten devices", () => {
    const opened = ev("send.accessed", { actor: null, target_user: { id: ME, email: me.email }, data: { send: "s1", count: 4 } });
    expect(describeEvent(opened, account)).toEqual({ text: "A Send of yours was opened", detail: "4 times in that hour." });
    expect(describeEvent(opened, admin).text).toBe("A Send of me@example.com was opened");
    expect(describeEvent(ev("send.updated", { data: { send: "s1", changed: ["password", "max_views", "data"] } }), account)).toEqual({
      text: "You changed a Send",
      detail: "Changed: password, view limit, text.",
    });
    const expired = ev("send.deleted", { actor: null, target_user: { id: ME, email: me.email }, data: { send: "s1", reason: "deletion_date" } });
    expect(describeEvent(expired, account).text).toBe("A Send of yours was deleted on its deletion date");
    expect(describeEvent(ev("session.device_forgotten", { data: { device: "d", count: 2 } }), account)).toEqual({
      text: "You signed out and forgot a device",
      detail: "2 sessions ended. Its next sign-in asks for two-step login again.",
    });
  });

  it("falls back to the category for types it doesn't know", () => {
    expect(describeEvent(ev("item.pinned"), account)).toEqual({ text: "Item activity by you", detail: "Recorded as item.pinned." });
    expect(describeEvent(ev("billing.paid", { actor: null }), account)).toEqual({ text: "Other activity", detail: "Recorded as billing.paid." });
    expect(describeEvent(ev("vault.archived", { actor: alex }), account).text).toBe("Vault activity by Alex Morgan");
  });
});

describe("collapseMoves", () => {
  const left = ev("item.moved", { id: "m1", vault_id: "v-personal", item_id: "i-github", data: { to: "v-family" } });
  const reached = ev("item.moved", { id: "m2", vault_id: "v-family", item_id: "i-github", data: { from: "v-personal" } });

  it("shows a move between two vaults once", () => {
    const out = collapseMoves([reached, left]);
    expect(out).toHaveLength(1);
    expect(describeEvent(out[0], account).text).toBe('You moved "GitHub" from "Personal" to "Family"');
    expect(collapseMoves([left, reached])).toEqual([left]);
  });

  it("keeps moves that don't belong together", () => {
    const later = { ...reached, at: reached.at + 1 };
    expect(collapseMoves([later, left])).toHaveLength(2);
    const other = { ...reached, item_id: "i-other" };
    expect(collapseMoves([other, left])).toHaveLength(2);
    const back = ev("item.moved", { id: "m3", vault_id: "v-personal", item_id: "i-github", data: { from: "v-family" } });
    expect(collapseMoves([back, left])).toHaveLength(2);
  });
});
