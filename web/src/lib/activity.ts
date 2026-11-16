/**
 * Activity log (servers with the `activity_log` feature): what happened in an account, a vault or the whole server, in
 * plain words. Events carry ids, counts, roles and method or setting names only, never vault content: names of vaults
 * and items are looked up on the device (`DescribeContext`), and what can't be decrypted is called "a vault you can't
 * open" or "an item". Pages come newest first; `next` asks for older ones (`?before=`).
 *
 * Pure (no WASM, no network, no React) and unit-tested in `activity.test.ts`.
 */

export interface ActivityUser {
  id: string;
  /** Null once the account is deleted. */
  email: string | null;
  name: string | null;
}

export interface ActivityEvent {
  id: string;
  /** Unix seconds. */
  at: number;
  /** E.g. "item.updated". Types this app doesn't know yet are shown by their category. */
  type: string;
  /** Who did it: null for the server's own actions, the admin page and attempts by someone not signed in. */
  actor: ActivityUser | null;
  /** The app that made the request (`X-PassAuth-Client`), when it said. */
  client: string | null;
  /** Only where the server kept it and may show it to this reader. */
  ip: string | null;
  vault_id: string | null;
  item_id: string | null;
  /** The account the action was done to: a member invited or removed, an account the admin disabled… */
  target_user: { id: string; email: string | null } | null;
  /** Counts, roles, method or setting names. */
  data: Record<string, unknown>;
}

export interface EventPage {
  events: ActivityEvent[];
  /** Send as `before` for the next (older) page; null on the last page. */
  next: string | null;
}

const str = (v: unknown): string | null => (typeof v === "string" && v ? v : null);

function readUser(v: unknown): ActivityUser | null {
  if (!v || typeof v !== "object") return null;
  const u = v as Record<string, unknown>;
  return str(u.id) ? { id: u.id as string, email: str(u.email), name: str(u.name) } : null;
}

function readEvent(v: unknown): ActivityEvent | null {
  if (!v || typeof v !== "object") return null;
  const e = v as Record<string, unknown>;
  if (!str(e.id) || !str(e.type) || typeof e.at !== "number" || !Number.isFinite(e.at)) return null;
  const target = e.target_user && typeof e.target_user === "object" ? (e.target_user as Record<string, unknown>) : null;
  return {
    id: e.id as string,
    at: e.at,
    type: e.type as string,
    actor: readUser(e.actor),
    client: str(e.client),
    ip: str(e.ip),
    vault_id: str(e.vault_id),
    item_id: str(e.item_id),
    target_user: target && str(target.id) ? { id: target.id as string, email: str(target.email) } : null,
    data: e.data && typeof e.data === "object" && !Array.isArray(e.data) ? (e.data as Record<string, unknown>) : {},
  };
}

/** A page of `GET /account/events`, `/vaults/{id}/events` or `/admin/events`; malformed events are left out. */
export function readEventPage(body: unknown): EventPage {
  const b = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  const events = Array.isArray(b.events) ? b.events.map(readEvent).filter((e): e is ActivityEvent => e !== null) : [];
  return { events, next: str(b.next) };
}

/**
 * A move between two vaults is recorded once in each vault (`to` in the one it left, `from` in the one it reached).
 * Where both are listed next to each other, show them as one.
 */
export function collapseMoves(events: ActivityEvent[]): ActivityEvent[] {
  const out: ActivityEvent[] = [];
  for (const e of events) {
    const prev = out[out.length - 1];
    if (prev && e.type === "item.moved" && prev.type === "item.moved" && e.item_id && e.item_id === prev.item_id && e.at === prev.at && e.actor?.id === prev.actor?.id) {
      const left = typeof prev.data.to === "string" ? prev : typeof e.data.to === "string" ? e : null;
      const reached = typeof prev.data.from === "string" ? prev : typeof e.data.from === "string" ? e : null;
      if (left && reached && left !== reached && left.data.to === reached.vault_id && reached.data.from === left.vault_id) {
        out[out.length - 1] = left;
        continue;
      }
    }
    out.push(e);
  }
  return out;
}

export interface DescribeContext {
  /** The reader's account id (null on the admin page): their own actions read "You …". */
  me: string | null;
  /** A vault's name when the reader can decrypt it, else null. */
  vaultName(id: string): string | null;
  /** An item's name when the reader can decrypt it, else null. */
  itemName(id: string): string | null;
  /** The vault whose activity is shown: it is "this vault". */
  vault?: string;
  /** The admin page: nothing is decrypted there, and the admin page's own actions are the reader's. */
  admin?: boolean;
}

export interface EventText {
  /** One sentence without a final full stop, e.g. `You edited "GitHub" in "Personal"`. */
  text: string;
  /** More about it, in full sentences. */
  detail?: string;
  /** Worth a second look (failed sign-ins, a session signed out to protect it…). */
  tone?: "warn";
}

const ROLE_WORDS: Record<string, string> = { read: "can view", write: "can edit", admin: "can manage and share", owner: "owner" };
const roleWords = (role: unknown): string | null => (typeof role === "string" && role ? (ROLE_WORDS[role] ?? role) : null);

/** Two-step methods as they read after "turned on two-step login with". */
const METHOD_NOUN: Record<string, string> = { totp: "an authenticator app", email: "email codes", passkey: "a security key" };

/** The second step of a sign-in. */
const SIGN_IN_STEP: Record<string, string> = {
  totp: "Second step: authenticator code.",
  email: "Second step: email code.",
  passkey: "Second step: security key.",
  recovery: "Second step: recovery code.",
  remembered_device: "No second step: remembered device.",
};

const FAILURE: Record<string, string> = {
  password: "Wrong master password",
  reauth: "Wrong master password when confirming a change",
  two_step: "Wrong two-step code",
  account_disabled: "The account is disabled",
  email_not_verified: "The email address isn't confirmed yet",
};

/** Names of server settings (never their values) for "changed server settings". */
const SETTING_NAMES: Record<string, string> = {
  log_level: "server log",
  icons: "website icons",
  signups_verify: "email confirmation for new accounts",
  breach_check: "Have I Been Pwned check",
  event_ip: "IP addresses in the activity log",
  signups_allowed: "sign-ups",
  signups_domains: "sign-up email domains",
  smtp: "email delivery",
  trash_days: "emptying the trash",
  tombstone_days: "remembering deletions",
  session_days: "sign-in length",
  refresh_days: "signing out unused devices",
  remember_device_days: "remembered devices",
  signin_attempts_per_minute: "sign-in attempts",
  two_step_attempts_per_hour: "two-step attempts",
  max_import_items: "items per import request",
  max_item_kib: "largest item",
  websocket_ping_seconds: "live-sync checks",
  max_items_per_user: "items per user",
  max_storage_mb_per_user: "storage per user",
  event_days: "keeping the activity log",
  item_versions_kept: "earlier versions kept",
  sends: "Send",
  send_max_days: "how long a Send can last",
  require_two_step: "required two-step login",
  require_secret_key: "required Secret Key",
  disable_export: "vault export",
  master_password_min_length: "shortest master password",
  min_kdf_iterations: "key derivation strength",
  min_kdf_memory_mib: "key derivation memory",
  max_vault_timeout_minutes: "longest vault timeout",
  login_with_device: "approving sign-ins from another device",
};

/** What a change to a Send touched (its contents are never named). */
const SEND_FIELDS: Record<string, string> = {
  name: "name",
  data: "text",
  owner_key: "key",
  password: "password",
  max_views: "view limit",
  expires_at: "expiry date",
  delete_at: "deletion date",
  disabled: "on or off",
  hide_email: "showing your email",
};

const CATEGORY: Record<string, string> = {
  account: "Account activity",
  auth: "Sign-in activity",
  session: "Session activity",
  vault: "Vault activity",
  member: "Vault member activity",
  item: "Item activity",
  trash: "Trash activity",
  admin: "Admin page activity",
  send: "Send activity",
  attachment: "Attachment activity",
  emergency: "Emergency access activity",
};

const count = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.floor(v) : null);
/** "800 bytes", "1.5 MB" (1 MB = 1024 KB, as the server counts). */
function formatSize(bytes: number): string {
  if (bytes < 1024) return plural(bytes, "byte");
  const units = ["KB", "MB", "GB", "TB"];
  let v = bytes / 1024;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  return `${v >= 100 ? Math.round(v) : Math.round(v * 10) / 10} ${units[u]}`;
}
const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString("en")} ${n === 1 ? one : many}`;
const sentence = (s: string) => {
  const t = s.trim();
  return t ? `${t.charAt(0).toUpperCase()}${t.slice(1)}${/[.!?]$/.test(t) ? "" : "."}` : "";
};
const joinDetail = (parts: (string | null | false | undefined)[]) => parts.filter((p): p is string => !!p).map(sentence).join(" ") || undefined;

function duration(seconds: number): string {
  if (seconds >= 3600 && seconds % 3600 === 0) return plural(seconds / 3600, "hour");
  return plural(Math.max(1, Math.round(seconds / 60)), "minute");
}

/** Who did it, at the start of a sentence. */
function subject(e: ActivityEvent, ctx: DescribeContext): string {
  const a = e.actor;
  if (a) {
    if (ctx.me && a.id === ctx.me) return "You";
    const name = ctx.admin ? a.email || a.name?.trim() : a.name?.trim() || a.email;
    return name || "A deleted account";
  }
  if (e.type.startsWith("admin.")) return ctx.admin ? "The admin" : "The server's admin";
  if (e.type.startsWith("auth.") || e.type.startsWith("session.")) return "Someone";
  return "The server";
}

/** The account an action was done to, in running text: "you", their email, or "a deleted account". */
function target(e: ActivityEvent, ctx: DescribeContext): string {
  const t = e.target_user;
  if (!t) return "someone";
  if (ctx.me && t.id === ctx.me) return "you";
  return t.email || "a deleted account";
}

const possessive = (who: string) => (who === "you" ? "your" : `${who}'s`);

/** The account a sign-in or admin action concerns: "your account", its email, or "an account". */
function accountRef(e: ActivityEvent, ctx: DescribeContext): string {
  const t = e.target_user ?? (e.actor ? { id: e.actor.id, email: e.actor.email } : null);
  if (!t) return "an account";
  if (ctx.me && t.id === ctx.me) return "your account";
  return t.email || "an account that was deleted";
}

export function describeEvent(e: ActivityEvent, ctx: DescribeContext): EventText {
  const S = subject(e, ctx);
  const you = S === "You";
  const d = e.data;
  /** `"Family"`, "this vault", or what is said when the name can't be read. */
  const V = (id: string | null = e.vault_id, unknown = "a vault you can't open"): string => {
    if (!id) return "a vault";
    if (ctx.vault === id) return "this vault";
    const name = ctx.admin ? null : ctx.vaultName(id);
    return name ? `"${name}"` : ctx.admin ? "a vault" : unknown;
  };
  /** As `V`, for sentences about the vault itself: `the vault "Family"`. */
  const VV = (id: string | null = e.vault_id, unknown?: string): string => {
    const v = V(id, unknown);
    return v.startsWith('"') ? `the vault ${v}` : v;
  };
  const item = (): string => {
    const name = e.item_id && !ctx.admin ? ctx.itemName(e.item_id) : null;
    return name ? `"${name}"` : "an item";
  };
  const inVault = () => (e.vault_id && ctx.vault === e.vault_id ? "" : ` in ${V()}`);
  const T = target(e, ctx);
  const role = roleWords(d.role);
  const access = role ? `Access: ${role}.` : undefined;

  switch (e.type) {
    // ------------------------------------------------------------ account
    case "account.created":
      if (you) return { text: "You created your account" };
      return { text: e.actor?.email || e.actor?.name ? `${S} created an account` : "An account was created" };
    case "account.deleted":
      if (you) return { text: "You deleted your account" };
      return { text: e.actor?.email || e.actor?.name ? `${S} deleted their account` : "An account was deleted by its owner" };
    case "account.password_changed": {
      const n = count(d.sessions_signed_out);
      return {
        text: `${S} changed ${you ? "your" : "their"} master password or Secret Key`,
        detail: joinDetail([
          d.secret_key === true ? "Uses a Secret Key" : d.secret_key === false ? "No Secret Key" : null,
          n ? `${plural(n, "other session")} signed out` : null,
        ]),
      };
    }
    case "account.two_step_enabled": {
      const noun = typeof d.method === "string" ? METHOD_NOUN[d.method] : undefined;
      return {
        text: `${S} turned on two-step login${noun ? ` with ${noun}` : ""}`,
        detail: d.recovery_codes === true ? "New recovery codes were made." : undefined,
      };
    }
    case "account.two_step_disabled": {
      const noun = typeof d.method === "string" ? METHOD_NOUN[d.method] : undefined;
      return { text: `${S} turned off two-step login${noun ? ` with ${noun}` : ""}` };
    }
    case "account.recovery_codes_created":
      return { text: `${S} made new recovery codes for two-step login` };
    case "account.security_key_added":
      return { text: `${S} added a security key for two-step login`, detail: d.recovery_codes === true ? "New recovery codes were made." : undefined };
    case "account.security_key_removed":
      return { text: `${S} removed a security key from two-step login` };

    // ---------------------------------------------------------- sign-ins
    case "auth.signed_in":
      return {
        text: `${S} signed in`,
        detail: joinDetail([
          d.new_device === true && "New device",
          d.method === "device" && "Approved on a signed-in device",
          typeof d.two_step === "string" && (SIGN_IN_STEP[d.two_step] ?? null),
        ]),
      };
    // The app asking (or answering) is the event's own `client`, shown with every event.
    case "auth.request_created":
      return { text: `A device asked to sign in to ${accountRef(e, ctx)}`, detail: "It can sign in only if a device that's signed in approves it." };
    case "auth.request_approved":
      return { text: `${S} approved a sign-in from another device` };
    case "auth.request_denied":
      return { text: `${S} denied a sign-in from another device` };
    case "auth.signin_failed": {
      const reason = typeof d.reason === "string" ? FAILURE[d.reason] : undefined;
      const n = count(d.count) ?? 1;
      const times = n > 1 ? `, ${plural(n, "time")}` : "";
      return {
        text: d.reason === "reauth" ? `Failed password check for ${accountRef(e, ctx)}` : `Failed sign-in to ${accountRef(e, ctx)}`,
        detail: reason ? `${reason}${times}.` : n > 1 ? `${plural(n, "attempt")}.` : undefined,
        tone: "warn",
      };
    }
    case "auth.two_step_locked": {
      const seconds = count(d.seconds);
      return {
        text: `Two-step login to ${accountRef(e, ctx)} was paused after too many wrong codes`,
        detail: seconds ? `For ${duration(seconds)}.` : undefined,
        tone: "warn",
      };
    }

    // ---------------------------------------------------------- sessions
    case "session.signed_out":
      return { text: `${S} signed out` };
    case "session.revoked":
      if (d.reason === "refresh_token_reused")
        return {
          text: `A session of ${accountRef(e, ctx)} was signed out to protect it`,
          detail: ctx.admin
            ? "Its sign-in token was used twice, which can mean someone copied it."
            : "Its sign-in token was used twice, which can mean someone copied it. If you don't recognize this, change your master password.",
          tone: "warn",
        };
      return { text: you ? "You signed out another session" : `${S} signed out one of their sessions` };
    case "session.revoked_others": {
      const n = count(d.count);
      return { text: n ? `${S} signed out ${plural(n, "other session")}` : `${S} signed out all other sessions` };
    }
    case "session.device_forgotten": {
      const n = count(d.count);
      return {
        text: `${S} signed out and forgot a device`,
        detail: joinDetail([n ? `${plural(n, "session")} ended` : null, "Its next sign-in asks for two-step login again"]),
      };
    }

    // ------------------------------------------------------------- Sends
    case "send.created":
      return { text: `${S} created a Send` };
    case "send.updated": {
      const fields = Array.isArray(d.changed) ? d.changed.filter((f): f is string => typeof f === "string").map((f) => SEND_FIELDS[f] ?? f.replace(/_/g, " ")) : [];
      return { text: `${S} changed a Send`, detail: fields.length ? `Changed: ${fields.join(", ")}.` : undefined };
    }
    case "send.deleted":
      if (d.reason === "deletion_date") return { text: `A Send of ${accountRef(e, ctx).replace(/^your account$/, "yours")} was deleted on its deletion date` };
      return { text: `${S} deleted a Send` };
    case "send.accessed": {
      const n = count(d.count) ?? 1;
      return { text: `A Send of ${accountRef(e, ctx).replace(/^your account$/, "yours")} was opened`, detail: n > 1 ? `${plural(n, "time")} in that hour.` : undefined };
    }

    // ------------------------------------------------------- attachments
    case "attachment.added":
    case "attachment.deleted": {
      const size = count(d.size);
      return {
        text: `${S} ${e.type === "attachment.added" ? "attached a file to" : "deleted a file of"} ${item()}${inVault()}`,
        detail: size ? `${formatSize(size)} encrypted.` : undefined,
      };
    }

    // -------------------------------------------------- emergency access
    // The actor is one side of the access, the target the other: grantor and contact read their own sentences.
    case "emergency.invited": {
      const wait = count(d.wait_days);
      return {
        text: T === "you" ? `${S} named you as their emergency contact` : `${S} named ${T} as ${you ? "your" : "their"} emergency contact`,
        detail: wait ? `Waiting period: ${plural(wait, "day")}.` : undefined,
      };
    }
    case "emergency.accepted":
      return { text: you ? `You accepted being ${possessive(T)} emergency contact` : `${S} accepted being ${possessive(T)} emergency contact` };
    case "emergency.confirmed": {
      const vaults = count(d.vaults);
      return {
        text: `${S} confirmed ${T} as ${you ? "your" : "their"} emergency contact`,
        detail: vaults !== null && T !== "you" ? `With a key to ${plural(vaults, "personal vault")}.` : undefined,
      };
    }
    case "emergency.vaults_added": {
      const vaults = count(d.vaults);
      return { text: `${S} gave an emergency contact the key to ${vaults !== null ? plural(vaults, "more personal vault") : "more personal vaults"}` };
    }
    case "emergency.reconfirm":
      // Written by the server for both sides of an access: one sentence for either.
      return { text: "Emergency access now uses a key to personal vaults only", detail: "A contact confirmed before has to be confirmed again." };
    case "emergency.updated": {
      const wait = count(d.wait_days);
      return { text: `${S} changed the waiting period for ${T}${wait ? ` to ${plural(wait, "day")}` : ""}` };
    }
    case "emergency.requested": {
      const wait = count(d.wait_days);
      return {
        text: `${S} asked for emergency access to ${T === "you" ? "your" : `${possessive(T)}`} vaults`,
        detail: wait ? `Granted after ${plural(wait, "day")} unless it is rejected.` : undefined,
        tone: T === "you" ? "warn" : undefined,
      };
    }
    case "emergency.approved":
      if (d.automatic === true || !e.actor)
        return {
          text: "Emergency access was granted after the waiting period",
          detail: T === "you" ? undefined : `For ${T}.`,
          tone: "warn",
        };
      return { text: `${S} approved ${possessive(T)} emergency access`, tone: T === "you" ? undefined : "warn" };
    case "emergency.rejected":
      return { text: d.status === "approved" ? `${S} ended ${possessive(T)} emergency access` : `${S} rejected ${possessive(T)} emergency access request` };
    case "emergency.removed": {
      const rotate = count(d.rotate_vaults);
      return {
        text: d.by === "grantee" ? `${S} stopped being ${possessive(T)} emergency contact` : `${S} removed ${T} as ${you ? "your" : "their"} emergency contact`,
        detail: rotate ? `The keys of ${plural(rotate, "personal vault")} are to be changed.` : undefined,
      };
    }
    case "emergency.viewed": {
      const items = count(d.items);
      return {
        text: `${S} viewed ${T === "you" ? "your" : `${possessive(T)}`} vaults through emergency access`,
        detail: items !== null ? `${plural(items, "item")}.` : undefined,
        tone: T === "you" ? "warn" : undefined,
      };
    }

    // ------------------------------------------------------------ vaults
    case "vault.created":
      return { text: `${S} created ${VV()}` };
    case "vault.renamed":
      return { text: `${S} renamed ${VV()}` };
    case "vault.deleted":
      return { text: `${S} deleted ${VV(e.vault_id, "a vault")}` };
    case "vault.key_rotated":
      return { text: `${S} replaced the key of ${VV()}`, detail: "Every item in it was encrypted again." };

    // ----------------------------------------------------------- members
    case "member.invited":
      return { text: `${S} invited ${T} to ${VV()}`, detail: access };
    case "member.key_updated":
      return { text: `${S} shared ${VV()} with ${T} again`, detail: access };
    case "member.role_changed": {
      const from = roleWords(d.from);
      return {
        text: `${S} changed ${possessive(T)} ${d.status === "invited" ? "invitation" : "access"} to ${VV()}`,
        detail: from && role ? `From ${from} to ${role}.` : access,
      };
    }
    case "member.accepted":
      return { text: `${S} accepted the invitation to ${VV()}` };
    case "member.declined":
      return { text: `${S} declined the invitation to ${VV()}` };
    case "member.left":
      return { text: `${S} left ${VV()}` };
    case "member.removed":
      return {
        text: d.status === "invited" ? `${S} cancelled ${possessive(T)} invitation to ${VV()}` : `${S} removed ${T} from ${VV()}`,
        detail: d.rotated === true ? "The vault key was replaced at the same time." : undefined,
      };

    // ------------------------------------------------------------- items
    case "item.created":
      return { text: `${S} added ${item()} to ${V()}` };
    case "item.updated":
      return { text: `${S} edited ${item()}${inVault()}` };
    case "item.moved":
      if (typeof d.to === "string") return { text: `${S} moved ${item()} from ${V()} to ${V(d.to)}` };
      if (typeof d.from === "string") return { text: `${S} moved ${item()} from ${V(d.from)} to ${V()}` };
      return { text: `${S} moved ${item()}` };
    case "item.trashed":
      return { text: `${S} moved ${item()} to the trash${inVault()}` };
    case "item.restored":
      return { text: `${S} restored ${item()} from the trash${inVault()}` };
    case "item.deleted":
      return { text: `${S} deleted ${item()} for good${inVault()}` };
    case "item.imported": {
      const n = count(d.count);
      return { text: `${S} imported ${n === null ? "items" : plural(n, "item")} into ${V()}` };
    }
    case "trash.emptied": {
      const n = count(d.count);
      const days = count(d.days);
      return {
        text: `${n === null ? "Items" : plural(n, "item")} in the trash of ${V()} ${n === 1 ? "was" : "were"} deleted for good`,
        detail: days ? `${n === 1 ? "It" : "They"} had been in the trash for more than ${plural(days, "day")}.` : undefined,
      };
    }

    // -------------------------------------------------------- admin page
    case "admin.signed_in":
      return { text: `${S} signed in to the admin page` };
    case "admin.two_step_enabled":
      return { text: `${S} turned on two-step login for the admin page` };
    case "admin.two_step_disabled":
      return { text: `${S} turned off two-step login for the admin page` };
    case "admin.recovery_codes_created":
      return { text: `${S} made new recovery codes for the admin page` };
    case "admin.user_disabled":
      return { text: `${S} disabled ${accountRef(e, ctx)}`, tone: ctx.me && e.target_user?.id === ctx.me ? "warn" : undefined };
    case "admin.user_enabled":
      return { text: `${S} turned sign-in back on for ${accountRef(e, ctx)}` };
    case "admin.sessions_revoked": {
      const n = count(d.count);
      return { text: `${S} signed out every session of ${accountRef(e, ctx)}`, detail: n ? `${plural(n, "session")} ended.` : undefined };
    }
    case "admin.two_step_reset":
      return {
        text: `${S} turned off two-step login for ${accountRef(e, ctx)}`,
        detail: "Every two-step method was removed.",
        tone: ctx.me && e.target_user?.id === ctx.me ? "warn" : undefined,
      };
    case "admin.user_deleted":
      return { text: `${S} deleted ${accountRef(e, ctx)}` };
    case "admin.settings_changed": {
      const names = Array.isArray(d.changed) ? d.changed.filter((n): n is string => typeof n === "string").map((n) => SETTING_NAMES[n] ?? n.replace(/_/g, " ")) : [];
      return { text: `${S} changed server settings`, detail: names.length ? `Changed: ${names.join(", ")}.` : undefined };
    }
  }
  // A type from a newer server: its category, who, and the type itself.
  const category = CATEGORY[e.type.split(".")[0]] ?? "Other activity";
  return { text: e.actor ? `${category} by ${you ? "you" : S}` : category, detail: `Recorded as ${e.type}.` };
}

/** Event types by category with short labels, for the admin page's filter. */
export const EVENT_TYPES: { category: string; label: string; types: [type: string, label: string][] }[] = [
  {
    category: "auth",
    label: "Sign-ins",
    types: [
      ["auth.signed_in", "Signed in"],
      ["auth.signin_failed", "Failed sign-in"],
      ["auth.two_step_locked", "Two-step login paused"],
      ["auth.request_created", "Asked to sign in from another device"],
      ["auth.request_approved", "Sign-in from another device approved"],
      ["auth.request_denied", "Sign-in from another device denied"],
    ],
  },
  {
    category: "session",
    label: "Sessions",
    types: [
      ["session.signed_out", "Signed out"],
      ["session.revoked", "Session signed out"],
      ["session.revoked_others", "Other sessions signed out"],
      ["session.device_forgotten", "Device forgotten"],
    ],
  },
  {
    category: "account",
    label: "Accounts",
    types: [
      ["account.created", "Account created"],
      ["account.deleted", "Account deleted by its owner"],
      ["account.password_changed", "Master password or Secret Key changed"],
      ["account.two_step_enabled", "Two-step login turned on"],
      ["account.two_step_disabled", "Two-step login turned off"],
      ["account.recovery_codes_created", "Recovery codes made"],
      ["account.security_key_added", "Security key added"],
      ["account.security_key_removed", "Security key removed"],
    ],
  },
  {
    category: "vault",
    label: "Vaults",
    types: [
      ["vault.created", "Vault created"],
      ["vault.renamed", "Vault renamed"],
      ["vault.deleted", "Vault deleted"],
      ["vault.key_rotated", "Vault key replaced"],
    ],
  },
  {
    category: "member",
    label: "Vault members",
    types: [
      ["member.invited", "Invited"],
      ["member.accepted", "Invitation accepted"],
      ["member.declined", "Invitation declined"],
      ["member.role_changed", "Access changed"],
      ["member.key_updated", "Shared again"],
      ["member.left", "Left a vault"],
      ["member.removed", "Removed, or invitation cancelled"],
    ],
  },
  {
    category: "item",
    label: "Items",
    types: [
      ["item.created", "Item added"],
      ["item.updated", "Item edited"],
      ["item.moved", "Item moved"],
      ["item.trashed", "Moved to the trash"],
      ["item.restored", "Restored from the trash"],
      ["item.deleted", "Deleted for good"],
      ["item.imported", "Items imported"],
    ],
  },
  { category: "trash", label: "Trash", types: [["trash.emptied", "Emptied by the server"]] },
  {
    category: "send",
    label: "Sends",
    types: [
      ["send.created", "Send created"],
      ["send.updated", "Send changed"],
      ["send.deleted", "Send deleted"],
      ["send.accessed", "Send opened"],
    ],
  },
  {
    category: "attachment",
    label: "Attachments",
    types: [
      ["attachment.added", "File attached"],
      ["attachment.deleted", "File deleted"],
    ],
  },
  {
    category: "emergency",
    label: "Emergency access",
    types: [
      ["emergency.invited", "Contact named"],
      ["emergency.accepted", "Contact accepted"],
      ["emergency.confirmed", "Contact confirmed"],
      ["emergency.vaults_added", "Vault keys added for a contact"],
      ["emergency.reconfirm", "Contact to confirm again"],
      ["emergency.updated", "Waiting period changed"],
      ["emergency.requested", "Access requested"],
      ["emergency.approved", "Access granted"],
      ["emergency.rejected", "Request rejected or access ended"],
      ["emergency.viewed", "Vaults viewed"],
      ["emergency.removed", "Contact removed"],
    ],
  },
  {
    category: "admin",
    label: "Admin page",
    types: [
      ["admin.signed_in", "Admin signed in"],
      ["admin.settings_changed", "Server settings changed"],
      ["admin.user_disabled", "Account disabled"],
      ["admin.user_enabled", "Sign-in turned back on"],
      ["admin.sessions_revoked", "Signed out everywhere"],
      ["admin.two_step_reset", "Two-step login reset"],
      ["admin.user_deleted", "Account deleted by the admin"],
      ["admin.two_step_enabled", "Admin page two-step login turned on"],
      ["admin.two_step_disabled", "Admin page two-step login turned off"],
      ["admin.recovery_codes_created", "Admin page recovery codes made"],
    ],
  },
];
