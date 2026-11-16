/**
 * The activity log in plain words: Settings → Activity (the account), a vault's activity (its owners and admins) and,
 * through `EventList`, the admin page. Wording and paging rules live in `lib/activity.ts`.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ErrorText, Icon, type IconName } from "../components/ui";
import { collapseMoves, describeEvent, readEventPage, type ActivityEvent, type DescribeContext } from "../lib/activity";
import { ApiError, api, friendlyError, hasFeature, usePublicConfig } from "../lib/api";
import { clientInfo } from "../lib/clients";
import { useVault, type Vault } from "../lib/vault";
import "../styles/activity.css";

const CATEGORY_ICON: Record<string, IconName> = {
  account: "person",
  auth: "key",
  session: "desktop",
  vault: "vault",
  member: "share",
  item: "note",
  trash: "trash",
  admin: "settings",
  send: "share",
};

const TYPE_ICON: Record<string, IconName> = {
  "auth.signin_failed": "shield",
  "auth.two_step_locked": "shield",
  "account.password_changed": "key",
  "account.two_step_enabled": "shield",
  "account.two_step_disabled": "shield",
  "account.recovery_codes_created": "shield",
  "account.security_key_added": "key",
  "account.security_key_removed": "key",
  "session.signed_out": "logout",
  "session.revoked": "logout",
  "session.revoked_others": "logout",
  "session.device_forgotten": "logout",
  "send.deleted": "trash",
  "vault.key_rotated": "key",
  "member.removed": "person",
  "member.left": "logout",
  "item.created": "plus",
  "item.updated": "edit",
  "item.moved": "folder",
  "item.trashed": "trash",
  "item.restored": "restore",
  "item.deleted": "trash",
  "item.imported": "upload",
  "admin.two_step_reset": "shield",
  "admin.sessions_revoked": "logout",
};

const eventIcon = (type: string): IconName => TYPE_ICON[type] ?? CATEGORY_ICON[type.split(".")[0]] ?? "info";

const timeOf = (at: number) => new Date(at * 1000).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });

function dayOf(at: number): { key: string; label: string } {
  const d = new Date(at * 1000);
  const key = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
  const today = new Date();
  const yesterday = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1);
  if (d.toDateString() === today.toDateString()) return { key, label: "Today" };
  if (d.toDateString() === yesterday.toDateString()) return { key, label: "Yesterday" };
  const sameYear = d.getFullYear() === today.getFullYear();
  return { key, label: d.toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long", ...(sameYear ? {} : { year: "numeric" }) }) };
}

/** Names of the vaults and items this device can decrypt, for the activity text (invitations included). */
export function useDescribeContext(vault?: string): DescribeContext {
  const { userId, vaults, items, invitations } = useVault();
  return useMemo(() => {
    const vaultNames = new Map<string, string>();
    for (const inv of invitations) if (inv.name) vaultNames.set(inv.vaultId, inv.name);
    for (const v of vaults) vaultNames.set(v.id, v.name);
    const itemNames = new Map(items.map((e) => [e.id, e.item.name.trim() || "Untitled"]));
    return { me: userId || null, vault, vaultName: (id) => vaultNames.get(id) ?? null, itemName: (id) => itemNames.get(id) ?? null };
  }, [userId, vaults, items, invitations, vault]);
}

const query = (before: string | null) => (before ? `?before=${encodeURIComponent(before)}` : "");

/**
 * A paged activity log, newest first, grouped by day. `load` (keep it stable with useCallback) fetches one page; a new
 * `load` starts again from the newest.
 */
export function EventList({
  load,
  context,
  label,
  empty,
  errorText = friendlyError,
  extra,
}: {
  load: (before: string | null) => Promise<unknown>;
  context: DescribeContext;
  /** Names the list for screen readers. */
  label: string;
  /** Said when there is nothing to show. */
  empty: string;
  errorText?: (e: unknown) => string;
  /** More under an event (the admin page's filter links). */
  extra?: (e: ActivityEvent) => ReactNode;
}) {
  const [events, setEvents] = useState<ActivityEvent[] | null>(null);
  const [next, setNext] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [more, setMore] = useState(false);
  // Answers for an earlier `load` (filters changed meanwhile) are dropped.
  const current = useRef(load);
  current.current = load;
  const errorRef = useRef(errorText);
  errorRef.current = errorText;

  useEffect(() => {
    let live = true;
    setEvents(null);
    setNext(null);
    setError(null);
    load(null)
      .then((body) => {
        if (!live) return;
        const page = readEventPage(body);
        setEvents(page.events);
        setNext(page.next);
      })
      .catch((e) => live && setError(errorRef.current(e)));
    return () => {
      live = false;
    };
  }, [load]);

  async function older() {
    if (!next) return;
    const from = load;
    setMore(true);
    setError(null);
    try {
      const page = readEventPage(await load(next));
      if (current.current !== from) return;
      setEvents((had) => {
        const seen = new Set((had ?? []).map((e) => e.id));
        return [...(had ?? []), ...page.events.filter((e) => !seen.has(e.id))];
      });
      setNext(page.next);
    } catch (e) {
      if (current.current === from) setError(errorRef.current(e));
    } finally {
      setMore(false);
    }
  }

  const days = useMemo(() => {
    const out: { key: string; label: string; events: ActivityEvent[] }[] = [];
    for (const e of collapseMoves(events ?? [])) {
      const day = dayOf(e.at);
      const last = out[out.length - 1];
      if (last?.key === day.key) last.events.push(e);
      else out.push({ ...day, events: [e] });
    }
    return out;
  }, [events]);

  if (events === null)
    return error ? (
      <ErrorText error={error} />
    ) : (
      <p className="muted small" role="status">
        Loading activity…
      </p>
    );

  return (
    <div className="activity" aria-label={label} role="region">
      {days.length === 0 && <p className="muted small">{empty}</p>}
      {days.map((day) => (
        <section key={day.key} className="activity-day" aria-label={day.label}>
          <h3>{day.label}</h3>
          <ol className="activity-list">
            {day.events.map((e) => {
              const t = describeEvent(e, context);
              const app = clientInfo(e.client)?.label;
              return (
                <li key={e.id}>
                  <span className={t.tone === "warn" ? "tile tile-danger" : "tile"} aria-hidden="true">
                    <Icon name={eventIcon(e.type)} />
                  </span>
                  <span className="grow">
                    <span className="row-title">{t.text}</span>
                    {t.detail && <span className="row-sub">{t.detail}</span>}
                    <span className="row-sub activity-meta">
                      <time dateTime={new Date(e.at * 1000).toISOString()} title={new Date(e.at * 1000).toLocaleString()}>
                        {timeOf(e.at)}
                      </time>
                      {app && <> · {app}</>}
                      {e.ip && (
                        <>
                          {" "}
                          · <span className="mono">{e.ip}</span>
                        </>
                      )}
                    </span>
                    {extra?.(e)}
                  </span>
                </li>
              );
            })}
          </ol>
        </section>
      ))}
      <ErrorText error={error} />
      {next && (
        <div className="activity-foot">
          <button type="button" className="btn" onClick={older} disabled={more}>
            {more ? "Loading…" : "Show older activity"}
          </button>
        </div>
      )}
    </div>
  );
}

const NO_LOG = "Your PassAuth server doesn't keep an activity log. Its admin can turn it on by updating the server.";

/** Settings → Activity: what happened in the account, by the user and to it. */
export function ActivityTab() {
  const context = useDescribeContext();
  const config = usePublicConfig();
  const load = useCallback((before: string | null) => api(`/account/events${query(before)}`), []);
  const errorText = useCallback((e: unknown) => (e instanceof ApiError && e.status === 404 ? NO_LOG : `Couldn't load your activity. ${friendlyError(e)}`), []);
  // A server that answered without the feature: say so rather than ask.
  if (config && !hasFeature(config, "activity_log"))
    return (
      <section className="card" aria-labelledby="activity-title">
        <h2 id="activity-title">Activity</h2>
        <p className="card-text">{NO_LOG}</p>
      </section>
    );
  return (
    <section className="card" aria-labelledby="activity-title">
      <div className="stack-s">
        <h2 id="activity-title">Activity</h2>
        <p className="card-text">
          Sign-ins, security changes, sharing and changes to items: what you did, and what was done to your account. If something here wasn't you, change
          your master password and sign out the other sessions.
        </p>
      </div>
      <EventList load={load} context={context} label="Account activity" empty="Nothing has happened in your account yet." errorText={errorText} />
    </section>
  );
}

/** A vault's activity for its owners and admins, under Manage and share. Loaded when opened. */
export function VaultActivity({ vault }: { vault: Vault }) {
  const [open, setOpen] = useState(false);
  const context = useDescribeContext(vault.id);
  const id = vault.id;
  const load = useCallback((before: string | null) => api(`/vaults/${id}/events${query(before)}`), [id]);
  // 403: no longer an owner or admin of it; 404: no longer a member (or the vault is gone).
  const errorText = useCallback(
    (e: unknown) =>
      e instanceof ApiError && (e.status === 403 || e.status === 404)
        ? "Only the vault's owner and admins can see its activity."
        : `Couldn't load this vault's activity. ${friendlyError(e)}`,
    [],
  );
  return (
    <details className="disclosure" onToggle={(e) => setOpen(e.currentTarget.open)}>
      <summary className="section-title">Activity</summary>
      {open && (
        <div className="stack-s">
          <p className="small muted">Who added, changed or shared what in this vault. Addresses show only for what you did yourself.</p>
          <EventList load={load} context={context} label={`Activity in ${vault.name}`} empty="Nothing has happened in this vault yet." errorText={errorText} />
        </div>
      )}
    </details>
  );
}
