import { Fragment, useCallback, useEffect, useState, type FormEvent } from "react";
import { Wordmark } from "../components/Logo";
import { ConfirmDialog, ErrorText, Icon, Modal, PasswordInput, SheetActions, toast } from "../components/ui";
import "../styles/tools.css";

const TOKEN_KEY = "pa.admin";

interface Overview {
  version: string;
  users: number;
  vaults: number;
  items: number;
  config: {
    domain: string;
    database: "sqlite" | "postgresql";
    signups_allowed: boolean;
    signups_domains: string[] | string | null;
    signups_verify: boolean;
    smtp_enabled: boolean;
    admin_token_hashed: boolean;
  };
}

interface User {
  id: string;
  email: string;
  name: string;
  email_verified: number;
  disabled: number;
  created_at: number;
  last_seen: number | null;
  items: number;
  two_factor: number;
}

interface Invite {
  email: string;
  created_at: number;
  expires_at: number;
}

class AdminError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

function loadToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

function saveToken(t: string | null) {
  try {
    if (t) sessionStorage.setItem(TOKEN_KEY, t);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: token lasts until reload */
  }
}

function sentence(s: string) {
  const t = s.trim();
  if (!t) return t;
  const up = t[0].toUpperCase() + t.slice(1);
  return /[.!?]$/.test(up) ? up : `${up}.`;
}

async function adminFetch<T = any>(token: string, path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
  const { body, method = body === undefined ? "GET" : "POST" } = opts;
  let res: Response;
  try {
    res = await fetch(`/api/admin${path}`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new AdminError(0, "Could not reach the PassAuth server. Check that it is running and that this device is online, then try again.");
  }
  const text = await res.text();
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    /* non-JSON error page from a proxy */
  }
  if (!res.ok) {
    const msg =
      res.status === 401
        ? "That admin token is not valid."
        : res.status === 429
          ? "Too many attempts from this address. Wait a minute, then try again."
          : json?.message
            ? sentence(String(json.message))
            : `The server answered with status ${res.status}. Check the server logs for details.`;
    throw new AdminError(res.status, msg);
  }
  return json as T;
}

const TURNED_OFF = "The admin panel is turned off. Set ADMIN_TOKEN on the server to enable it.";

function formatDate(t: number) {
  return new Date(t * 1000).toLocaleDateString(undefined, { dateStyle: "medium" });
}

function formatDateTime(t: number) {
  return new Date(t * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function relative(t: number) {
  const diff = t - Date.now() / 1000;
  const abs = Math.abs(diff);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (abs < 60) return "Just now";
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour");
  if (abs < 30 * 86400) return rtf.format(Math.round(diff / 86400), "day");
  return formatDate(t);
}

function signupText(c: Overview["config"]) {
  if (!c.signups_allowed) return "Invite only";
  const domains = Array.isArray(c.signups_domains) ? c.signups_domains : c.signups_domains ? String(c.signups_domains).split(",") : [];
  const list = domains.map((d) => d.trim()).filter(Boolean);
  return list.length ? `Open to ${list.join(", ")}` : "Open to anyone";
}

// ------------------------------------------------------------------- page

export function AdminPage() {
  const [token, setToken] = useState(loadToken);
  const [fatal, setFatal] = useState<string | null>(null);

  useEffect(() => {
    document.title = "Administration - PassAuth";
  }, []);

  const signOut = useCallback((message: string | null = null) => {
    saveToken(null);
    setToken("");
    setFatal(message);
  }, []);

  return (
    <div className="admin">
      <header className="admin-header">
        <div className="title">
          <Wordmark />
          <span className="muted">Server administration</span>
        </div>
        {token && (
          <button type="button" className="btn btn-text" onClick={() => signOut()}>
            <Icon name="logout" /> Sign out
          </button>
        )}
      </header>
      {token ? (
        <Dashboard token={token} onAuthLost={signOut} />
      ) : (
        <TokenForm
          initialError={fatal}
          onSignedIn={(t) => {
            saveToken(t);
            setFatal(null);
            setToken(t);
          }}
        />
      )}
    </div>
  );
}

// ------------------------------------------------------------- token form

function TokenForm({ initialError, onSignedIn }: { initialError: string | null; onSignedIn: (token: string) => void }) {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(initialError);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const t = value.trim();
    if (!t) return setError("Enter the admin token from your server configuration.");
    setBusy(true);
    setError(null);
    try {
      await adminFetch(t, "/overview");
      onSignedIn(t);
    } catch (err) {
      setError(err instanceof AdminError && err.status === 404 ? TURNED_OFF : (err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth">
      <div className="auth-card">
        <div className="auth-head">
          <h1>Server administration</h1>
          <p className="muted">Manage users, invitations and email for this PassAuth server.</p>
        </div>
        <form className="auth-panel stack" onSubmit={submit}>
          <div className="field">
            <label htmlFor="admin-token">Admin token</label>
            <PasswordInput id="admin-token" value={value} onChange={setValue} autoComplete="off" autoFocus />
            <span className="field-hint">The token you set in ADMIN_TOKEN, not a user password. It is kept only in this tab and forgotten when you close it.</span>
          </div>
          <ErrorText error={error} />
          <SheetActions>
            <button type="submit" className="btn btn-accent btn-block" disabled={busy}>
              {busy ? "Checking token…" : "Open admin panel"}
            </button>
          </SheetActions>
        </form>
      </div>
    </main>
  );
}

// -------------------------------------------------------------- dashboard

function Dashboard({ token, onAuthLost }: { token: string; onAuthLost: (message: string | null) => void }) {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [users, setUsers] = useState<User[] | null>(null);
  const [invites, setInvites] = useState<Invite[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  /** Run an admin call; a 401 or 404 here means the token or panel is gone. */
  const call = useCallback(
    async <T,>(path: string, opts?: { method?: string; body?: unknown }): Promise<T> => {
      try {
        return await adminFetch<T>(token, path, opts);
      } catch (e) {
        if (e instanceof AdminError && e.status === 401) onAuthLost("That admin token is no longer valid. Enter the current token to continue.");
        throw e;
      }
    },
    [token, onAuthLost],
  );

  const load = useCallback(async () => {
    try {
      const [o, u, i] = await Promise.all([
        call<Overview>("/overview"),
        call<{ users: User[] }>("/users"),
        call<{ invites: Invite[] }>("/invites"),
      ]);
      setOverview(o);
      setUsers(u.users);
      setInvites(i.invites);
      setLoadError(null);
    } catch (e) {
      if (e instanceof AdminError && e.status === 404) return onAuthLost(TURNED_OFF);
      if (!(e instanceof AdminError && e.status === 401)) setLoadError((e as Error).message);
    }
  }, [call, onAuthLost]);

  useEffect(() => {
    load();
  }, [load]);

  if (!overview || !users || !invites) {
    return (
      <main className="admin-main">
        {loadError ? (
          <div className="stack">
            <ErrorText error={loadError} />
            <div className="row">
              <button type="button" className="btn" onClick={load}>
                Try again
              </button>
            </div>
          </div>
        ) : (
          <p className="muted" role="status">
            Loading server details…
          </p>
        )}
      </main>
    );
  }

  return (
    <main className="admin-main">
      <OverviewCard o={overview} />
      <SignupsCard config={overview.config} call={call} reload={load} />
      <UsersCard users={users} call={call} reload={load} />
      <InvitesCard invites={invites} smtp={overview.config.smtp_enabled} domain={overview.config.domain} call={call} reload={load} />
      <SmtpCard smtp={overview.config.smtp_enabled} call={call} />
    </main>
  );
}

type Call = <T>(path: string, opts?: { method?: string; body?: unknown }) => Promise<T>;

function OverviewCard({ o }: { o: Overview }) {
  const c = o.config;
  return (
    <section className="stack" aria-labelledby="ov-title">
      <div className="row-between">
        <h1 id="ov-title">Overview</h1>
        <span className="small muted">PassAuth server version {o.version}</span>
      </div>
      {!c.admin_token_hashed && (
        <div className="alert alert-info" role="note">
          ADMIN_TOKEN is stored as plain text in your server configuration. Run <code className="mono">passauth-server hash-admin-token</code>, set ADMIN_TOKEN to
          the hash it prints and restart the server. You keep signing in here with the same token.
        </div>
      )}
      <div className="stat-grid">
        <div className="stat">
          <span className="num">{o.users.toLocaleString()}</span>
          <span className="lbl">{o.users === 1 ? "User" : "Users"}</span>
        </div>
        <div className="stat">
          <span className="num">{o.vaults.toLocaleString()}</span>
          <span className="lbl">{o.vaults === 1 ? "Vault" : "Vaults"}</span>
        </div>
        <div className="stat">
          <span className="num">{o.items.toLocaleString()}</span>
          <span className="lbl">{o.items === 1 ? "Item" : "Items"}</span>
        </div>
      </div>
      <div className="card">
        <h2>Configuration</h2>
        <dl className="facts">
          <div>
            <dt>Domain</dt>
            <dd className="wrap-anywhere">{c.domain}</dd>
          </div>
          <div>
            <dt>Database</dt>
            <dd>{c.database === "postgresql" ? "PostgreSQL" : "SQLite"}</dd>
          </div>
          <div>
            <dt>Sign-ups</dt>
            <dd>{signupText(c)}</dd>
          </div>
          <div>
            <dt>Email verification on sign-up</dt>
            <dd>{c.signups_verify ? "Required" : "Not required"}</dd>
          </div>
          <div>
            <dt>Email (SMTP)</dt>
            <dd>{c.smtp_enabled ? <span className="badge badge-ok">On</span> : <span className="badge">Off</span>}</dd>
          </div>
          <div>
            <dt>Admin token</dt>
            <dd>{c.admin_token_hashed ? <span className="badge badge-ok">Hashed</span> : <span className="badge badge-warn">Plain text</span>}</dd>
          </div>
        </dl>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- sign-ups

function SignupsCard({ config, call, reload }: { config: Overview["config"]; call: Call; reload: () => Promise<void> }) {
  const current = Array.isArray(config.signups_domains) ? config.signups_domains : config.signups_domains ? String(config.signups_domains).split(",") : [];
  const [allowed, setAllowed] = useState(config.signups_allowed);
  const [domains, setDomains] = useState(current.join(", "));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const list = domains
    .split(/[\s,]+/)
    .map((d) => d.trim())
    .filter(Boolean);
  const changed = allowed !== config.signups_allowed || list.join(",") !== current.join(",");

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await call("/settings/signups", { method: "PUT", body: { allowed, domains: list } });
      await reload();
      toast(allowed ? "Sign-ups are open" : "Sign-ups are closed");
    } catch (err) {
      if (!(err instanceof AdminError && err.status === 401)) setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card" aria-labelledby="signups-title">
      <h2 id="signups-title">Sign-ups</h2>
      <form className="stack" onSubmit={save}>
        <label className="check">
          <input type="checkbox" checked={allowed} onChange={(e) => setAllowed(e.target.checked)} />
          <span>
            Allow new accounts to sign up
            <span className="field-hint block">When off, only people you invite below can create an account. Existing accounts are not affected.</span>
          </span>
        </label>
        {allowed && (
          <label className="field">
            <span>Only these email domains (optional)</span>
            <input className="input" value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="example.com, example.org" spellCheck={false} />
            <span className="field-hint">Leave empty to allow any email address. Separate domains with commas.</span>
          </label>
        )}
        <ErrorText error={error} />
        <div className="card-actions">
          <button type="submit" className="btn btn-primary" disabled={busy || !changed}>
            {busy ? "Saving…" : "Save sign-up settings"}
          </button>
          <span className="small muted">Takes effect immediately and overrides SIGNUPS_ALLOWED and SIGNUPS_DOMAINS_WHITELIST from the server configuration.</span>
        </div>
      </form>
    </section>
  );
}

// ------------------------------------------------------------------ users

function UsersCard({ users, call, reload }: { users: User[]; call: Call; reload: () => Promise<void> }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<User | null>(null);
  const [resetting, setResetting] = useState<User | null>(null);
  const [managing, setManaging] = useState<string | null>(null);

  async function act(u: User, path: string, done: string) {
    setBusy(u.id);
    setError(null);
    try {
      await call(`/users/${encodeURIComponent(u.id)}${path}`, { method: "POST" });
      toast(done);
      await reload();
    } catch (e) {
      if (e instanceof AdminError && e.status === 404) {
        setError(`${u.email} no longer exists. The list has been refreshed.`);
        await reload();
      } else if (!(e instanceof AdminError && e.status === 401)) {
        setError((e as Error).message);
      }
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="card" aria-labelledby="users-title">
      <div className="card-head">
        <h2 id="users-title">Users</h2>
        <span className="small muted">{users.length === 1 ? "1 account" : `${users.length.toLocaleString()} accounts`}</span>
      </div>
      <ErrorText error={error} />
      {users.length === 0 ? (
        <p className="muted">No one has created an account yet. Invite someone below.</p>
      ) : (
        <div className="table-wrap">
          <table className="table users-table">
            <thead>
              <tr>
                <th scope="col">User</th>
                <th scope="col">Two-step login</th>
                <th scope="col" className="col-wide">
                  Items
                </th>
                <th scope="col" className="col-wide">
                  Last seen
                </th>
                <th scope="col">Status</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const open = managing === u.id;
                return (
                  <Fragment key={u.id}>
                    <tr className={open ? "is-open" : undefined}>
                      <td>
                        <div className="user-cell">
                          <span className="avatar" aria-hidden="true">
                            {((u.name || u.email).trim()[0] ?? "?").toUpperCase()}
                          </span>
                          <div className="grow">
                            <div className="row-title">{u.name || u.email}</div>
                            {u.name && <div className="row-sub">{u.email}</div>}
                            {!u.email_verified && <div className="row-sub">Email not verified</div>}
                          </div>
                        </div>
                      </td>
                      <td>{u.two_factor ? <span className="badge badge-ok">On</span> : <span className="badge">Off</span>}</td>
                      <td className="col-wide num">{u.items.toLocaleString()}</td>
                      <td className="col-wide" title={u.last_seen ? formatDateTime(u.last_seen) : undefined}>
                        {u.last_seen ? relative(u.last_seen) : <span className="muted">Never</span>}
                      </td>
                      <td>{u.disabled ? <span className="badge badge-warn">Disabled</span> : <span className="badge badge-ok">Active</span>}</td>
                      <td className="actions">
                        <button type="button" className="btn btn-text btn-sm" aria-expanded={open} aria-label={`Manage ${u.email}`} onClick={() => setManaging(open ? null : u.id)}>
                          {open ? "Done" : "Manage"}
                        </button>
                      </td>
                    </tr>
                    {open && (
                      <tr className="row-detail">
                        <td colSpan={6}>
                          <div className="card-actions">
                            {u.disabled ? (
                              <button type="button" className="btn btn-sm" disabled={busy === u.id} onClick={() => act(u, "/enable", `${u.email} can sign in again`)}>
                                Allow sign-in
                              </button>
                            ) : (
                              <button
                                type="button"
                                className="btn btn-sm"
                                disabled={busy === u.id}
                                title="Block sign-in and end all sessions"
                                onClick={() => act(u, "/disable", `${u.email} is disabled and signed out`)}
                              >
                                Disable account
                              </button>
                            )}
                            <button type="button" className="btn btn-sm" disabled={busy === u.id} onClick={() => act(u, "/sessions/revoke", `${u.email} is signed out on every device`)}>
                              Sign out everywhere
                            </button>
                            {u.two_factor > 0 && (
                              <button type="button" className="btn btn-sm" disabled={busy === u.id} onClick={() => setResetting(u)}>
                                Reset two-step login…
                              </button>
                            )}
                            <button type="button" className="btn btn-sm btn-text btn-danger" disabled={busy === u.id} onClick={() => setDeleting(u)}>
                              Delete account…
                            </button>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {deleting && <DeleteUserModal user={deleting} call={call} onClose={() => setDeleting(null)} onDeleted={reload} />}
      {resetting && <ResetTwoFactorModal user={resetting} call={call} onClose={() => setResetting(null)} onDone={reload} />}
    </section>
  );
}

/** Turn off every two-step method of a user who lost them all, after the admin confirms who asked. */
function ResetTwoFactorModal({ user, call, onClose, onDone }: { user: User; call: Call; onClose: () => void; onDone: () => Promise<void> }) {
  const [checked, setChecked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!checked) return setError("Confirm that the account owner asked for this.");
    setBusy(true);
    setError(null);
    try {
      const r = await call<{ email_sent?: boolean }>(`/users/${encodeURIComponent(user.id)}/two-factor/reset`, { method: "POST" });
      toast(r?.email_sent ? `Two-step login turned off for ${user.email}. They were emailed.` : `Two-step login turned off for ${user.email}`);
      onClose();
      await onDone();
    } catch (err) {
      setBusy(false);
      if (err instanceof AdminError && err.status === 404) setError(`${user.email} no longer exists.`);
      else if (!(err instanceof AdminError && err.status === 401)) setError((err as Error).message);
    }
  }

  return (
    <Modal title="Reset two-step login?" subtitle={user.email} icon="shield" tone="danger" onClose={() => !busy && onClose()}>
      <form onSubmit={submit}>
        <p className="card-text">
          This turns off every two-step method for this account: authenticator app, email codes, security keys and recovery codes, and forgets the
          devices they marked as trusted. They can then sign in with their master password (and Secret Key, if they use one) and turn two-step login
          on again. Their vault stays encrypted and nothing else changes.
        </p>
        <p className="small muted">
          Only do this when you're sure the request comes from the account owner, for example in person or over a channel you already trust. They
          get an email about it if this server can send email.
        </p>
        <label className="check">
          <input type="checkbox" checked={checked} onChange={(e) => setChecked(e.target.checked)} data-autofocus="" />
          <span>I confirmed this request with the account owner</span>
        </label>
        <ErrorText error={error} />
        <SheetActions
          quiet={
            <button type="button" className="btn btn-text" onClick={onClose} disabled={busy}>
              Cancel
            </button>
          }
        >
          <button type="submit" className="btn btn-danger-solid btn-block" disabled={!checked || busy}>
            {busy ? "Resetting…" : "Reset two-step login"}
          </button>
        </SheetActions>
      </form>
    </Modal>
  );
}

function DeleteUserModal({ user, call, onClose, onDeleted }: { user: User; call: Call; onClose: () => void; onDeleted: () => Promise<void> }) {
  return (
    <ConfirmDialog
      title="Delete this account?"
      subtitle={user.email}
      icon="trash"
      action="Delete account"
      busyAction="Deleting account…"
      confirmText={user.email}
      matchCase={false}
      onClose={onClose}
      onConfirm={async () => {
        try {
          await call(`/users/${encodeURIComponent(user.id)}`, { method: "DELETE" });
        } catch (err) {
          // A lost admin session already sends the admin back to the token form.
          if (err instanceof AdminError && err.status === 401) return;
          throw err;
        }
        toast(`${user.email} was deleted`);
        onClose();
        await onDeleted();
      }}
    >
      <p className="card-text">
        This permanently deletes the account, every vault they own and all items in those vaults ({user.items.toLocaleString()}{" "}
        {user.items === 1 ? "item" : "items"}). They lose access to vaults shared with them. This cannot be undone.
      </p>
    </ConfirmDialog>
  );
}

// ---------------------------------------------------------------- invites

function InvitesCard({ invites, smtp, domain, call, reload }: { invites: Invite[]; smtp: boolean; domain: string; call: Call; reload: () => Promise<void> }) {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const now = Date.now() / 1000;

  async function invite(e: FormEvent) {
    e.preventDefault();
    const addr = email.trim();
    if (!addr.includes("@")) return setError("Enter a full email address, such as name@example.com.");
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const r = await call<{ invited: string; email_sent: boolean }>("/invites", { body: { email: addr } });
      setEmail("");
      setNotice(
        r.email_sent
          ? `Invitation sent to ${r.invited}. It is valid for 7 days.`
          : `Invitation saved for ${r.invited}, but email is not set up on this server. Send them this link yourself: ${domain}/register?email=${encodeURIComponent(r.invited)}`,
      );
      await reload();
    } catch (err) {
      if (!(err instanceof AdminError && err.status === 401)) setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function revoke(addr: string) {
    setError(null);
    setNotice(null);
    try {
      await call(`/invites/${encodeURIComponent(addr)}`, { method: "DELETE" });
      toast(`Invitation for ${addr} revoked`);
      await reload();
    } catch (err) {
      if (!(err instanceof AdminError && err.status === 401)) setError((err as Error).message);
    }
  }

  return (
    <section className="card" aria-labelledby="inv-title">
      <h2 id="inv-title">Invitations</h2>
      <p className="card-text">
        Invited people can create an account even when sign-ups are closed.{" "}
        {smtp ? "They receive an email with a sign-up link." : "Email is off, so share the sign-up link with them yourself."}
      </p>
      <form className="inline-form" onSubmit={invite}>
        <label className="field">
          <span>Email address</span>
          <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" placeholder="name@example.com" />
        </label>
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? "Sending invitation…" : smtp ? "Send invitation" : "Create invitation"}
        </button>
      </form>
      <ErrorText error={error} />
      {notice && (
        <div className="alert alert-ok wrap-anywhere" role="status">
          {notice}
        </div>
      )}
      {invites.length === 0 ? (
        <p className="muted">There are no open invitations.</p>
      ) : (
        <div className="fields" role="list" aria-label="Open invitations">
          {invites.map((i) => (
            <div key={i.email} role="listitem">
              <span className="tile" aria-hidden="true">
                <Icon name="mail" />
              </span>
              <span className="grow">
                <span className="row-title">{i.email}</span>
                <span className="row-sub" title={`Invited ${formatDateTime(i.created_at)}, expires ${formatDateTime(i.expires_at)}`}>
                  Invited {formatDate(i.created_at)}. {i.expires_at < now ? "The invitation has expired." : `Expires ${formatDate(i.expires_at)}.`}
                </span>
              </span>
              {i.expires_at < now && <span className="badge badge-warn">Expired</span>}
              <button type="button" className="btn btn-text btn-danger btn-sm" onClick={() => revoke(i.email)} aria-label={`Revoke invitation for ${i.email}`}>
                Revoke
              </button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

// ------------------------------------------------------------------- smtp

function SmtpCard({ smtp, call }: { smtp: boolean; call: Call }) {
  const [to, setTo] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState<string | null>(null);

  async function send(e: FormEvent) {
    e.preventDefault();
    const addr = to.trim();
    if (!addr.includes("@")) return setError("Enter a full email address, such as name@example.com.");
    setBusy(true);
    setError(null);
    setSent(null);
    try {
      await call("/smtp/test", { body: { to: addr } });
      setSent(`Test email sent to ${addr}. If it does not arrive within a few minutes, check the spam folder and the server logs.`);
    } catch (err) {
      if (!(err instanceof AdminError && err.status === 401)) setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card" aria-labelledby="smtp-title">
      <h2 id="smtp-title">Email delivery</h2>
      {smtp ? (
        <>
          <p className="card-text">Send a test message to confirm the server can deliver verification codes and invitations.</p>
          <form className="inline-form" onSubmit={send}>
            <label className="field">
              <span>Send test email to</span>
              <input className="input" type="email" value={to} onChange={(e) => setTo(e.target.value)} autoComplete="email" placeholder="you@example.com" />
            </label>
            <button type="submit" className="btn" disabled={busy}>
              {busy ? "Sending test email…" : "Send test email"}
            </button>
          </form>
          <ErrorText error={error} />
          {sent && (
            <div className="alert alert-ok" role="status">
              {sent}
            </div>
          )}
        </>
      ) : (
        <p className="card-text">
          Email is off. Set the SMTP settings in the server configuration and restart the server to send verification codes, invitations and test emails.
        </p>
      )}
    </section>
  );
}
