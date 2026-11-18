import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router";
import { SignInRequestSheet } from "../components/DeviceSignIn";
import { SigningNotices } from "../components/SignedSharing";
import { StartNewListButton, UseServerListButton } from "../components/EmergencyRoster";
import { Wordmark } from "../components/Logo";
import { ConfirmDialog, Icon, toast, type IconName } from "../components/ui";
import { SERVER_UPDATE_NEEDED, api, friendlyError, hasFeature, usePolicies, usePublicConfig } from "../lib/api";
import { keepDraftFor } from "../lib/drafts";
import { invitationNotice, invitationsKey } from "../lib/invitations";
import { getDesktop } from "../lib/platform";
import { USE_SERVER_COPY, USE_SERVER_COPY_BODY, USE_SERVER_COPY_TITLE, VAULT_WARNING, VAULT_WARNING_READER } from "../lib/manifest";
import { exportAllowed, policyNotices, violationsKey } from "../lib/policies";
import { ROSTER_ROLLED_BACK, ROSTER_UNREADABLE } from "../lib/emergency-client";
import { acceptServerCopy, dismissWarnings, lock, logout, useVault } from "../lib/vault";
import { isTrashed, kindOf, type ItemKind } from "../lib/types";

const KINDS: [ItemKind, string, IconName][] = [
  ["login", "Logins", "globe"],
  ["note", "Secure notes", "note"],
  ["card", "Cards", "card"],
  ["identity", "Identities", "person"],
  ["ssh_key", "SSH keys", "terminal"],
];

export const filterPath = (filter: string) => `/vault/${encodeURIComponent(filter)}`;

/** Item counts for the sidebar, in one pass over the vault. */
function useCounts() {
  const { items } = useVault();
  const counts = { all: 0, favorites: 0, login: 0, note: 0, card: 0, identity: 0, ssh_key: 0 } as Record<string, number>;
  const folders = new Set<string>();
  for (const e of items) {
    if (isTrashed(e)) continue;
    counts.all++;
    if (e.item.favorite) counts.favorites++;
    counts[kindOf(e.item)]++;
    if (e.item.folder) folders.add(e.item.folder);
  }
  return { counts, folders: [...folders].sort() };
}

export function Shell() {
  const { vaults, invitations } = useVault();
  const { counts, folders } = useCounts();
  const lockShortcut = getDesktop()?.lockShortcut;
  const canExport = exportAllowed(usePolicies());
  const sends = hasFeature(usePublicConfig(), "sends");
  // A prepared edit (desktop) lives only while its item's route is open.
  const { pathname } = useLocation();
  useEffect(() => keepDraftFor(pathname), [pathname]);

  return (
    <div className="shell" data-shell>
      <aside className="sidebar">
        <Wordmark />
        <nav className="nav" aria-label="Items">
          <NavLink to={filterPath("all")} end>
            <Icon name="vault" /> <span className="label">All items</span> <span className="count">{counts.all}</span>
          </NavLink>
          <NavLink to={filterPath("favorites")}>
            <Icon name="star" /> <span className="label">Favorites</span> <span className="count">{counts.favorites}</span>
          </NavLink>
          {KINDS.map(([k, label, icon]) => (
            <NavLink key={k} to={filterPath(k)}>
              <Icon name={icon} /> <span className="label">{label}</span> <span className="count">{counts[k]}</span>
            </NavLink>
          ))}
        </nav>
        {vaults.length > 1 && (
          <nav className="nav" aria-label="Vaults">
            <div className="nav-title">Vaults</div>
            {vaults.map((v) => (
              <NavLink key={v.id} to={filterPath(`vault:${v.id}`)}>
                <Icon name={v.kind === "sealed" ? "share" : "lock"} /> <span className="label">{v.name}</span>
              </NavLink>
            ))}
          </nav>
        )}
        {folders.length > 0 && (
          <nav className="nav" aria-label="Folders">
            <div className="nav-title">Folders</div>
            {folders.map((f) => (
              <NavLink key={f} to={filterPath(`folder:${f}`)}>
                <Icon name="folder" /> <span className="label">{f}</span>
              </NavLink>
            ))}
          </nav>
        )}
        <nav className="nav" aria-label="Tools">
          <div className="nav-title">Tools</div>
          <NavLink to="/generator">
            <Icon name="dice" /> Generator
          </NavLink>
          <NavLink to="/health">
            <Icon name="shield" /> Password health
          </NavLink>
          {sends && (
            <NavLink to="/sends">
              <Icon name="send" /> Send
            </NavLink>
          )}
          <NavLink to="/import">
            <Icon name="upload" /> Import
          </NavLink>
          {canExport && (
            <NavLink to="/export">
              <Icon name="download" /> Export
            </NavLink>
          )}
          <NavLink to={filterPath("trash")}>
            <Icon name="trash" /> Trash
          </NavLink>
        </nav>
        <nav className="nav sidebar-foot" aria-label="Account">
          <NavLink to="/settings">
            <Icon name="settings" /> <span className="label">Settings</span>
            {invitations.length > 0 && (
              <span className="count" title={invitations.length === 1 ? "1 vault invitation" : `${invitations.length} vault invitations`}>
                {invitations.length}
                <span className="sr-only"> {invitations.length === 1 ? "invitation" : "invitations"}</span>
              </span>
            )}
          </NavLink>
          <button type="button" onClick={() => lock()}>
            <Icon name="lock" /> Lock
            {lockShortcut && <kbd className="nav-kbd">{lockShortcut}</kbd>}
          </button>
          <button type="button" onClick={logout}>
            <Icon name="logout" /> Sign out
          </button>
        </nav>
      </aside>
      <Outlet />
      {/* A device asking to sign in to this account: the approval sheet, on every page of the vault. */}
      <SignInRequestSheet />
      <nav className="tabbar" aria-label="Main">
        <NavLink to="/vault">
          <Icon name="vault" size={22} /> Vault
        </NavLink>
        <NavLink to="/generator">
          <Icon name="dice" size={22} /> Generator
        </NavLink>
        <NavLink to="/settings">
          <Icon name="settings" size={22} /> Settings
        </NavLink>
        <button type="button" onClick={() => lock()}>
          <Icon name="lock" size={22} /> Lock
        </button>
      </nav>
    </div>
  );
}

/** Phones: the sidebar's filters and tools as one select above the item list. */
export function FilterSelect({ filter }: { filter: string }) {
  const nav = useNavigate();
  const { vaults } = useVault();
  const { counts, folders } = useCounts();
  const canExport = exportAllowed(usePolicies());
  const sends = hasFeature(usePublicConfig(), "sends");
  return (
    <label className="field list-filter">
      <span className="sr-only">Show</span>
      <select
        className="select"
        value={filter}
        onChange={(e) => {
          const v = e.target.value;
          if (v === "#health") nav("/health");
          else if (v === "#sends") nav("/sends");
          else if (v === "#import") nav("/import");
          else if (v === "#export") nav("/export");
          else if (v === "#signout") logout();
          else nav(filterPath(v));
        }}
      >
        <optgroup label="Items">
          <option value="all">All items ({counts.all})</option>
          <option value="favorites">Favorites ({counts.favorites})</option>
          {KINDS.map(([k, label]) => (
            <option key={k} value={k}>
              {label} ({counts[k]})
            </option>
          ))}
        </optgroup>
        {vaults.length > 1 && (
          <optgroup label="Vaults">
            {vaults.map((v) => (
              <option key={v.id} value={`vault:${v.id}`}>
                {v.name}
              </option>
            ))}
          </optgroup>
        )}
        {folders.length > 0 && (
          <optgroup label="Folders">
            {folders.map((f) => (
              <option key={f} value={`folder:${f}`}>
                {f}
              </option>
            ))}
          </optgroup>
        )}
        <optgroup label="More">
          <option value="trash">Trash</option>
          <option value="#health">Password health…</option>
          {sends && <option value="#sends">Send…</option>}
          <option value="#import">Import…</option>
          {canExport && <option value="#export">Export…</option>}
          <option value="#signout">Sign out</option>
        </optgroup>
      </select>
    </label>
  );
}

const VERIFY_DISMISSED = "pa.verify-dismissed";
/** The invitations whose notice was dismissed in this tab (a new invitation shows it again). */
const INVITATIONS_DISMISSED = "pa.invitations-dismissed";
/** The policy violations whose notice was dismissed in this tab (another set shows it again). */
const POLICY_DISMISSED = "pa.policy-dismissed";

function readSession(key: string): string | null {
  try {
    return sessionStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeSession(key: string, value: string) {
  try {
    sessionStorage.setItem(key, value);
  } catch {
    /* ignore */
  }
}

/**
 * Vault manifests: one warning for each vault whose items don't match its record of changes (`Vault.manifestWarning`).
 * The vault stays readable and takes no changes; someone who can edit it may accept the server's copy, after a
 * confirmation that says what that means.
 */
export function ManifestNotices() {
  const { vaults } = useVault();
  const [asking, setAsking] = useState<string | null>(null);
  const flagged = vaults.filter((v) => v.manifestWarning);
  const target = flagged.find((v) => v.id === asking);
  if (!flagged.length) return null;
  return (
    <>
      {flagged.map((v) => (
        <div key={v.id} className="alert alert-warn small notice" role="alert" data-manifest-warning={v.id}>
          <div className="grow">
            <span>
              <strong>{v.name}:</strong> {VAULT_WARNING}
            </span>
            <div className="row">
              {v.role === "read" ? (
                <span className="muted">{VAULT_WARNING_READER}</span>
              ) : (
                <button type="button" className="link" onClick={() => setAsking(v.id)}>
                  {USE_SERVER_COPY}
                </button>
              )}
            </div>
          </div>
        </div>
      ))}
      {target && (
        <ConfirmDialog
          title={USE_SERVER_COPY_TITLE}
          subtitle={target.name}
          icon="shield"
          action={USE_SERVER_COPY}
          onClose={() => setAsking(null)}
          onConfirm={async () => {
            await acceptServerCopy(target.id);
            setAsking(null);
          }}
        >
          <p className="card-text">{USE_SERVER_COPY_BODY}</p>
        </ConfirmDialog>
      )}
    </>
  );
}

/** Account and vault notices shown above the item list, in the page flow (never over the toolbar). */
export function Notices() {
  const { email, emailVerified, warnings, pendingRotations, vaults, invitations, policyViolations, emergencyNotice, serverOutdated } = useVault();
  const policies = usePolicies();
  const [hideVerify, setHideVerify] = useState(() => readSession(VERIFY_DISMISSED) === "1");
  const [invitesDismissed, setInvitesDismissed] = useState(() => readSession(INVITATIONS_DISMISSED));
  const [policyDismissed, setPolicyDismissed] = useState(() => readSession(POLICY_DISMISSED));
  const [sending, setSending] = useState(false);
  const rotating = vaults.filter((v) => pendingRotations.includes(v.id));
  const invitesKey = invitationsKey(invitations);
  const invitesText = invitesDismissed === invitesKey ? null : invitationNotice(invitations);
  const policyKey = `${email}|${violationsKey(policyViolations)}`;
  const policyLines = policyDismissed === policyKey ? [] : policyNotices(policyViolations, policies);
  // One link per destination (a Secret Key change also re-creates the keys), the first one's wording.
  const policyActions = policyLines.flatMap((n) => (n.action ? [n.action] : [])).filter((a, i, all) => all.findIndex((b) => b.to === a.to) === i);

  async function resend() {
    setSending(true);
    try {
      await api("/auth/verify-email/resend", { body: { email }, auth: false });
      toast("Verification link sent. Check your inbox.");
    } catch (e) {
      toast(friendlyError(e));
    } finally {
      setSending(false);
    }
  }

  return (
    <>
      {serverOutdated && (
        <div className="alert alert-warn small notice" role="alert" data-server-outdated>
          <div className="grow">
            <span>{SERVER_UPDATE_NEEDED} Changes aren't saved or synced until then.</span>
          </div>
        </div>
      )}
      {policyLines.length > 0 && (
        <div className="alert alert-warn small notice" role="note">
          <div className="grow">
            {policyLines.length === 1 ? (
              <span>{policyLines[0].text}</span>
            ) : (
              <ul>
                {policyLines.map((n) => (
                  <li key={n.violation}>{n.text}</li>
                ))}
              </ul>
            )}
            {policyActions.length > 0 && (
              <div className="row">
                {policyActions.map((a) => (
                  <Link key={a.to} to={a.to}>
                    {a.label}
                  </Link>
                ))}
              </div>
            )}
          </div>
          <button
            type="button"
            className="btn btn-icon"
            aria-label="Dismiss"
            onClick={() => {
              setPolicyDismissed(policyKey);
              writeSession(POLICY_DISMISSED, policyKey);
            }}
          >
            <Icon name="close" size={16} />
          </button>
        </div>
      )}
      {!emailVerified && !hideVerify && (
        <div className="alert alert-info small notice" role="note">
          <div className="grow">
            <span>Confirm your email address to receive security alerts. Check your inbox for the verification link.</span>
            <div className="row">
              <button type="button" className="link" onClick={resend} disabled={sending}>
                {sending ? "Sending…" : "Resend link"}
              </button>
            </div>
          </div>
          <button
            type="button"
            className="btn btn-icon"
            aria-label="Dismiss"
            onClick={() => {
              setHideVerify(true);
              writeSession(VERIFY_DISMISSED, "1");
            }}
          >
            <Icon name="close" size={16} />
          </button>
        </div>
      )}
      {invitesText && (
        <div className="alert alert-info small notice" role="note">
          <div className="grow">
            <span>
              {invitesText} Nothing from {invitations.length === 1 ? "it" : "them"} reaches your apps until you accept.
            </span>
            <div className="row">
              <Link to="/settings/vaults">{invitations.length === 1 ? "See the invitation" : "See the invitations"}</Link>
            </div>
          </div>
          <button
            type="button"
            className="btn btn-icon"
            aria-label="Dismiss"
            onClick={() => {
              setInvitesDismissed(invitesKey);
              writeSession(INVITATIONS_DISMISSED, invitesKey);
            }}
          >
            <Icon name="close" size={16} />
          </button>
        </div>
      )}
      {rotating.length > 0 && (
        <div className="alert alert-warn small notice" role="alert">
          <div className="grow">
            <span>
              Someone who had the key of {rotating.map((v) => `"${v.name}"`).join(", ")} left or was removed (a member, or an emergency contact), but the key
              wasn't replaced yet, so they could still read new items.
            </span>
            <div className="row">
              <Link to="/settings/vaults">Finish securing the vault</Link>
            </div>
          </div>
        </div>
      )}
      {emergencyNotice && (
        <div className="alert alert-warn small notice" role="alert">
          <div className="grow">
            <span>{emergencyNotice}</span>
            <div className="row">
              {emergencyNotice === ROSTER_ROLLED_BACK && <UseServerListButton />}
              {emergencyNotice === ROSTER_UNREADABLE && <StartNewListButton />}
              <Link to="/settings/emergency">Emergency access</Link>
            </div>
          </div>
        </div>
      )}
      <SigningNotices link />
      <ManifestNotices />
      {warnings.length > 0 && (
        <div className="alert alert-warn small notice" role="alert">
          <div className="grow">
            <ul>
              {[...new Set(warnings)].map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
            <div className="row">
              <Link to="/settings/vaults">Vaults & sharing</Link>
            </div>
          </div>
          <button type="button" className="btn btn-icon" aria-label="Dismiss" onClick={dismissWarnings}>
            <Icon name="close" size={16} />
          </button>
        </div>
      )}
    </>
  );
}
