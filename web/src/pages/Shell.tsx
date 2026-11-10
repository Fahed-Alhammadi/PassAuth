import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router";
import { Wordmark } from "../components/Logo";
import { Icon, toast, type IconName } from "../components/ui";
import { api, friendlyError } from "../lib/api";
import { keepDraftFor } from "../lib/drafts";
import { getDesktop } from "../lib/platform";
import { dismissWarnings, lock, logout, useVault } from "../lib/vault";
import { kindOf, type ItemKind } from "../lib/types";

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
    if (e.deletedAt) continue;
    counts.all++;
    if (e.item.favorite) counts.favorites++;
    counts[kindOf(e.item)]++;
    if (e.item.folder) folders.add(e.item.folder);
  }
  return { counts, folders: [...folders].sort() };
}

export function Shell() {
  const { vaults } = useVault();
  const { counts, folders } = useCounts();
  const lockShortcut = getDesktop()?.lockShortcut;
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
          <NavLink to="/import">
            <Icon name="upload" /> Import
          </NavLink>
          <NavLink to="/export">
            <Icon name="download" /> Export
          </NavLink>
          <NavLink to={filterPath("trash")}>
            <Icon name="trash" /> Trash
          </NavLink>
        </nav>
        <nav className="nav sidebar-foot" aria-label="Account">
          <NavLink to="/settings">
            <Icon name="settings" /> Settings
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
  return (
    <label className="field list-filter">
      <span className="sr-only">Show</span>
      <select
        className="select"
        value={filter}
        onChange={(e) => {
          const v = e.target.value;
          if (v === "#import") nav("/import");
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
          <option value="#import">Import…</option>
          <option value="#export">Export…</option>
          <option value="#signout">Sign out</option>
        </optgroup>
      </select>
    </label>
  );
}

const VERIFY_DISMISSED = "pa.verify-dismissed";

/** Account and vault notices shown above the item list, in the page flow (never over the toolbar). */
export function Notices() {
  const { email, emailVerified, warnings, pendingRotations, vaults } = useVault();
  const [hideVerify, setHideVerify] = useState(() => {
    try {
      return sessionStorage.getItem(VERIFY_DISMISSED) === "1";
    } catch {
      return false;
    }
  });
  const [sending, setSending] = useState(false);
  const rotating = vaults.filter((v) => pendingRotations.includes(v.id));

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
              try {
                sessionStorage.setItem(VERIFY_DISMISSED, "1");
              } catch {
                /* ignore */
              }
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
              Someone left or was removed from {rotating.map((v) => `"${v.name}"`).join(", ")}, but the vault key wasn't replaced yet, so they could still
              read new items.
            </span>
            <div className="row">
              <Link to="/settings/vaults">Finish securing the vault</Link>
            </div>
          </div>
        </div>
      )}
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
