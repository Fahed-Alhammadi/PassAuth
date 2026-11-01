import { NavLink, Outlet } from "react-router";
import { Wordmark } from "../components/Logo";
import { Icon, type IconName } from "../components/ui";
import { lock, logout, useVault } from "../lib/vault";
import { kindOf, type ItemKind } from "../lib/types";

const KINDS: [ItemKind, string, IconName][] = [
  ["login", "Logins", "globe"],
  ["note", "Secure notes", "note"],
  ["card", "Cards", "card"],
  ["identity", "Identities", "person"],
  ["ssh_key", "SSH keys", "terminal"],
];

export const filterPath = (filter: string) => `/vault/${encodeURIComponent(filter)}`;

export function Shell() {
  const { items, vaults, emailVerified } = useVault();
  const live = items.filter((e) => !e.deletedAt);
  const count = (pred: (k: ItemKind) => boolean) => live.filter((e) => pred(kindOf(e.item))).length;
  const folders = [...new Set(live.map((e) => e.item.folder).filter((f): f is string => !!f))].sort();

  return (
    <div className="shell" data-shell>
      <aside className="sidebar">
        <Wordmark />
        <nav className="nav" aria-label="Items">
          <NavLink to={filterPath("all")} end>
            <Icon name="vault" /> All items <span className="count">{live.length}</span>
          </NavLink>
          <NavLink to={filterPath("favorites")}>
            <Icon name="star" /> Favorites <span className="count">{live.filter((e) => e.item.favorite).length}</span>
          </NavLink>
          {KINDS.map(([k, label, icon]) => (
            <NavLink key={k} to={filterPath(k)}>
              <Icon name={icon} /> {label} <span className="count">{count((x) => x === k)}</span>
            </NavLink>
          ))}
        </nav>
        {vaults.length > 1 && (
          <nav className="nav" aria-label="Vaults">
            <div className="nav-title">Vaults</div>
            {vaults.map((v) => (
              <NavLink key={v.id} to={filterPath(`vault:${v.id}`)}>
                <Icon name={v.kind === "sealed" ? "share" : "lock"} /> {v.name}
              </NavLink>
            ))}
          </nav>
        )}
        {folders.length > 0 && (
          <nav className="nav" aria-label="Folders">
            <div className="nav-title">Folders</div>
            {folders.map((f) => (
              <NavLink key={f} to={filterPath(`folder:${f}`)}>
                <Icon name="note" /> {f}
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
          <NavLink to={filterPath("trash")}>
            <Icon name="trash" /> Trash
          </NavLink>
        </nav>
        <nav className="nav sidebar-foot" aria-label="Account">
          <NavLink to="/settings">
            <Icon name="settings" /> <span className="label">Settings</span>
          </NavLink>
          <button type="button" onClick={lock}>
            <Icon name="lock" /> <span className="label">Lock</span>
          </button>
          <button type="button" onClick={logout}>
            <Icon name="logout" /> <span className="label">Sign out</span>
          </button>
        </nav>
      </aside>
      {!emailVerified && (
        <div className="alert alert-brass small" style={{ position: "fixed", top: 12, right: 12, zIndex: 30, maxWidth: 360 }}>
          Confirm your email address to receive security alerts. Check your inbox for the verification link.
        </div>
      )}
      <Outlet />
    </div>
  );
}
