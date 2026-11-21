/**
 * Password health: the "Website matching" section. Lists logins whose websites have their own match, grouped by base
 * domain, and sets the checked groups to "Default" so each app's "Default URI match detection" setting applies. The
 * rules are in `lib/matching.ts`; the write is the vault's own `updateItem`.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { ConfirmDialog, Icon, SiteIcon, toast } from "../components/ui";
import { applyDefaultMatch, findMatchGroups, matchLabel, onlyBaseDomain, type MatchGroup } from "../lib/matching";
import { useSiteIconsShown } from "../lib/site-icons";
import type { VaultEntry } from "../lib/types";
import { getState, updateItem, useVault } from "../lib/vault";
import { baseDomain } from "../wasm/passauth_core";
import "../styles/duplicates.css";
import "../styles/matching.css";

type Group = MatchGroup<VaultEntry>;

const count = (n: number, one: string, many: string) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
const nameOf = (e: VaultEntry) => e.item.name || "Untitled";

function useOnline(): boolean {
  const [online, setOnline] = useState(() => navigator.onLine);
  useEffect(() => {
    const on = () => setOnline(true);
    const off = () => setOnline(false);
    window.addEventListener("online", on);
    window.addEventListener("offline", off);
    return () => {
      window.removeEventListener("online", on);
      window.removeEventListener("offline", off);
    };
  }, []);
  return online;
}

function useMatchReport() {
  const { items, vaults, offlineChanges, deviceRecordUnreadable } = useVault();
  return useMemo(() => {
    const writable = new Set(vaults.filter((v) => v.role !== "read" && !v.manifestWarning && !deviceRecordUnreadable).map((v) => v.id));
    const pending = new Set(offlineChanges.map((c) => c.item_id));
    return findMatchGroups(items, { baseDomain, writableVault: (id) => writable.has(id), pending });
  }, [items, vaults, offlineChanges, deviceRecordUnreadable]);
}

export function MatchingSection() {
  const { groups, left } = useMatchReport();
  const showIcons = useSiteIconsShown();
  const online = useOnline();
  const heading = useRef<HTMLHeadingElement>(null);
  // Groups that are all "Base domain" start checked; the others (Default could widen them) unchecked. `flipped`
  // holds the groups the user switched from that start.
  const [flipped, setFlipped] = useState<Set<string>>(() => new Set());
  const isChecked = (g: MatchGroup) => onlyBaseDomain(g) !== flipped.has(g.domain);
  const [confirming, setConfirming] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);

  const chosen = groups.filter(isChecked);
  const widens = chosen.some((g) => !onlyBaseDomain(g));
  const chosenLogins = new Set(chosen.flatMap((g) => g.logins.map((l) => l.entry.id))).size;
  const chosenWebsites = chosen.reduce((n, g) => n + g.websites, 0);

  const toggle = (domain: string) =>
    setFlipped((s) => {
      const next = new Set(s);
      if (next.has(domain)) next.delete(domain);
      else next.add(domain);
      return next;
    });

  async function apply() {
    setProblem(null);
    try {
      const done = await applyDefaultMatch(chosen, new Set(chosen.map((g) => g.domain)), {
        update: (entry, item) => updateItem(entry, item),
        current: (id) => getState().items.find((e) => e.id === id),
        baseDomain,
      });
      setConfirming(false);
      toast(`${count(done.websites, "website", "websites")} in ${count(done.logins, "login", "logins")} now use the default match.`);
    } catch (e) {
      setConfirming(false);
      setProblem(e instanceof Error ? e.message : String(e));
    }
    heading.current?.focus();
  }

  return (
    <section className="card dup-section" aria-labelledby="health-matching">
      <div className="card-head">
        <div className="card-title">
          <h2 id="health-matching" ref={heading} tabIndex={-1}>
            Website matching
          </h2>
          {groups.length > 0 && <span className="badge">{groups.length}</span>}
        </div>
      </div>
      <p className="card-text">
        Websites set to Default follow the Default URI match detection setting of each app (Host, Base domain…). Websites with their own match ignore it.
      </p>

      {problem && (
        <div className="alert alert-error" role="alert">
          {problem}
        </div>
      )}

      {groups.length === 0 ? (
        <div className="health-clear">
          <span className="tile tile-ok" aria-hidden="true">
            <Icon name="check" />
          </span>
          <span className="grow">
            <span className="row-title">Every website uses the default match</span>
            <span className="row-sub">A website shows here when it has its own match, such as Host or Base domain.</span>
          </span>
        </div>
      ) : (
        <>
          <ul className="dup-list" aria-labelledby="health-matching">
            {groups.map((g) => (
              <GroupRow key={g.domain} group={g} checked={isChecked(g)} showIcons={showIcons} onToggle={() => toggle(g.domain)} />
            ))}
          </ul>
          {!online && <p className="small muted">You're offline. Changing logins needs a connection to your server.</p>}
          <div className="match-actions">
            <button type="button" className="btn btn-primary" disabled={!online || chosen.length === 0} onClick={() => setConfirming(true)}>
              Use the default match
            </button>
          </div>
        </>
      )}

      {left > 0 && <p className="small muted">{count(left, "website uses", "websites use")} a regular expression or Never and {left === 1 ? "is" : "are"} left as {left === 1 ? "it is" : "they are"}.</p>}

      {confirming && (
        <ConfirmDialog
          title="Use the default match?"
          icon="info"
          danger={false}
          action={`Change ${count(chosenLogins, "login", "logins")}`}
          busyAction="Saving…"
          onConfirm={apply}
          onClose={() => setConfirming(false)}
        >
          <p>
            {count(chosenWebsites, "website", "websites")} in {count(chosenLogins, "login", "logins")} will follow the Default URI match detection setting of each
            app. You can change a website's match again in the login.
          </p>
          {widens && (
            <p>
              Some of them use Host, Starts with or Exact. In an app whose setting is Base domain, those logins will be offered on every site of
              their domain.
            </p>
          )}
        </ConfirmDialog>
      )}
    </section>
  );
}

function GroupRow({ group, checked, showIcons, onToggle }: { group: Group; checked: boolean; showIcons: boolean; onToggle: () => void }) {
  const id = `match-${group.domain}`;
  return (
    <li className="dup-row match-row">
      <input id={id} type="checkbox" className="match-check" checked={checked} onChange={onToggle} />
      <SiteIcon host={group.domain} name={group.domain} enabled={showIcons} />
      <div className="dup-row-text">
        <label htmlFor={id} className="dup-row-site" title={group.domain}>
          {group.domain}
        </label>
        <span className="dup-row-names">
          {count(group.logins.length, "login", "logins")}, {count(group.websites, "website", "websites")}
        </span>
        <ul className="match-logins">
          {group.logins.map((l) => (
            <li key={l.entry.id} className="match-login">
              <span className="match-login-name" title={nameOf(l.entry)}>
                {nameOf(l.entry)}
                {l.entry.item.login?.username && <span className="muted">{` · ${l.entry.item.login.username}`}</span>}
              </span>
              {l.urls.map((u, n) => (
                <span key={`${n}\u0000${u.url}`} className="match-url">
                  <span className="match-url-text" title={u.url}>
                    {u.url}
                  </span>
                  <span className="dup-chip">{matchLabel(u.match)}</span>
                </span>
              ))}
            </li>
          ))}
        </ul>
      </div>
    </li>
  );
}
